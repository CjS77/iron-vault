// SPDX-License-Identifier: MPL-2.0
//! Runs the host unlock at startup
//! ([Docker Compose: In the container](../../../../design/docker-compose.md#in-the-container);
//! [specification §15](../../../../design/iron-vault-specification.md#15-service-states-and-errors)). A Protected or
//! Container service leaves Starting for Checking when the unlock handoff opens the vault, and for Locked otherwise.
//!
//! ```text
//!   Starting
//!     owner-lock file present? ──yes──▶ Locked   owner_locked
//!     memory locked?           ──no───▶ Locked   refused: memory_unprotected
//!     handoff present?         ──no───▶ Locked   absent, or unseal_failed beside the unseal-failure file
//!     handoff trusted and readable, an identity, vault Initialized, identity.age wrapped for it?
//!                              ──no───▶ Locked   refused: untrusted, unreadable, not_an_identity, not_initialized,
//!                                                not_a_recipient
//!                              ──yes──▶ Checking ──▶ Ready or Unavailable   unlocked
//! ```
//!
//! Every step's failure leaves the service Locked with passphrase `unlock` still offered, since the operational
//! identity is still a recipient. None counts toward the passphrase attempt limit: a host unlock failure is not a
//! guess, and only root can change the file.

use std::path::Path;
use std::sync::Arc;

use iron_vault_store::{
    EnvelopeError, RecipientKey, StoreFs, UnlockError, VaultIdentity, read_identity_envelope, require_initialized, unwrap_identity,
};

use super::unlock::log_foreign_files;
use super::{Inner, ServiceContext, ServiceLocks, ServiceSetup, apply};
use crate::audit::AuditEvent;
use crate::audit::vault::HostUnlock;
use crate::deployment::DeploymentProfile;
use crate::service_state::{ServiceEvent, ServiceState};
use crate::unlock_handoff::UNSEAL_FAILED_NAME;
use crate::unlock_handoff::{HandoffError, read_handoff, unseal_failed_present};

/// What one host unlock attempt came to, as `vault.host-unlock` records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostUnlockOutcome {
    /// The handoff unwrapped the vault identity, and the config check followed.
    Unlocked,
    /// Neither the handoff nor the unseal-failure file was there: a machine never provisioned for host unlock.
    Absent,
    /// No handoff was there, but the handoff unit left the unseal-failure file: its unseal failed, as after a `dbx`
    /// or KEK update changes PCR 7. The file is a diagnostic only; the service waits Locked for passphrase `unlock`,
    /// as for `Absent`.
    UnsealFailed,
    /// The owner-lock file is there: an explicit `lock` stands, so the handoff and the memory guard were never reached.
    OwnerLocked,
    /// The handoff was there, or memory was not locked, and the vault stayed shut.
    Refused(HostUnlockRefusal),
}

/// Why a host unlock left the service Locked. No variant carries the handoff's bytes or its recipient key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostUnlockRefusal {
    /// Memory is not locked against swap, so the handoff was never opened
    /// ([specification §14](../../../../design/iron-vault-specification.md#14-recipients-startup-and-memory)).
    MemoryUnprotected,
    /// The handoff or a directory above it broke the `UnlockHandoff` trusted-path rule.
    Untrusted,
    /// The handoff, the state directory or `identity.age` could not be read, or `identity.age` is malformed.
    Unreadable,
    /// The handoff is not one `age` secret key.
    NotAnIdentity,
    /// The vault is not Initialized.
    NotInitialized,
    /// `identity.age` is not wrapped for the handoff's identity.
    NotARecipient,
}

impl HostUnlockOutcome {
    /// Returns the snake_case label that the `host_unlock_outcome` field records, such as `unseal_failed`.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Unlocked => "unlocked",
            Self::Absent => "absent",
            Self::UnsealFailed => "unseal_failed",
            Self::OwnerLocked => "owner_locked",
            Self::Refused(_) => "refused",
        }
    }
}

impl HostUnlockRefusal {
    /// Returns the snake_case label that the `refusal` field records, such as `not_a_recipient`.
    pub const fn label(self) -> &'static str {
        match self {
            Self::MemoryUnprotected => "memory_unprotected",
            Self::Untrusted => "untrusted",
            Self::Unreadable => "unreadable",
            Self::NotAnIdentity => "not_an_identity",
            Self::NotInitialized => "not_initialized",
            Self::NotARecipient => "not_a_recipient",
        }
    }
}

impl From<HandoffError> for HostUnlockRefusal {
    fn from(error: HandoffError) -> Self {
        match error {
            HandoffError::Untrusted(_) => Self::Untrusted,
            HandoffError::TooLong | HandoffError::NotAnIdentity => Self::NotAnIdentity,
            HandoffError::Unreadable(_) => Self::Unreadable,
        }
    }
}

impl From<UnlockError> for HostUnlockRefusal {
    fn from(error: UnlockError) -> Self {
        match error {
            UnlockError::Read(_) | UnlockError::InitializationState(_) | UnlockError::ListStateDir { .. } => Self::Unreadable,
            _ => Self::NotInitialized,
        }
    }
}

impl From<EnvelopeError> for HostUnlockRefusal {
    fn from(error: EnvelopeError) -> Self {
        match error {
            EnvelopeError::NotARecipient => Self::NotARecipient,
            _ => Self::Unreadable,
        }
    }
}

impl<F: StoreFs + Send + Sync + 'static> ServiceContext<F> {
    /// Leaves Starting: goes to Checking when the unlock handoff at `handoff` opens the vault, then on to Ready or
    /// Unavailable as the config check settles, and to Locked otherwise. Call it once, right after
    /// [`start`](Self::start).
    ///
    /// Only the Protected and Container profiles try a host unlock, and only they leave `start` in Starting; in any
    /// other state this returns the state unchanged, so a Development service stays Locked, as `start` left it. Each
    /// attempt writes one `vault.host-unlock` record. The owner-lock file is read first, before the memory guard and
    /// before the handoff is opened: while anything is at that name the attempt is `owner_locked` and the service
    /// goes to Locked. Host unlock never removes the file.
    ///
    /// Cancel-safe once the service enters Checking, as [`enter_checking`](Self::enter_checking) is. A future dropped
    /// before then leaves the service in Starting, which refuses requests as Locked does and unlocks nothing.
    pub async fn unlock_at_start(&self, handoff: &Path) -> ServiceState {
        let service_wide = Arc::clone(&self.service_wide).lock_owned().await;
        let mut inner = Arc::clone(&self.inner).lock_owned().await;
        if inner.state != ServiceState::Starting {
            return inner.state;
        }
        if self.owner_lock_present().await {
            record_and_emit(&mut inner, HostUnlockOutcome::OwnerLocked);
            return apply(&self.holder, &mut inner, ServiceEvent::InteractiveUnlockRequired).unwrap_or(inner.state);
        }
        let opened = self.open_with_handoff(handoff).await;
        let outcome = match opened {
            Ok(None) => self.missing_handoff_outcome(handoff).await,
            _ => outcome_of(&opened),
        };
        record_and_emit(&mut inner, outcome);
        match opened {
            Ok(Some(identity)) => self
                .check_and_settle_detached(service_wide, inner, ServiceEvent::HostUnlockSucceeded, Arc::new(identity))
                .await
                .unwrap_or_else(|illegal| illegal.state),
            Ok(None) | Err(_) => apply(&self.holder, &mut inner, ServiceEvent::InteractiveUnlockRequired).unwrap_or(inner.state),
        }
    }

    /// Returns the vault identity the handoff unwraps, or `None` when there is no handoff. The memory guard comes
    /// first, so without locked memory the file is never opened. The rest reads files, so it runs on the blocking pool.
    async fn open_with_handoff(&self, handoff: &Path) -> Result<Option<VaultIdentity>, HostUnlockRefusal> {
        self.require_locked_memory().map_err(|_| HostUnlockRefusal::MemoryUnprotected)?;
        let (locks, setup, handoff) = (Arc::clone(&self.locks), Arc::clone(&self.setup), handoff.to_path_buf());
        tokio::task::spawn_blocking(move || unwrap_with_handoff(&locks, &setup, &handoff))
            .await
            .unwrap_or(Err(HostUnlockRefusal::Unreadable))
    }

    /// Returns `UnsealFailed` when the unseal-failure file sits beside the missing `handoff`, and `Absent` otherwise.
    /// The file is read only now, so a handoff that is there is never second-guessed by a stale one.
    async fn missing_handoff_outcome(&self, handoff: &Path) -> HostUnlockOutcome {
        let (owner, flag) = (self.unseal_failure_owner, handoff.with_file_name(UNSEAL_FAILED_NAME));
        let present = tokio::task::spawn_blocking(move || unseal_failed_present(owner, &flag)).await;
        match present {
            Ok(true) => HostUnlockOutcome::UnsealFailed,
            _ => HostUnlockOutcome::Absent,
        }
    }

    /// Returns the recipient key of the configured host unlock adapter, which part 1 of the independence rule keeps:
    /// the identity the unlock handoff holds now, in the Protected and Container profiles
    /// ([TPM unlock: The recipient role](../../../../design/tpm-unlock.md#the-recipient-role);
    /// [Docker Compose: Its role among the recipients](../../../../design/docker-compose.md#its-role-among-the-recipients)).
    /// With no readable handoff, or in a Development service, which has none, no host unlock is configured and this
    /// returns `None`. The identity is dropped as this returns; only its public key is kept.
    pub(super) async fn configured_host_unlock(&self) -> Option<RecipientKey> {
        let setup = Arc::clone(&self.setup);
        if !tries_host_unlock(setup.paths.profile) {
            return None;
        }
        let path = self.handoff.clone();
        let read = tokio::task::spawn_blocking(move || read_handoff(setup.paths.profile, setup.paths.owner, &path)).await;
        match read {
            Ok(Ok(Some(host))) => Some(host.recipient_key()),
            _ => None,
        }
    }
}

/// Reads the handoff, requires an Initialized vault and unwraps `identity.age` with the handoff's identity, which is
/// dropped, its key bytes cleared, as this returns.
fn unwrap_with_handoff<F: StoreFs>(
    locks: &ServiceLocks,
    setup: &ServiceSetup<F>,
    handoff: &Path,
) -> Result<Option<VaultIdentity>, HostUnlockRefusal> {
    let Some(host) = read_handoff(setup.paths.profile, setup.paths.owner, handoff)? else {
        return Ok(None);
    };
    log_foreign_files(&require_initialized(&locks.state, &locks.config, &setup.fs)?);
    let envelope = read_identity_envelope(&locks.state, &setup.fs).map_err(|_| HostUnlockRefusal::Unreadable)?;
    Ok(Some(unwrap_identity(&envelope, &host)?))
}

/// Keeps the startup outcome for `status` and writes its `vault.host-unlock` record, so no path through the attempt
/// does one without the other.
fn record_and_emit(inner: &mut Inner, outcome: HostUnlockOutcome) {
    inner.host_unlock_outcome = Some(outcome);
    HostUnlock { outcome }.emit();
}

const fn outcome_of(opened: &Result<Option<VaultIdentity>, HostUnlockRefusal>) -> HostUnlockOutcome {
    match opened {
        Ok(Some(_)) => HostUnlockOutcome::Unlocked,
        Ok(None) => HostUnlockOutcome::Absent,
        Err(refusal) => HostUnlockOutcome::Refused(*refusal),
    }
}

/// Returns `true` if and only if `start` leaves this profile in Starting for [`ServiceContext::unlock_at_start`]: the
/// Protected and Container profiles try a host unlock. A Development service runs as the invoking user, so no
/// root-owned handoff unit exists to trust.
pub(super) const fn tries_host_unlock(profile: DeploymentProfile) -> bool {
    matches!(profile, DeploymentProfile::Protected | DeploymentProfile::Container)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_protected_and_container_profiles_try_a_host_unlock() {
        assert!(tries_host_unlock(DeploymentProfile::Protected));
        assert!(tries_host_unlock(DeploymentProfile::Container));
        assert!(!tries_host_unlock(DeploymentProfile::Development));
    }
}
