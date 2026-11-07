//! The host unlock at startup (`design/docker-compose.md`, "In the container"; specification §3.12): a container-profile
//! service leaves Starting for Checking when the unlock handoff opens the vault, and for Locked otherwise.
//!
//! Every step's failure leaves the service Locked with passphrase `unlock` still offered, since the operational identity
//! is still a recipient. None counts toward the passphrase attempt limit: a host unlock failure is not a guess, and only
//! root can change the file.

use std::path::Path;
use std::sync::Arc;

use iron_vault_store::{EnvelopeError, StoreFs, UnlockError, VaultIdentity, read_identity_envelope, require_initialized, unwrap_identity};

use super::unlock::log_foreign_files;
use super::{ServiceContext, ServiceLocks, ServiceSetup, apply};
use crate::audit::AuditEvent;
use crate::audit::vault::HostUnlock;
use crate::deployment::DeploymentProfile;
use crate::service_state::{ServiceEvent, ServiceState};
use crate::unlock_handoff::{HandoffError, read_handoff};

/// What one host unlock attempt came to, as `vault.host-unlock` records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostUnlockOutcome {
    /// The handoff unwrapped the vault identity, and the config check followed.
    Unlocked,
    /// No handoff was there.
    Absent,
    /// The handoff was there, or memory was not locked, and the vault stayed shut.
    Refused(HostUnlockRefusal),
}

/// Why a host unlock left the service Locked. No variant carries the handoff's bytes or its recipient key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostUnlockRefusal {
    /// Memory is not locked against swap, so the handoff was never opened (§3.11).
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
    /// The snake_case label `host_unlock_outcome` records.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Unlocked => "unlocked",
            Self::Absent => "absent",
            Self::Refused(_) => "refused",
        }
    }
}

impl HostUnlockRefusal {
    /// The snake_case label `refusal` records.
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
    /// Leaves Starting: to Checking when the unlock handoff at `handoff` opens the vault, then on to Ready or Unavailable
    /// as the config check settles, and to Locked otherwise. Call it once, right after [`start`](Self::start).
    ///
    /// Only the Container profile tries a host unlock, and only it leaves `start` in Starting; in any other state this
    /// returns the state unchanged, so another profile is exactly as `start` left it. Each attempt writes one
    /// `vault.host-unlock` record.
    ///
    /// Cancel-safe once the service enters Checking, as [`enter_checking`](Self::enter_checking) is. A future dropped
    /// before then leaves the service in Starting, which refuses requests as Locked does and unlocks nothing.
    pub async fn unlock_at_start(&self, handoff: &Path) -> ServiceState {
        let service_wide = Arc::clone(&self.service_wide).lock_owned().await;
        let mut inner = Arc::clone(&self.inner).lock_owned().await;
        if inner.state != ServiceState::Starting {
            return inner.state;
        }
        let opened = self.open_with_handoff(handoff).await;
        HostUnlock {
            outcome: outcome_of(&opened),
        }
        .emit();
        match opened {
            Ok(Some(identity)) => self
                .check_and_settle_detached(service_wide, inner, ServiceEvent::HostUnlockSucceeded, Arc::new(identity))
                .await
                .unwrap_or_else(|illegal| illegal.state),
            Ok(None) | Err(_) => apply(&self.holder, &mut inner, ServiceEvent::InteractiveUnlockRequired).unwrap_or(inner.state),
        }
    }

    /// The vault identity the handoff unwraps, `None` when there is no handoff. The memory guard comes first, so without
    /// locked memory the file is never opened; the rest reads files, so it runs on the blocking pool.
    async fn open_with_handoff(&self, handoff: &Path) -> Result<Option<VaultIdentity>, HostUnlockRefusal> {
        self.require_locked_memory().map_err(|_| HostUnlockRefusal::MemoryUnprotected)?;
        let (locks, setup, handoff) = (Arc::clone(&self.locks), Arc::clone(&self.setup), handoff.to_path_buf());
        tokio::task::spawn_blocking(move || unwrap_with_handoff(&locks, &setup, &handoff))
            .await
            .unwrap_or(Err(HostUnlockRefusal::Unreadable))
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

const fn outcome_of(opened: &Result<Option<VaultIdentity>, HostUnlockRefusal>) -> HostUnlockOutcome {
    match opened {
        Ok(Some(_)) => HostUnlockOutcome::Unlocked,
        Ok(None) => HostUnlockOutcome::Absent,
        Err(refusal) => HostUnlockOutcome::Refused(*refusal),
    }
}

/// Whether `start` leaves this profile in Starting for [`ServiceContext::unlock_at_start`]: only the Container profile
/// tries a host unlock.
pub(super) const fn tries_host_unlock(profile: DeploymentProfile) -> bool {
    matches!(profile, DeploymentProfile::Container)
}
