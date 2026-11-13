// SPDX-License-Identifier: MPL-2.0
//! Checks, for one migration operation, that the owner proves now a factor already enrolled for this vault
//! ([spec §16](../../../design/iron-vault-specification.md#16-administration-recovery-and-migration),
//! [§19](../../../design/iron-vault-specification.md#19-v0-user-acceptance);
//! [migration authorization](../../../design/migration-authorization.md)).
//! `export` and `recipient add` each need one before they hand the vault identity to anyone new, so a service that is
//! merely unlocked can do neither.
//!
//! This module holds the challenge the service issues for one pending migration, the pending slot that makes the
//! challenge single-use, and the move-only proof that the owner authorized that one operation. The admin step that
//! drives them is `admin::migration_authorization`. A proof moves through them like this:
//!
//! ```text
//! PendingMigration::issue(vault ID, operation, now, nonce) ────→ ChallengeBusy  (a challenge is already pending)
//!            │ the slot holds the new MigrationChallenge; its BindingDigest goes to the exchange
//!            ▼
//! PendingMigration::take(digest, now) ─────────────────────────→ NotPending, Expired  (the slot is empty either way)
//!            │ the challenge, out of the slot
//!            ▼
//! prove_challenge(method, challenge, owner input) ─────────────→ Denied, Unavailable, TpmLockedOut, TpmUnavailable
//!            │
//!            ▼
//! MigrationAuthorization (no Clone, never serialized)
//!            │ authorize(vault ID, operation, now)
//!            ├─────────────────────────────────────────────────→ BindingMismatch, Expired
//!            ▼
//! AuthorizedMigration ──→ export writes its bundle, or recipient add rewraps identity.age
//! ```
//!
//! Nothing here reads a clock or a random source: the time and the nonce are arguments, so tests can drive the
//! replay, expiry and binding rules exactly. The source-owner methods that check the owner's input are in `method`.

mod challenge;
mod method;
mod pending;
#[cfg(test)]
mod tests;

use iron_vault_store::{ApproverId, RecipientKey, VaultId};

use crate::attempt_limit::AttemptsCoolingDown;
use crate::service_state::ServiceState;
use thiserror::Error;
use tokio::time::Instant;

pub use challenge::{BindingDigest, CHALLENGE_LIFETIME, MigrationChallenge};
#[cfg(target_os = "linux")]
pub use method::{AskableMethod, AskableMethods, TpmApprovalPinMethod, VaultPassphraseMethod};
// Only the service context's migration session proves a challenge, and it is Linux-only.
#[cfg(target_os = "linux")]
pub(crate) use method::prove_challenge;
pub use method::{MethodRefusal, OwnerRefusal, SourceOwnerMethod};
pub use pending::{ChallengeBusy, PendingMigration};

/// What a migration authorization permits ([glossary: *Migration operation*](../../../design/glossary.md#terms)).
///
/// The destination of `AddRecipient` is part of the operation, so an authorization to add one recipient never adds
/// another. `Export` names none: its export passphrase is chosen only after authorization and is never evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationOperation {
    /// `export`, before it writes a migration bundle.
    Export,
    /// `recipient add`, enrolling this recipient key in the identity envelope.
    AddRecipient(RecipientKey),
}

impl MigrationOperation {
    /// The label the audit events' `operation` field records.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Export => "export",
            Self::AddRecipient(_) => "add_recipient",
        }
    }

    /// The destination recipient, when the operation has one.
    pub fn destination(&self) -> Option<&RecipientKey> {
        match self {
            Self::Export => None,
            Self::AddRecipient(key) => Some(key),
        }
    }

    /// The operation's tag in the binding digest's canonical encoding.
    fn tag(&self) -> u8 {
        match self {
            Self::Export => 0x01,
            Self::AddRecipient(_) => 0x02,
        }
    }
}

/// Why a migration authorization was refused, at its issue, its proof or its consumption. The messages are fixed phrases
/// and hold no owner input.
///
/// Each refusal ends the admin exchange with one error code
/// ([migration authorization: Error codes](../../../design/migration-authorization.md#error-codes)):
///
/// ```text
/// Expired, NotPending, BindingMismatch, Denied ────────────→ migration-denied
/// Unavailable, TpmUnavailable, WrongState(Locked) ─────────→ migration-unavailable   (Locked: a `lock` during the check)
/// AttemptsCoolingDown ─────────────────────────────────────→ migration-rate-limited
/// TpmLockedOut ────────────────────────────────────────────→ tpm-locked-out
/// Busy ────────────────────────────────────────────────────→ busy
/// any other WrongState ────────────────────────────────────→ wrong-state
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum MigrationRefusal {
    /// The challenge was taken, or the authorization consumed, at or after its expiry.
    #[error("the migration authorization expired")]
    Expired,
    /// The slot does not hold the named challenge: it was already taken or retired.
    #[error("no such migration challenge is pending")]
    NotPending,
    /// The consuming operation's vault ID, operation or destination is not the authorization's.
    #[error("the migration authorization is for another migration")]
    BindingMismatch,
    /// The source-owner method checked the owner's input, and it proves no authority.
    #[error("migration authorization was refused: {0}")]
    Denied(OwnerRefusal),
    /// The passphrase attempt limit is in a cooldown, so no input was asked for or checked.
    #[error(transparent)]
    AttemptsCoolingDown(AttemptsCoolingDown),
    /// The service is not Ready holding the vault identity, or it locked while the method ran.
    #[error("migration authorization needs the service ready, holding the vault identity")]
    WrongState(ServiceState),
    /// The source-owner factor could not be checked, or the random source failed, so nothing was judged.
    #[error("migration authorization could not be checked")]
    Unavailable,
    /// The TPM is in dictionary-attack lockout, or the helper's lockout reserve withheld the try.
    #[error("the TPM is locked out; try again in {wait_seconds} seconds")]
    TpmLockedOut {
        /// The whole seconds to wait.
        wait_seconds: u64,
    },
    /// The TPM signing helper answered `status`, which is neither a signature nor a wrong PIN nor a lockout.
    #[error("the TPM approver cannot be checked: the helper answered {status}")]
    TpmUnavailable {
        /// The helper's status label.
        status: &'static str,
    },
    /// A challenge is already pending, so no other is issued.
    #[error(transparent)]
    Busy(#[from] ChallengeBusy),
}

impl MigrationRefusal {
    /// Returns the label the audit events' `refusal` field records. A `lock` during the check is `locked`. `busy` and
    /// `wrong_state` end an exchange before its challenge is issued, so no audit event carries them.
    pub fn label(self) -> &'static str {
        match self {
            Self::Expired => "expired",
            Self::NotPending => "not_pending",
            Self::BindingMismatch => "binding_mismatch",
            Self::Denied(refusal) => refusal.label(),
            Self::AttemptsCoolingDown(_) => "rate_limited",
            Self::WrongState(ServiceState::Locked) => "locked",
            Self::WrongState(_) => "wrong_state",
            Self::Unavailable | Self::TpmUnavailable { .. } => "unavailable",
            Self::TpmLockedOut { .. } => "tpm_locked_out",
            Self::Busy(_) => "busy",
        }
    }
}

impl From<MethodRefusal> for MigrationRefusal {
    fn from(refusal: MethodRefusal) -> Self {
        match refusal {
            MethodRefusal::Owner(owner) => Self::Denied(owner),
            MethodRefusal::Unavailable => Self::Unavailable,
            MethodRefusal::TpmLockedOut { wait_seconds } => Self::TpmLockedOut { wait_seconds },
            MethodRefusal::TpmUnavailable { status } => Self::TpmUnavailable { status },
        }
    }
}

/// The move-only proof that the owner authorized one migration operation
/// ([glossary: *Migration authorization*](../../../design/glossary.md#terms)).
///
/// Only `method::prove_challenge` makes one, from a challenge a source-owner method has just proved. It has no `Clone`
/// or `Copy` and is never serialized, so the operation it permits consumes it exactly once. Its `Debug` shows only the
/// operation and the expiry.
///
/// Being unlocked is not enough: nothing about the service's state makes one. Code outside this crate cannot build one
/// from its fields, cannot call its private constructor, and cannot write a source-owner method that proves every
/// challenge, because the trait is sealed. Each of these fails to compile:
///
/// ```compile_fail,E0451
/// use iron_vault::migration_authorization::{MethodName, MigrationAuthorization, MigrationChallenge};
///
/// fn forge(challenge: MigrationChallenge, proved_by: MethodName) -> MigrationAuthorization {
///     MigrationAuthorization { challenge, proved_by }
/// }
/// ```
///
/// ```compile_fail,E0624
/// use iron_vault::migration_authorization::{MethodName, MigrationAuthorization, MigrationChallenge};
///
/// fn forge(challenge: MigrationChallenge, proved_by: MethodName) -> MigrationAuthorization {
///     MigrationAuthorization::proved(challenge, proved_by)
/// }
/// ```
///
/// ```compile_fail,E0277
/// use iron_vault::admin::protocol::OwnerInput;
/// use iron_vault::migration_authorization::{MethodRefusal, MigrationChallenge, SourceOwnerMethod};
///
/// struct AlwaysYes;
///
/// impl SourceOwnerMethod for AlwaysYes {
///     fn label(&self) -> &'static str {
///         "always_yes"
///     }
///
///     async fn prove(&self, _: &MigrationChallenge, _: OwnerInput) -> Result<(), MethodRefusal> {
///         Ok(())
///     }
/// }
/// ```
pub struct MigrationAuthorization {
    challenge: MigrationChallenge,
    proved_by: MethodName,
}

impl MigrationAuthorization {
    /// Makes the authorization for `challenge`, which the method `proved_by` has just proved after the challenge was
    /// taken out of the pending slot. It is private, so [`method::prove_challenge`] is the only way to one.
    #[cfg(target_os = "linux")]
    fn proved(challenge: MigrationChallenge, proved_by: MethodName) -> Self {
        Self { challenge, proved_by }
    }

    /// Returns the method that proved the challenge, which a refusal at consumption names.
    pub fn proved_by(&self) -> MethodName {
        self.proved_by
    }

    /// Returns the operation this authorization permits.
    pub fn operation(&self) -> &MigrationOperation {
        self.challenge.operation()
    }

    /// Consumes the authorization for `operation` on `vault_id` at `now`, as that operation starts.
    ///
    /// Refuses with [`MigrationRefusal::BindingMismatch`] when the vault ID or the operation, destination included, is
    /// not the challenge's, and with [`MigrationRefusal::Expired`] at or after the challenge's expiry. The binding is
    /// checked first, so a proof for another migration is always reported as a mismatch.
    pub fn authorize(
        self,
        vault_id: VaultId,
        operation: &MigrationOperation,
        now: Instant,
    ) -> Result<AuthorizedMigration, MigrationRefusal> {
        if self.challenge.vault_id() != vault_id || self.challenge.operation() != operation {
            return Err(MigrationRefusal::BindingMismatch);
        }
        match self.challenge.is_expired(now) {
            true => Err(MigrationRefusal::Expired),
            false => Ok(AuthorizedMigration {
                operation: operation.clone(),
            }),
        }
    }
}

impl std::fmt::Debug for MigrationAuthorization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MigrationAuthorization")
            .field("operation", self.challenge.operation())
            .field("expires_at", &self.challenge.expires_at())
            .finish_non_exhaustive()
    }
}

/// How the audit events name a source-owner method: its label and, for a method that proves with a pinned approver's
/// key, that approver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodName {
    /// The method's label, the `method` field.
    pub label: &'static str,
    /// The approver whose key proves the challenge, the `approver_id` field.
    pub approver: Option<ApproverId>,
}

impl MethodName {
    /// Returns the name of `method`.
    pub fn of(method: &impl SourceOwnerMethod) -> Self {
        Self {
            label: method.label(),
            approver: method.approver(),
        }
    }
}

/// A consumed migration authorization: the witness that the operation it names may start now.
///
/// Only [`MigrationAuthorization::authorize`] makes one, so an operation that takes it as an argument cannot run
/// unauthorized.
#[derive(Debug)]
pub struct AuthorizedMigration {
    operation: MigrationOperation,
}

impl AuthorizedMigration {
    /// Returns the operation that was authorized.
    pub fn operation(&self) -> &MigrationOperation {
        &self.operation
    }
}
