//! Migration authorization (specification §3.13, §3.15, R-23; design/migration-authorization.md): the challenge the
//! service issues for one pending migration, the pending slot that makes it single-use, and the move-only proof that
//! the owner authorized that one migration operation.
//!
//! Pure domain logic: the clock and the nonce are arguments, so the replay, expiry and binding rules are deterministic
//! under test. The source-owner methods that prove a challenge live beside this module and construct an authorization
//! through it; nothing else can.

mod attempt_limit;
mod challenge;
mod pending;
#[cfg(test)]
mod tests;

use iron_vault_store::{RecipientKey, VaultId};
use thiserror::Error;
use tokio::time::Instant;

pub use attempt_limit::{AttemptLimiter, BASE_COOLDOWN, FAILURE_THRESHOLD, MAX_COOLDOWN, RateLimited};
pub use challenge::{BindingDigest, CHALLENGE_LIFETIME, MigrationChallenge};
pub use pending::{ChallengeBusy, PendingMigration};

/// What a migration authorization permits (glossary: *Migration operation*).
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

/// Why the pending slot or a consuming operation refused a migration authorization. Each ends the exchange with
/// `migration-denied`; the messages are fixed phrases and hold no owner input.
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
}

impl MigrationRefusal {
    /// The label the audit events' `refusal` field records.
    pub fn label(self) -> &'static str {
        match self {
            Self::Expired => "expired",
            Self::NotPending => "not_pending",
            Self::BindingMismatch => "binding_mismatch",
        }
    }
}

/// The move-only proof that the owner authorized one migration operation (glossary: *Migration authorization*).
///
/// Only this module and the source-owner methods beside it construct one, from a challenge a method has just proved.
/// It has no `Clone` or `Copy` and is never serialized, so it is consumed exactly once, by the operation it permits.
/// Its `Debug` shows only the operation and the expiry.
pub struct MigrationAuthorization {
    challenge: MigrationChallenge,
}

impl MigrationAuthorization {
    /// The authorization a source-owner method yields once it has proved `challenge`, taken out of the pending slot.
    #[allow(dead_code, reason = "the source-owner methods (K-209) are its first callers outside tests")]
    fn proved(challenge: MigrationChallenge) -> Self {
        Self { challenge }
    }

    /// The operation this authorization permits.
    pub fn operation(&self) -> &MigrationOperation {
        self.challenge.operation()
    }

    /// Consumes the authorization for `operation` on `vault_id` at `now`, as that operation starts.
    ///
    /// The binding is checked before the expiry, so a proof for another migration is always reported as a mismatch.
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

/// A consumed migration authorization: the witness that the operation it names may start now. Only
/// [`MigrationAuthorization::authorize`] makes one, so an operation that takes it cannot run unauthorized.
#[derive(Debug)]
pub struct AuthorizedMigration {
    operation: MigrationOperation,
}

impl AuthorizedMigration {
    /// The operation that was authorized.
    pub fn operation(&self) -> &MigrationOperation {
        &self.operation
    }
}
