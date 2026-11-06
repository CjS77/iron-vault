//! The pending slot: the one migration challenge the service holds (design/migration-authorization.md, "Lifetime").

use iron_vault_store::VaultId;
use thiserror::Error;
use tokio::time::Instant;

use super::{BindingDigest, MigrationChallenge, MigrationOperation, MigrationRefusal};

/// A challenge is already pending, so no other is issued. The exchange ends with `busy` and records no migration event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("a migration challenge is already pending")]
pub struct ChallengeBusy;

/// The slot holding at most one pending migration challenge.
///
/// Issuing never replaces a pending challenge, expired or not, because that would retire the challenge of an owner
/// still typing at its prompt. Taking empties the slot whatever it finds, so no challenge is ever verified twice.
#[derive(Debug)]
pub struct PendingMigration {
    /// The service's clock origin, fixed when the service starts, which every challenge's encoding measures from.
    origin: Instant,
    slot: Option<MigrationChallenge>,
}

impl PendingMigration {
    /// An empty slot whose challenges measure their times from `origin`.
    pub fn new(origin: Instant) -> Self {
        Self { origin, slot: None }
    }

    /// Issues a challenge for `operation` on `vault_id` at `now`, with the `nonce` the caller drew from the operating
    /// system's random source, and returns its binding digest. Refused while a challenge is pending.
    pub fn issue(
        &mut self,
        vault_id: VaultId,
        operation: MigrationOperation,
        now: Instant,
        nonce: [u8; 32],
    ) -> Result<BindingDigest, ChallengeBusy> {
        if self.slot.is_some() {
            return Err(ChallengeBusy);
        }
        let challenge = MigrationChallenge::new(vault_id, operation, nonce, self.origin, now);
        let digest = challenge.binding_digest();
        self.slot = Some(challenge);
        Ok(digest)
    }

    /// Takes the challenge named by `digest` out of the slot at `now`, before any source-owner method runs.
    ///
    /// The slot is empty afterwards, whatever this returns: a challenge taken after its expiry is retired, and so is
    /// one that a take with another digest finds, so a defect fails closed. An expired challenge is refused here, so
    /// no passphrase is ever checked against one.
    pub fn take(&mut self, digest: &BindingDigest, now: Instant) -> Result<MigrationChallenge, MigrationRefusal> {
        let challenge = self
            .slot
            .take()
            .filter(|pending| pending.binding_digest() == *digest)
            .ok_or(MigrationRefusal::NotPending)?;
        match challenge.is_expired(now) {
            true => Err(MigrationRefusal::Expired),
            false => Ok(challenge),
        }
    }

    /// Retires any pending challenge: when its exchange ends, its prompt is cancelled, or the service locks.
    pub fn retire(&mut self) {
        self.slot = None;
    }

    /// Whether a challenge is pending.
    pub fn is_pending(&self) -> bool {
        self.slot.is_some()
    }
}
