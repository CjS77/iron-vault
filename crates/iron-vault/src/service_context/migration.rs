//! Migration authorization in the running service (design/migration-authorization.md, "Admin exchange", steps 5 to 7):
//! issuing the migration challenge, the passphrase attempt limit before the prompt, and running a source-owner method
//! on the challenge the owner answers.
//!
//! The context's mutex is never held across a method's check, which runs scrypt for about a second: it is taken to
//! check the limit and take the challenge, released for the check, and taken again to record the outcome.
//!
//! **The caller holds the service-wide lock from step 2 until its response, prompts included.** The attempt limit
//! depends on it: with the mutex released during the check, two exchanges without that lock could each issue and take
//! a challenge, and guess in parallel before the first failure is recorded. The context cannot check that the caller
//! holds it, so `export` and `recipient add` must take it before step 5. A `lock` waits for the service-wide lock, so
//! it ends such an exchange at a prompt, not mid-check. Should the vault identity still go during the check, the
//! outcome is discarded unrecorded and the authorization never leaves.

use std::sync::{Arc, Weak};

use iron_vault_store::{StoreFs, VaultId, VaultIdentity, verify_vault_passphrase};
use rand_core::{OsRng, RngCore};
use tokio::time::Instant;

use super::{Inner, ServiceContext};
use crate::admin::protocol::OwnerInput;
use crate::migration_authorization::{
    AttemptLimiter, BindingDigest, MethodRefusal, MigrationAuthorization, MigrationChallenge, MigrationOperation, MigrationRefusal,
    SourceOwnerMethod, VaultPassphraseMethod, prove_challenge,
};
use crate::service_state::ServiceState;

impl<F: StoreFs + Send + Sync + 'static> ServiceContext<F> {
    /// Issues the migration challenge for `operation` (step 5), with a nonce from the operating system's random source,
    /// and returns its binding digest, which names it when the owner's input arrives.
    ///
    /// Refused unless the service is Ready with the vault identity held, while a challenge is pending (`Busy`), and when
    /// the random source fails (`Unavailable`).
    ///
    /// The caller holds the service-wide lock from step 2 until its response (see the module documentation).
    pub async fn issue_migration_challenge(&self, operation: MigrationOperation) -> Result<BindingDigest, MigrationRefusal> {
        let mut inner = self.inner.lock().await;
        let vault_id = open_vault_id(&inner)?;
        let mut nonce = [0; 32];
        OsRng.try_fill_bytes(&mut nonce).map_err(|_| MigrationRefusal::Unavailable)?;
        Ok(inner.migration.issue(vault_id, operation, Instant::now(), nonce)?)
    }

    /// Whether the passphrase attempt limit allows another attempt (step 6), checked before the prompt so a limited
    /// owner is not asked to type. A refusal retires the pending challenge, which ends the exchange.
    pub async fn check_migration_attempts(&self) -> Result<(), MigrationRefusal> {
        let mut inner = self.inner.lock().await;
        allow_attempt(&inner.attempts).inspect_err(|_| inner.migration.retire())
    }

    /// Retires any pending migration challenge: the exchange that issued it ended without proving it, for instance at
    /// a cancelled prompt. Records nothing in the attempt limit, since no input was checked.
    pub async fn retire_migration_challenge(&self) {
        self.inner.lock().await.migration.retire();
    }

    /// The vault passphrase method, checking against the state directory and the vault identity the service holds now.
    /// Build it in the exchange that takes the challenge, after issuing it: a method built under an earlier unlock checks
    /// against that unlock's vault identity.
    pub async fn vault_passphrase_method(&self) -> Result<VaultPassphraseMethod, MigrationRefusal> {
        let inner = self.inner.lock().await;
        let held = inner
            .identity
            .as_ref()
            .ok_or(MigrationRefusal::WrongState(inner.state))?
            .public_key();
        let (locks, setup) = (Arc::clone(&self.locks), Arc::clone(&self.setup));
        Ok(VaultPassphraseMethod::new(move |passphrase| {
            verify_vault_passphrase(&locks.state, &setup.fs, passphrase, &held)
        }))
    }

    /// Takes the challenge named by `digest` out of the pending slot and runs `method` on it with the owner's `input`
    /// (step 7). Only a proof yields the authorization; every path retires the challenge.
    ///
    /// In order: the service must be Ready holding the vault identity, the attempt limit must allow an attempt, and the
    /// challenge must be pending and unexpired, all before the method runs. Then the method's outcome is recorded in the
    /// attempt limit: an owner refusal counts as a failure and a proof resets the count, while an unavailable check
    /// records nothing. If the service locked, or holds another vault identity, by the time the method ends, the outcome
    /// is discarded unrecorded and the refusal is `WrongState`.
    ///
    /// The caller holds the service-wide lock from step 2 until its response, so no other exchange guesses while this
    /// one's outcome is unrecorded (see the module documentation). If this future is dropped mid-check, the challenge
    /// is already gone and nothing is recorded.
    pub async fn authorize_migration<M: SourceOwnerMethod>(
        &self,
        digest: &BindingDigest,
        method: &M,
        input: OwnerInput,
    ) -> Result<MigrationAuthorization, MigrationRefusal> {
        let (challenge, held) = self.take_migration_challenge(digest).await?;
        let proved = prove_challenge(method, challenge, input).await;
        let mut inner = self.inner.lock().await;
        if !holds(&inner, &held) {
            return Err(MigrationRefusal::WrongState(inner.state));
        }
        record_outcome(&mut inner.attempts, proved.as_ref().map(|_| ()));
        proved.map_err(MigrationRefusal::from)
    }

    /// The checks before a method runs: Ready with the vault identity held, the attempt limit, then the challenge itself.
    /// Returns the challenge and a weak reference to the identity it was taken under, which keeps the identity's memory
    /// cleared on lock while still telling it apart from any identity a later unlock brings.
    async fn take_migration_challenge(
        &self,
        digest: &BindingDigest,
    ) -> Result<(MigrationChallenge, Weak<VaultIdentity>), MigrationRefusal> {
        let mut inner = self.inner.lock().await;
        let now = Instant::now();
        let allowed = ready_identity(&inner).and_then(|held| allow_attempt(&inner.attempts).map(|()| held));
        match allowed {
            Ok(held) => inner.migration.take(digest, now).map(|challenge| (challenge, held)),
            Err(refusal) => {
                inner.migration.retire();
                Err(refusal)
            }
        }
    }
}

/// The open vault's ID, which a challenge binds; known only when Ready with the vault identity held.
fn open_vault_id(inner: &Inner) -> Result<VaultId, MigrationRefusal> {
    ready_identity(inner)?;
    inner
        .open
        .as_ref()
        .map(|open| open.approval.vault_id())
        .ok_or(MigrationRefusal::WrongState(inner.state))
}

/// The vault identity the service holds, as a weak reference, when it is Ready.
fn ready_identity(inner: &Inner) -> Result<Weak<VaultIdentity>, MigrationRefusal> {
    match (inner.state, inner.identity.as_ref()) {
        (ServiceState::Ready, Some(identity)) => Ok(Arc::downgrade(identity)),
        (state, _) => Err(MigrationRefusal::WrongState(state)),
    }
}

/// Whether the service is still Ready with the very identity `held` names. A `Weak` keeps its allocation, so no later
/// identity can reuse the address.
fn holds(inner: &Inner, held: &Weak<VaultIdentity>) -> bool {
    ready_identity(inner).is_ok_and(|current| Weak::ptr_eq(&current, held))
}

/// The attempt limit's answer now, as a migration refusal.
fn allow_attempt(attempts: &AttemptLimiter) -> Result<(), MigrationRefusal> {
    attempts.check(Instant::now()).map_err(MigrationRefusal::AttemptsCoolingDown)
}

/// Records a method's outcome in the attempt limit. Only an owner refusal shows a wrong guess, so only it counts.
fn record_outcome(attempts: &mut AttemptLimiter, outcome: Result<(), &MethodRefusal>) {
    match outcome {
        Ok(()) => attempts.record_success(),
        Err(MethodRefusal::Owner(_)) => attempts.record_failure(Instant::now()),
        Err(MethodRefusal::Unavailable) => {}
    }
}
