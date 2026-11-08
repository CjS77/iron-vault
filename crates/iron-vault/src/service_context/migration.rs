//! Migration authorization in the running service (design/migration-authorization.md, "Admin exchange", steps 5 to 7):
//! issuing the migration challenge, the passphrase attempt limit before the prompt, and running a source-owner method
//! on the challenge the owner answers.
//!
//! The context's mutex is never held across a method's check, which runs scrypt for about a second: it is taken to
//! check the limit and take the challenge, released for the check, and taken again to record the outcome.
//!
//! **The caller holds the service-wide lock from step 2 until its response, and the type enforces it.** The attempt limit
//! depends on it: with the mutex released during the check, two exchanges without that lock could each issue and take
//! a challenge, and guess in parallel before the first failure is recorded. [`ServiceContext::begin_migration`] takes the
//! lock and returns a [`MigrationSession`] that owns it, and the admin step takes the session, so it cannot run without
//! the lock. A `lock` waits for the service-wide lock, so it ends such an exchange at a prompt, not mid-check. Should the
//! vault identity still go during the check, the outcome is discarded unrecorded and the authorization never leaves.
//!
//! The session's drop retires any pending challenge, so an exchange whose future is dropped (a connection task aborted at
//! shutdown) leaves none behind: no challenge outlives its exchange.

use std::sync::{Arc, Weak};

use tokio::sync::OwnedMutexGuard;

use iron_vault_store::{StoreFs, VaultId, VaultIdentity, verify_vault_passphrase};
use rand_core::{OsRng, RngCore};
use tokio::time::Instant;

use super::{Inner, ServiceContext};
use crate::admin::protocol::OwnerInput;
use crate::attempt_limit::AttemptLimiter;
use crate::audit::AuditEvent;
use crate::audit::migration::{AuthorizationRefused, Refusal};
use crate::migration_authorization::{
    AuthorizedMigration, BindingDigest, ChallengeBusy, MethodRefusal, MigrationAuthorization, MigrationChallenge, MigrationOperation,
    MigrationRefusal, SourceOwnerMethod, VaultPassphraseMethod, prove_challenge,
};
use crate::service_state::ServiceState;

/// Steps 1 and 2 of a migration exchange done: the service is Ready holding the vault identity, and the service-wide lock
/// is held until this session drops. See the module docs.
pub struct MigrationSession<'a, F> {
    service: &'a ServiceContext<F>,
    /// Taken out in `drop`, so a contended retire can carry it into a task and keep the lock until the slot is empty.
    /// Shared, so a blocking write can keep the lock to its end even when the exchange's future is dropped meanwhile.
    service_wide: Option<Arc<OwnedMutexGuard<()>>>,
    /// The service state and check generation at step 2, which step 9 checks again.
    state: ServiceState,
    checks: u64,
}

impl<F: StoreFs + Send + Sync + 'static> ServiceContext<F> {
    /// Step 2: takes the service-wide lock, refusing at once with `Busy` while another command holds it, then checks that
    /// the service is Ready holding the vault identity (step 1) and records its state and check generation.
    pub async fn begin_migration(&self) -> Result<MigrationSession<'_, F>, MigrationRefusal> {
        let service_wide = Arc::clone(&self.service_wide)
            .try_lock_owned()
            .map_err(|_| MigrationRefusal::Busy(ChallengeBusy))?;
        let inner = self.inner.lock().await;
        ready_identity(&inner)?;
        Ok(MigrationSession {
            service: self,
            service_wide: Some(Arc::new(service_wide)),
            state: inner.state,
            checks: inner.checks,
        })
    }

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
    /// Build it in the exchange that takes the challenge, under the session's service-wide lock: a method built under an
    /// earlier unlock checks against that unlock's vault identity. Building it just before issuing the challenge is as
    /// fresh as just after, and leaves nothing to fail between the challenge and its closing record.
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

impl<F: StoreFs + Send + Sync + 'static> MigrationSession<'_, F> {
    /// The service the session holds the lock of.
    pub(crate) fn service(&self) -> &ServiceContext<F> {
        self.service
    }

    /// The service-wide lock, for a blocking task that writes under it: the lock stays held until the task drops this, even
    /// if the exchange is dropped first.
    pub(crate) fn hold(&self) -> Option<Arc<OwnedMutexGuard<()>>> {
        self.service_wide.clone()
    }

    /// Completes once a `lock` is waiting for the service-wide lock this session holds, so a prompt can end the exchange
    /// rather than make the `lock` wait for the owner.
    pub async fn lock_requested(&self) {
        self.service.lock_requested().await;
    }

    /// Step 9's check: the service is still in the state and at the check generation recorded at step 2, so the summary
    /// the owner confirmed is still true. The refusal names the state the service is in now.
    pub async fn ensure_unchanged(&self) -> Result<(), MigrationRefusal> {
        let inner = self.service.inner.lock().await;
        ready_identity(&inner)?;
        match inner.state == self.state && inner.checks == self.checks {
            true => Ok(()),
            false => Err(MigrationRefusal::WrongState(inner.state)),
        }
    }

    /// Step 9: the service is still as it was at step 2, then the authorization is consumed for `operation` on the open
    /// vault, which checks its binding and its expiry. The result is the witness the operation takes to start. A binding
    /// or expiry refusal is recorded as the one consume-time `migration.authorization-refused`; a `wrong-state` adds no
    /// migration record.
    pub async fn consume(
        &self,
        authorization: MigrationAuthorization,
        operation: &MigrationOperation,
    ) -> Result<AuthorizedMigration, MigrationRefusal> {
        self.ensure_unchanged().await?;
        let vault_id = open_vault_id(&*self.service.inner.lock().await)?;
        authorization
            .authorize(vault_id, operation, Instant::now())
            .inspect_err(|refusal| record_refused_on_consume(operation, *refusal))
    }
}

/// Records the refusal of an authorization at step 9, when it names the authorization rather than the service's state.
fn record_refused_on_consume(operation: &MigrationOperation, refusal: MigrationRefusal) {
    if matches!(refusal, MigrationRefusal::Expired | MigrationRefusal::BindingMismatch) {
        AuthorizationRefused {
            operation,
            method: VaultPassphraseMethod::LABEL,
            refusal: Refusal::Refused(refusal),
        }
        .emit();
    }
}

impl<F> Drop for MigrationSession<'_, F> {
    /// Retires any challenge this exchange left pending. When the context's mutex is contended the retire runs in a task
    /// that owns the service-wide guard, so a later session cannot issue a challenge that the late retire then removes.
    fn drop(&mut self) {
        let Some(service_wide) = self.service_wide.take() else { return };
        let inner = Arc::clone(&self.service.inner);
        if let Ok(mut held) = inner.try_lock() {
            held.migration.retire();
            return;
        }
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                inner.lock().await.migration.retire();
                drop(service_wide);
            });
        }
    }
}
