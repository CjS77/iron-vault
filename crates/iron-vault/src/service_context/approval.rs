//! `config approve`'s side of the service context: the approval transaction (specification §3.9;
//! design/config-approval.md, "The transaction") driven through the service state model.
//!
//! [`ServiceContext::review_approval`] takes the service-wide lock and runs step 1. The [`ApprovalReview`] it returns
//! holds that lock until it is committed or abandoned, so the predicted version stays exact and nothing changes the
//! credential catalog while the owner reads the summary. The review keeps no vault identity, so a `lock` while the owner
//! is at a prompt leaves no copy of it behind.
//!
//! An unlock does not take the service-wide lock, so a `lock` and an `unlock` can both happen while the owner is at a
//! prompt, and the unlock's config check discards this approval's pending config. The review therefore records the
//! service state and the context's check generation when it starts, and the commit refuses before reserving anything
//! unless both are unchanged.
//!
//! [`ApprovalReview::commit`] runs steps 2 to 6 under the context's mutex: reserve, sign and stage, then the admission
//! pause, the commit and publish, then the config check that ends the pause in Ready or Unavailable. A task of its own
//! owns the mutex guard and runs all of it (see [`ApprovalReview::commit`] for what that guarantees).

use std::sync::Arc;

use iron_vault_policy::{ActivePolicy, ApprovalSummary, ValidatedConfig, summarize};
use iron_vault_store::{
    ApprovalError, ApprovalPassphrase, ApprovalProgress, ApprovalSigner, ApprovalState, ApprovalStorage, ConfigDigest, PendingConfig,
    SignError, SoftwareSigner, StoreFs, Vault, VaultIdentity, open_signer_key, read_signer_key,
};
use tokio::sync::MutexGuard;

use super::{Inner, ServiceContext, ServiceLocks, SettleGuard, Settler, apply};
use crate::admin::protocol::ApprovalResult;
use crate::config_check::{InvalidConfig, activate_config};
use crate::service_state::{AdminOperation, FailureReason, ServiceEvent, ServiceState, UnavailableReason};
use crate::serving_snapshot::Admission;

/// How a `config approve` ended without an active new config. Each variant is one `config approve` error code, and no
/// message holds config bytes or anything the owner typed.
#[derive(Debug, thiserror::Error)]
pub enum ApprovalEnd {
    /// Another approval, vault write or reload holds the service-wide lock.
    #[error("another approval, vault write or reload is running; try again")]
    Busy,
    /// The service state does not allow an approval.
    #[error("the service is {0:?}; only Ready, or Unavailable with an invalid policy, can approve a config")]
    WrongState(ServiceState),
    /// The proposed config does not parse, validate, activate or build its upstream clients.
    #[error("the proposed config is invalid: {0}")]
    Invalid(String),
    /// The owner did not confirm the summary.
    #[error("the config was not approved: the confirmation was not `yes`")]
    Declined,
    /// The approval passphrase did not open the pinned approver's key.
    #[error("the approval passphrase does not open the approver key")]
    Denied,
    /// Nothing was reserved, and the approval cannot run: the approval state, the approver key or a write failed. Also
    /// the answer when the task running the transaction ended without a result, which leaves the service Unavailable
    /// and a version possibly reserved or committed; its message says so.
    #[error("the service cannot approve now: {0}")]
    Unavailable(String),
    /// A version was reserved, and so consumed, but nothing was committed; the active config is unchanged.
    #[error("version {version} is consumed and nothing was committed; the active config is unchanged: {cause}")]
    Failed {
        /// The consumed version.
        version: u64,
        /// What failed, without config bytes.
        cause: String,
    },
    /// The version was committed, or may have been, but the config it approves is not active.
    #[error("version {version} was committed but is not active; the service is {state:?}")]
    NotActive {
        /// The committed version.
        version: u64,
        /// The state the service settled in.
        state: ServiceState,
    },
}

/// Step 1 done: the pending config is durable and valid, and the owner has yet to review it. See the module docs.
pub struct ApprovalReview<'a, F> {
    service: &'a ServiceContext<F>,
    _service_wide: MutexGuard<'a, ()>,
    started: Started,
    pending: PendingConfig,
    approval: ApprovalState,
    summary: ApprovalSummary,
}

/// Where an approval started: the service state and the context's check generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Started {
    state: ServiceState,
    checks: u64,
}

impl<F: StoreFs + Send + Sync + 'static> ServiceContext<F> {
    /// Takes the service-wide lock, refusing at once with [`ApprovalEnd::Busy`] while another holds it, and runs step 1:
    /// writes `config` as the pending config, then validates and activates it against a vault freshly opened from the
    /// kept vault identity, so a credential added since the last config check is in the catalog. The upstream clients
    /// are built too, so a config that cannot be served is invalid before any version is reserved.
    pub async fn review_approval(&self, config: Vec<u8>) -> Result<ApprovalReview<'_, F>, ApprovalEnd> {
        let service_wide = self.service_wide.try_lock().map_err(|_| ApprovalEnd::Busy)?;
        let (started, identity, active) = self.approval_start().await?;
        let (vault, _) = Vault::open(&self.locks.state, &self.setup.fs, Arc::clone(&identity)).map_err(unavailable)?;
        let approval = vault.load_approval_state(&self.locks.state, &self.setup.fs).map_err(unavailable)?;
        let pending = PendingConfig::write(&self.storage(&identity), config).map_err(unavailable)?;
        let policy = match self.servable(pending.bytes(), &vault) {
            Ok(policy) => policy,
            Err(invalid) => {
                pending.abandon(&self.locks.config, &self.setup.fs);
                return Err(ApprovalEnd::Invalid(invalid.detail()));
            }
        };
        Ok(ApprovalReview {
            service: self,
            _service_wide: service_wide,
            started,
            summary: summarize(active.as_ref(), policy.config()),
            pending,
            approval,
        })
    }

    /// Where the approval starts, the kept vault identity, and the config of the serving snapshot, which the summary
    /// diffs against; none when the service is not serving one.
    async fn approval_start(&self) -> Result<(Started, Arc<VaultIdentity>, Option<ValidatedConfig>), ApprovalEnd> {
        let inner = self.inner.lock().await;
        let identity = match &inner.identity {
            Some(identity) if inner.state.admin_allows(AdminOperation::Approve) => Arc::clone(identity),
            _ => return Err(ApprovalEnd::WrongState(inner.state)),
        };
        let active = match self.holder.load() {
            Admission::Serve(snapshot) => Some(snapshot.policy().config().clone()),
            Admission::Refuse(_) => None,
        };
        let started = Started {
            state: inner.state,
            checks: inner.checks,
        };
        Ok((started, identity, active))
    }

    /// The pending config activated against `vault`, once its upstream clients build.
    fn servable(&self, bytes: &[u8], vault: &Vault) -> Result<ActivePolicy, InvalidConfig> {
        let policy = activate_config(bytes, &self.setup.capabilities, vault, &self.setup.accounts)?;
        self.setup.upstream.clients(&policy).map_err(InvalidConfig::Clients)?;
        Ok(policy)
    }

    fn storage<'s>(&'s self, identity: &'s VaultIdentity) -> ApprovalStorage<'s, F> {
        approval_storage(&self.locks, &self.setup.fs, identity)
    }
}

impl<F: StoreFs + Send + Sync + 'static> ApprovalReview<'_, F> {
    /// What the owner reviews before confirming: the header, then the summary's sections.
    pub fn summary(&self) -> String {
        let committed = self
            .approval
            .committed()
            .map_or_else(|| "none".to_owned(), |(version, _)| version.to_string());
        format!(
            "Approval summary\nvault: {}\nversion to commit: {}\nconfig digest: {}\ncommitted version: {committed}\n{}",
            self.approval.vault_id(),
            self.version(),
            self.pending.digest(),
            self.summary.render(),
        )
    }

    /// The version this approval will commit. Exact, because the service-wide lock keeps anything else from reserving.
    pub fn version(&self) -> u64 {
        self.approval.highest_reserved().saturating_add(1)
    }

    /// Opens `approver.age` with `passphrase` as the pinned approver's signer, on the blocking pool, since scrypt holds
    /// a thread for seconds. A wrong passphrase, or a key that is not the pinned approver's, is [`ApprovalEnd::Denied`].
    ///
    /// The task owns the passphrase and drops it when it ends. A task that ends without a result refuses the approval
    /// before anything is reserved; if this future is dropped first, the task still ends and drops the signer it opened.
    pub async fn open_signer(&self, passphrase: ApprovalPassphrase) -> Result<SoftwareSigner, ApprovalEnd> {
        let (locks, setup, approver) = (
            Arc::clone(&self.service.locks),
            Arc::clone(&self.service.setup),
            self.approval.approver().clone(),
        );
        let opened = tokio::task::spawn_blocking(move || {
            let envelope = read_signer_key(&locks.state, &setup.fs).map_err(unavailable)?;
            open_signer_key(&envelope, &passphrase, &approver).map_err(denied_or_unavailable)
        });
        opened
            .await
            .unwrap_or_else(|_| Err(unavailable("the approver key check was interrupted; nothing was reserved")))
    }

    /// Ends the approval before any reservation: removes the pending config and releases the service-wide lock.
    pub fn abandon(self) {
        self.pending.abandon(&self.service.locks.config, &self.service.setup.fs);
    }

    /// Steps 2 to 6 with `signer`, which is dropped once it has signed: reserve, sign and stage; then the admission
    /// pause (from Ready, the move to Checking), the commit and publish; then the config check that ends the pause.
    ///
    /// Refuses before reserving unless the service is in the state, and at the check generation, the approval started
    /// at: a `lock`, or a `lock` and an `unlock`, while the owner was at a prompt ends it with nothing reserved.
    ///
    /// Cancel-safe: from the first reservation on, a task of its own owns the context's guard and runs every step to
    /// its end, as [`ServiceContext::unlock`] does for a config check. Dropping this future after the commit therefore
    /// never leaves the service in Checking (§3.12): the task still settles in Ready on the new config, or in
    /// Unavailable. A task that ends without a result fails closed through its [`SettleGuard`], and this call then
    /// answers [`ApprovalEnd::Unavailable`].
    pub async fn commit<S: ApprovalSigner + Send + 'static>(self, signer: S) -> Result<ApprovalResult, ApprovalEnd> {
        let Self {
            service,
            _service_wide: _held,
            started: Started { state: started, checks },
            pending,
            approval,
            summary,
        } = self;
        let inner = Arc::clone(&service.inner).lock_owned().await;
        let Some(identity) = inner.identity.clone().filter(|_| inner.state == started && inner.checks == checks) else {
            pending.abandon(&service.locks.config, &service.setup.fs);
            return Err(ApprovalEnd::Unavailable(
                "the service was locked or checked again while the owner was at a prompt; nothing was reserved".to_owned(),
            ));
        };
        let (settler, mut guard) = (service.settler(), SettleGuard::new(inner, Arc::clone(&service.holder)));
        let transaction = Transaction {
            started,
            identity,
            pending,
            approval,
            summary,
            signer,
        };
        let running = tokio::spawn(async move { settler.run(&mut guard.inner, transaction).await });
        running.await.unwrap_or_else(|crashed| {
            let ended = if crashed.is_panic() { "panicked" } else { "was cancelled" };
            tracing::error!("the approval transaction's task {ended} before it gave a result");
            Err(unavailable(
                "the approval did not finish; a version may be consumed or committed, and the service is Unavailable if it was checking",
            ))
        })
    }
}

/// What the task that runs steps 2 to 6 owns: everything the transaction reads, so it can outlive the call that started it.
struct Transaction<S> {
    started: ServiceState,
    identity: Arc<VaultIdentity>,
    pending: PendingConfig,
    approval: ApprovalState,
    summary: ApprovalSummary,
    signer: S,
}

impl<F: StoreFs + Send + Sync + 'static> Settler<F> {
    /// Steps 2 to 6 of `transaction` under `inner`, which the caller's task owns.
    async fn run<S: ApprovalSigner>(&self, inner: &mut Inner, transaction: Transaction<S>) -> Result<ApprovalResult, ApprovalEnd> {
        let Transaction {
            started,
            identity,
            pending,
            mut approval,
            summary,
            signer,
        } = transaction;
        let storage = approval_storage(&self.locks, &self.setup.fs, &identity);
        let digest = pending.digest();
        let prepared = match pending.prepare(&storage, &mut approval, signer) {
            Ok(prepared) => prepared,
            Err(error) => {
                // A reservation that took is consumed: `status` reports the counter as it now is.
                if let Some(open) = &mut inner.open {
                    open.approval = approval;
                }
                return Err(not_committed(error, digest));
            }
        };
        let version = prepared.version().get();
        if started == ServiceState::Ready {
            inner.open = None;
            // Cannot fail: the state was checked as Ready under this same guard. Were it to, the version is consumed.
            apply(&self.holder, inner, ServiceEvent::ApprovalCommitting).map_err(|illegal| ApprovalEnd::Failed {
                version,
                cause: illegal.to_string(),
            })?;
        }
        let committed = {
            let pause = self.holder.pause();
            prepared.commit(&storage, &pause).map(drop)
        };
        self.durable(inner, started, &identity, committed, digest).await?;
        tracing::info!(
            event = "config.approval-completed",
            version,
            %digest,
            summary = %summary.render(),
            "config approval completed",
        );
        match self.check_committed(inner, started, identity).await {
            ServiceState::Ready => Ok(ApprovalResult {
                version,
                digest: *digest.as_bytes(),
                headline: summary.headline(),
            }),
            state => {
                activation_failed(version, state, "the config check after the commit failed; see config.check-failed");
                Err(ApprovalEnd::NotActive { version, state })
            }
        }
    }

    /// Steps 5 and 6 after a durable commit: the config check, from Checking when the approval started in Ready, or
    /// through `Repaired` when it started in Unavailable.
    async fn check_committed(&self, inner: &mut Inner, started: ServiceState, identity: Arc<VaultIdentity>) -> ServiceState {
        let checked = match started {
            ServiceState::Ready => self.settle(inner, identity, ServiceEvent::ApprovalCommitting, None).await,
            _ => self.check_and_settle(inner, ServiceEvent::Repaired, identity).await,
        };
        checked.unwrap_or_else(|illegal| illegal.state)
    }

    /// An uncertain commit that could not be settled: Unavailable needing recovery, through Checking from either start.
    fn recovery_needed(&self, inner: &mut Inner, started: ServiceState) -> ServiceState {
        if started != ServiceState::Ready {
            inner.open = None;
            let _ = apply(&self.holder, inner, ServiceEvent::Repaired);
        }
        apply(&self.holder, inner, ServiceEvent::CheckFailed(FailureReason::RecoveryNeeded)).unwrap_or(inner.state)
    }

    /// Whether step 5 left a durable commit. A commit whose publish failed is durable: the config check's recovery
    /// finishes the publish. Otherwise this ends the admission pause and the approval:
    ///
    /// - a clean failure before the commit leaves the committed approval and the published pair as they were. From
    ///   Ready the config check runs on them and normally returns to Ready on the old policy; from Unavailable nothing
    ///   moves;
    /// - an uncertain commit that could not be settled leaves the service Unavailable, needing recovery.
    async fn durable(
        &self,
        inner: &mut Inner,
        started: ServiceState,
        identity: &Arc<VaultIdentity>,
        committed: Result<(), ApprovalError>,
        digest: ConfigDigest,
    ) -> Result<(), ApprovalEnd> {
        let Err(error) = committed else {
            return Ok(());
        };
        match error.progress() {
            ApprovalProgress::Committed(_) => {
                tracing::warn!(%error, "the approval committed but its publish failed; the config check finishes it");
                Ok(())
            }
            ApprovalProgress::CommitUncertain(version) => {
                let state = self.recovery_needed(inner, started);
                activation_failed(version.get(), state, &error);
                Err(ApprovalEnd::NotActive {
                    version: version.get(),
                    state,
                })
            }
            ApprovalProgress::Reserved(_) | ApprovalProgress::NothingReserved => {
                if started == ServiceState::Ready {
                    let _ = self
                        .settle(inner, Arc::clone(identity), ServiceEvent::ApprovalCommitting, None)
                        .await;
                }
                Err(not_committed(error, digest))
            }
        }
    }
}

/// A failure before the commit: the version consumed when one was reserved, logged as a failed approval of `digest`.
fn not_committed(error: ApprovalError, digest: ConfigDigest) -> ApprovalEnd {
    match error.progress() {
        ApprovalProgress::Reserved(version) => {
            let (version, step) = (version.get(), error.step());
            tracing::warn!(
                event = "config.approval-failed",
                version,
                %digest,
                %step,
                %error,
                "config approval failed after its reservation"
            );
            ApprovalEnd::Failed {
                version,
                cause: error.to_string(),
            }
        }
        _ => unavailable(error),
    }
}

/// A wrong approval passphrase, or a key that is not the pinned approver's, is the owner's refusal; anything else is
/// the service's.
fn denied_or_unavailable(error: SignError) -> ApprovalEnd {
    match error {
        SignError::WrongPassphrase | SignError::KeyMismatch => {
            tracing::warn!(%error, "config approval refused before any reservation");
            ApprovalEnd::Denied
        }
        other => unavailable(other),
    }
}

/// Records that the committed `version` is not active: the service settled in `state`, for the reason `detail` gives.
fn activation_failed(version: u64, state: ServiceState, detail: impl std::fmt::Display) {
    let reason = match state {
        ServiceState::Unavailable(reason) => UnavailableReason::from_failure(reason).as_str(),
        _ => "not ready",
    };
    tracing::warn!(event = "config.activation-failed", version, reason, %detail, "the approved config is not active");
}

fn unavailable(error: impl std::fmt::Display) -> ApprovalEnd {
    ApprovalEnd::Unavailable(error.to_string())
}

/// The durable steps' storage over the context's locks and filesystem, for the review (step 1) and the task that runs
/// the rest.
fn approval_storage<'s, F>(locks: &'s ServiceLocks, fs: &'s F, identity: &'s VaultIdentity) -> ApprovalStorage<'s, F> {
    ApprovalStorage {
        state_dir: &locks.state,
        config_dir: &locks.config,
        identity,
        fs,
    }
}
