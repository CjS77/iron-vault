//! Runs `config approve`: the approval transaction that makes a new config active
//! ([spec §12](../../../../design/iron-vault-specification.md#12-configuration-approval-and-reload);
//! [config approval: The transaction](../../../../design/config-approval.md#the-transaction)). The admin handler
//! drives it through the two halves below, with the owner's prompts between them.
//!
//! ```text
//!   review_approval ── step 1: write config.toml.pending, validate and activate it ──→ ApprovalReview
//!        │                                                                              holds the service-wide lock
//!        │  owner confirms the summary, then answers the approver prompt (open_signer)
//!        ↓
//!   commit ── step 2: reserve the next version          (approval.age)
//!             step 3: sign the approval payload
//!             step 4: stage config.toml.sig.staged
//!             step 5: admission pause (Ready → Checking), commit (version, digest)
//!             step 6: publish config.toml and config.toml.sig, run the config check → Ready or Unavailable
//! ```
//!
//! A version reserved in step 2 is consumed even if a later step fails. So `open_signer` checks the approver's
//! passphrase or PIN before step 2, and a mistyped one costs no version.
//!
//! [`ServiceContext::review_approval`] takes the service-wide lock and runs step 1. The [`ApprovalReview`] it returns
//! holds that lock until it is committed or abandoned, so the predicted version stays exact and nothing changes the
//! credential catalog while the owner reads the summary. The review keeps no vault identity, so a `lock` while the
//! owner is at a prompt leaves no copy of it behind.
//!
//! A `lock` cancels a review still at a prompt: [`ApprovalReview::lock_requested`] completes once a `lock` waits for
//! the service-wide lock, and the prompt ends the approval with [`ApprovalEnd::CancelledByLock`]. Every other config
//! check waits for the service-wide lock, so none runs during the review. As a backstop, the review records the
//! service state and the context's check generation when it starts, and the commit refuses before reserving anything
//! unless both are unchanged, since each check discards uncommitted pending files.
//!
//! [`ApprovalReview::commit`] runs steps 2 to 6 under the context's mutex: reserve, sign and stage, then the admission
//! pause, the commit and publish, then the config check that ends the pause in Ready or Unavailable. A task of its own
//! owns the mutex guard and runs all of it; [`ApprovalReview::commit`] says what that guarantees.
//!
//! The service-wide guard moves into that task too, so it is held until the transaction ends, whether or not the caller
//! is dropped meanwhile. A caller dropped before `commit` takes the context mutex releases it with the review, and the
//! task never starts.

use std::sync::Arc;

use iron_vault_policy::{ActivePolicy, ApprovalSummary, ValidatedConfig, summarize};
use iron_vault_store::{
    ApprovalEnvelope, ApprovalError, ApprovalPayload, ApprovalProgress, ApprovalSigner, ApprovalState, ApprovalStorage, ApprovalVersion,
    ApproverPublicKey, CommittedApproval, ConfigDigest, PendingConfig, PinnedApprover, PreparedApproval, SignError, SignatureAlgorithm,
    StoreFs, Vault, VaultIdentity,
};
use tokio::sync::OwnedMutexGuard;

use super::{
    ApproverSecret, ApproverSigner, DenialKind, Inner, PresenceRefusal, ServiceContext, ServiceLocks, SettleGuard, Settler, apply,
    log_destination, log_task_crash,
};
use crate::admin::protocol::ApprovalResult;
use crate::audit::config::{VersionReserved, record_commit_uncertain, record_uncertain_writes};
use crate::audit::corruption::open_vault;
use crate::audit::{ActivationCause, ActivationFailed, ApprovalCompleted, ApprovalFailed, ApprovalRefused, AuditEvent, NamedApprover};
use crate::config_check::{InvalidConfig, activate_config};
use crate::service_state::{AdminOperation, FailureReason, ServiceEvent, ServiceState};
use crate::serving_snapshot::Admission;

/// How a `config approve` ended without an active new config. Each variant maps to one `config approve` error code, and
/// no message holds config bytes or anything the owner typed.
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
    /// A `lock` cancelled the approval while it waited at a prompt; nothing was reserved.
    #[error("a `lock` cancelled the approval at its prompt; no version was reserved")]
    CancelledByLock,
    /// The owner did not confirm the summary.
    #[error("the config was not approved: the confirmation was not `yes`")]
    Declined,
    /// The approval passphrase did not open the pinned approver's key.
    #[error("the approval passphrase does not open the approver key")]
    Denied,
    /// The TPM refused the approval PIN of a TPM approver; nothing was reserved.
    #[error("the TPM approval PIN is wrong; each wrong PIN counts against the TPM's lockout; no version was reserved")]
    PinDenied,
    /// The TPM is in lockout, or the lockout reserve withheld the try; nothing was reserved or signed.
    #[error("the TPM is locked out; try again in {wait_seconds} seconds; nothing was reserved, signed or changed")]
    LockedOut {
        /// The whole seconds to wait.
        wait_seconds: u64,
    },
    /// The approval cannot run: the approval state, the approver key or a write failed, and nothing was reserved.
    ///
    /// One exception: when the task running the transaction ends without a result (it panicked, or the runtime is
    /// shutting down), a version may already be reserved or committed. The message says so, and the service is
    /// Unavailable if it was Checking.
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

/// What an approval or presence prompt says when no pinned approver can be asked on this install.
pub const NO_ASKABLE_APPROVER: &str =
    "no pinned approver can be asked on this install; a TPM approver needs its key file and the TPM signing helper";

/// An approval past step 1: the pending config is durable and valid, and the owner has yet to review it. It holds the
/// service-wide lock until [`commit`](Self::commit) or [`abandon`](Self::abandon). See the module documentation.
pub struct ApprovalReview<'a, F> {
    service: &'a ServiceContext<F>,
    /// Owned, so [`ApprovalReview::commit`] can hand it to the transaction task.
    service_wide: OwnedMutexGuard<()>,
    started: Started,
    pending: PendingConfig,
    approval: ApprovalState,
    summary: ApprovalSummary,
    /// The pinned approvers in approver order: step 2 asks the first and lets the owner switch through the rest.
    approvers: Vec<PinnedApprover>,
}

/// Where an approval started: the service state and the context's check generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Started {
    state: ServiceState,
    checks: u64,
}

impl<F: StoreFs + Send + Sync + 'static> ServiceContext<F> {
    /// Takes the service-wide lock, refusing at once with [`ApprovalEnd::Busy`] while another holds it, and runs step
    /// 1: writes `config` as the pending config, then validates and activates it against a vault freshly opened from
    /// the kept vault identity, so a credential added since the last config check is in the catalog. The upstream
    /// clients are built too, so a config that cannot be served is invalid before any version is reserved.
    pub async fn review_approval(&self, config: Vec<u8>) -> Result<ApprovalReview<'_, F>, ApprovalEnd> {
        let service_wide = Arc::clone(&self.service_wide).try_lock_owned().map_err(|_| ApprovalEnd::Busy)?;
        let (started, identity, active) = self.approval_start().await?;
        let (vault, _) = open_vault(&self.locks.state, &self.setup.fs, Arc::clone(&identity)).map_err(unavailable)?;
        let approval = vault.load_approval_state(&self.locks.state, &self.setup.fs).map_err(unavailable)?;
        let approvers = self.askable_approvers(approval.approvers());
        if approvers.is_empty() {
            return Err(unavailable(NO_ASKABLE_APPROVER));
        }
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
            service_wide,
            started,
            summary: summary_of(active.as_ref(), policy.config(), &approval, pending.digest()),
            pending,
            approval,
            approvers,
        })
    }

    /// Returns where the approval starts, the kept vault identity, and the config of the serving snapshot, which the
    /// summary diffs against; that config is `None` when the service is not serving one.
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

    /// Activates the pending config against `vault`, and returns the policy once its upstream clients build and the log
    /// destination it chooses passes its pre-check.
    fn servable(&self, bytes: &[u8], vault: &Vault) -> Result<ActivePolicy, InvalidConfig> {
        let policy = activate_config(bytes, vault, &self.setup.accounts)?;
        self.setup.upstream.clients(&policy).map_err(InvalidConfig::Clients)?;
        log_destination::precheck(policy.config(), &self.setup.log, &self.setup.paths)?;
        Ok(policy)
    }

    fn storage<'s>(&'s self, identity: &'s VaultIdentity) -> ApprovalStorage<'s, F> {
        approval_storage(&self.locks, &self.setup.fs, identity)
    }
}

/// Builds the summary of `pending` against `active`. When the service serves the committed config and `pending` has the
/// same digest, nothing is diffed: the approval only signs the same bytes again, which is how an approval signer is
/// rotated. With no active config, as after `import`, the committed config was approved for another host, so the
/// summary lists the whole of it.
fn summary_of(
    active: Option<&ValidatedConfig>,
    pending: &ValidatedConfig,
    approval: &ApprovalState,
    digest: ConfigDigest,
) -> ApprovalSummary {
    match (active, approval.committed()) {
        (Some(_), Some((version, committed))) if committed == digest => ApprovalSummary::same_config(version.get()),
        _ => summarize(active, pending),
    }
}

impl<F: StoreFs + Send + Sync + 'static> ApprovalReview<'_, F> {
    /// Returns what the owner reviews before confirming: the header, then the summary's sections.
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

    /// Returns the version this approval will commit. It is exact, because the service-wide lock keeps anything else
    /// from reserving one.
    pub fn version(&self) -> u64 {
        self.approval.highest_reserved().saturating_add(1)
    }

    /// Completes once a `lock` is waiting for the service-wide lock this review holds, or at once when one already
    /// waits. A prompt ends the approval when it completes, so the `lock` does not wait for the owner to answer.
    pub async fn lock_requested(&self) {
        self.service.lock_requested().await;
    }

    /// Returns the pinned approvers in approver order: the prompt asks the first, and each switch moves to the next.
    pub fn approvers(&self) -> &[PinnedApprover] {
        &self.approvers
    }

    /// Opens `approver`'s own key with what the owner typed, through the check owner presence makes too. For a TPM
    /// approver that is step 2's presence payload, signed under the PIN. A wrong secret, or a key that is not
    /// `approver`'s, is [`ApprovalEnd::Denied`] (or [`ApprovalEnd::PinDenied`]), with no fall-through to another
    /// approver; a lockout is [`ApprovalEnd::LockedOut`]; a check that cannot run or does not finish refuses the
    /// approval before anything is reserved.
    pub async fn open_signer(&self, approver: &PinnedApprover, secret: impl Into<ApproverSecret>) -> Result<ApproverSigner, ApprovalEnd> {
        let vault_id = Some(self.approval.vault_id());
        self.service
            .open_approver(secret.into(), approver.clone(), vault_id)
            .await
            .map_err(|refusal| self.refused(refusal, approver))
    }

    /// Ends the approval for a secret to `approver` that cannot be the approval passphrase or PIN (empty, not UTF-8,
    /// or a PIN shorter than enrollment allows), which is answered as a wrong one without asking the key or the TPM:
    /// records `config.approval-refused`, with no `tpm_status`, and returns the denial.
    pub fn refuse_unusable_passphrase(&self, approver: &PinnedApprover) -> ApprovalEnd {
        self.refused(PresenceRefusal::Unusable(DenialKind::wrong_answer(approver.kind())), approver)
    }

    /// Records a refused approval as `config.approval-refused`, with the digest of the config it was for and the
    /// approver answered. Every refusal is recorded here and nowhere else.
    fn refused(&self, refusal: PresenceRefusal, approver: &PinnedApprover) -> ApprovalEnd {
        if let Some((kind, tpm_status)) = refusal.audit() {
            ApprovalRefused {
                refusal: kind,
                tpm_status,
                digest: self.pending.digest(),
                approver: NamedApprover::from(approver),
            }
            .emit();
        }
        match refusal {
            PresenceRefusal::Denied(DenialKind::WrongPin) | PresenceRefusal::Unusable(DenialKind::WrongPin) => ApprovalEnd::PinDenied,
            PresenceRefusal::Denied(_) | PresenceRefusal::Unusable(_) => ApprovalEnd::Denied,
            PresenceRefusal::TpmLockedOut { wait_seconds } => ApprovalEnd::LockedOut { wait_seconds },
            PresenceRefusal::Unavailable(cause) | PresenceRefusal::TpmUnavailable { message: cause, .. } => {
                ApprovalEnd::Unavailable(format!("{cause}; nothing was reserved"))
            }
        }
    }

    /// Ends the approval before any reservation: removes the pending config and releases the service-wide lock.
    pub fn abandon(self) {
        self.pending.abandon(&self.service.locks.config, &self.service.setup.fs);
    }

    /// Runs steps 2 to 6 with `signer`, the key of `approver` that [`open_signer`](Self::open_signer) opened, and drops
    /// the signer once it has signed: reserve, sign and stage; then the admission pause (from Ready, the move to
    /// Checking), the commit and publish; then the config check that ends the pause.
    ///
    /// Refuses before reserving unless the service is in the state, and at the check generation, the approval started
    /// at. This is the backstop for a state or generation change made without the service-wide lock, which today is
    /// only a `stop`: a `lock` cancels the approval at its prompt, and every config check waits for the lock.
    ///
    /// Cancel-safe: once `commit` holds the context mutex, a task of its own owns that guard, and the service-wide
    /// guard with it, and runs every step to its end, as [`ServiceContext::unlock`] does for a config check. Dropping
    /// this future after the commit therefore never leaves the service in Checking
    /// ([spec §15](../../../../design/iron-vault-specification.md#15-service-states-and-errors)): the task still
    /// settles in Ready on the new config, or in Unavailable. A task that ends without a result fails closed through
    /// its `SettleGuard`, and this call then answers [`ApprovalEnd::Unavailable`], whose message says a version may
    /// be consumed or committed.
    pub async fn commit<S: ApprovalSigner + Send + 'static>(
        self,
        approver: PinnedApprover,
        signer: S,
    ) -> Result<ApprovalResult, ApprovalEnd> {
        let Self {
            service,
            service_wide,
            started: Started { state: started, checks },
            pending,
            approval,
            summary,
            approvers: _,
        } = self;
        let inner = Arc::clone(&service.inner).lock_owned().await;
        let Some(identity) = inner.identity.clone().filter(|_| inner.state == started && inner.checks == checks) else {
            pending.abandon(&service.locks.config, &service.setup.fs);
            return Err(ApprovalEnd::Unavailable(
                "the service was stopped or checked again while the owner was at a prompt; nothing was reserved".to_owned(),
            ));
        };
        let (settler, mut guard) = (service.settler(), SettleGuard::new(inner, Arc::clone(&service.holder)));
        let transaction = Transaction {
            started,
            identity,
            pending,
            approval,
            summary,
            approver,
            signer,
        };
        let running = tokio::spawn(async move {
            // Held until the task ends, so no other approval or vault write starts while this one settles.
            let _service_wide = service_wide;
            settler.run_approval(&mut guard.inner, transaction).await
        });
        running.await.unwrap_or_else(|crashed| {
            log_task_crash("the approval transaction's task", &crashed);
            Err(unavailable(
                "the approval did not finish; a version may be consumed or committed, and the service is Unavailable if it was checking",
            ))
        })
    }
}

/// What the task that runs steps 2 to 6 owns: everything the transaction reads, so it can outlive the call that started
/// it.
struct Transaction<S> {
    started: ServiceState,
    identity: Arc<VaultIdentity>,
    pending: PendingConfig,
    approval: ApprovalState,
    summary: ApprovalSummary,
    approver: PinnedApprover,
    signer: S,
}

impl<F: StoreFs + Send + Sync + 'static> Settler<F> {
    /// Runs steps 2 to 6 of `transaction` under `inner`, which the caller's task owns.
    async fn run_approval<S: ApprovalSigner + Send + 'static>(
        &self,
        inner: &mut Inner,
        transaction: Transaction<S>,
    ) -> Result<ApprovalResult, ApprovalEnd> {
        let Transaction {
            started,
            identity,
            pending,
            mut approval,
            summary,
            approver,
            signer,
        } = transaction;
        let named = NamedApprover::from(&approver);
        let storage = approval_storage(&self.locks, &self.setup.fs, &identity);
        let digest = pending.digest();
        let prepared = match reserve_and_sign(&storage, pending, &mut approval, (named, signer)).await {
            Ok(prepared) => prepared,
            Err(error) => {
                // A reservation that took is consumed: `status` reports the counter as it now is.
                if let Some(open) = &mut inner.open {
                    open.approval = approval;
                }
                return Err(not_committed(error, digest));
            }
        };
        let approved = prepared.version();
        let version = approved.get();
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
            prepared.commit(&storage, &pause)
        };
        record_commit(approved, &committed);
        let committed = committed.map(drop);
        self.durable(inner, started, &identity, committed, digest).await?;
        ApprovalCompleted {
            version: approved,
            digest,
            summary: &summary.render(),
            approver: named,
        }
        .emit();
        match self.check_committed(inner, started, identity).await {
            ServiceState::Ready => Ok(ApprovalResult {
                version,
                digest: *digest.as_bytes(),
                headline: summary.headline(),
            }),
            state => {
                activation_failed(approved, state, ActivationCause::CheckFailed);
                Err(ApprovalEnd::NotActive { version, state })
            }
        }
    }

    /// Finishes steps 5 and 6 after a durable commit: runs the config check from Checking when the approval started in
    /// Ready, or through `Repaired` when it started in Unavailable.
    async fn check_committed(&self, inner: &mut Inner, started: ServiceState, identity: Arc<VaultIdentity>) -> ServiceState {
        let checked = match started {
            ServiceState::Ready => self.settle(inner, identity, ServiceEvent::ApprovalCommitting, None).await,
            _ => self.check_and_settle(inner, ServiceEvent::Repaired, identity).await,
        };
        checked.unwrap_or_else(|illegal| illegal.state)
    }

    /// Handles an uncertain commit that could not be settled: moves the service through Checking to Unavailable needing
    /// recovery, from either start, and returns that state.
    fn recovery_needed(&self, inner: &mut Inner, started: ServiceState) -> ServiceState {
        if started != ServiceState::Ready {
            inner.open = None;
            let _ = apply(&self.holder, inner, ServiceEvent::Repaired);
        }
        apply(&self.holder, inner, ServiceEvent::CheckFailed(FailureReason::RecoveryNeeded)).unwrap_or(inner.state)
    }

    /// Returns `Ok` if and only if step 5 left a durable commit. A commit whose publish failed is durable: the config
    /// check's recovery finishes the publish. Otherwise this ends the admission pause and the approval:
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
                activation_failed(version, state, ActivationCause::CommitUnsettled);
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

/// Runs steps 2 to 4: reserve, sign and stage. The reservation is recorded before signing starts, so a signing failure,
/// or a crash while the signer waits for the owner, follows it in the log.
async fn reserve_and_sign<'s, F: StoreFs, S: ApprovalSigner + Send + 'static>(
    storage: &ApprovalStorage<'_, F>,
    pending: PendingConfig,
    approval: &'s mut ApprovalState,
    (approver, signer): (NamedApprover<'_>, S),
) -> Result<PreparedApproval<'s>, ApprovalError> {
    let reserved = pending.reserve(storage, approval).inspect_err(record_uncertain_writes)?;
    VersionReserved {
        version: reserved.version(),
        digest: reserved.digest(),
        approver,
    }
    .emit();
    let presigned = Presigned::sign(signer, reserved.payload()).await;
    reserved.sign(storage, presigned)
}

/// A signature made on the blocking pool, handed to step 3 as its signer.
///
/// A TPM approver's signature is a round trip to the signing helper, which can take hundreds of milliseconds and,
/// from a hung helper, up to its 30 s deadline. Made on the service's runtime thread, it would stall proxying, admin
/// connections and timers meanwhile. Step 3 still checks the envelope against the reserved payload, and a failure
/// here, including a task that ended without an answer, is a step 3 failure that consumes the version.
struct Presigned {
    algorithm: SignatureAlgorithm,
    public_key: ApproverPublicKey,
    signed: Result<ApprovalEnvelope, SignError>,
}

impl Presigned {
    /// Has `signer` sign `payload` on the blocking pool. The task owns the signer, and with it any TPM authorization
    /// value, and drops it when it ends, even if the transaction's task is gone by then.
    async fn sign<S: ApprovalSigner + Send + 'static>(signer: S, payload: ApprovalPayload) -> Self {
        let (algorithm, public_key) = (signer.algorithm(), signer.public_key());
        let signed = tokio::task::spawn_blocking(move || signer.sign(&payload))
            .await
            .unwrap_or(Err(SignError::Interrupted));
        Self {
            algorithm,
            public_key,
            signed,
        }
    }
}

impl ApprovalSigner for Presigned {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    fn public_key(&self) -> ApproverPublicKey {
        self.public_key
    }

    /// Returns the envelope made for the payload [`Presigned::sign`] was given, and ignores `_payload`. That is safe
    /// only because step 3 checks the envelope against the reserved payload, and refuses one signed for another.
    fn sign(&self, _payload: &ApprovalPayload) -> Result<ApprovalEnvelope, SignError> {
        self.signed.clone()
    }
}

/// Records every uncertain write of the commit of `version`, whether the commit then succeeded or failed.
fn record_commit(version: ApprovalVersion, committed: &Result<CommittedApproval, ApprovalError>) {
    match committed {
        Ok(committed) => committed
            .commit_uncertain()
            .into_iter()
            .for_each(|kind| record_commit_uncertain(version, kind)),
        Err(error) => record_uncertain_writes(error),
    }
}

/// Ends an approval that failed before the commit. When a version was reserved, logs a failed approval of `digest` and
/// returns [`ApprovalEnd::Failed`] with that consumed version; otherwise returns [`ApprovalEnd::Unavailable`].
fn not_committed(error: ApprovalError, digest: ConfigDigest) -> ApprovalEnd {
    match error.progress() {
        ApprovalProgress::Reserved(version) => {
            ApprovalFailed {
                version,
                digest,
                error: &error,
            }
            .emit();
            ApprovalEnd::Failed {
                version: version.get(),
                cause: error.to_string(),
            }
        }
        _ => unavailable(error),
    }
}

/// Records that the committed `version` is not active: the service settled in `state`, for `cause`.
fn activation_failed(version: ApprovalVersion, state: ServiceState, cause: ActivationCause) {
    ActivationFailed { version, state, cause }.emit();
}

fn unavailable(error: impl std::fmt::Display) -> ApprovalEnd {
    ApprovalEnd::Unavailable(error.to_string())
}

/// Builds the durable steps' storage over the context's locks and filesystem, for the review (step 1) and for the task
/// that runs the rest.
fn approval_storage<'s, F>(locks: &'s ServiceLocks, fs: &'s F, identity: &'s VaultIdentity) -> ApprovalStorage<'s, F> {
    ApprovalStorage {
        state_dir: &locks.state,
        config_dir: &locks.config,
        identity,
        fs,
    }
}
