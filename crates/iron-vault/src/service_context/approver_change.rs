//! The approver commands' side of the service context (`design/approval-signers.md`, "States and the service-wide lock").
//!
//! [`ServiceContext::plan_approver_enrollment`] and [`ServiceContext::plan_approver_removal`] take the service-wide lock without waiting and runs step 3: it reads
//! `approval.age` back, sweeps orphan key files against the state read, and check the approver set. The
//! [`ApproverChangePlan`] it returns holds the lock through the summary, owner presence, the new signer's prompts and the
//! write, so the summary stays true until the write. Like a recipient removal's plan it keeps no vault identity, so a
//! `lock` while the owner is at a prompt leaves no copy behind; the write takes the identity from the context again, and
//! refuses unless the service is still in the state and at the check generation it recorded.
//!
//! Every write runs on a blocking task that owns the lock guard and the approval state, and hands both back, so the
//! in-memory approval state is replaced under the lock even when the caller's future is dropped mid-write.

use std::sync::Arc;

use iron_vault_store::{
    ApprovalPassphrase, ApprovalState, ApproverChangeError, ApproverChanges, ApproverId, ApproverLabel, KeyFileOutcome, MAX_APPROVERS,
    MayHaveCommitted, PinnedApprover, StoreFs, VaultId, VaultIdentity,
};
use tokio::sync::OwnedMutexGuard;

use super::{OwnerPresence, PresenceRefusal, ServiceContext};
use crate::audit::approver::{ChangeFailed, ChangeFailure, Enrolled, OrphanRemoved, Removed};
use crate::audit::{AuditEvent, NamedApprover};
use crate::service_state::{AdminOperation, ServiceState};

/// The `change` label of an enrollment's audit records.
const ADD: &str = "add";
/// The `change` label of a removal's audit records.
const REMOVE: &str = "remove";

/// Why an approver command ended without changing the approvers.
#[derive(Debug, thiserror::Error)]
pub enum ApproverRefusal {
    /// Another operation holds the service-wide lock.
    #[error("another operation holds the service-wide lock")]
    Busy,
    /// The service is not Ready, or left the state or check generation it was in when the command took the lock.
    #[error("the service is {0:?}")]
    WrongState(ServiceState),
    /// The approver set after the change would break its count limits; the message names the rule.
    #[error("{0}")]
    SetInvalid(&'static str),
    /// `approver remove` named an ID that no pinned approver has.
    #[error("no pinned approver has this ID")]
    UnknownApprover,
    /// `approver remove` named the approver that signed the active approval.
    #[error("this approver signed the active approval")]
    InUse,
    /// Step 3's read-back or orphan sweep, or the approver change, failed; `committed` says whether it may have committed.
    #[error("{cause}")]
    Failed {
        /// Whether the change may have committed.
        committed: MayHaveCommitted,
        /// What failed, without key material.
        cause: String,
    },
}

/// Step 3 of an approver command done: the service-wide lock is held, `approval.age` read back and the orphans swept. See
/// the module docs.
pub struct ApproverChangePlan<'a, F> {
    service: &'a ServiceContext<F>,
    service_wide: OwnedMutexGuard<()>,
    /// The service state and check generation at step 2, which the write checks again.
    state: ServiceState,
    checks: u64,
    /// The approval state step 3 read back, which the change writes from.
    approval: ApprovalState,
    /// The pinned approvers in approver order, which owner presence asks.
    approvers: Vec<PinnedApprover>,
}

impl<F: StoreFs + Send + Sync + 'static> ServiceContext<F> {
    /// Steps 2 and 3 of `approver add`: takes the service-wide lock, refusing at once with [`ApproverRefusal::Busy`] while
    /// another holds it, reads the approval state back and sweeps orphans, then refuses a seventeenth approver.
    pub async fn plan_approver_enrollment(&self) -> Result<ApproverChangePlan<'_, F>, ApproverRefusal> {
        let plan = self.plan_approver_change(ADD).await?;
        if plan.approval.approvers().len() >= MAX_APPROVERS {
            log_failure(ADD, ChangeFailure::SetInvalid);
            return Err(ApproverRefusal::SetInvalid("16 approvers are already pinned"));
        }
        Ok(plan)
    }

    /// Steps 2 and 3 of `approver remove`: the lock, the read-back and the orphan sweep, then refuses an ID that no pinned
    /// approver has, the last approver, and the approver that signed the active approval, in that order. Returns the plan
    /// and the approver `id` names, which the summary describes.
    pub async fn plan_approver_removal(&self, id: ApproverId) -> Result<(ApproverChangePlan<'_, F>, PinnedApprover), ApproverRefusal> {
        let plan = self.plan_approver_change(REMOVE).await?;
        let refuse = |failure, refusal| {
            ChangeFailed {
                change: REMOVE,
                approver: Some(id),
                failure,
            }
            .emit();
            Err(refusal)
        };
        let Some(approver) = plan.approval.approver(id).cloned() else {
            return refuse(ChangeFailure::UnknownApprover, ApproverRefusal::UnknownApprover);
        };
        if plan.approver_count() == 1 {
            return refuse(ChangeFailure::SetInvalid, ApproverRefusal::SetInvalid("it is the last approver"));
        }
        if self.active_signer() == Some(id) {
            return refuse(ChangeFailure::InUse, ApproverRefusal::InUse);
        }
        Ok((plan, approver))
    }

    /// Steps 2 and 3 of an approver command (`change` is `add` or `remove`): the lock, the read-back and the orphan sweep.
    async fn plan_approver_change(&self, change: &'static str) -> Result<ApproverChangePlan<'_, F>, ApproverRefusal> {
        let service_wide = Arc::clone(&self.service_wide).try_lock_owned().map_err(|_| ApproverRefusal::Busy)?;
        let (state, checks, identity, approval) = {
            let inner = self.inner.lock().await;
            match (&inner.identity, &inner.open) {
                (Some(identity), Some(open)) if inner.state.admin_allows(AdminOperation::VaultChange) => {
                    (inner.state, inner.checks, Arc::clone(identity), open.approval.clone())
                }
                _ => return Err(ApproverRefusal::WrongState(inner.state)),
            }
        };
        let (service_wide, approval) = self.read_back(change, service_wide, identity, approval).await?;
        self.keep_approval(&approval, (state, checks)).await;
        Ok(ApproverChangePlan {
            service: self,
            service_wide,
            state,
            checks,
            approvers: self.ordered_approvers(approval.approvers()),
            approval,
        })
    }

    /// Reads the approval state back and sweeps orphans on a blocking task that owns `held` until both end, and returns the
    /// state read. Each orphan removed is logged as `approver.orphan-removed`; a read-back or sweep that fails is logged as
    /// `approver.change-failed` at step `read_back`, and never committed anything.
    async fn read_back(
        &self,
        change: &'static str,
        held: OwnedMutexGuard<()>,
        identity: Arc<VaultIdentity>,
        mut approval: ApprovalState,
    ) -> Result<(OwnedMutexGuard<()>, ApprovalState), ApproverRefusal> {
        let (locks, setup) = (Arc::clone(&self.locks), Arc::clone(&self.setup));
        let task = tokio::task::spawn_blocking(move || {
            let changes = ApproverChanges::new(&locks.state, &setup.fs, &identity);
            let swept = changes
                .read_back_approval_state(&mut approval)
                .and_then(|read_back| changes.remove_orphan_key_files(&read_back));
            (held, approval, swept)
        });
        let (held, approval, swept) = task.await.map_err(|_| ApproverRefusal::Failed {
            committed: MayHaveCommitted::No,
            cause: "reading the approval state back did not finish; nothing was changed".to_owned(),
        })?;
        let orphans = match &swept {
            Ok(removed) | Err(ApproverChangeError::OrphanSweep { removed, .. }) => removed.as_slice(),
            Err(_) => &[],
        };
        orphans.iter().copied().map(OrphanRemoved).for_each(|event| event.emit());
        match swept {
            Ok(_) => Ok((held, approval)),
            Err(error) => {
                log_failure(change, ChangeFailure::WriteFailed(&error));
                Err(failed(&error))
            }
        }
    }

    /// Replaces the in-memory approval state with `approval` while the service is still where `at` recorded it.
    async fn keep_approval(&self, approval: &ApprovalState, (state, checks): (ServiceState, u64)) {
        let mut inner = self.inner.lock().await;
        if inner.state == state
            && inner.checks == checks
            && let Some(open) = &mut inner.open
        {
            open.approval = approval.clone();
        }
    }
}

impl<F: StoreFs + Send + Sync + 'static> ApproverChangePlan<'_, F> {
    /// The vault the approval state belongs to, which the summary names.
    pub fn vault_id(&self) -> VaultId {
        self.approval.vault_id()
    }

    /// How many approvers are pinned now.
    pub fn approver_count(&self) -> usize {
        self.approval.approvers().len()
    }

    /// The pinned approvers in approver order: owner presence asks the first and lets the owner switch to the rest.
    pub fn approvers(&self) -> &[PinnedApprover] {
        &self.approvers
    }

    /// Completes once a `lock` is waiting for the service-wide lock this plan holds, so a prompt can end the change rather
    /// than make the `lock` wait for the owner.
    pub async fn lock_requested(&self) {
        self.service.lock_requested().await;
    }

    /// Owner presence with `approver`'s key; see [`ServiceContext::prove_presence`].
    pub async fn prove_presence(
        &self,
        passphrase: ApprovalPassphrase,
        approver: &PinnedApprover,
    ) -> Result<OwnerPresence, PresenceRefusal> {
        self.service.prove_presence(passphrase, approver).await
    }

    /// Records step 6's refusal of the new signer's secret as `approver.change-failed`.
    pub fn passphrase_rejected(&self) {
        log_failure(ADD, ChangeFailure::PassphraseRejected);
    }

    /// Steps 7 and 8 for `software`: refuses unless the service is still in the state and at the check generation of step
    /// 2, then enrolls a software approver named `label` with its key sealed to `passphrase`. Logs `approver.enrolled` at
    /// the commit point, naming the approver `proof` came from, and `approver.change-failed` when the change fails. Taking
    /// the proof by value makes one proof authorize one change.
    pub async fn enroll_software(
        self,
        proof: OwnerPresence,
        label: ApproverLabel,
        passphrase: ApprovalPassphrase,
    ) -> Result<(PinnedApprover, usize), ApproverRefusal> {
        let Self {
            service,
            service_wide,
            state,
            checks,
            mut approval,
            ..
        } = self;
        let identity = service.identity_at(state, checks).await?;
        let now = service.clock.now().map_err(|error| ApproverRefusal::Failed {
            committed: MayHaveCommitted::No,
            cause: format!("the clock cannot be read ({error})"),
        })?;
        let (locks, setup) = (Arc::clone(&service.locks), Arc::clone(&service.setup));
        let task = tokio::task::spawn_blocking(move || {
            let enrolled =
                ApproverChanges::new(&locks.state, &setup.fs, &identity).enroll_software_approver(&mut approval, label, &passphrase, now);
            (service_wide, approval, enrolled)
        });
        let (_held, approval, enrolled) = task.await.map_err(|_| interrupted())?;
        service.keep_approval(&approval, (state, checks)).await;
        let approver = enrolled.map_err(|error| {
            log_failure(ADD, ChangeFailure::WriteFailed(&error));
            failed(&error)
        })?;
        let approvers = approval.approvers().len();
        Enrolled {
            approver: &approver,
            approvers,
            authorizing: NamedApprover::from(proof.approver()),
        }
        .emit();
        Ok((approver, approvers))
    }
}

impl<F: StoreFs + Send + Sync + 'static> ApproverChangePlan<'_, F> {
    /// Steps 6 and 7 of `approver remove`: refuses unless the service is still in the state and at the check generation of
    /// step 2, then unpins `approver` and deletes its key file. Logs `approver.removed` at the commit point, naming the
    /// approver `proof` came from, and `approver.change-failed` when the change fails. A key file that cannot be deleted
    /// is [`KeyFileOutcome::Left`], not a failure: the approver is gone and the next approver command sweeps the file.
    /// Returns how many approvers remain.
    pub async fn remove_approver(
        self,
        proof: OwnerPresence,
        approver: &PinnedApprover,
    ) -> Result<(usize, KeyFileOutcome), ApproverRefusal> {
        let Self {
            service,
            service_wide,
            state,
            checks,
            mut approval,
            ..
        } = self;
        let identity = service.identity_at(state, checks).await?;
        let (locks, setup, id) = (Arc::clone(&service.locks), Arc::clone(&service.setup), approver.id());
        let task = tokio::task::spawn_blocking(move || {
            let removed = ApproverChanges::new(&locks.state, &setup.fs, &identity).remove_approver(&mut approval, id);
            (service_wide, approval, removed)
        });
        let (_held, approval, removed) = task.await.map_err(|_| interrupted())?;
        service.keep_approval(&approval, (state, checks)).await;
        let key_file = removed.map_err(|error| {
            ChangeFailed {
                change: REMOVE,
                approver: Some(id),
                failure: ChangeFailure::WriteFailed(&error),
            }
            .emit();
            failed(&error)
        })?;
        let approvers = approval.approvers().len();
        Removed {
            approver,
            approvers,
            authorizing: NamedApprover::from(proof.approver()),
            key_file: &key_file,
        }
        .emit();
        Ok((approvers, key_file))
    }
}

impl<F: StoreFs + Send + Sync + 'static> ServiceContext<F> {
    /// The vault identity, provided the service is still in `state` at check generation `checks`, as when a change took
    /// the lock. The plan keeps no identity so that a `lock` while the owner is at a prompt leaves no copy behind.
    async fn identity_at(&self, state: ServiceState, checks: u64) -> Result<Arc<VaultIdentity>, ApproverRefusal> {
        let inner = self.inner.lock().await;
        let unchanged = inner.state == state && inner.checks == checks;
        inner
            .identity
            .clone()
            .filter(|_| unchanged)
            .ok_or(ApproverRefusal::WrongState(inner.state))
    }
}

fn log_failure(change: &'static str, failure: ChangeFailure<'_>) {
    ChangeFailed {
        change,
        approver: None,
        failure,
    }
    .emit();
}

fn failed(error: &ApproverChangeError) -> ApproverRefusal {
    ApproverRefusal::Failed {
        committed: error.may_have_committed(),
        cause: error.to_string(),
    }
}

/// A blocking task that ended without a result. Whether it committed cannot be known from here.
fn interrupted() -> ApproverRefusal {
    ApproverRefusal::Failed {
        committed: MayHaveCommitted::Unknown,
        cause: "the approver change's task did not finish".to_owned(),
    }
}
