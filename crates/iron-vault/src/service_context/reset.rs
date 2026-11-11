//! `reset`'s side of the service context (`design/reset.md`, "The exchange"): the plan read before the summary, and the
//! withdrawal and discard once the owner has confirmed.
//!
//! The summary and the confirmation hold no lock. After the confirmation the rest runs in a task the service owns, so a
//! CLI that closes does not stop it: it takes the service-wide lock, checks the service and the directories again under
//! the context's mutex, withdraws the vault as `lock` does, releases the mutex and keeps the service-wide lock to the end.
//! Releasing the mutex before `discard_vault` lets `status` answer while the files go; the service-wide lock, which every
//! store writer takes, is what keeps the directories still.

use std::sync::Arc;
use std::time::Duration;

use iron_vault_store::{
    DiscardError, DiscardFailure, DiscardedVault, ErrorKindLabel, InitializationState, ResetScope, ResetStep, StoreFs, VaultId,
    discard_vault, read_unverified_vault_id, reset_scope,
};
use tokio::sync::OwnedMutexGuard;

use super::{LockOutcome, LockRequest, ServiceContext, lock_outcome};
use crate::audit::AuditEvent;
use crate::audit::vault::{ResetConfirmed, ResetFailed, VaultReset};
use crate::service_state::{AdminOperation, ServiceEvent, ServiceState, next};
use crate::serving_snapshot::Withdrawn;

/// The vault reset would discard, when the state is Initialized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlannedVault {
    /// The vault ID: from the open vault in Ready, else from the manifest's clear header.
    pub id: VaultId,
    /// Whether the ID came from an open vault. Without one nothing checks the manifest's MAC.
    pub verified: bool,
}

/// What reset read before the summary: the scope, the vault, and what the confirmation must be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResetPlan {
    /// What the directories hold.
    pub scope: ResetScope,
    /// The vault, when the state is Initialized.
    pub vault: Option<PlannedVault>,
    /// The service state reset started from.
    pub from: ServiceState,
    /// The credentials' names, as `list` shows them, while the vault is open.
    pub credentials: Option<Vec<String>>,
    /// The state directory's absolute path, as text.
    pub state_dir: String,
}

impl ResetPlan {
    /// The text the owner must type: the vault ID of an Initialized vault, else the state directory's path.
    pub fn confirmation(&self) -> String {
        self.vault.map_or_else(|| self.state_dir.clone(), |vault| vault.id.to_string())
    }

    /// Whether `typed` is the confirmation. A vault ID is hex, so it matches in either case; a path matches byte for byte.
    pub fn confirmed_by(&self, typed: &[u8]) -> bool {
        match self.vault {
            Some(vault) => typed.eq_ignore_ascii_case(vault.id.to_string().as_bytes()),
            None => typed == self.state_dir.as_bytes(),
        }
    }

    /// Whether this resumes an interrupted reset.
    pub fn resumes(&self) -> bool {
        self.scope.state == InitializationState::UnfinishedReset
    }
}

/// Why a reset removed nothing, or stopped part-way.
#[derive(Debug)]
pub enum ResetRefusal {
    /// The service is not Locked, Ready or Unavailable.
    WrongState(ServiceState),
    /// No vault file is there; the message says what to run next.
    NothingToReset(String),
    /// The directories changed between the summary and the confirmation; the message names the change.
    Changed(String),
    /// The directories could not be read, so nothing was removed.
    Unreadable(String),
    /// The discard stopped; the error names the step and the files removed before it.
    Failed(DiscardError),
    /// The task ended without a result, so how far it got is unknown.
    Interrupted,
}

/// A finished reset.
#[derive(Debug)]
pub struct ResetOutcome {
    /// The vault ID that was confirmed, when the state was Initialized.
    pub vault_id: Option<VaultId>,
    /// What the discard removed and left.
    pub discarded: DiscardedVault,
    /// Whether the lock drain cleared the vault identity.
    pub cleared: bool,
}

/// The step a failed discard names: the step of a failed file operation, else `begin`, since every other failure comes
/// before the first write.
pub fn failure_step(cause: &DiscardFailure) -> ResetStep {
    match cause {
        DiscardFailure::Io { step, .. } => *step,
        _ => ResetStep::Begin,
    }
}

/// The file, if any, and the error kind a failed discard logs.
fn failure_facts(cause: &DiscardFailure) -> (&str, ErrorKindLabel) {
    match cause {
        DiscardFailure::NothingToReset => ("", ErrorKindLabel::fixed("nothing_to_reset")),
        DiscardFailure::ListStateDir { kind } | DiscardFailure::ListConfigDir { kind } => ("", ErrorKindLabel::from(*kind)),
        DiscardFailure::NotARegularFile { file } => (file, ErrorKindLabel::fixed("not_a_regular_file")),
        DiscardFailure::Inspect { file, kind } | DiscardFailure::Io { file, kind, .. } => (file, ErrorKindLabel::from(*kind)),
    }
}

impl<F: StoreFs + Send + Sync + 'static> ServiceContext<F> {
    /// Steps 1 and 2: checks the service state, reads the directories without the vault identity, and works out the
    /// confirmation. Nothing is locked.
    pub async fn reset_plan(&self) -> Result<ResetPlan, ResetRefusal> {
        let (from, open) = {
            let inner = self.inner.lock().await;
            let open = inner.open.as_ref();
            let credentials = open.map(|open| open.credentials.iter().map(|c| c.name.to_string()).collect());
            (inner.state, open.map(|open| (open.approval.vault_id(), credentials)))
        };
        if !from.admin_allows(AdminOperation::Reset) {
            return Err(ResetRefusal::WrongState(from));
        }
        let scope = self.read_reset_scope().await?;
        if !scope.has_vault_file {
            return Err(nothing_to_reset(&scope));
        }
        let (open_id, credentials) = open.map_or((None, None), |(id, credentials)| (Some(id), credentials));
        let vault = match scope.state {
            InitializationState::Initialized => Some(self.planned_vault(open_id).await?),
            _ => None,
        };
        let state_dir = self.setup.paths.state_dir.to_str().map(str::to_owned);
        let state_dir = state_dir.ok_or_else(|| ResetRefusal::Unreadable("the state directory's path is not UTF-8".to_owned()))?;
        Ok(ResetPlan {
            scope,
            vault,
            from,
            credentials,
            state_dir,
        })
    }

    /// Steps 4 to 8, in a task the service owns. Withdraws the vault as `lock` does, discards it, clears the passphrase
    /// attempt limit and waits up to `drain` for the last holder of the old snapshot.
    pub async fn reset(self: &Arc<Self>, plan: ResetPlan, drain: Duration) -> Result<ResetOutcome, ResetRefusal> {
        let service = Arc::clone(self);
        tokio::spawn(async move { service.run_reset(plan, drain).await })
            .await
            .unwrap_or(Err(ResetRefusal::Interrupted))
    }

    async fn run_reset(&self, plan: ResetPlan, drain: Duration) -> Result<ResetOutcome, ResetRefusal> {
        let (service_wide, mut withdrawn, identity) = self.withdraw_for_reset(&plan).await?;
        let vault_id = plan.vault.map(|vault| vault.id);
        ResetConfirmed {
            vault_id,
            verified: plan.vault.is_some_and(|vault| vault.verified),
            initialization: plan.scope.state,
            from_state: plan.from,
            resumes: plan.resumes(),
        }
        .emit();
        // K-338: `lock` writes `locked-by-owner` before the snapshot is withdrawn; reset's withdrawal writes it the same way.
        let discarded = self.discard().await?;
        // The passphrase the attempt limit counted guesses against is gone with the vault.
        self.inner.lock().await.attempts.record_success();
        VaultReset {
            vault_id,
            files: &discarded.removed,
            foreign: &discarded.foreign,
            finish_uncertain: discarded.finish_uncertain.is_some(),
        }
        .emit();
        drop(service_wide);
        let snapshots = withdrawn.released(drain).await;
        let cleared = lock_outcome(snapshots, identity.strong_count()) == LockOutcome::Cleared;
        Ok(ResetOutcome {
            vault_id,
            discarded,
            cleared,
        })
    }

    /// Step 4: announces a lock request, which cancels an approval or vault change waiting at a prompt, waits for the
    /// service-wide lock, checks the service and the directories again under the context's mutex, and withdraws the
    /// vault. The mutex is released on return; the service-wide lock is handed back to be held to the end.
    async fn withdraw_for_reset(
        &self,
        plan: &ResetPlan,
    ) -> Result<(OwnedMutexGuard<()>, Withdrawn, std::sync::Weak<iron_vault_store::VaultIdentity>), ResetRefusal> {
        let _request = LockRequest::announce(&self.lock_requests);
        let service_wide = Arc::clone(&self.service_wide).lock_owned().await;
        let mut inner = self.inner.lock().await;
        let from = inner.state;
        if !from.admin_allows(AdminOperation::Reset) {
            return Err(ResetRefusal::WrongState(from));
        }
        self.recheck_scope(plan).await?;
        let to = match from {
            ServiceState::Locked => ServiceState::Locked,
            _ => next(from, ServiceEvent::Lock).map_err(|refused| ResetRefusal::WrongState(refused.state))?,
        };
        let (withdrawn, identity) = self.withdraw(&mut inner, from, to);
        Ok((service_wide, withdrawn, identity))
    }

    /// Steps 5 to 7: the store's discard on the blocking pool, logging `vault.reset-failed` when it stops.
    async fn discard(&self) -> Result<DiscardedVault, ResetRefusal> {
        let (locks, setup) = (Arc::clone(&self.locks), Arc::clone(&self.setup));
        let discarded = tokio::task::spawn_blocking(move || discard_vault(&locks.state, &locks.config, &setup.fs)).await;
        match discarded {
            Ok(Ok(done)) => Ok(done),
            Ok(Err(error)) => {
                let (file, error_kind) = failure_facts(&error.cause);
                ResetFailed {
                    step: failure_step(&error.cause),
                    file,
                    error_kind: &error_kind,
                    removed: &error.removed,
                }
                .emit();
                Err(ResetRefusal::Failed(error))
            }
            Err(_) => {
                tracing::error!("the reset's discard task ended without a result");
                Err(ResetRefusal::Interrupted)
            }
        }
    }

    /// Step 4's second look at the directories: nothing there ends with `NothingToReset`, any other change from what the
    /// summary described with `Changed`.
    async fn recheck_scope(&self, plan: &ResetPlan) -> Result<(), ResetRefusal> {
        let now = self.read_reset_scope().await?;
        if !now.has_vault_file {
            return Err(nothing_to_reset(&now));
        }
        if now.state != plan.scope.state {
            let was = plan.scope.state;
            return Err(ResetRefusal::Changed(format!(
                "the directories were {was:?} at the summary and are {:?} now",
                now.state
            )));
        }
        match plan.vault {
            Some(vault) if self.read_vault_id().await? != vault.id => Err(ResetRefusal::Changed(
                "the vault in the directories is not the one the summary named".to_owned(),
            )),
            _ => Ok(()),
        }
    }

    /// The vault of an Initialized state: the open vault's ID, else the manifest's clear header.
    async fn planned_vault(&self, open_id: Option<VaultId>) -> Result<PlannedVault, ResetRefusal> {
        match open_id {
            Some(id) => Ok(PlannedVault { id, verified: true }),
            None => Ok(PlannedVault {
                id: self.read_vault_id().await?,
                verified: false,
            }),
        }
    }

    async fn read_reset_scope(&self) -> Result<ResetScope, ResetRefusal> {
        let (locks, setup) = (Arc::clone(&self.locks), Arc::clone(&self.setup));
        let read = tokio::task::spawn_blocking(move || reset_scope(&locks.state, &locks.config, &setup.fs)).await;
        read.map_err(|_| unreadable("the read did not finish"))?.map_err(|e| unreadable(e))
    }

    async fn read_vault_id(&self) -> Result<VaultId, ResetRefusal> {
        let (locks, setup) = (Arc::clone(&self.locks), Arc::clone(&self.setup));
        let read = tokio::task::spawn_blocking(move || read_unverified_vault_id(&locks.state, &setup.fs)).await;
        read.map_err(|_| unreadable("the read did not finish"))?
            .map_err(|e| unreadable(format!("cannot read the vault ID from the manifest: {e}")))
    }
}

fn unreadable(why: impl ToString) -> ResetRefusal {
    ResetRefusal::Unreadable(why.to_string())
}

/// The refusal for directories with no vault file: a clean one says to run `init`; one holding other files names the first.
fn nothing_to_reset(scope: &ResetScope) -> ResetRefusal {
    let first = scope
        .foreign
        .first()
        .map(|name| iron_vault_policy::escaped(name))
        .or_else(|| scope.config_files.first().map(ToString::to_string));
    ResetRefusal::NothingToReset(match (scope.state, first) {
        (InitializationState::Uninitialized, _) | (_, None) => "no vault is there; run `iron-vault init` to make one".to_owned(),
        (_, Some(first)) => format!("no vault file is there, only {first}; move it aside, then run `iron-vault init`"),
    })
}
