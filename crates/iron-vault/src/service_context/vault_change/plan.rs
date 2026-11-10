//! `replace` and `rm`'s side of the service context (design/credential-commands.md, "Order of steps").
//!
//! [`ServiceContext::plan_vault_change`] takes the service-wide lock and runs steps 2 to 4: the lock, the manifest
//! lookup and the vault change check. The [`VaultChangePlan`] it returns holds that lock until the change is written or
//! abandoned, prompts included, so the check stays true until the write and owner presence authorizes exactly the change
//! the check passed. Like an approval's review, the plan keeps no vault identity and no serving snapshot, so a `lock`
//! while the owner is at a prompt leaves no copy of either behind.
//!
//! A `lock` cancels a plan still at a prompt: [`VaultChangePlan::lock_requested`] completes once a `lock` waits for the
//! service-wide lock, and the prompt ends the change. Every config check waits for that lock too. As a backstop, the
//! plan records the check generation, and the write refuses unless the service is still Ready at it.
//!
//! [`VaultChangePlan::change_credential`] runs steps 8 and 9: the write through a fresh [`Vault`] opened from the kept
//! identity, then the config check from Ready through [`ServiceEvent::VaultChanged`]. A task of its own owns the context
//! mutex guard and the service-wide guard and runs both, as an approval's commit does, so a dropped caller never leaves
//! the service in Checking and nothing else changes the vault until the check has settled. The write and the check share
//! the one task, rather than the check running through `check_and_settle_detached`, because a caller dropped between
//! them would leave a committed write unchecked, its removed or replaced secret still served.

use std::sync::Arc;

use iron_vault_kinds::CredentialMaterial;
use iron_vault_policy::CredentialName;
use iron_vault_store::{ApprovalPassphrase, PermittedOrigins, PinnedApprover, RecordId, StoreFs, VaultError, VaultIdentity};
use tokio::sync::OwnedMutexGuard;

use super::super::presence::asked_approver;
use super::super::{Inner, OpenVault, OwnerPresence, PresenceRefusal, ServiceContext, ServiceLocks, SettleGuard, Settler, log_task_crash};
use super::{VaultChangeRefusal, audit_write_report, kind_of, log_committed};
use crate::audit::corruption::open_vault;
use crate::audit::vault::emit_commit_uncertain;
use crate::service_state::{AdminOperation, ServiceEvent, ServiceState};
use crate::serving_snapshot::Admission;
use crate::standing::{CredentialStanding, RecordSummary, Standing};
use crate::vault_change_check::{AffectedRoute, PlannedChange, vault_change_check};
use crate::vault_change_summary::VaultChangeSummary;

/// Steps 2 to 4 of a `replace` or `rm` done: the service-wide lock is held and the vault change check passed. See the
/// module docs.
pub struct VaultChangePlan<'a, F> {
    service: &'a ServiceContext<F>,
    /// Owned, so [`VaultChangePlan::change_credential`] can hand it to the task that writes and checks.
    service_wide: OwnedMutexGuard<()>,
    /// The check generation at step 2, which the write checks again.
    checks: u64,
    /// The pinned approvers, from the approval state the service holds; owner presence asks the first of
    /// them ([`asked_approver`]).
    approvers: Vec<PinnedApprover>,
    /// The change the check passed, the record it acts on and the routes that use it, as the owner is shown them.
    summary: VaultChangeSummary,
}

/// The record a `replace` or `rm` acts on, as the vault change summary describes it (design/credential-commands.md,
/// "Vault change summary"). Read under the service-wide lock, so it stays true until the write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentRecord {
    /// The record's ID, which the write supersedes or removes.
    pub record_id: RecordId,
    /// Whether the record loaded.
    pub standing: Standing,
    /// The record's kind and permitted origins; `None` for a damaged record, whose origins cannot be trusted.
    pub summary: Option<RecordSummary>,
}

/// What a committed `replace` or `rm` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialChanged {
    /// The record was removed.
    Removed,
    /// The record was replaced by one with this new record ID.
    Replaced(RecordId),
}

/// The write a plan makes, with the material the owner typed after presence.
enum Write {
    Remove(CredentialName),
    Replace {
        name: CredentialName,
        material: CredentialMaterial,
        origins: PermittedOrigins,
    },
}

impl Write {
    fn name(&self) -> &CredentialName {
        match self {
            Self::Remove(name) | Self::Replace { name, .. } => name,
        }
    }
}

/// What the write left on disk, from the blocking task.
enum Written {
    Committed(CredentialChanged),
    /// It may have committed; the cause says why it is not known to be durable.
    Uncertain(String),
    /// Nothing changed.
    Refused(VaultChangeRefusal),
}

impl<F: StoreFs + Send + Sync + 'static> ServiceContext<F> {
    /// Takes the service-wide lock, refusing at once with [`VaultChangeRefusal::Busy`] while another holds it, and runs
    /// the checks a `replace` or `rm` makes before any prompt: the service is Ready, the manifest lists the name (healthy
    /// or damaged), and the vault change check passes on the served config.
    pub async fn plan_vault_change(&self, change: PlannedChange) -> Result<VaultChangePlan<'_, F>, VaultChangeRefusal> {
        let service_wide = Arc::clone(&self.service_wide)
            .try_lock_owned()
            .map_err(|_| VaultChangeRefusal::Busy)?;
        let inner = self.inner.lock().await;
        let ready = inner.state.admin_allows(AdminOperation::VaultChange);
        let (Some(open), Admission::Serve(snapshot), true) = (inner.open.as_ref(), self.holder.load(), ready) else {
            return Err(VaultChangeRefusal::WrongState(inner.state));
        };
        let Some((current, before)) = current_record(open, change.name()) else {
            return Err(VaultChangeRefusal::UnknownCredential(change.name().clone()));
        };
        let config = snapshot.policy().config();
        vault_change_check(config, &self.setup.capabilities, &*snapshot, &self.setup.accounts, &change)
            .map_err(|routes| in_use(&change, routes))?;
        Ok(VaultChangePlan {
            service: self,
            service_wide,
            checks: inner.checks,
            approvers: open.approval.approvers().to_vec(),
            summary: VaultChangeSummary::new(change, current, before, snapshot.policy()),
        })
    }
}

/// The refusal for a failed vault change check. A removal fails only because routes use the name, so it names them; a
/// replacement names the rule each route would break with the new record.
fn in_use(change: &PlannedChange, routes: Vec<AffectedRoute>) -> VaultChangeRefusal {
    let name = change.name().clone();
    match change {
        PlannedChange::Remove(_) => {
            let mut routes: Vec<_> = routes.into_iter().map(|affected| affected.route).collect();
            routes.dedup();
            VaultChangeRefusal::UsedByRoutes { name, routes }
        }
        PlannedChange::Replace { .. } => VaultChangeRefusal::InUse { name, routes },
    }
}

impl<F: StoreFs + Send + Sync + 'static> VaultChangePlan<'_, F> {
    /// The vault change summary the owner reads before owner presence, true until the write.
    pub fn summary(&self) -> &VaultChangeSummary {
        &self.summary
    }

    /// Completes once a `lock` is waiting for the service-wide lock this plan holds, so a prompt can end the change
    /// rather than make the `lock` wait for the owner (design/credential-commands.md, "Order of steps").
    pub async fn lock_requested(&self) {
        self.service.lock_requested().await;
    }

    /// The approver owner presence asks for, whose label the passphrase prompt names.
    pub fn asked_approver(&self) -> Result<&PinnedApprover, PresenceRefusal> {
        asked_approver(&self.approvers)
    }

    /// Owner presence (design/credential-commands.md): opens `approver.age` with `passphrase` as the asked approver's
    /// key and drops the signer at once. Nothing is reserved, signed or written.
    pub async fn prove_presence(&self, passphrase: ApprovalPassphrase) -> Result<OwnerPresence, PresenceRefusal> {
        self.service.prove_presence(passphrase, &self.approvers).await
    }

    /// Writes the planned change, then runs the config check from Ready through [`ServiceEvent::VaultChanged`] and
    /// releases the service-wide lock once it has settled. `material` is the new secret for a `replace` and `None` for
    /// an `rm`; material missing, extra or of another kind than planned is refused before anything is written.
    ///
    /// Refuses with [`VaultChangeRefusal::WrongState`] before writing unless the service is still Ready at the check
    /// generation of the plan. This is the backstop for a state or generation change made without the service-wide
    /// lock, which today is only a `stop`: a `lock` cancels the change at its prompt, and every config check waits.
    ///
    /// A write that failed cleanly runs no check. A committed one answers success only when the check settles in
    /// Ready, on a new serving snapshot; requests admitted earlier finish on the old one, whose vault, and the secret
    /// replaced or removed with it, drops when the last of them ends (§14).
    ///
    /// Cancel-safe as an approval's commit is: a task of its own owns both guards and runs the write and the check to
    /// their end, and one that ends without a result fails closed through its [`SettleGuard`].
    pub async fn change_credential(
        self,
        material: Option<CredentialMaterial>,
        // Taken by value, so one proof authorizes one change.
        _proof: OwnerPresence,
    ) -> Result<CredentialChanged, VaultChangeRefusal> {
        let Self {
            service,
            service_wide,
            checks,
            summary,
            ..
        } = self;
        let write = write_of(summary.change().clone(), material)?;
        let inner = Arc::clone(&service.inner).lock_owned().await;
        let Some(identity) = inner
            .identity
            .clone()
            .filter(|_| inner.state == ServiceState::Ready && inner.checks == checks)
        else {
            return Err(VaultChangeRefusal::WrongState(inner.state));
        };
        let (settler, mut guard) = (service.settler(), SettleGuard::new(inner, Arc::clone(&service.holder)));
        let running = tokio::spawn(async move {
            // Held until the task ends, so no approval or other vault write starts while this one settles.
            let _service_wide = service_wide;
            settler.run_vault_change(&mut guard.inner, identity, write, &summary).await
        });
        match running.await {
            Ok(changed) => changed,
            Err(crashed) => {
                log_task_crash("the vault change's task", &crashed);
                Err(VaultChangeRefusal::ChangeUncertain {
                    cause: "the vault change did not finish".to_owned(),
                    state: service.inner.lock().await.state,
                })
            }
        }
    }
}

/// The record `open` holds under `name`, healthy or damaged, with its full standing.
fn current_record<'a>(open: &'a OpenVault, name: &CredentialName) -> Option<(CurrentRecord, &'a CredentialStanding)> {
    let standing = open.credentials.iter().find(|standing| &standing.name == name)?;
    let current = CurrentRecord {
        record_id: *open.record_ids.get(name)?,
        standing: standing.standing,
        summary: standing.summary.clone(),
    };
    Some((current, standing))
}

impl<F: StoreFs + Send + Sync + 'static> Settler<F> {
    /// Steps 8 and 9 under `inner`, which the caller's task owns: the write, then the config check unless the write
    /// failed cleanly.
    async fn run_vault_change(
        &self,
        inner: &mut Inner,
        identity: Arc<VaultIdentity>,
        write: Write,
        summary: &VaultChangeSummary,
    ) -> Result<CredentialChanged, VaultChangeRefusal> {
        let committed = match self.write_on_blocking_pool(Arc::clone(&identity), write).await {
            Written::Refused(refusal) => return Err(refusal),
            Written::Committed(changed) => {
                // Logged at the commit: a config check that then fails answers `committed-not-active`, which carries no
                // record ID, although the change is durable.
                log_committed(summary, &changed);
                Ok(changed)
            }
            Written::Uncertain(cause) => Err(cause),
        };
        let state = self
            .check_and_settle(inner, ServiceEvent::VaultChanged, identity)
            .await
            .unwrap_or_else(|illegal| illegal.state);
        match (committed, state) {
            (Ok(changed), ServiceState::Ready) => Ok(changed),
            (Ok(_), state) => Err(VaultChangeRefusal::NotActive(state)),
            (Err(cause), state) => Err(VaultChangeRefusal::ChangeUncertain { cause, state }),
        }
    }

    /// Opens a fresh vault, writes and drops the vault, on the blocking pool, since it reads, decrypts and fsyncs vault
    /// files. A task that ends without a result may have committed.
    async fn write_on_blocking_pool(&self, identity: Arc<VaultIdentity>, write: Write) -> Written {
        let (locks, setup) = (Arc::clone(&self.locks), Arc::clone(&self.setup));
        tokio::task::spawn_blocking(move || write_record(&locks, &setup.fs, identity, write))
            .await
            .unwrap_or_else(|_| Written::Uncertain("the vault write did not finish".to_owned()))
    }
}

/// The write for `change` with `material`, which must be present for a replace, of the planned kind, and absent for a
/// remove.
fn write_of(change: PlannedChange, material: Option<CredentialMaterial>) -> Result<Write, VaultChangeRefusal> {
    match (change, material) {
        (PlannedChange::Remove(name), None) => Ok(Write::Remove(name)),
        (PlannedChange::Replace { name, kind, origins }, Some(material)) if kind_of(&material) == kind => {
            Ok(Write::Replace { name, material, origins })
        }
        _ => Err(VaultChangeRefusal::Invalid(
            "the material does not match the planned change".to_owned(),
        )),
    }
}

/// Replaces or removes the record through a vault opened for this write alone.
fn write_record(locks: &ServiceLocks, fs: &impl StoreFs, identity: Arc<VaultIdentity>, write: Write) -> Written {
    let mut vault = match open_vault(&locks.state, fs, identity) {
        Ok((vault, _)) => vault,
        Err(error) => return Written::Refused(VaultChangeRefusal::Failed(error.to_string())),
    };
    let credential = write.name().clone();
    let written = match write {
        Write::Remove(name) => vault
            .remove(&locks.state, fs, &name)
            .map(|report| (CredentialChanged::Removed, report)),
        Write::Replace { name, material, origins } => vault
            .replace(&locks.state, fs, name, material, origins)
            .map(|(id, report)| (CredentialChanged::Replaced(id), report)),
    };
    drop(vault);
    match written.inspect_err(emit_commit_uncertain) {
        Ok((changed, report)) => {
            audit_write_report(&report, &credential);
            Written::Committed(changed)
        }
        Err(VaultError::UnknownName(name)) => Written::Refused(VaultChangeRefusal::UnknownCredential(name)),
        Err(VaultError::InvalidMaterial(error)) => Written::Refused(VaultChangeRefusal::Invalid(error.to_string())),
        Err(VaultError::CommitUncertain(error)) => Written::Uncertain(error.to_string()),
        Err(other) => Written::Refused(VaultChangeRefusal::Failed(other.to_string())),
    }
}
