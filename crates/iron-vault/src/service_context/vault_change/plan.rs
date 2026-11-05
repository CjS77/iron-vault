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
use iron_vault_store::{
    ApprovalPassphrase, PermittedOrigins, PinnedApprover, RecordId, StoreFs, Vault, VaultError, VaultIdentity, WriteReport,
};
use tokio::sync::OwnedMutexGuard;

use super::super::{Inner, OwnerPresence, PresenceRefusal, ServiceContext, ServiceLocks, SettleGuard, Settler, log_task_crash};
use super::{VaultChangeRefusal, kind_of};
use crate::service_state::{AdminOperation, ServiceEvent, ServiceState};
use crate::serving_snapshot::Admission;
use crate::vault_change_check::{PlannedChange, vault_change_check};

/// Steps 2 to 4 of a `replace` or `rm` done: the service-wide lock is held and the vault change check passed. See the
/// module docs.
pub struct VaultChangePlan<'a, F> {
    service: &'a ServiceContext<F>,
    /// Owned, so [`VaultChangePlan::change_credential`] can hand it to the task that writes and checks.
    service_wide: OwnedMutexGuard<()>,
    /// The check generation at step 2, which the write checks again.
    checks: u64,
    /// The pinned approver owner presence must open, from the approval state the service holds.
    approver: PinnedApprover,
    change: PlannedChange,
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
        if !open.credentials.iter().any(|standing| &standing.name == change.name()) {
            return Err(VaultChangeRefusal::UnknownCredential(change.name().clone()));
        }
        let config = snapshot.policy().config();
        vault_change_check(config, &self.setup.capabilities, &*snapshot, &self.setup.accounts, &change).map_err(|routes| {
            VaultChangeRefusal::InUse {
                name: change.name().clone(),
                routes,
            }
        })?;
        Ok(VaultChangePlan {
            service: self,
            service_wide,
            checks: inner.checks,
            approver: open.approval.approver().clone(),
            change,
        })
    }
}

impl<F: StoreFs + Send + Sync + 'static> VaultChangePlan<'_, F> {
    /// The change the check passed, which the summary describes.
    pub fn change(&self) -> &PlannedChange {
        &self.change
    }

    /// Completes once a `lock` is waiting for the service-wide lock this plan holds, so a prompt can end the change
    /// rather than make the `lock` wait for the owner (design/credential-commands.md, "Order of steps").
    pub async fn lock_requested(&self) {
        self.service.lock_requested().await;
    }

    /// Owner presence (design/credential-commands.md): opens `approver.age` with `passphrase` as the pinned approver's
    /// key and drops the signer at once. Nothing is reserved, signed or written.
    pub async fn prove_presence(&self, passphrase: ApprovalPassphrase) -> Result<OwnerPresence, PresenceRefusal> {
        self.service.prove_presence(passphrase, self.approver.clone()).await
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
    /// replaced or removed with it, drops when the last of them ends (§3.11).
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
            change,
            ..
        } = self;
        let write = write_of(change, material)?;
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
            settler.run_vault_change(&mut guard.inner, identity, write).await
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

impl<F: StoreFs + Send + Sync + 'static> Settler<F> {
    /// Steps 8 and 9 under `inner`, which the caller's task owns: the write, then the config check unless the write
    /// failed cleanly.
    async fn run_vault_change(
        &self,
        inner: &mut Inner,
        identity: Arc<VaultIdentity>,
        write: Write,
    ) -> Result<CredentialChanged, VaultChangeRefusal> {
        let committed = match self.write_on_blocking_pool(Arc::clone(&identity), write).await {
            Written::Refused(refusal) => return Err(refusal),
            Written::Committed(changed) => Ok(changed),
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
    let mut vault = match Vault::open(&locks.state, fs, identity) {
        Ok((vault, _)) => vault,
        Err(error) => return Written::Refused(VaultChangeRefusal::Failed(error.to_string())),
    };
    let written = match write {
        Write::Remove(name) => vault
            .remove(&locks.state, fs, &name)
            .map(|report| (CredentialChanged::Removed, report)),
        Write::Replace { name, material, origins } => vault
            .replace(&locks.state, fs, name, material, origins)
            .map(|(id, report)| (CredentialChanged::Replaced(id), report)),
    };
    drop(vault);
    match written {
        Ok((changed, report)) => {
            warn_left_unindexed(&report);
            Written::Committed(changed)
        }
        Err(VaultError::UnknownName(name)) => Written::Refused(VaultChangeRefusal::UnknownCredential(name)),
        Err(VaultError::InvalidMaterial(error)) => Written::Refused(VaultChangeRefusal::Invalid(error.to_string())),
        Err(VaultError::CommitUncertain(error)) => Written::Uncertain(error.to_string()),
        Err(other) => Written::Refused(VaultChangeRefusal::Failed(other.to_string())),
    }
}

/// Warns of a superseded record file the write could not remove; the next vault write removes it.
fn warn_left_unindexed(report: &WriteReport) {
    if let Some(file) = report.left_unindexed() {
        tracing::warn!(%file, "a superseded record file could not be removed; the next vault write removes it");
    }
}
