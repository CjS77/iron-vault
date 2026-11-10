//! The recipient commands' side of the service context (`design/recipients.md`, "States and the service-wide lock").
//!
//! A recipient command takes the service-wide lock without waiting, so the inventory check, and the change after it, see
//! `recipients.age` and `recipients.age.staged` as the previous change left them. The check can write (it finishes or
//! discards a staged change), so the blocking task owns the lock guard and keeps it to the end of the check even if the
//! future that started it is dropped. The vault identity that keys the inventory is cloned out of the context's mutex,
//! which is released before the task starts, as `lock` waits for the service-wide lock before it clears the identity.

use std::sync::Arc;

use iron_vault_store::{
    ChangeCommitted, ErrorKindLabel, InventoryCheckError, InventoryDamage, PinnedApprover, RecipientChangeFault, RecipientChangeWriteError,
    RecipientEntry, RecipientInventory, RecipientKey, StoreFs, VaultId, VaultIdentity, check_recipient_inventory,
};

use super::{Inner, ServiceContext};
use crate::audit::AuditEvent;
use crate::audit::recipient::{ChangeFailed, ChangeFailure, ChangeRecovered, InventoryDamaged};
use crate::service_state::{AdminOperation, ServiceState};

/// Why `recipient list` ended without a list.
#[derive(Debug, thiserror::Error)]
pub enum RecipientRefusal {
    /// Another operation holds the service-wide lock.
    #[error("another operation holds the service-wide lock")]
    Busy,
    /// The service is not Ready, so it holds no vault identity.
    #[error("the service is {0:?}")]
    WrongState(ServiceState),
    /// The inventory check found the inventory missing or damaged; nothing was written.
    #[error("{0}")]
    Damaged(InventoryDamage),
    /// Settling a staged inventory failed; the message says which write.
    #[error("{0}")]
    Write(String),
    /// The task running the check ended without a result.
    #[error("the inventory check did not finish")]
    Interrupted,
}

impl<F: StoreFs + Send + Sync + 'static> ServiceContext<F> {
    /// Every enrolled recipient, in inventory order, from the inventory bound to the `identity.age` on disk.
    ///
    /// Fails with [`RecipientRefusal::Busy`] at once while another operation holds the service-wide lock. The check may
    /// finish or discard a staged recipient change, which it logs as `recipient.change-recovered`; a damaged inventory
    /// is logged as `recipient.inventory-damaged` and never repaired.
    pub async fn list_recipients(&self) -> Result<Vec<RecipientEntry>, RecipientRefusal> {
        let service_wide = Arc::clone(&self.service_wide)
            .try_lock_owned()
            .map_err(|_| RecipientRefusal::Busy)?;
        let ReadyVault { identity, vault_id, .. } = ready_vault(&*self.inner.lock().await)?;
        let (_, inventory) = self.check_inventory(service_wide, identity, vault_id).await?;
        Ok(inventory.entries().cloned().collect())
    }

    /// The inventory check, run by a blocking task that owns `held` (the service-wide lock, in whatever guard the caller has)
    /// until the check ends, even if the future that started it is dropped. A check that succeeds hands it back, so a
    /// recipient change can keep the lock; a refused one releases it.
    pub(super) async fn check_inventory<H: Send + 'static>(
        &self,
        held: H,
        identity: Arc<VaultIdentity>,
        vault_id: VaultId,
    ) -> Result<(H, RecipientInventory), RecipientRefusal> {
        let (locks, setup) = (Arc::clone(&self.locks), Arc::clone(&self.setup));
        let checked = tokio::task::spawn_blocking(move || {
            check_recipient_inventory(&locks.state, &setup.fs, &identity, vault_id).map(|checked| (held, checked))
        })
        .await
        .map_err(|_| RecipientRefusal::Interrupted)?;
        match checked {
            Ok((held, checked)) => {
                checked.recovered.map(ChangeRecovered).iter().for_each(AuditEvent::emit);
                Ok((held, checked.inventory))
            }
            Err(InventoryCheckError::Damaged(damage)) => {
                InventoryDamaged(damage).emit();
                Err(RecipientRefusal::Damaged(damage))
            }
            Err(InventoryCheckError::Write(error)) => Err(RecipientRefusal::Write(error.to_string())),
        }
    }
}

/// What a recipient command reads of the service while it takes the lock: the vault identity and the open vault's ID, and
/// the state and check generation a change records so it can refuse if either moved, and the pinned approvers for owner presence.
pub(super) struct ReadyVault {
    pub(super) identity: Arc<VaultIdentity>,
    pub(super) vault_id: VaultId,
    pub(super) state: ServiceState,
    pub(super) checks: u64,
    pub(super) approvers: Vec<PinnedApprover>,
}

/// The vault the service holds; known only when the state allows a vault change.
pub(super) fn ready_vault(inner: &Inner) -> Result<ReadyVault, RecipientRefusal> {
    match (&inner.identity, &inner.open) {
        (Some(identity), Some(open)) if inner.state.admin_allows(AdminOperation::VaultChange) => Ok(ReadyVault {
            identity: Arc::clone(identity),
            vault_id: open.approval.vault_id(),
            state: inner.state,
            checks: inner.checks,
            approvers: open.approval.approvers().to_vec(),
        }),
        _ => Err(RecipientRefusal::WrongState(inner.state)),
    }
}

/// Logs `recipient.change-failed` for a `change` (`add` or `remove`) of `key`.
pub(super) fn log_failure(change: &'static str, key: &RecipientKey, failure: ChangeFailure) {
    ChangeFailed {
        change,
        recipient: key,
        failure,
    }
    .emit();
}

/// A change that ended before its first write: wrapping, proving and sealing failed, so nothing reached the disk.
pub(super) fn unwritten() -> ChangeFailure {
    ChangeFailure::WriteFailed {
        step: None,
        error_kind: ErrorKindLabel::fixed("not_written"),
        committed: ChangeCommitted::No,
    }
}

/// A step that failed, naming its kind and whether the change committed.
pub(super) fn step_failure(error: &RecipientChangeWriteError) -> ChangeFailure {
    let error_kind = match error.fault() {
        RecipientChangeFault::Write(write) => write.error_kind_label(),
        RecipientChangeFault::Read(_) => ErrorKindLabel::fixed("read_failed"),
        RecipientChangeFault::EnvelopeMismatch => ErrorKindLabel::fixed("envelope_mismatch"),
    };
    ChangeFailure::WriteFailed {
        step: Some(error.step()),
        error_kind,
        committed: error.committed(),
    }
}
