//! The recipient commands' side of the service context (`design/recipients.md`, "States and the service-wide lock").
//!
//! A recipient command takes the service-wide lock without waiting, so the inventory check, and the change after it, see
//! `recipients.age` and `recipients.age.staged` as the previous change left them. The check can write (it finishes or
//! discards a staged change), so the blocking task owns the lock guard and keeps it to the end of the check even if the
//! future that started it is dropped. The vault identity that keys the inventory is cloned out of the context's mutex,
//! which is released before the task starts, as `lock` waits for the service-wide lock before it clears the identity.

use std::sync::Arc;

use iron_vault_store::{
    InventoryCheckError, InventoryDamage, RecipientEntry, RecipientInventory, StoreFs, VaultId, VaultIdentity, check_recipient_inventory,
};
use tokio::sync::OwnedMutexGuard;

use super::{Inner, ServiceContext};
use crate::audit::AuditEvent;
use crate::audit::recipient::{ChangeRecovered, InventoryDamaged};
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
        let (identity, vault_id) = ready_vault(&*self.inner.lock().await)?;
        let (_, inventory) = self.check_inventory(service_wide, identity, vault_id).await?;
        Ok(inventory.entries().cloned().collect())
    }

    /// The inventory check, run by a blocking task that owns `service_wide` until the check ends, even if the future that
    /// started it is dropped. A check that succeeds hands the guard back, so a recipient change can keep the lock; a refused
    /// one releases it.
    pub(super) async fn check_inventory(
        &self,
        service_wide: OwnedMutexGuard<()>,
        identity: Arc<VaultIdentity>,
        vault_id: VaultId,
    ) -> Result<(OwnedMutexGuard<()>, RecipientInventory), RecipientRefusal> {
        let (locks, setup) = (Arc::clone(&self.locks), Arc::clone(&self.setup));
        let checked = tokio::task::spawn_blocking(move || {
            check_recipient_inventory(&locks.state, &setup.fs, &identity, vault_id).map(|checked| (service_wide, checked))
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

/// The vault identity the service holds and the open vault's ID; known only when the state allows a vault change.
fn ready_vault(inner: &Inner) -> Result<(Arc<VaultIdentity>, VaultId), RecipientRefusal> {
    match (&inner.identity, &inner.open) {
        (Some(identity), Some(open)) if inner.state.admin_allows(AdminOperation::VaultChange) => {
            Ok((Arc::clone(identity), open.approval.vault_id()))
        }
        _ => Err(RecipientRefusal::WrongState(inner.state)),
    }
}
