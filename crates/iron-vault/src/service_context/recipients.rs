//! The recipient commands' side of the service context (`design/recipients.md`, "States and the service-wide lock").
//!
//! A recipient command takes the service-wide lock without waiting, so the inventory check, and the change after it, see
//! `recipients.age` and `recipients.age.staged` as the previous change left them. The vault identity that keys the
//! inventory is cloned out of the context's mutex, which is released before the blocking task starts, as `lock` waits for
//! the service-wide lock before it clears the identity.

use std::sync::Arc;

use iron_vault_store::{InventoryCheckError, InventoryDamage, RecipientEntry, StoreFs, VaultId, VaultIdentity, check_recipient_inventory};

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
        let _service_wide = self.service_wide.try_lock().map_err(|_| RecipientRefusal::Busy)?;
        let (identity, vault_id) = ready_vault(&*self.inner.lock().await)?;
        let (locks, setup) = (Arc::clone(&self.locks), Arc::clone(&self.setup));
        let checked = tokio::task::spawn_blocking(move || check_recipient_inventory(&locks.state, &setup.fs, &identity, vault_id))
            .await
            .map_err(|_| RecipientRefusal::Interrupted)?;
        match checked {
            Ok(checked) => {
                checked.recovered.map(ChangeRecovered).iter().for_each(AuditEvent::emit);
                Ok(checked.inventory.entries().cloned().collect())
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
