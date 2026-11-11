//! `approver list`'s side of the service context (`design/approval-signers.md`, "`approver list`").

use std::sync::Arc;

use iron_vault_store::{PinnedApprover, StoreFs};

use super::ServiceContext;
use super::recipients::ready_vault;
use crate::service_state::ServiceState;

/// Why `approver list` was refused.
#[derive(Debug, thiserror::Error)]
pub enum ApproverListRefusal {
    /// Another operation holds the service-wide lock.
    #[error("another operation is running; try again shortly")]
    Busy,
    /// The service is not Ready.
    #[error("the service is {0:?}, not Ready")]
    WrongState(ServiceState),
}

impl<F: StoreFs + Send + Sync + 'static> ServiceContext<F> {
    /// Every pinned approver in approver order, each with whether it signed the active approval.
    ///
    /// Fails with [`ApproverListRefusal::Busy`] at once while another operation holds the service-wide lock, and with
    /// [`ApproverListRefusal::WrongState`] outside Ready. The lock is held only while the approvers are read, so the order
    /// and the active marker come from one moment.
    pub async fn list_approvers(&self) -> Result<Vec<(PinnedApprover, bool)>, ApproverListRefusal> {
        let _service_wide = Arc::clone(&self.service_wide)
            .try_lock_owned()
            .map_err(|_| ApproverListRefusal::Busy)?;
        let inner = self.inner.lock().await;
        let approvers = ready_vault(&inner)
            .map_err(|_| ApproverListRefusal::WrongState(inner.state))?
            .approvers;
        drop(inner);
        let active = self.active_signer();
        Ok(self
            .ordered_approvers(&approvers)
            .into_iter()
            .map(|approver| {
                let signed = Some(approver.id()) == active;
                (approver, signed)
            })
            .collect())
    }
}
