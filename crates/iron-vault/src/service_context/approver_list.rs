//! `approver list`'s side of the service context (`design/approval-signers.md`, "`approver list`").

use std::sync::Arc;

use iron_vault_store::{PinnedApprover, StoreFs};

use super::ServiceContext;
use super::recipients::{RecipientRefusal, ready_vault};

impl<F: StoreFs + Send + Sync + 'static> ServiceContext<F> {
    /// Every pinned approver in approver order, each with whether it signed the active approval.
    ///
    /// Fails with [`RecipientRefusal::Busy`] at once while another operation holds the service-wide lock, and with
    /// [`RecipientRefusal::WrongState`] outside Ready. The lock is held only while the approvers are read, so the order
    /// and the active marker come from one moment.
    pub async fn list_approvers(&self) -> Result<Vec<(PinnedApprover, bool)>, RecipientRefusal> {
        let _service_wide = Arc::clone(&self.service_wide)
            .try_lock_owned()
            .map_err(|_| RecipientRefusal::Busy)?;
        let approvers = ready_vault(&*self.inner.lock().await)?.approvers;
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
