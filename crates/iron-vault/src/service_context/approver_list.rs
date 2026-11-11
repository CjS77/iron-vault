//! `approver list`'s side of the service context (`design/approval-signers.md`, "`approver list`").

use std::sync::Arc;

use iron_vault_store::{PinnedApprover, StoreFs};

use super::ServiceContext;
use super::recipients::{RecipientRefusal, ready_vault};
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

/// `ready_vault` refuses only for the state; any other refusal cannot occur there.
fn wrong_state(refusal: RecipientRefusal) -> ApproverListRefusal {
    match refusal {
        RecipientRefusal::WrongState(state) => ApproverListRefusal::WrongState(state),
        _ => ApproverListRefusal::Busy,
    }
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
        let approvers = ready_vault(&*self.inner.lock().await).map_err(wrong_state)?.approvers;
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
