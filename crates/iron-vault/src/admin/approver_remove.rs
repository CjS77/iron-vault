// SPDX-License-Identifier: MPL-2.0
//! `approver remove`: unpins an approval signer after owner presence from any pinned approver, the removed one included
//! ([approval signers: `approver remove <approver ID>`](../../../../design/approval-signers.md#approver-remove-approver-id)).
//!
//! [`ServiceContext::plan_approver_removal`] refuses an ID no pinned approver has, the last approver and the approver
//! that signed the active approval before any prompt, so no proof removes either of the last two: removing the active
//! signer would stop the active `config.toml.sig` verifying and take every route down at the next config check.

use std::sync::Arc;

use iron_vault_store::{ApproverId, KeyFileOutcome, PinnedApprover, StoreFs};

use super::approver_answer::{error, refused, wrong_state};
use super::dispatch::{AdminHandler, HandlerFuture};
use super::owner_presence::{no_presence, require_owner_presence};
use super::principal::AdminPrincipal;
use super::protocol::{AdminRequest, AdminResponse, ErrorCode};
use super::server::{Exchange, ExchangeError};
use crate::service_context::{ApproverChangePlan, ServiceContext};
use crate::service_state::AdminOperation;

/// The command's name in refusal messages.
const COMMAND: &str = "approver remove";

/// `approver remove`'s handler, acting on the running service.
pub(super) struct ApproverRemove<F> {
    service: Arc<ServiceContext<F>>,
}

impl<F> ApproverRemove<F> {
    pub(super) fn new(service: Arc<ServiceContext<F>>) -> Self {
        Self { service }
    }
}

impl<F: StoreFs + Send + Sync + 'static> AdminHandler for ApproverRemove<F> {
    fn handle<'a>(&'a self, _principal: AdminPrincipal, request: AdminRequest, exchange: &'a mut Exchange) -> HandlerFuture<'a> {
        Box::pin(self.run(request, exchange))
    }
}

impl<F: StoreFs + Send + Sync + 'static> ApproverRemove<F> {
    /// Runs steps 1 to 7. A prompt that gets no owner input drops the plan, which releases the service-wide lock, before
    /// anything is written.
    async fn run(&self, request: AdminRequest, exchange: &mut Exchange) -> Result<AdminResponse, ExchangeError> {
        let AdminRequest::ApproverRemove { approver } = request else {
            return Ok(error(ErrorCode::ApproverInvalid, "the request is not `approver remove`".to_owned()));
        };
        let id = match self.checked(approver).await {
            Ok(id) => id,
            Err(refusal) => return Ok(refusal),
        };
        let (plan, approver) = match self.service.plan_approver_removal(id).await {
            Ok(planned) => planned,
            Err(refusal) => return Ok(refused(COMMAND, refusal)),
        };
        exchange.notice(&summary(&plan, &approver)).await?;
        let proof = match require_owner_presence(exchange, &plan).await? {
            Ok(proof) => proof,
            Err(none) => return Ok(no_presence(COMMAND, none)),
        };
        match plan.remove_approver(proof, &approver).await {
            Ok((approvers, key_file)) => {
                exchange.notice(&completion(approver.id(), approvers, &key_file)).await?;
                // At most `MAX_APPROVERS` (16) are ever pinned, so the count always fits and the clamp never applies.
                Ok(AdminResponse::ApproverRemove {
                    approvers: u8::try_from(approvers).unwrap_or(u8::MAX),
                })
            }
            Err(refusal) => Ok(refused(COMMAND, refusal)),
        }
    }

    /// Runs step 1: checks that the service is Ready and the argument is a version 4 UUID.
    async fn checked(&self, bytes: [u8; 16]) -> Result<ApproverId, AdminResponse> {
        let state = self.service.state().await;
        if !state.admin_allows(AdminOperation::VaultChange) {
            return Err(wrong_state(COMMAND, state));
        }
        ApproverId::from_bytes(bytes).map_err(|_| error(ErrorCode::ApproverInvalid, "the approver ID is not a version 4 UUID".to_owned()))
    }
}

/// Returns the summary the owner reads before owner presence.
fn summary<F: StoreFs + Send + Sync + 'static>(plan: &ApproverChangePlan<'_, F>, approver: &PinnedApprover) -> String {
    format!(
        "remove an approval signer\n  vault: {}\n  approver: {}\n  kind: {}\n  label: {}\n  enrolled: {}\n  \
         approvers after the change: {}\n  it can no longer approve or give owner presence; copies of the state directory made \
         before still pin it\n  authorize with: any pinned approver\n",
        plan.vault_id(),
        approver.id(),
        approver.kind().name(),
        iron_vault_policy::escaped(approver.label().as_str()),
        approver.enrolled_at(),
        plan.approver_count() - 1,
    )
}

/// Returns the notice after the removal committed, with a further line when the key file could not be removed.
fn completion(id: ApproverId, approvers: usize, key_file: &KeyFileOutcome) -> String {
    let left = match key_file {
        KeyFileOutcome::Removed => "",
        KeyFileOutcome::Left(_) => "Its key file could not be removed; the next approver add or remove removes it.\n",
    };
    format!("removed approver {id}; the vault has {approvers} approvers.\n{left}")
}
