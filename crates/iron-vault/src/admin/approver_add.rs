//! `approver add`: enrolls a new approval signer after owner presence from a pinned approver
//! (`design/approval-signers.md`, "`approver add`").
//!
//! Only a pinned approver's proof authorizes it: the vault passphrase, migration authorization or a recovery key would let
//! a stolen unlock secret enroll a signer of its own and then approve any config. Owner presence comes before the new
//! signer's secret, so the owner never chooses a passphrase for a change that is then refused. The new approval passphrase
//! is not compared with the vault passphrase, since that comparison would be an unlimited guessing oracle.

use std::sync::Arc;

use iron_vault_store::{ApprovalPassphrase, ApproverLabel, PinnedApprover, StoreFs, WhichPassphrase};

use super::approver_answer::{error, refused, wrong_state};
use super::dispatch::{AdminHandler, HandlerFuture};
use super::init::entry_text;
use super::owner_presence::{no_presence, require_owner_presence};
use super::principal::AdminPrincipal;
use super::protocol::{AdminRequest, AdminResponse, ErrorCode, OwnerInput, Prompt, RequestedSignerKind};
use super::server::{Exchange, ExchangeError};
use crate::service_context::{ApproverChangePlan, ServiceContext};
use crate::service_state::AdminOperation;

/// The command's name in refusal messages.
const COMMAND: &str = "approver add";

/// `approver add`'s handler, acting on the running service.
pub(super) struct ApproverAdd<F> {
    service: Arc<ServiceContext<F>>,
}

impl<F> ApproverAdd<F> {
    pub(super) fn new(service: Arc<ServiceContext<F>>) -> Self {
        Self { service }
    }
}

impl<F: StoreFs + Send + Sync + 'static> AdminHandler for ApproverAdd<F> {
    fn handle<'a>(&'a self, _principal: AdminPrincipal, request: AdminRequest, exchange: &'a mut Exchange) -> HandlerFuture<'a> {
        Box::pin(self.run(request, exchange))
    }
}

impl<F: StoreFs + Send + Sync + 'static> ApproverAdd<F> {
    /// Steps 1 to 8. A prompt that gets no owner input drops the plan, which releases the service-wide lock, before
    /// anything is written.
    async fn run(&self, request: AdminRequest, exchange: &mut Exchange) -> Result<AdminResponse, ExchangeError> {
        let AdminRequest::ApproverAdd { kind, label } = request else {
            return Ok(error(ErrorCode::ApproverInvalid, "the request is not `approver add`".to_owned()));
        };
        let label = match self.checked(kind, &label).await {
            Ok(label) => label,
            Err(refusal) => return Ok(refusal),
        };
        let plan = match self.service.plan_approver_enrollment().await {
            Ok(plan) => plan,
            Err(refusal) => return Ok(refused(COMMAND, refusal)),
        };
        exchange.notice(&summary(&plan, &label)).await?;
        let proof = match require_owner_presence(exchange, &plan).await? {
            Ok(proof) => proof,
            Err(none) => return Ok(no_presence(COMMAND, none)),
        };
        let passphrase = match new_passphrase(exchange, &plan, &label).await? {
            Ok(passphrase) => passphrase,
            Err(refusal) => return Ok(refusal),
        };
        match plan.enroll_software(proof, label, passphrase).await {
            Ok((approver, approvers)) => {
                exchange.notice(&completion(&approver, approvers)).await?;
                Ok(AdminResponse::ApproverAdd {
                    approver: approver.id(),
                    // At most `MAX_APPROVERS` (16) are ever pinned, so the count always fits and the clamp never applies.
                    approvers: u8::try_from(approvers).unwrap_or(u8::MAX),
                })
            }
            Err(refusal) => Ok(refused(COMMAND, refusal)),
        }
    }

    /// Step 1: the service is Ready, the label follows its rule and this install offers the kind. Only `software` is
    /// offered until a later kind passes its release checks.
    async fn checked(&self, kind: RequestedSignerKind, label: &str) -> Result<ApproverLabel, AdminResponse> {
        let state = self.service.state().await;
        if !state.admin_allows(AdminOperation::VaultChange) {
            return Err(wrong_state(COMMAND, state));
        }
        let label = ApproverLabel::new(label).map_err(|rule| error(ErrorCode::ApproverInvalid, format!("the label is invalid: {rule}")))?;
        match kind {
            RequestedSignerKind::Software => Ok(label),
            other => Err(error(
                ErrorCode::ApproverKindUnavailable,
                format!("this install does not offer {} approvers yet; nothing was changed", other.name()),
            )),
        }
    }
}

/// Step 6 for `software`: the new approval passphrase, entered twice and checked by the passphrase rules. A `lock` at
/// either prompt ends the command with `wrong-state`, as it would at step 7. Both inputs are cleared when they drop here.
async fn new_passphrase<F: StoreFs + Send + Sync + 'static>(
    exchange: &mut Exchange,
    plan: &ApproverChangePlan<'_, F>,
    label: &ApproverLabel,
) -> Result<Result<ApprovalPassphrase, AdminResponse>, ExchangeError> {
    let shown = shown_label(label);
    let Some(entry) = secret_prompt(exchange, plan, format!("New approval passphrase for \"{shown}\"")).await? else {
        return Ok(Err(cancelled_by_lock()));
    };
    let Some(repeated) = secret_prompt(exchange, plan, "Repeat the new approval passphrase".to_owned()).await? else {
        return Ok(Err(cancelled_by_lock()));
    };
    let chosen = entry_text(&entry, &repeated, WhichPassphrase::Approval)
        .and_then(|text| ApprovalPassphrase::new(text).map_err(|rule| rule.to_string()));
    Ok(chosen.map_err(|rule| {
        plan.passphrase_rejected();
        error(ErrorCode::PassphraseRejected, format!("{rule}; nothing was changed"))
    }))
}

/// One secret prompt of step 6, ended by a `lock` waiting for the service-wide lock the plan holds (`None`).
async fn secret_prompt<F: StoreFs + Send + Sync + 'static>(
    exchange: &mut Exchange,
    plan: &ApproverChangePlan<'_, F>,
    label: String,
) -> Result<Option<OwnerInput>, ExchangeError> {
    let prompt = Prompt {
        label,
        secret: true,
        switchable: false,
    };
    exchange.prompt_unless(&prompt, plan.lock_requested()).await
}

/// The summary the owner reads before owner presence.
fn summary<F: StoreFs + Send + Sync + 'static>(plan: &ApproverChangePlan<'_, F>, label: &ApproverLabel) -> String {
    let label = shown_label(label);
    format!(
        "enroll an approval signer\n  vault: {}\n  kind: software\n  label: {label}\n  approvers after the change: {}\n  \
         the new signer alone can approve a config and authorize replace, rm, recipient remove and approver changes\n  \
         next: choose its approval passphrase, different from the vault passphrase\n  authorize with: any pinned approver\n",
        plan.vault_id(),
        plan.approver_count() + 1,
    )
}

/// `label` as the owner sees it, escaped as the approver prompt escapes a pinned approver's label, since the owner chose it.
fn shown_label(label: &ApproverLabel) -> String {
    iron_vault_policy::escaped(label.as_str())
}

/// The notice after the enrollment committed.
fn completion(approver: &PinnedApprover, approvers: usize) -> String {
    format!(
        "enrolled approver {} ({}); the vault has {approvers} approvers.\n",
        approver.id(),
        approver.kind().name()
    )
}

fn cancelled_by_lock() -> AdminResponse {
    error(
        ErrorCode::WrongState,
        format!("`{COMMAND}` was cancelled because a `lock` ran while it waited for the new passphrase; nothing was written"),
    )
}
