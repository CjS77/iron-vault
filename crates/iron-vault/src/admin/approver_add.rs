//! `approver add`: enrolls a new approval signer after owner presence from a pinned approver
//! (`design/approval-signers.md`, "`approver add`").
//!
//! Only a pinned approver's proof authorizes it: the vault passphrase, migration authorization or a recovery key would let
//! a stolen unlock secret enroll a signer of its own and then approve any config. Owner presence comes before the new
//! signer's secret, so the owner never chooses a passphrase for a change that is then refused. The new approval passphrase
//! is not compared with the vault passphrase, since that comparison would be an unlimited guessing oracle.

use std::path::PathBuf;
use std::sync::Arc;

use iron_vault_store::{ApprovalPassphrase, ApproverLabel, PinnedApprover, StoreFs, WhichPassphrase};
use iron_vault_tpm_protocol::TpmApprovalPin;

use super::approver_answer::{error, refused, wrong_state};
use super::dispatch::{AdminHandler, HandlerFuture};
use super::init::entry_text;
use super::owner_presence::{no_presence, require_owner_presence};
use super::principal::AdminPrincipal;
use super::protocol::{AdminRequest, AdminResponse, ErrorCode, OwnerInput, Prompt, RequestedSignerKind};
use super::server::{Exchange, ExchangeError};
use crate::service_context::{ApproverChangePlan, OwnerPresence, ServiceContext};
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
        let (label, signer) = match self.checked(kind, &label).await {
            Ok(checked) => checked,
            Err(refusal) => return Ok(refusal),
        };
        let plan = match self.service.plan_approver_enrollment().await {
            Ok(plan) => plan,
            Err(refusal) => return Ok(refused(COMMAND, refusal)),
        };
        exchange.notice(&summary(&plan, &label, &signer)).await?;
        let proof = match require_owner_presence(exchange, &plan).await? {
            Ok(proof) => proof,
            Err(none) => return Ok(no_presence(COMMAND, none)),
        };
        let enrolled = match enroll(exchange, plan, proof, label, signer).await? {
            Ok(enrolled) => enrolled,
            Err(refusal) => return Ok(refusal),
        };
        let (approver, approvers) = enrolled;
        exchange.notice(&completion(&approver, approvers)).await?;
        Ok(AdminResponse::ApproverAdd {
            approver: approver.id(),
            // At most `MAX_APPROVERS` (16) are ever pinned, so the count always fits and the clamp never applies.
            approvers: u8::try_from(approvers).unwrap_or(u8::MAX),
        })
    }

    /// Step 1: the service is Ready, the label follows its rule and this install offers the kind. `software` is always
    /// offered; `tpm` only where [`ServiceContext::tpm_helper_socket`] finds the helper; `hardware` not yet.
    async fn checked(&self, kind: RequestedSignerKind, label: &str) -> Result<(ApproverLabel, NewSigner), AdminResponse> {
        let state = self.service.state().await;
        if !state.admin_allows(AdminOperation::VaultChange) {
            return Err(wrong_state(COMMAND, state));
        }
        let label = ApproverLabel::new(label).map_err(|rule| error(ErrorCode::ApproverInvalid, format!("the label is invalid: {rule}")))?;
        let unavailable = |why: &str| {
            error(
                ErrorCode::ApproverKindUnavailable,
                format!("this install does not offer {} approvers {why}; nothing was changed", kind.name()),
            )
        };
        match kind {
            RequestedSignerKind::Software => Ok((label, NewSigner::Software)),
            RequestedSignerKind::Tpm => match self.service.tpm_helper_socket() {
                Some(socket) => Ok((label, NewSigner::Tpm { socket })),
                None => Err(unavailable("(it needs a protected install whose TPM signing helper socket exists)")),
            },
            RequestedSignerKind::Hardware => Err(unavailable("yet")),
        }
    }
}

/// The kind of signer `approver add` enrolls, with what its enrollment needs.
enum NewSigner {
    /// An Ed25519 key sealed to a new approval passphrase.
    Software,
    /// A TPM key made by the helper whose socket is `socket`, under a new PIN.
    Tpm { socket: PathBuf },
}

/// Step 6 for the signer's kind, then steps 7 and 8: asks for the new secret and runs the approver change that enrolls.
async fn enroll<F: StoreFs + Send + Sync + 'static>(
    exchange: &mut Exchange,
    plan: ApproverChangePlan<'_, F>,
    proof: OwnerPresence,
    label: ApproverLabel,
    signer: NewSigner,
) -> Result<Result<(PinnedApprover, usize), AdminResponse>, ExchangeError> {
    let enrolled = match signer {
        NewSigner::Software => match new_passphrase(exchange, &plan, &label).await? {
            Ok(passphrase) => plan.enroll_software(proof, label, passphrase).await,
            Err(refusal) => return Ok(Err(refusal)),
        },
        NewSigner::Tpm { socket } => match new_pin(exchange, &plan, &label).await? {
            Ok(pin) => plan.enroll_tpm(proof, socket, label, pin).await,
            Err(refusal) => return Ok(Err(refusal)),
        },
    };
    Ok(enrolled.map_err(|refusal| refused(COMMAND, refusal)))
}

/// Step 6 for `tpm`: the new TPM approval PIN, entered twice and checked by the PIN rules. A `lock` at either prompt ends
/// the command, as for `software`.
async fn new_pin<F: StoreFs + Send + Sync + 'static>(
    exchange: &mut Exchange,
    plan: &ApproverChangePlan<'_, F>,
    label: &ApproverLabel,
) -> Result<Result<TpmApprovalPin, AdminResponse>, ExchangeError> {
    let shown = shown_label(label);
    let Some(entry) = secret_prompt(exchange, plan, format!("New TPM approval PIN for \"{shown}\"")).await? else {
        return Ok(Err(cancelled_by_lock()));
    };
    let Some(repeated) = secret_prompt(exchange, plan, "Repeat the new TPM approval PIN".to_owned()).await? else {
        return Ok(Err(cancelled_by_lock()));
    };
    let chosen = TpmApprovalPin::from_entries(entry.expose_secret(), repeated.expose_secret());
    Ok(chosen.map_err(|rule| {
        plan.passphrase_rejected();
        error(ErrorCode::PassphraseRejected, format!("{rule}; nothing was changed"))
    }))
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
fn summary<F: StoreFs + Send + Sync + 'static>(plan: &ApproverChangePlan<'_, F>, label: &ApproverLabel, signer: &NewSigner) -> String {
    let (kind, next) = match signer {
        NewSigner::Software => ("software", SOFTWARE_NEXT),
        NewSigner::Tpm { .. } => ("tpm", TPM_NEXT),
    };
    format!(
        "enroll an approval signer\n  vault: {}\n  kind: {kind}\n  label: {}\n  approvers after the change: {}\n  \
         the new signer alone can approve a config and authorize replace, rm, recipient remove and approver changes\n  \
         {next}\n  authorize with: any pinned approver\n",
        plan.vault_id(),
        shown_label(label),
        plan.approver_count() + 1,
    )
}

/// The summary lines that say what the owner chooses next, and for a TPM what the key costs.
const SOFTWARE_NEXT: &str = "next: choose its approval passphrase, different from the vault passphrase";
const TPM_NEXT: &str = "next: choose its TPM approval PIN, at least 6 characters\n  \
     the key works only on this machine's TPM and will not move with a migration bundle\n  \
     a forgotten PIN is recovered only through another approver, so keep a software approver";

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
