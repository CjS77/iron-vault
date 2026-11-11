//! The approval passphrase prompt (specification §12, §6): `config approve` asks it before signing, and `replace`
//! and `rm` ask it as owner presence (design/credential-commands.md, "Owner presence"). Both use this one prompt and
//! the service context's one key check, so the two cannot drift apart.

use std::future::Future;

use iron_vault_store::{ApprovalPassphrase, PinnedApprover, StoreFs};
use secrecy::SecretString;

use super::protocol::{AdminResponse, ErrorCode, OwnerInput, Prompt, PromptAnswer};
use super::server::{Exchange, ExchangeError};
use crate::audit::{AuditEvent, NamedApprover, vault::PresenceRefused};
use crate::service_context::{ApproverChangePlan, DenialKind, OwnerPresence, PresenceRefusal, RecipientRemoval, VaultChangePlan};

/// The label of the secret prompt for the approval passphrase of `approver`, which names it by its label, escaped since
/// the owner chose it.
fn passphrase_prompt(approver: &PinnedApprover) -> String {
    format!("Approval passphrase for \"{}\"", NamedApprover::from(approver).label_text())
}

/// The owner's answer to the approval passphrase prompt.
pub(super) enum PassphraseAnswer {
    /// Input that can be the approval passphrase, still to be checked against the approver key.
    Typed(ApprovalPassphrase),
    /// Empty or non-UTF-8 input, which cannot be the passphrase and is refused as a wrong one.
    Unusable,
    /// A `lock` came for the service-wide lock while the owner was at the prompt.
    CancelledByLock,
}

/// Why owner presence was not shown. Nothing was written either way.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum NoPresence {
    /// The passphrase was refused (`approval-denied` for [`PresenceRefusal::Denied`]), or the key check could not run.
    Refused(PresenceRefusal),
    /// A `lock` came for the service-wide lock while the owner was at the prompt; the key was never checked.
    CancelledByLock,
}

/// Asks for an approval passphrase with the approver prompt: it names the first of `approvers` by its label, and when more
/// than one is pinned the owner may switch, which moves to the next and wraps after the last. Returns the approver the
/// answer is for, so the caller checks that approver's key and names it in its audit event. `None` when `approvers` is
/// empty. `lock_requested` is called once per prompt and ends it.
///
/// One prompt deadline covers every switch (`Exchange::prompt_or_switch_unless`), and a wrong answer is never retried
/// with another approver here: the caller ends the exchange on it. The error is a prompt that got no owner input.
pub(super) async fn ask_approval_passphrase<'a, L: Future<Output = ()>>(
    exchange: &mut Exchange,
    approvers: &'a [PinnedApprover],
    lock_requested: impl Fn() -> L,
) -> Result<Option<(&'a PinnedApprover, PassphraseAnswer)>, ExchangeError> {
    let switchable = approvers.len() > 1;
    for approver in approvers.iter().cycle() {
        let prompt = Prompt {
            label: passphrase_prompt(approver),
            secret: true,
            switchable,
        };
        let answer = match exchange.prompt_or_switch_unless(&prompt, lock_requested()).await? {
            None => PassphraseAnswer::CancelledByLock,
            Some(PromptAnswer::Switch) => continue,
            Some(PromptAnswer::OwnerInput(input)) => approval_passphrase(input).map_or(PassphraseAnswer::Unusable, PassphraseAnswer::Typed),
        };
        return Ok(Some((approver, answer)));
    }
    Ok(None)
}

/// A change that holds the service-wide lock while the owner proves presence: what the prompt needs of it.
pub(super) trait PresencePlan {
    /// The pinned approvers in approver order, the first of which owner presence asks.
    fn approvers(&self) -> &[PinnedApprover];
    /// Completes once a `lock` is waiting for the lock the plan holds.
    fn lock_requested(&self) -> impl Future<Output = ()> + Send;
    /// Opens `approver`'s key with `passphrase`; see [`require_owner_presence`].
    fn prove_presence(
        &self,
        passphrase: ApprovalPassphrase,
        approver: &PinnedApprover,
    ) -> impl Future<Output = Result<OwnerPresence, PresenceRefusal>> + Send;
}

impl<F: StoreFs + Send + Sync + 'static> PresencePlan for VaultChangePlan<'_, F> {
    fn approvers(&self) -> &[PinnedApprover] {
        VaultChangePlan::approvers(self)
    }

    fn lock_requested(&self) -> impl Future<Output = ()> + Send {
        VaultChangePlan::lock_requested(self)
    }

    fn prove_presence(
        &self,
        passphrase: ApprovalPassphrase,
        approver: &PinnedApprover,
    ) -> impl Future<Output = Result<OwnerPresence, PresenceRefusal>> + Send {
        VaultChangePlan::prove_presence(self, passphrase, approver)
    }
}

impl<F: StoreFs + Send + Sync + 'static> PresencePlan for RecipientRemoval<'_, F> {
    fn approvers(&self) -> &[PinnedApprover] {
        RecipientRemoval::approvers(self)
    }

    fn lock_requested(&self) -> impl Future<Output = ()> + Send {
        RecipientRemoval::lock_requested(self)
    }

    fn prove_presence(
        &self,
        passphrase: ApprovalPassphrase,
        approver: &PinnedApprover,
    ) -> impl Future<Output = Result<OwnerPresence, PresenceRefusal>> + Send {
        RecipientRemoval::prove_presence(self, passphrase, approver)
    }
}

impl<F: StoreFs + Send + Sync + 'static> PresencePlan for ApproverChangePlan<'_, F> {
    fn approvers(&self) -> &[PinnedApprover] {
        ApproverChangePlan::approvers(self)
    }

    fn lock_requested(&self) -> impl Future<Output = ()> + Send {
        ApproverChangePlan::lock_requested(self)
    }

    fn prove_presence(
        &self,
        passphrase: ApprovalPassphrase,
        approver: &PinnedApprover,
    ) -> impl Future<Output = Result<OwnerPresence, PresenceRefusal>> + Send {
        ApproverChangePlan::prove_presence(self, passphrase, approver)
    }
}

/// Owner presence for `plan`: asks for an approver's passphrase through the approver prompt and opens that approver's key
/// with it. There is no second try, and no fall-through to another approver after a wrong answer. The outer error is a
/// prompt that got no owner input, which cancels the command.
///
/// Every denial, a typed one or an unusable one, passes through here, so it is the one place that records
/// `vault.presence-refused`, naming the approver that was answered.
///
/// A `lock` waiting for the service-wide lock the plan holds ends the prompt with [`NoPresence::CancelledByLock`], as
/// it ends an approval's.
pub(super) async fn require_owner_presence(
    exchange: &mut Exchange,
    plan: &impl PresencePlan,
) -> Result<Result<OwnerPresence, NoPresence>, ExchangeError> {
    let Some((approver, answer)) = ask_approval_passphrase(exchange, plan.approvers(), || plan.lock_requested()).await? else {
        let none = PresenceRefusal::Unavailable("the approval state pins no approver".to_owned());
        return Ok(Err(NoPresence::Refused(none)));
    };
    let checked = match answer {
        PassphraseAnswer::Typed(passphrase) => plan.prove_presence(passphrase, approver).await.map_err(NoPresence::Refused),
        PassphraseAnswer::Unusable => Err(NoPresence::Refused(PresenceRefusal::Denied(DenialKind::WrongPassphrase))),
        PassphraseAnswer::CancelledByLock => {
            tracing::warn!("change cancelled at its prompt by a lock; nothing was written");
            Err(NoPresence::CancelledByLock)
        }
    };
    if let Err(NoPresence::Refused(PresenceRefusal::Denied(refusal))) = &checked {
        PresenceRefused {
            refusal: *refusal,
            approver: approver.into(),
        }
        .emit();
    }
    Ok(checked)
}

/// The answer when owner presence for `command` was not shown, so nothing was written. A wrong passphrase is
/// `approval-denied`, and a key check that could not run or a `lock` at the passphrase prompt is
/// `approval-unavailable` (design/admin-protocol.md).
pub(super) fn no_presence(command: &str, none: NoPresence) -> AdminResponse {
    let (code, message) = match none {
        NoPresence::Refused(denied @ PresenceRefusal::Denied(_)) => (ErrorCode::ApprovalDenied, denied.to_string()),
        NoPresence::Refused(unavailable) => (ErrorCode::ApprovalUnavailable, unavailable.to_string()),
        NoPresence::CancelledByLock => (
            ErrorCode::ApprovalUnavailable,
            format!("`{command}` was cancelled because a `lock` ran while it waited for the approval passphrase; nothing was written"),
        ),
    };
    AdminResponse::Error { code, message }
}

/// The owner's input as an approval passphrase. The input's buffer is cleared when it drops here.
fn approval_passphrase(input: OwnerInput) -> Option<ApprovalPassphrase> {
    let text = std::str::from_utf8(input.expose_secret()).ok()?;
    ApprovalPassphrase::new(SecretString::from(text)).ok()
}

#[cfg(test)]
mod tests;
