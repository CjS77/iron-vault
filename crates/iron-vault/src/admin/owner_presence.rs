//! The approval passphrase prompt (specification §12, §6): `config approve` asks it before signing, and `replace`
//! and `rm` ask it as owner presence (design/credential-commands.md, "Owner presence"). Both use this one prompt and
//! the service context's one key check, so the two cannot drift apart.

use std::future::Future;

use iron_vault_store::{ApprovalPassphrase, StoreFs};
use secrecy::SecretString;

use super::protocol::{AdminResponse, ErrorCode, OwnerInput, Prompt};
use super::server::{Exchange, ExchangeError};
use crate::audit::{AuditEvent, vault::PresenceRefused};
use crate::service_context::{DenialKind, OwnerPresence, PresenceRefusal, RecipientRemoval, VaultChangePlan};

/// The label of the secret prompt for the approval passphrase.
const PASSPHRASE_PROMPT: &str = "Approval passphrase";

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

/// Asks for the approval passphrase with a secret prompt, which `lock_requested` ends. The error is a prompt that got no
/// owner input.
pub(super) async fn ask_approval_passphrase(
    exchange: &mut Exchange,
    lock_requested: impl Future<Output = ()>,
) -> Result<PassphraseAnswer, ExchangeError> {
    let prompt = Prompt {
        label: PASSPHRASE_PROMPT.to_owned(),
        secret: true,
    };
    let answer = match exchange.prompt_unless(&prompt, lock_requested).await? {
        None => PassphraseAnswer::CancelledByLock,
        Some(input) => approval_passphrase(input).map_or(PassphraseAnswer::Unusable, PassphraseAnswer::Typed),
    };
    Ok(answer)
}

/// A change that holds the service-wide lock while the owner proves presence: what the prompt needs of it.
pub(super) trait PresencePlan {
    /// Completes once a `lock` is waiting for the lock the plan holds.
    fn lock_requested(&self) -> impl Future<Output = ()> + Send;
    /// Opens the pinned approver's key with `passphrase`; see [`require_owner_presence`].
    fn prove_presence(&self, passphrase: ApprovalPassphrase) -> impl Future<Output = Result<OwnerPresence, PresenceRefusal>> + Send;
}

impl<F: StoreFs + Send + Sync + 'static> PresencePlan for VaultChangePlan<'_, F> {
    fn lock_requested(&self) -> impl Future<Output = ()> + Send {
        VaultChangePlan::lock_requested(self)
    }

    fn prove_presence(&self, passphrase: ApprovalPassphrase) -> impl Future<Output = Result<OwnerPresence, PresenceRefusal>> + Send {
        VaultChangePlan::prove_presence(self, passphrase)
    }
}

impl<F: StoreFs + Send + Sync + 'static> PresencePlan for RecipientRemoval<'_, F> {
    fn lock_requested(&self) -> impl Future<Output = ()> + Send {
        RecipientRemoval::lock_requested(self)
    }

    fn prove_presence(&self, passphrase: ApprovalPassphrase) -> impl Future<Output = Result<OwnerPresence, PresenceRefusal>> + Send {
        RecipientRemoval::prove_presence(self, passphrase)
    }
}

/// Owner presence for `plan`: asks for the approval passphrase and opens the pinned approver key with it. There is no
/// second try. The outer error is a prompt that got no owner input, which cancels the command.
///
/// A `lock` waiting for the service-wide lock the plan holds ends the prompt with [`NoPresence::CancelledByLock`], as
/// it ends an approval's.
pub(super) async fn require_owner_presence(
    exchange: &mut Exchange,
    plan: &impl PresencePlan,
) -> Result<Result<OwnerPresence, NoPresence>, ExchangeError> {
    let checked = match presence_passphrase(exchange, plan.lock_requested()).await? {
        Ok(passphrase) => plan.prove_presence(passphrase).await.map_err(NoPresence::Refused),
        Err(unchecked) => Err(unchecked),
    };
    Ok(checked)
}

/// The passphrase owner presence checks, or why it ends before any check: input that cannot be the passphrase is
/// refused as a wrong one, and a `lock` cancels the change.
async fn presence_passphrase(
    exchange: &mut Exchange,
    lock_requested: impl Future<Output = ()>,
) -> Result<Result<ApprovalPassphrase, NoPresence>, ExchangeError> {
    let passphrase = match ask_approval_passphrase(exchange, lock_requested).await? {
        PassphraseAnswer::Typed(passphrase) => Ok(passphrase),
        PassphraseAnswer::Unusable => Err(NoPresence::Refused(PresenceRefusal::Denied(DenialKind::WrongPassphrase))),
        PassphraseAnswer::CancelledByLock => {
            tracing::warn!("change cancelled at its prompt by a lock; nothing was written");
            Err(NoPresence::CancelledByLock)
        }
    };
    Ok(passphrase)
}

/// The answer when owner presence for `command` was not shown, so nothing was written. Every denial, a typed one or an
/// unusable one, passes through here, so it is the one place that records `vault.presence-refused`. A wrong passphrase is
/// `approval-denied`, and a key check that could not run or a `lock` at the passphrase prompt is
/// `approval-unavailable` (design/admin-protocol.md).
pub(super) fn no_presence(command: &str, none: NoPresence) -> AdminResponse {
    let (code, message) = match none {
        NoPresence::Refused(denied @ PresenceRefusal::Denied(kind)) => {
            PresenceRefused { refusal: kind }.emit();
            (ErrorCode::ApprovalDenied, denied.to_string())
        }
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
