// SPDX-License-Identifier: MPL-2.0
//! The approver prompt (spec [§6][s6], [§12][s12]): `config approve` asks it before signing, and `replace`, `rm`,
//! `recipient remove`, `approver add` and `approver remove` ask it as owner presence
//! ([credential commands: Owner presence](../../../../design/credential-commands.md#owner-presence)). All of them use this one prompt and
//! the service context's one key check, so they cannot drift apart. A software approver is asked for its approval
//! passphrase and a TPM approver for its TPM approval PIN.
//!
//! With more than one approver pinned, the prompt is switchable: each switch frame moves to the next approver, wrapping
//! after the last, under one prompt deadline. With approvers "laptop" (software) and "tpm" (TPM):
//!
//! ```text
//! service: Approval passphrase for "laptop"     CLI: switch
//! service: TPM approval PIN for "tpm"           CLI: switch
//! service: Approval passphrase for "laptop"     CLI: owner input   -> check the "laptop" key, once
//! ```
//!
//! [s6]: ../../../../design/iron-vault-specification.md#6-credential-records-and-configuration
//! [s12]: ../../../../design/iron-vault-specification.md#12-configuration-approval-and-reload

use std::future::Future;

use iron_vault_store::{ApprovalPassphrase, PinnedApprover, SignerKind, StoreFs};
use iron_vault_tpm_protocol::TpmApprovalPin;
use secrecy::SecretString;

use super::protocol::{AdminResponse, ErrorCode, OwnerInput, Prompt, PromptAnswer};
use super::server::{Exchange, ExchangeError};
use crate::audit::{AuditEvent, NamedApprover, vault::PresenceRefused};
use crate::service_context::NO_ASKABLE_APPROVER;
use crate::service_context::{
    ApproverChangePlan, ApproverSecret, DenialKind, OwnerPresence, PresenceRefusal, RecipientRemoval, VaultChangePlan,
};

/// Returns the label of the secret prompt for `approver`, naming it by its label, escaped since the owner chose it. A
/// software approver is asked for `Approval passphrase for "<label>"` and a TPM approver for
/// `TPM approval PIN for "<label>"`.
pub(super) fn passphrase_prompt(approver: &PinnedApprover) -> String {
    let (what, label) = match approver.kind() {
        SignerKind::Software => ("Approval passphrase", NamedApprover::from(approver).label_text()),
        SignerKind::Tpm => ("TPM approval PIN", NamedApprover::from(approver).label_text()),
    };
    format!("{what} for \"{label}\"")
}

/// The owner's answer to the approver prompt.
pub(super) enum PassphraseAnswer {
    /// Input that can be the approver's passphrase or PIN, still to be checked against its key.
    Typed(ApproverSecret),
    /// Input that cannot be the passphrase or PIN (empty, not UTF-8, or a PIN shorter than enrollment allows), refused as
    /// a wrong one before the key or the TPM is asked.
    Unusable,
    /// A `lock` came for the service-wide lock while the owner was at the prompt.
    CancelledByLock,
}

/// Why owner presence was not shown. Nothing was written either way.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum NoPresence {
    /// The passphrase was refused (`approval-denied` for [`PresenceRefusal::Denied`] and
    /// [`PresenceRefusal::Unusable`]), or the key check could not run.
    Refused(PresenceRefusal),
    /// A `lock` came for the service-wide lock while the owner was at the prompt; the key was never checked.
    CancelledByLock,
}

/// Asks for an approval passphrase with the approver prompt: it names the first of `approvers` by its label, and when
/// more than one is pinned the owner may switch, which moves to the next and wraps after the last. Returns the approver
/// the answer is for, so the caller checks that approver's key and names it in its audit event, or `None` when
/// `approvers` is empty. `lock_requested` is called once per prompt, and the future it returns ends that prompt.
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
            Some(PromptAnswer::OwnerInput(input)) => {
                typed_secret(approver.kind(), input).map_or(PassphraseAnswer::Unusable, PassphraseAnswer::Typed)
            }
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
        secret: ApproverSecret,
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
        secret: ApproverSecret,
        approver: &PinnedApprover,
    ) -> impl Future<Output = Result<OwnerPresence, PresenceRefusal>> + Send {
        VaultChangePlan::prove_presence(self, secret, approver)
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
        secret: ApproverSecret,
        approver: &PinnedApprover,
    ) -> impl Future<Output = Result<OwnerPresence, PresenceRefusal>> + Send {
        RecipientRemoval::prove_presence(self, secret, approver)
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
        secret: ApproverSecret,
        approver: &PinnedApprover,
    ) -> impl Future<Output = Result<OwnerPresence, PresenceRefusal>> + Send {
        ApproverChangePlan::prove_presence(self, secret, approver)
    }
}

/// Requires owner presence for `plan`: asks for an approver's passphrase through the approver prompt and opens that
/// approver's key with it. There is no second try, and no fall-through to another approver after a wrong answer. The outer error is a
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
        let none = PresenceRefusal::Unavailable(NO_ASKABLE_APPROVER.to_owned());
        return Ok(Err(NoPresence::Refused(none)));
    };
    let checked = match answer {
        PassphraseAnswer::Typed(passphrase) => plan.prove_presence(passphrase, approver).await.map_err(NoPresence::Refused),
        PassphraseAnswer::Unusable => Err(NoPresence::Refused(PresenceRefusal::Unusable(DenialKind::wrong_answer(
            approver.kind(),
        )))),
        PassphraseAnswer::CancelledByLock => {
            tracing::warn!("change cancelled at its prompt by a lock; nothing was written");
            Err(NoPresence::CancelledByLock)
        }
    };
    if let Err(NoPresence::Refused(refusal)) = &checked
        && let Some((refusal, tpm_status)) = refusal.audit()
    {
        PresenceRefused {
            refusal,
            tpm_status,
            approver: approver.into(),
        }
        .emit();
    }
    Ok(checked)
}

/// Returns the answer when owner presence for `command` was not shown, so nothing was written. A wrong passphrase or PIN
/// is `approval-denied`, a TPM lockout is `tpm-locked-out`, and a key check that could not run or a `lock` at the
/// passphrase prompt is `approval-unavailable`
/// ([admin protocol: errors](../../../../design/admin-protocol.md#admin-response-error-kind-5)).
pub(super) fn no_presence(command: &str, none: NoPresence) -> AdminResponse {
    let (code, message) = match none {
        NoPresence::Refused(denied @ (PresenceRefusal::Denied(_) | PresenceRefusal::Unusable(_))) => {
            (ErrorCode::ApprovalDenied, denied.to_string())
        }
        NoPresence::Refused(locked @ PresenceRefusal::TpmLockedOut { .. }) => (ErrorCode::TpmLockedOut, locked.to_string()),
        NoPresence::Refused(unavailable) => (ErrorCode::ApprovalUnavailable, unavailable.to_string()),
        NoPresence::CancelledByLock => (
            ErrorCode::ApprovalUnavailable,
            format!("`{command}` was cancelled because a `lock` ran while it waited for the approval passphrase; nothing was written"),
        ),
    };
    AdminResponse::Error { code, message }
}

/// Reads the owner's input as the secret a `kind` approver asks for. The input's buffer is cleared when it drops here; a
/// PIN is not held in plain `String` longer than the authorization value takes to derive. Returns `None` for a PIN too
/// short to have been enrolled, so it never reaches the TPM and spends no lockout try.
fn typed_secret(kind: SignerKind, input: OwnerInput) -> Option<ApproverSecret> {
    let text = std::str::from_utf8(input.expose_secret()).ok()?;
    match kind {
        SignerKind::Software => ApprovalPassphrase::new(SecretString::from(text))
            .ok()
            .map(ApproverSecret::Passphrase),
        SignerKind::Tpm => TpmApprovalPin::answered(text).map(ApproverSecret::Pin),
    }
}

#[cfg(test)]
mod tests;
