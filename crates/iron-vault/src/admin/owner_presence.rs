//! The approval passphrase prompt (specification §3.9, §3.3): `config approve` asks it before signing, and `replace`
//! and `rm` ask it as owner presence (design/credential-commands.md, "Owner presence"). Both use this one prompt and
//! the service context's one key check, so the two cannot drift apart.

use std::future::Future;

use iron_vault_store::{ApprovalPassphrase, StoreFs};
use secrecy::SecretString;

use super::protocol::{OwnerInput, Prompt};
use super::server::{Exchange, ExchangeError};
use crate::service_context::{OwnerPresence, PresenceRefusal, VaultChangePlan};

/// The label of the secret prompt for the approval passphrase.
pub const PASSPHRASE_PROMPT: &str = "Approval passphrase";

/// The owner's answer to the approval passphrase prompt.
pub enum PassphraseAnswer {
    /// Input that can be the approval passphrase, still to be checked against the approver key.
    Typed(ApprovalPassphrase),
    /// Empty or non-UTF-8 input, which cannot be the passphrase and is refused as a wrong one.
    Unusable,
    /// A `lock` came for the service-wide lock while the owner was at the prompt.
    CancelledByLock,
}

/// Asks for the approval passphrase with a secret prompt, which `lock_requested` ends. The error is a prompt that got no
/// owner input.
pub async fn ask_approval_passphrase(
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

/// Owner presence for `plan`: asks for the approval passphrase and opens the pinned approver key with it. There is no
/// second try. The outer error is a prompt that got no owner input, which cancels the command; the inner one is
/// `approval-denied` for [`PresenceRefusal::Denied`].
///
/// A `lock` waiting for the service-wide lock the plan holds ends the prompt with [`PresenceRefusal::CancelledByLock`],
/// as it ends an approval's.
pub async fn require_owner_presence<F: StoreFs + Send + Sync + 'static>(
    exchange: &mut Exchange,
    plan: &VaultChangePlan<'_, F>,
) -> Result<Result<OwnerPresence, PresenceRefusal>, ExchangeError> {
    let refusal = match ask_approval_passphrase(exchange, plan.lock_requested()).await? {
        PassphraseAnswer::Typed(passphrase) => return Ok(plan.prove_presence(passphrase).await),
        PassphraseAnswer::Unusable => PresenceRefusal::Denied,
        PassphraseAnswer::CancelledByLock => {
            tracing::warn!("vault change cancelled at its prompt by a lock; nothing was written");
            PresenceRefusal::CancelledByLock
        }
    };
    Ok(Err(refusal))
}

/// The owner's input as an approval passphrase. The input's buffer is cleared when it drops here.
fn approval_passphrase(input: OwnerInput) -> Option<ApprovalPassphrase> {
    let text = std::str::from_utf8(input.expose_secret()).ok()?;
    ApprovalPassphrase::new(SecretString::from(text)).ok()
}
