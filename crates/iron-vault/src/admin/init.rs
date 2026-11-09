//! `init`: creates the vault, its two recovery paths and its first committed approval (specification §12, §14,
//! §16; design/vault-initialization.md, "The exchange").
//!
//! The service, not the CLI, prompts for both passphrases, so neither travels as an argument (§5), and it generates
//! every key and shows the recovery key once, in a reveal. Nothing is written until the owner confirms they saved it.
//! From the reveal on, every ending but success says what to do with the key shown.

use std::sync::Arc;

use iron_vault_store::{
    ApprovalPassphrase, InitError, InitFailure, InitPassphrases, InitStateError, InitializationState, NewVaultKeys, Passphrase,
    RecipientIdentity, RecoveryKeySecret, SealingKeys, StoreFs, WhichPassphrase,
};
use secrecy::{ExposeSecret, SecretString};
use subtle::ConstantTimeEq;

use super::dispatch::{AdminHandler, HandlerFuture};
use super::principal::AdminPrincipal;
use super::protocol::{AdminRequest, AdminResponse, ErrorCode, OwnerInput, Prompt};
use super::server::{Exchange, ExchangeError};
use super::unlock::state_name;
use super::{DEAD_RECOVERY_KEY, UNCONFIRMED_RECOVERY_KEY};
use crate::service_context::{InitRefusal, ServiceContext, step_names};
use crate::service_state::AdminOperation;

/// The vault passphrase's two secret prompts: the entry, then its repeat.
const VAULT_PROMPTS: [&str; 2] = ["Vault passphrase", "Repeat the vault passphrase"];
/// The approval passphrase's two secret prompts.
const APPROVAL_PROMPTS: [&str; 2] = ["Approval passphrase", "Repeat the approval passphrase"];
/// The confirmation after the reveal; any answer but exactly `yes` writes nothing.
const CONFIRMATION: &str = "Type yes once you have saved the recovery key";

/// Sent on Unfinished. The prompts hold no lock, so the service cannot tell an initialization a crash left unfinished
/// from one another init is writing now; the notice says what happens in either case.
const UNFINISHED_NOTICE: &str = "An unfinished initialization is here, or another init is writing its vault right now. \
Once you confirm the new recovery key, an unfinished initialization is discarded, and any recovery key it showed opens nothing. \
A run still writing is never discarded: this init then writes nothing and ends with `busy`, or with `already-initialized` once \
that run has finished.\n";

const RECOVERY_NOTICE: &str = "\
The recovery key follows. It is shown this once, and the service keeps no copy.
It is the second way into the vault if the vault passphrase or this machine is lost.
Store it in an independent password manager or on paper, never beside the vault.
You may also keep it in a passphrase-encrypted file of your own.
";

/// `init`'s handler, acting on the running service.
pub(super) struct Init<F> {
    service: Arc<ServiceContext<F>>,
}

impl<F> Init<F> {
    pub(super) fn new(service: Arc<ServiceContext<F>>) -> Self {
        Self { service }
    }
}

impl<F: StoreFs + Send + Sync + 'static> AdminHandler for Init<F> {
    fn handle<'a>(&'a self, _principal: AdminPrincipal, request: AdminRequest, exchange: &'a mut Exchange) -> HandlerFuture<'a> {
        let host_unlock = matches!(request, AdminRequest::Init { host_unlock: true });
        Box::pin(self.run(exchange, host_unlock))
    }
}

impl<F: StoreFs + Send + Sync + 'static> Init<F> {
    /// Checks the state and the directories, and with `host_unlock` reads the handoff, all before any prompt; collects
    /// both passphrases, reveals the recovery key, and writes only once the owner answers `yes`; the service context
    /// checks the state again under its locks.
    async fn run(&self, exchange: &mut Exchange, host_unlock: bool) -> Result<AdminResponse, ExchangeError> {
        let state = self.service.state().await;
        if !state.admin_allows(AdminOperation::Initialize) {
            return Ok(refused(InitRefusal::WrongState(state), false));
        }
        let existing = match self.service.initializable().await {
            Ok(existing) => existing,
            Err(refusal) => return Ok(refused(refusal, false)),
        };
        let host = match self.host_identity(host_unlock).await {
            Ok(host) => host,
            Err(refusal) => return Ok(refused(refusal, false)),
        };
        if existing == InitializationState::Unfinished {
            exchange.notice(UNFINISHED_NOTICE).await?;
        }
        let passphrases = match chosen_passphrases(exchange).await? {
            Ok(passphrases) => passphrases,
            Err(rule) => return Ok(error(ErrorCode::PassphraseRejected, rule)),
        };
        let keys = match NewVaultKeys::generate() {
            Ok(keys) => keys,
            Err(e) => {
                return Ok(error(
                    ErrorCode::InitFailed,
                    format!("cannot generate the keys, so nothing was written: {e}"),
                ));
            }
        };
        let keys = match reveal_and_confirm(exchange, keys).await? {
            Ok(keys) => keys,
            Err(declined) => return Ok(declined),
        };
        let keys = host.into_iter().fold(keys, SealingKeys::with_host_unlock);
        Ok(match self.service.initialize(keys, passphrases).await {
            Ok(vault) => AdminResponse::Init {
                vault_id: vault.vault_id,
                version: vault.version.get(),
                recipients: vault.recipients,
            },
            Err(refusal) => refused(refusal, true),
        })
    }

    /// The identity in the unlock handoff when `--host-unlock` asked for it, `None` when it did not.
    async fn host_identity(&self, host_unlock: bool) -> Result<Option<RecipientIdentity>, InitRefusal> {
        match host_unlock {
            true => self.service.read_host_unlock().await.map(Some),
            false => Ok(None),
        }
    }
}

/// Shows the recovery key once, after the notice, and asks the owner to confirm they saved it: the keys to seal once they
/// answer exactly `yes`, or `declined`. The recovery key's text is dropped as soon as the reveal is written.
async fn reveal_and_confirm(exchange: &mut Exchange, keys: NewVaultKeys) -> Result<Result<SealingKeys, AdminResponse>, ExchangeError> {
    let confirmed = reveal_recovery_key(exchange, keys.recovery_secret()).await?;
    Ok(confirmed.map(|()| keys.into_sealing()))
}

/// The reveal `init` and `recipient add --recovery` share: the notice, the key's text and QR code, and the confirmation
/// prompt. Anything but exactly `yes` is `declined`, with the advice that the key opens nothing.
pub(super) async fn reveal_recovery_key(
    exchange: &mut Exchange,
    secret: &RecoveryKeySecret,
) -> Result<Result<(), AdminResponse>, ExchangeError> {
    exchange.notice(RECOVERY_NOTICE).await?;
    exchange.reveal(secret.expose_secret().as_bytes()).await?;
    let confirmation = Prompt {
        label: CONFIRMATION.to_owned(),
        secret: false,
    };
    if exchange.prompt(&confirmation).await?.expose_secret() != b"yes" {
        let message = format!("the recovery key was not confirmed as saved, so nothing was written; {DEAD_RECOVERY_KEY}");
        return Ok(Err(error(ErrorCode::Declined, message)));
    }
    Ok(Ok(()))
}

/// The vault and approval passphrases, each entered twice, or the rule one broke. Each passphrase's rules are checked
/// once both its entries are in, so a broken rule ends the exchange before the next prompt; there is no second try.
async fn chosen_passphrases(exchange: &mut Exchange) -> Result<Result<InitPassphrases, String>, ExchangeError> {
    let vault = match chosen(exchange, VAULT_PROMPTS, WhichPassphrase::Vault).await? {
        Ok(vault) => vault,
        Err(rule) => return Ok(Err(rule)),
    };
    let approval = chosen(exchange, APPROVAL_PROMPTS, WhichPassphrase::Approval).await?;
    Ok(approval.and_then(|approval| both(vault, approval)))
}

/// One passphrase, entered twice. Both inputs are cleared when they drop here.
async fn chosen(
    exchange: &mut Exchange,
    [label, repeat]: [&str; 2],
    which: WhichPassphrase,
) -> Result<Result<SecretString, String>, ExchangeError> {
    let secret = |label: &str| Prompt {
        label: label.to_owned(),
        secret: true,
    };
    let entry = exchange.prompt(&secret(label)).await?;
    let repeated = exchange.prompt(&secret(repeat)).await?;
    Ok(entry_text(&entry, &repeated, which))
}

/// The entry as text, once it equals its repeat, compared in constant time, is UTF-8 and is long enough. A refusal
/// names the rule and nothing typed.
fn entry_text(entry: &OwnerInput, repeated: &OwnerInput, which: WhichPassphrase) -> Result<SecretString, String> {
    if !bool::from(entry.expose_secret().ct_eq(repeated.expose_secret())) {
        return Err(format!("the two entries of {which} differ"));
    }
    let text = std::str::from_utf8(entry.expose_secret()).map_err(|_| format!("{which} is not valid UTF-8"))?;
    InitPassphrases::ensure_long_enough(text, which).map_err(|rule| rule.to_string())?;
    Ok(SecretString::from(text))
}

/// Both passphrases as their own types, once the two differ.
fn both(vault: SecretString, approval: SecretString) -> Result<InitPassphrases, String> {
    let vault = Passphrase::new(vault).map_err(|e| e.to_string())?;
    let approval = ApprovalPassphrase::new(approval).map_err(|e| e.to_string())?;
    InitPassphrases::new(vault, approval).map_err(|rule| rule.to_string())
}

/// The response for `refusal`. After the reveal, a refusal also says the recovery key shown is dead.
fn refused(refusal: InitRefusal, revealed: bool) -> AdminResponse {
    let dead = |message: String| match revealed {
        true => format!("{message}; {DEAD_RECOVERY_KEY}"),
        false => message,
    };
    match refusal {
        InitRefusal::Busy => error(
            ErrorCode::Busy,
            dead(
                "another init, an approval, a vault write, a reload or a config check is running, so nothing was written; \
                 run `iron-vault init` again"
                    .to_owned(),
            ),
        ),
        InitRefusal::WrongState(state) => error(
            ErrorCode::WrongState,
            dead(format!(
                "`init` is allowed only while the service is Locked; it is {}",
                state_name(state)
            )),
        ),
        InitRefusal::Initialized => error(
            ErrorCode::AlreadyInitialized,
            dead("the vault is Initialized, so nothing was changed".to_owned()),
        ),
        InitRefusal::Unrecognized(files) => error(
            ErrorCode::AlreadyInitialized,
            dead(format!(
                "the directories are Unrecognized: they hold files init did not write, first {}; nothing was changed: move \
                 them aside and run `iron-vault init` again",
                files.join(", ")
            )),
        ),
        InitRefusal::Unreadable(detail) => error(
            ErrorCode::InitFailed,
            format!("cannot read the initialization state, so nothing was written: {detail}"),
        ),
        InitRefusal::HostUnlock(reason) => error(
            ErrorCode::InitFailed,
            format!("cannot enrol the host unlock identity, so nothing was written: {reason}"),
        ),
        InitRefusal::Clock(detail) => error(
            ErrorCode::InitFailed,
            dead(format!("cannot read the service clock, so nothing was written: {detail}")),
        ),
        InitRefusal::Failed(failure) => failed(&failure),
        InitRefusal::Interrupted => error(
            ErrorCode::InitFailed,
            format!("init did not finish: its task ended without a result; {UNCONFIRMED_RECOVERY_KEY}"),
        ),
    }
}

/// `init-failed`, naming the step. Only when the commit point's unlink landed and its directory fsync failed is the
/// outcome unknown; any other failure leaves the vault Unfinished, which a re-run discards.
fn failed(failure: &InitError) -> AdminResponse {
    let advice = match failure.cause() {
        InitFailure::State(InitStateError::FinishUncertain { .. }) => UNCONFIRMED_RECOVERY_KEY.to_owned(),
        _ => format!("run `iron-vault init` again, which discards the unfinished vault; {DEAD_RECOVERY_KEY}"),
    };
    let (_, at) = step_names(failure.step());
    error(ErrorCode::InitFailed, format!("init failed at {at}: {}; {advice}", failure.cause()))
}

fn error(code: ErrorCode, message: String) -> AdminResponse {
    AdminResponse::Error { code, message }
}

#[cfg(test)]
mod tests;
