//! `init`: creates the vault, its two recovery paths and its first committed approval (spec [§12][s12], [§14][s14],
//! [§16][s16]; [vault initialization: The exchange](../../../../design/vault-initialization.md#the-exchange)).
//!
//! The service, not the CLI, prompts for both passphrases, so neither travels as an argument ([§5][s5]), and it
//! generates every key and shows the recovery key once, in a reveal. Nothing is written until the owner confirms they
//! saved it. From the reveal on, every ending but success says what to do with the key shown
//! ([Failing after the reveal](../../../../design/vault-initialization.md#failing-after-the-reveal)).
//!
//! ```text
//! 1  check     Locked, directories Uninitialized or Unfinished, memory locked;   refusals end here, nothing written
//!              with --host-unlock, read the unlock handoff
//! 2  prompts   vault passphrase twice, approval passphrase twice                 passphrase-rejected
//! 3  keys      vault identity, vault ID, operational identity, recovery key, software signer key
//! 4  reveal    notice, the recovery key, "Type yes once you have saved ..."       declined; the key opens nothing
//! 5  writes    service-wide lock, the checks again, the write order               busy, init-failed
//! 6  result    the vault ID and committed version 1; the service stays Locked
//! ```
//!
//! [s5]: ../../../../design/iron-vault-specification.md#5-service-and-cli-separation-of-concerns
//! [s12]: ../../../../design/iron-vault-specification.md#12-configuration-approval-and-reload
//! [s14]: ../../../../design/iron-vault-specification.md#14-recipients-startup-and-memory
//! [s16]: ../../../../design/iron-vault-specification.md#16-administration-recovery-and-migration

use std::sync::Arc;

use iron_vault_store::{
    ApprovalPassphrase, InitError, InitFailure, InitPassphrases, InitStateError, InitializationState, NewVaultKeys, Passphrase,
    RecipientIdentity, RecoveryKeySecret, SealingKeys, StoreFs, UnfinishedKind, WhichPassphrase,
};
use secrecy::{ExposeSecret, SecretString};
use subtle::ConstantTimeEq;

use super::dispatch::{AdminHandler, HandlerFuture};
use super::principal::AdminPrincipal;
use super::protocol::{AdminRequest, AdminResponse, ErrorCode, OwnerInput, Prompt};
use super::server::{Exchange, ExchangeError};
use super::unlock::state_name;
use super::{DEAD_RECOVERY_KEY, UNCONFIRMED_IMPORT_KEY, UNCONFIRMED_RECOVERY_KEY, import};
use crate::service_context::{InitRefusal, ServiceContext, step_names, unprotected_reason};
use crate::service_state::AdminOperation;

/// The vault passphrase's two secret prompts: the entry, then its repeat.
pub(super) const VAULT_PROMPTS: [&str; 2] = ["Vault passphrase", "Repeat the vault passphrase"];
/// The approval passphrase's two secret prompts.
const APPROVAL_PROMPTS: [&str; 2] = ["Approval passphrase", "Repeat the approval passphrase"];
/// The confirmation after the reveal; any answer but exactly `yes` writes nothing.
const CONFIRMATION: &str = "Type yes once you have saved the recovery key";

/// The notice sent when the directories are Unfinished. The prompts hold no lock, so the service cannot tell an
/// initialization a crash left unfinished from one another init is writing now; the notice says what happens in either
/// case.
const UNFINISHED_NOTICE: &str = "An unfinished initialization is here, or another init is writing its vault right now. \
Once you confirm the new recovery key, an unfinished initialization is discarded, and any recovery key it showed opens nothing. \
A run still writing is never discarded: this init then writes nothing and ends with `busy`, or with `already-initialized` once \
that run has finished.\n";

/// The notice sent when an unfinished import is there. Like [`UNFINISHED_NOTICE`], it covers an import still writing.
const UNFINISHED_IMPORT_NOTICE: &str = "An unfinished import is here, or an import is writing its vault right now. \
Once you confirm the new recovery key, the unfinished import is discarded, its copy of the config included, and any recovery key it \
showed opens nothing. A run still writing is never discarded: this init then writes nothing and ends with `busy`, or with \
`already-initialized` once that run has finished.\n";

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
    /// Runs the exchange in the module diagram. Every check and the handoff read come before any prompt, and the
    /// service context checks the state again under its locks before it writes.
    async fn run(&self, exchange: &mut Exchange, host_unlock: bool) -> Result<AdminResponse, ExchangeError> {
        let state = self.service.state().await;
        if !state.admin_allows(AdminOperation::Initialize) {
            return Ok(refused(InitRefusal::WrongState(state), false));
        }
        let existing = match self.service.initializable().await {
            Ok(existing) => existing,
            Err(refusal) => return Ok(refused(refusal, false)),
        };
        if let Err(refusal) = self.service.require_locked_memory_for_init() {
            return Ok(refused(refusal, false));
        }
        let host = match self.host_identity(host_unlock).await {
            Ok(host) => host,
            Err(refusal) => return Ok(refused(refusal, false)),
        };
        match existing {
            InitializationState::Unfinished(UnfinishedKind::Initialization) => exchange.notice(UNFINISHED_NOTICE).await?,
            InitializationState::Unfinished(UnfinishedKind::Import) => exchange.notice(UNFINISHED_IMPORT_NOTICE).await?,
            _ => {}
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

    /// Reads the identity in the unlock handoff when `--host-unlock` asked for it. Returns `None` when it did not.
    async fn host_identity(&self, host_unlock: bool) -> Result<Option<RecipientIdentity>, InitRefusal> {
        match host_unlock {
            true => self.service.read_host_unlock().await.map(Some),
            false => Ok(None),
        }
    }
}

/// Shows the recovery key once, after the notice, and asks the owner to confirm they saved it. Returns the keys to seal
/// once they answer exactly `yes`, or `declined`. The recovery key's text is dropped as soon as the reveal is written.
async fn reveal_and_confirm(exchange: &mut Exchange, keys: NewVaultKeys) -> Result<Result<SealingKeys, AdminResponse>, ExchangeError> {
    let confirmed = reveal_recovery_key(exchange, keys.recovery_secret()).await?;
    Ok(confirmed.map(|()| keys.into_sealing()))
}

/// Sends the reveal `init` and `recipient add --recovery` share: the notice, the key's text and QR code, and the
/// confirmation prompt. Anything but exactly `yes` is `declined`, with the advice that the key opens nothing.
pub(super) async fn reveal_recovery_key(
    exchange: &mut Exchange,
    secret: &RecoveryKeySecret,
) -> Result<Result<(), AdminResponse>, ExchangeError> {
    exchange.notice(RECOVERY_NOTICE).await?;
    exchange.reveal(secret.expose_secret().as_bytes()).await?;
    let confirmation = Prompt {
        label: CONFIRMATION.to_owned(),
        secret: false,
        switchable: false,
    };
    if exchange.prompt(&confirmation).await?.expose_secret() != b"yes" {
        let message = format!("the recovery key was not confirmed as saved, so nothing was written; {DEAD_RECOVERY_KEY}");
        return Ok(Err(error(ErrorCode::Declined, message)));
    }
    Ok(Ok(()))
}

/// Collects the vault and approval passphrases, each entered twice. Returns the rule one broke as the inner error. Each
/// passphrase's rules are checked once both its entries are in, so a broken rule ends the exchange before the next
/// prompt; there is no second try.
async fn chosen_passphrases(exchange: &mut Exchange) -> Result<Result<InitPassphrases, String>, ExchangeError> {
    let vault = match chosen(exchange, VAULT_PROMPTS, WhichPassphrase::Vault).await? {
        Ok(vault) => vault,
        Err(rule) => return Ok(Err(rule)),
    };
    let approval = chosen(exchange, APPROVAL_PROMPTS, WhichPassphrase::Approval).await?;
    Ok(approval.and_then(|approval| both(vault, approval)))
}

/// Collects one passphrase, entered twice. Both inputs are cleared when they drop here.
pub(super) async fn chosen(
    exchange: &mut Exchange,
    [label, repeat]: [&str; 2],
    which: WhichPassphrase,
) -> Result<Result<SecretString, String>, ExchangeError> {
    let secret = |label: &str| Prompt {
        label: label.to_owned(),
        secret: true,
        switchable: false,
    };
    let entry = exchange.prompt(&secret(label)).await?;
    let repeated = exchange.prompt(&secret(repeat)).await?;
    Ok(entry_text(&entry, &repeated, which))
}

/// Returns the entry as text once it equals its repeat (compared in constant time), is UTF-8 and is long enough. A
/// refusal names the rule and nothing typed.
pub(super) fn entry_text(entry: &OwnerInput, repeated: &OwnerInput, which: WhichPassphrase) -> Result<SecretString, String> {
    if !bool::from(entry.expose_secret().ct_eq(repeated.expose_secret())) {
        return Err(format!("the two entries of {which} differ"));
    }
    let text = std::str::from_utf8(entry.expose_secret()).map_err(|_| format!("{which} is not valid UTF-8"))?;
    InitPassphrases::ensure_long_enough(text, which).map_err(|rule| rule.to_string())?;
    Ok(SecretString::from(text))
}

/// Wraps both passphrases in their own types. Refuses them if the two are the same.
fn both(vault: SecretString, approval: SecretString) -> Result<InitPassphrases, String> {
    let vault = Passphrase::new(vault).map_err(|e| e.to_string())?;
    let approval = ApprovalPassphrase::new(approval).map_err(|e| e.to_string())?;
    InitPassphrases::new(vault, approval).map_err(|rule| rule.to_string())
}

/// Which command is creating the vault: it names itself in a refusal's advice and picks the code of a failed write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Creating {
    Init,
    Import,
}

impl Creating {
    fn name(self) -> &'static str {
        match self {
            Self::Init => "init",
            Self::Import => "import",
        }
    }

    const fn failed_code(self) -> ErrorCode {
        match self {
            Self::Init => ErrorCode::InitFailed,
            Self::Import => ErrorCode::ImportFailed,
        }
    }
}

/// Returns the response for `refusal`. After the reveal, a refusal also says the recovery key shown is dead.
fn refused(refusal: InitRefusal, revealed: bool) -> AdminResponse {
    refused_by(Creating::Init, refusal, revealed)
}

/// Returns [`refused`]'s response for `creating`, which `import` shares: the same endings, worded for the command that
/// ran.
pub(super) fn refused_by(creating: Creating, refusal: InitRefusal, revealed: bool) -> AdminResponse {
    let command = creating.name();
    let dead = |message: String| match revealed {
        true => format!("{message}; {DEAD_RECOVERY_KEY}"),
        false => message,
    };
    match refusal {
        InitRefusal::Busy => error(
            ErrorCode::Busy,
            dead(format!(
                "another init or import, an approval, a vault write, a reload or a config check is running, so nothing was written; \
                 run `iron-vault {command}` again"
            )),
        ),
        InitRefusal::WrongState(state) => error(
            ErrorCode::WrongState,
            dead(format!(
                "`{command}` is allowed only while the service is Locked; it is {}",
                state_name(state)
            )),
        ),
        InitRefusal::Initialized => error(
            ErrorCode::AlreadyInitialized,
            dead("the vault is Initialized, so nothing was changed".to_owned()),
        ),
        InitRefusal::ResetUnfinished => error(
            ErrorCode::AlreadyInitialized,
            dead("a reset was interrupted, so nothing was changed; run `iron-vault reset` again".to_owned()),
        ),
        InitRefusal::Unrecognized(files) => error(
            ErrorCode::AlreadyInitialized,
            dead(format!(
                "the directories are Unrecognized: they hold files {command} did not write, first {}; nothing was changed: move \
                 them aside and run `iron-vault {command}` again",
                files.join(", ")
            )),
        ),
        InitRefusal::Unreadable(detail) => error(
            creating.failed_code(),
            format!("cannot read the initialization state, so nothing was written: {detail}"),
        ),
        InitRefusal::MemoryUnprotected(memory) => error(
            ErrorCode::MemoryUnprotected,
            format!(
                "memory is not locked against swap ({}), so a protected install does not generate keys or take passphrases; \
                 nothing was written",
                unprotected_reason(&memory)
            ),
        ),
        InitRefusal::HostUnlock(reason) => error(
            creating.failed_code(),
            format!("cannot enrol the host unlock identity, so nothing was written: {reason}"),
        ),
        InitRefusal::Clock(detail) => error(
            creating.failed_code(),
            dead(format!("cannot read the service clock, so nothing was written: {detail}")),
        ),
        InitRefusal::Failed(failure) => failed(&failure),
        InitRefusal::Import(failure) => import::failed(&failure),
        InitRefusal::Interrupted => error(
            creating.failed_code(),
            format!(
                "{command} did not finish: its task ended without a result; {}",
                unconfirmed(creating)
            ),
        ),
    }
}

/// Returns what the owner does with a recovery key when `creating` may or may not have written its vault.
const fn unconfirmed(creating: Creating) -> &'static str {
    match creating {
        Creating::Init => UNCONFIRMED_RECOVERY_KEY,
        Creating::Import => UNCONFIRMED_IMPORT_KEY,
    }
}

/// Returns `init-failed`, naming the step. Only when the commit point's unlink landed and its directory fsync failed is
/// the outcome unknown; any other failure leaves the vault Unfinished, which a re-run discards.
fn failed(failure: &InitError) -> AdminResponse {
    let advice = match failure.cause() {
        InitFailure::State(InitStateError::FinishUncertain { .. }) => UNCONFIRMED_RECOVERY_KEY.to_owned(),
        _ => format!("run `iron-vault init` again, which discards the unfinished vault; {DEAD_RECOVERY_KEY}"),
    };
    let (_, at) = step_names(failure.step());
    error(ErrorCode::InitFailed, format!("init failed at {at}: {}; {advice}", failure.cause()))
}

pub(super) fn error(code: ErrorCode, message: String) -> AdminResponse {
    AdminResponse::Error { code, message }
}

#[cfg(test)]
mod tests;
