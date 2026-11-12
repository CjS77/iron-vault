//! `import`: makes a vault from a migration bundle that `export` wrote on another machine
//! ([spec §16](../../../../design/iron-vault-specification.md#16-administration-recovery-and-migration) steps 3 to 6;
//! [migration bundle: Admin exchanges, Import](../../../../design/migration-bundle.md#import-1)).
//!
//! The bundle follows the request as bundle data frames and is decoded as it arrives. The service, not the CLI, prompts
//! for the export passphrase and the new vault passphrase, generates the destination's keys and shows the recovery key
//! once, so nothing secret crosses the socket but what the owner types. Nothing is written until the owner confirms the
//! recovery key, and the vault routes nothing afterwards until the owner approves a config.
//!
//! ```text
//! 1  Locked, memory locked, directories free, import slot, handoff     wrong-state, memory-unprotected, busy, ...
//! 2  bundle data frames to the empty one, decoded as they arrive       bundle-invalid
//! 3  export passphrase; open the exported identity envelope            import-denied
//! 4  verify the bundle with the vault identity                         bundle-invalid
//! 5  summary, from the verified files only
//! 6  new vault passphrase, twice                                       passphrase-rejected
//! 7  new keys; reveal the recovery key; "Type yes ..."                 declined
//! 8  service-wide lock, the checks again, the write order              busy, wrong-state, import-failed
//! 9  success: the import result; the service stays Locked
//! ```

use std::sync::Arc;
use std::time::{Duration, Instant};

use iron_vault_store::migration_bundle::{BundleDecoder, DecodedBundle};
use iron_vault_store::{
    ExportPassphrase, ImportError, ImportFailure, ImportKeys, ImportProgress, ImportStep, ImportedVault, InitStateError,
    InitializationState, OpenBundleError, Passphrase, RecipientIdentity, SignerKind, StoreFs, UnfinishedKind, VerifiedBundle,
    WhichPassphrase,
};
use secrecy::SecretString;
use tokio::sync::mpsc;

use super::dispatch::{AdminHandler, HandlerFuture};
use super::export::secret_prompt;
use super::init::{Creating, VAULT_PROMPTS, chosen, error, refused_by, reveal_recovery_key};
use super::principal::AdminPrincipal;
use super::protocol::{AdminRequest, AdminResponse, ErrorCode, ImportResult, OwnerInput};
use super::server::{Exchange, ExchangeError};
use super::{DEAD_RECOVERY_KEY, UNCONFIRMED_IMPORT_KEY};
use crate::audit::AuditEvent;
use crate::audit::migration::ImportRefused;
use crate::service_context::{BundleRefusal, ImportSlot, InitRefusal, ServiceContext};
use crate::service_state::AdminOperation;

/// How long the write order goes without telling the owner something. The design asks for a notice at least every 10
/// seconds within the record steps, so half of that leaves room for a slow fsync between two records.
const NOTICE_INTERVAL: Duration = Duration::from_secs(5);

/// `import`'s handler, acting on the running service.
pub(super) struct Import<F> {
    service: Arc<ServiceContext<F>>,
}

impl<F> Import<F> {
    pub(super) fn new(service: Arc<ServiceContext<F>>) -> Self {
        Self { service }
    }
}

impl<F: StoreFs + Send + Sync + 'static> AdminHandler for Import<F> {
    fn handle<'a>(&'a self, _principal: AdminPrincipal, request: AdminRequest, exchange: &'a mut Exchange) -> HandlerFuture<'a> {
        let host_unlock = matches!(request, AdminRequest::Import { host_unlock: true });
        Box::pin(self.run(exchange, host_unlock))
    }
}

/// What step 1 established, which the rest of the exchange relies on.
struct Checked {
    /// Held until the exchange ends.
    _slot: ImportSlot,
    existing: InitializationState,
    /// The identity in the unlock handoff, read when `--host-unlock` asked for it.
    host: Option<RecipientIdentity>,
}

impl<F: StoreFs + Send + Sync + 'static> Import<F> {
    /// Runs the nine steps of the exchange.
    async fn run(&self, exchange: &mut Exchange, host_unlock: bool) -> Result<AdminResponse, ExchangeError> {
        let checked = match self.check(host_unlock).await {
            Ok(checked) => checked,
            Err(refusal) => return Ok(refused_by(Creating::Import, refusal, false)),
        };
        if let InitializationState::Unfinished(kind) = checked.existing {
            exchange.notice(&unfinished_notice(kind)).await?;
        }
        let decoded = match receive(exchange).await? {
            Ok(decoded) => decoded,
            Err(response) => return Ok(response),
        };
        let bundle = match self.open(exchange, decoded).await? {
            Ok(bundle) => bundle,
            Err(response) => return Ok(response),
        };
        exchange.notice(&summary_text(&bundle, checked.host.is_some())).await?;
        let passphrase = match vault_passphrase(exchange).await? {
            Ok(passphrase) => passphrase,
            Err(rule) => return Ok(error(ErrorCode::PassphraseRejected, rule)),
        };
        let (keys, secret) = ImportKeys::generate();
        let keys = checked.host.into_iter().fold(keys, ImportKeys::with_host_unlock);
        if let Err(declined) = reveal_recovery_key(exchange, &secret).await? {
            return Ok(declined);
        }
        drop(secret);
        Ok(self.write(exchange, bundle, (keys, passphrase)).await)
    }

    /// Runs step 1, before any prompt: checks for Locked, locked memory in a protected install and an initialization
    /// state import may write over, takes the import slot and, with `host_unlock`, reads the unlock handoff. The
    /// handoff is read last, so a service whose memory is not locked never opens it.
    async fn check(&self, host_unlock: bool) -> Result<Checked, InitRefusal> {
        let state = self.service.state().await;
        if !state.admin_allows(AdminOperation::Initialize) {
            return Err(InitRefusal::WrongState(state));
        }
        self.service.require_locked_memory_for_init()?;
        let existing = self.service.initializable().await?;
        let slot = self.service.take_import_slot()?;
        let host = match host_unlock {
            true => Some(self.service.read_host_unlock().await?),
            false => None,
        };
        Ok(Checked {
            _slot: slot,
            existing,
            host,
        })
    }

    /// Runs steps 3 and 4: asks for the export passphrase, then opens and verifies the bundle with it.
    async fn open(&self, exchange: &mut Exchange, decoded: DecodedBundle) -> Result<Result<VerifiedBundle, AdminResponse>, ExchangeError> {
        let input = exchange.prompt(&secret_prompt("Export passphrase")).await?;
        let Some(passphrase) = export_passphrase(&input) else {
            return Ok(Err(denied()));
        };
        drop(input);
        Ok(match self.service.open_bundle(decoded, passphrase).await {
            Ok(bundle) => Ok(bundle),
            Err(BundleRefusal::Open(OpenBundleError::WrongPassphrase)) => Err(denied()),
            Err(BundleRefusal::Open(OpenBundleError::Invalid(check))) => Err(invalid("check", check.name())),
            Err(BundleRefusal::Interrupted) => Err(error(
                ErrorCode::ImportFailed,
                "the check of the bundle did not finish, so nothing was written".to_owned(),
            )),
        })
    }

    /// Runs step 8, then 9: the write order with its progress notices, and the result. A notice that cannot be written
    /// does not stop the write order, which runs on to its commit point.
    async fn write(&self, exchange: &mut Exchange, bundle: VerifiedBundle, secrets: (ImportKeys, Passphrase)) -> AdminResponse {
        let (sender, mut notices) = mpsc::unbounded_channel();
        let import = self.service.import(bundle, secrets, Progress::new(sender));
        tokio::pin!(import);
        let written = loop {
            tokio::select! {
                biased;
                Some(notice) = notices.recv() => { let _ = exchange.notice(&notice).await; }
                written = &mut import => break written,
            }
        };
        while let Ok(notice) = notices.try_recv() {
            let _ = exchange.notice(&notice).await;
        }
        match written {
            Ok(vault) => AdminResponse::Import(result(&vault)),
            Err(refusal) => refused_by(Creating::Import, refusal, true),
        }
    }
}

/// Runs step 2: reads bundle data frames to the empty one and decodes them as they arrive, so a bundle that breaks a rule is
/// refused at that frame. A missed deadline is the exchange's error, which closes it without a response.
async fn receive(exchange: &mut Exchange) -> Result<Result<DecodedBundle, AdminResponse>, ExchangeError> {
    let mut decoder = BundleDecoder::new();
    loop {
        let chunk = exchange.receive_bundle_chunk().await?;
        if chunk.is_end() {
            return Ok(decoder.finish().map_err(|rule| invalid("rule", rule.rule())));
        }
        if let Err(rule) = decoder.push(chunk.bytes()) {
            return Ok(Err(invalid("rule", rule.rule())));
        }
    }
}

/// Runs step 6: asks for the new vault passphrase twice and holds it to the passphrase rules.
async fn vault_passphrase(exchange: &mut Exchange) -> Result<Result<Passphrase, String>, ExchangeError> {
    let entered = chosen(exchange, VAULT_PROMPTS, WhichPassphrase::Vault).await?;
    Ok(entered.and_then(|text| Passphrase::new(text).map_err(|e| e.to_string())))
}

/// Reads the typed export passphrase. Returns `None` when it is not text, which no export passphrase is.
fn export_passphrase(input: &OwnerInput) -> Option<ExportPassphrase> {
    let text = std::str::from_utf8(input.expose_secret()).ok()?;
    ExportPassphrase::new(SecretString::from(text)).ok()
}

/// Returns the notice for an Unfinished state: what is there, and that confirming the new recovery key discards it.
fn unfinished_notice(kind: UnfinishedKind) -> String {
    let (what, writer, config) = match kind {
        UnfinishedKind::Initialization => ("initialization", "an init is", ""),
        UnfinishedKind::Import => ("import", "an import is", ", its copy of config.toml included"),
    };
    format!(
        "An unfinished {what} is here, or {writer} writing its vault right now. Once you confirm the new recovery key, the \
         unfinished {what} is discarded{config}, and any recovery key it showed opens nothing. A run still writing is never \
         discarded: this import then writes nothing and ends with `busy`, or with `already-initialized` once that run has \
         finished.\n"
    )
}

/// Returns the summary the owner reads before choosing a passphrase, built from the verified files only.
fn summary_text(bundle: &VerifiedBundle, host_unlock: bool) -> String {
    let approvers = bundle
        .approvers()
        .iter()
        .map(|approver| match approver.kind() {
            SignerKind::Software => approver.label().to_string(),
            SignerKind::Tpm => format!("{} (bound to the source machine)", approver.label()),
        })
        .collect::<Vec<_>>();
    let host_line = if host_unlock {
        "  host unlock: enrolled from this machine's unlock handoff\n"
    } else {
        ""
    };
    format!(
        "import a migration bundle\n  vault: {}\n  credentials: {}\n  approvers: {}\n  committed approval: version {}; highest reserved \
         version: {}\n  config: the source's committed config, to be approved on this machine\n  then: a new vault passphrase and a new \
         recovery key for this machine\n{host_line}  routing starts after iron-vault config approve, at version {} or later\n",
        bundle.vault_id(),
        bundle.record_count(),
        approvers.join(", "),
        bundle.committed_version().get(),
        bundle.highest_reserved(),
        bundle.highest_reserved().saturating_add(1),
    )
}

fn result(vault: &ImportedVault) -> ImportResult {
    ImportResult {
        vault_id: vault.vault_id,
        records: u64::try_from(vault.records).unwrap_or(u64::MAX),
        version: vault.committed_version.get(),
        highest_reserved: vault.highest_reserved,
        digest: *vault.config_digest.as_bytes(),
        recipients: vault.recipients.clone(),
    }
}

/// Returns `bundle-invalid` naming the `rule` of the encoding or the `check` with the vault identity, never a byte of
/// the bundle.
fn invalid(kind: &str, name: &'static str) -> AdminResponse {
    ImportRefused::BundleInvalid { detail: name }.emit();
    error(
        ErrorCode::BundleInvalid,
        format!("the bundle fails the {kind} `{name}`; nothing was written"),
    )
}

/// Returns `import-denied`: the passphrase does not open the bundle. There is no attempt limit, since whoever holds the
/// bundle can guess at it offline.
fn denied() -> AdminResponse {
    ImportRefused::WrongPassphrase.emit();
    error(
        ErrorCode::ImportDenied,
        "the export passphrase does not open the migration bundle; nothing was written".to_owned(),
    )
}

/// Returns `import-failed`, naming the step. Only when the commit point's unlink landed and its directory fsync failed is the
/// outcome unknown; any other failure leaves the vault Unfinished, which a re-run discards.
pub(super) fn failed(failure: &ImportError) -> AdminResponse {
    let advice = match failure.cause() {
        ImportFailure::State(InitStateError::ImportFinishUncertain { .. }) => UNCONFIRMED_IMPORT_KEY.to_owned(),
        _ => format!("run `iron-vault import` again, which discards the unfinished import; {DEAD_RECOVERY_KEY}"),
    };
    error(ErrorCode::ImportFailed, format!("{failure}; {advice}"))
}

/// Turns the store's progress into notices for the owner: one before each step, and within a step that counts records,
/// one whenever [`NOTICE_INTERVAL`] has passed. It runs on the blocking pool, so it only queues text for the exchange.
struct Progress {
    sender: mpsc::UnboundedSender<String>,
    last: Instant,
}

impl Progress {
    fn new(sender: mpsc::UnboundedSender<String>) -> Self {
        Self {
            sender,
            last: Instant::now(),
        }
    }

    fn notify(&mut self, text: String) {
        self.last = Instant::now();
        // A closed receiver means the owner is no longer watching; the write order goes on regardless.
        let _ = self.sender.send(text);
    }
}

impl ImportProgress for Progress {
    fn step(&mut self, step: ImportStep) {
        self.notify(format!("{step}\n"));
    }

    fn records(&mut self, step: ImportStep, done: usize, total: usize) {
        if self.last.elapsed() >= NOTICE_INTERVAL {
            self.notify(format!("{step}: {done} of {total}\n"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drained(notices: &mut mpsc::UnboundedReceiver<String>) -> Vec<String> {
        std::iter::from_fn(|| notices.try_recv().ok()).collect()
    }

    #[test]
    fn every_step_is_announced_and_a_record_count_waits_for_the_interval() {
        let (sender, mut notices) = mpsc::unbounded_channel();
        let mut progress = Progress::new(sender);
        progress.step(ImportStep::Records);
        progress.records(ImportStep::Records, 1, 4096);
        assert_eq!(drained(&mut notices), ["step 2, writing the record files\n"]);

        progress.last = Instant::now().checked_sub(NOTICE_INTERVAL).unwrap();
        progress.records(ImportStep::Records, 1024, 4096);
        progress.records(ImportStep::Records, 1025, 4096);
        assert_eq!(drained(&mut notices), ["step 2, writing the record files: 1024 of 4096\n"]);
    }

    #[test]
    fn a_notice_nobody_reads_does_not_stop_the_write_order() {
        let (sender, notices) = mpsc::unbounded_channel();
        drop(notices);
        let mut progress = Progress::new(sender);
        progress.step(ImportStep::Check);
        progress.records(ImportStep::Check, 1, 1);
    }
}
