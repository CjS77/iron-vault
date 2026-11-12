//! `export`: releases the vault as a migration bundle sealed to an export passphrase, only after fresh source-owner
//! authorization ([spec §16](../../../../design/iron-vault-specification.md#16-administration-recovery-and-migration);
//! [migration bundle: Export](../../../../design/migration-bundle.md#export-1);
//! [migration authorization: Admin exchange](../../../../design/migration-authorization.md#admin-exchange)).
//!
//! An admin connection or an unlocked vault is not enough: the bundle carries every credential, so the exchange holds
//! the service-wide lock from the session through the response, checks the snapshot before any prompt, and asks for the
//! vault passphrase or a `tpm` approver's TPM approval PIN. Only the authorization that answer proves starts the
//! stream. The bundle reaches the CLI as bundle data frames; it is ciphertext and public metadata, so no plaintext
//! secret leaves the service.
//!
//! ```text
//! 1     Ready, holding the vault identity                   wrong-state
//! 2     take the service-wide lock                          busy
//! 3     snapshot checks                                     export-failed, approver-set-invalid
//! 4     summary, naming the method asked first
//! 5-7   migration authorization                             migration-denied, migration-unavailable,
//!                                                           migration-rate-limited, tpm-locked-out
//! 8     export passphrase, twice                            passphrase-rejected, migration-unavailable
//! 9     same state and check generation; consume the proof  wrong-state, migration-denied
//! 10    snapshot read again, streamed as bundle data        export-failed
//! 11    success: vault ID, record count, byte count
//! ```

use std::sync::Arc;

use iron_vault_store::{
    ErrorKindLabel, ExportPassphrase, ExportedBundle, SnapshotError, SnapshotStep, SnapshotSummary, StoreFs, WhichPassphrase,
};
use tokio::sync::mpsc;

use super::dispatch::{AdminHandler, HandlerFuture};
use super::init::entry_text;
use super::migration_authorization::{NoAuthorization, askable_methods, authorize_with, no_authorization, require_migration_authorization};
use super::principal::AdminPrincipal;
use super::protocol::{AdminRequest, AdminResponse, ErrorCode, Prompt};
use super::server::{Exchange, ExchangeError};
use super::unlock::state_name;
use crate::audit::AuditEvent;
use crate::audit::migration::{ExportFailed, Exported};
use crate::migration_authorization::{MigrationAuthorization, MigrationOperation, MigrationRefusal};
use crate::service_context::{ExportError, ExportStream, MigrationSession, ServiceContext};
use crate::service_state::ServiceState;

const COMMAND: &str = "export";

/// The phrase every `export-failed` message ends with.
const NO_BUNDLE: &str = "no bundle was completed";

/// The notice before the export passphrase prompts.
const CHOOSE_PASSPHRASE: &str = "Choose an export passphrase used nowhere else. It protects the migration bundle, \
                                 and import asks for it.\n";

/// `export`'s handler, acting on the running service.
pub(super) struct Export<F> {
    service: Arc<ServiceContext<F>>,
}

impl<F> Export<F> {
    pub(super) fn new(service: Arc<ServiceContext<F>>) -> Self {
        Self { service }
    }
}

impl<F: StoreFs + Send + Sync + 'static> AdminHandler for Export<F> {
    fn handle<'a>(&'a self, _principal: AdminPrincipal, _request: AdminRequest, exchange: &'a mut Exchange) -> HandlerFuture<'a> {
        Box::pin(self.run(exchange))
    }
}

impl<F: StoreFs + Send + Sync + 'static> Export<F> {
    /// Runs the eleven steps of the exchange. Every early return drops the session, which releases the service-wide lock and
    /// retires any pending challenge.
    async fn run(&self, exchange: &mut Exchange) -> Result<AdminResponse, ExchangeError> {
        let session = match self.service.begin_migration().await {
            Ok(session) => session,
            Err(refusal) => return Ok(refused(refusal)),
        };
        let summary = match self.service.check_export(&session).await {
            Ok(summary) => summary,
            Err(error) => return Ok(check_failed(error)),
        };
        let methods = match askable_methods(&session).await {
            Ok(methods) => methods,
            Err(none) => return Ok(no_authorization(COMMAND, none)),
        };
        exchange.notice(&summary_text(&summary, &authorize_with(&methods))).await?;
        let authorization = match require_migration_authorization(exchange, &session, MigrationOperation::Export, &methods).await? {
            Ok(authorization) => authorization,
            Err(none) => return Ok(no_authorization(COMMAND, none)),
        };
        let passphrase = match export_passphrase(exchange, &session).await? {
            Ok(passphrase) => passphrase,
            Err(response) => return Ok(response),
        };
        self.stream(exchange, &session, authorization, passphrase).await
    }

    /// Runs steps 9 to 11: consumes the authorization, relays the bundle, then ends it with the empty frame and the
    /// result.
    async fn stream(
        &self,
        exchange: &mut Exchange,
        session: &MigrationSession<'_, F>,
        authorization: MigrationAuthorization,
        passphrase: ExportPassphrase,
    ) -> Result<AdminResponse, ExchangeError> {
        let ExportStream { mut chunks, task } = match self.service.start_export(session, authorization, passphrase).await {
            Ok(stream) => stream,
            Err(refusal) => return Ok(refused(refusal)),
        };
        let relayed = relay(exchange, session, &mut chunks).await;
        // Dropping the receiver fails the task's next write, so it stops reading the vault; waiting for it keeps the
        // response after its last read.
        drop(chunks);
        let streamed = task.await;
        if let Err(ended) = relayed {
            return transfer_ended(ended);
        }
        let exported = match streamed {
            Ok(Ok(exported)) => exported,
            Ok(Err(error)) => {
                ExportFailed::of(&error).emit();
                return Ok(export_failed(error.to_string()));
            }
            Err(_) => return Ok(task_ended()),
        };
        match exchange.send_bundle_chunk(&[]).await {
            Ok(()) => Ok(completed(&exported)),
            Err(error) => transfer_ended(RelayEnded::Exchange(error)),
        }
    }
}

/// Runs step 8: asks for the export passphrase twice and checks it by the passphrase rules once both are in. A `lock` at either
/// prompt ends the exchange with `migration-unavailable`, and the unused authorization drops with it.
async fn export_passphrase<F: StoreFs + Send + Sync + 'static>(
    exchange: &mut Exchange,
    session: &MigrationSession<'_, F>,
) -> Result<Result<ExportPassphrase, AdminResponse>, ExchangeError> {
    exchange.notice(CHOOSE_PASSPHRASE).await?;
    let Some(entry) = exchange
        .prompt_unless(&secret_prompt("Export passphrase"), session.lock_requested())
        .await?
    else {
        return Ok(Err(locked_at_passphrase()));
    };
    let Some(repeated) = exchange
        .prompt_unless(&secret_prompt("Repeat the export passphrase"), session.lock_requested())
        .await?
    else {
        return Ok(Err(locked_at_passphrase()));
    };
    let rejected = |rule: String| error(ErrorCode::PassphraseRejected, format!("{rule}; nothing was exported"));
    Ok(entry_text(&entry, &repeated, WhichPassphrase::Export)
        .map_err(rejected)
        .and_then(|text| ExportPassphrase::new(text).map_err(|e| rejected(e.to_string()))))
}

pub(super) fn secret_prompt(label: &str) -> Prompt {
    Prompt {
        label: label.to_owned(),
        secret: true,
        switchable: false,
    }
}

/// Why the relay stopped before the bundle's last chunk.
enum RelayEnded {
    /// A `lock` was waiting between frames.
    Locked,
    /// A frame did not reach the CLI: a deadline passed, or the connection closed or failed.
    Exchange(ExchangeError),
}

/// Writes each chunk as a bundle data frame until the stream ends, checking for a waiting `lock` before each.
async fn relay<F: StoreFs + Send + Sync + 'static>(
    exchange: &mut Exchange,
    session: &MigrationSession<'_, F>,
    chunks: &mut mpsc::Receiver<Vec<u8>>,
) -> Result<(), RelayEnded> {
    loop {
        let chunk = tokio::select! {
            biased;
            () = session.lock_requested() => return Err(RelayEnded::Locked),
            chunk = chunks.recv() => chunk,
        };
        let Some(bytes) = chunk else { return Ok(()) };
        exchange.send_bundle_chunk(&bytes).await.map_err(RelayEnded::Exchange)?;
    }
}

/// Records a transfer that stopped and answers it: `export-failed` for a `lock` or a missed deadline, which the exchange
/// still sends when no frame was cut off, and a close for a CLI that has gone.
fn transfer_ended(ended: RelayEnded) -> Result<AdminResponse, ExchangeError> {
    let failed = |reason: &str| Ok(export_failed(format!("export transfer step: {reason}")));
    let (kind, answer) = match ended {
        RelayEnded::Locked => (ErrorKindLabel::fixed("locked"), failed("cancelled by lock")),
        RelayEnded::Exchange(ExchangeError::TimedOut | ExchangeError::TransferTimedOut) => {
            (ErrorKindLabel::fixed("deadline"), failed("a transfer deadline passed"))
        }
        RelayEnded::Exchange(ExchangeError::Io(kind)) => (ErrorKindLabel::from(kind), Err(ExchangeError::Io(kind))),
        RelayEnded::Exchange(other) => (ErrorKindLabel::fixed("closed"), Err(other)),
    };
    ExportFailed::transfer(kind).emit();
    answer
}

/// Answers a stream whose task ended without a result.
fn task_ended() -> AdminResponse {
    ExportFailed {
        step: SnapshotStep::Snapshot,
        error_kind: ErrorKindLabel::fixed("task_ended"),
        file: None,
    }
    .emit();
    export_failed("export snapshot step: the export did not finish".to_owned())
}

/// Runs step 11: emits `migration.exported`, then returns the result the CLI checks its byte count against.
fn completed(exported: &ExportedBundle) -> AdminResponse {
    let summary = &exported.summary;
    Exported { summary }.emit();
    AdminResponse::Export {
        vault_id: summary.vault_id,
        records: u64::try_from(summary.record_count).unwrap_or(u64::MAX),
        bytes: exported.byte_count,
    }
}

/// Returns the summary the owner confirms by typing the secret of the method named `authorize`.
fn summary_text(summary: &SnapshotSummary, authorize: &str) -> String {
    format!(
        "export the vault\n  vault: {}\n  credentials: {}\n  approver keys: {}\n  authorize with: {authorize}\n  \
         then: a new export passphrase to protect the migration bundle\n",
        summary.vault_id, summary.record_count, summary.approver_count,
    )
}

/// Answers step 3's failure: the snapshot check, recorded by the service, names the step and the file.
fn check_failed(failure: ExportError) -> AdminResponse {
    match failure {
        ExportError::WrongState(state) => wrong_state(state),
        ExportError::Snapshot(SnapshotError::NoSoftwareApprover) => error(
            ErrorCode::ApproverSetInvalid,
            "no software approver is pinned, and a TPM approver's key cannot move to another machine; enroll a software approver \
             first with `approver add`; nothing was exported"
                .to_owned(),
        ),
        ExportError::Snapshot(error) => export_failed(error.to_string()),
        ExportError::Interrupted => export_failed("export check step: the snapshot check did not finish".to_owned()),
    }
}

/// Answers a refusal at step 2 or step 9. Before any prompt a state other than Ready is `wrong-state`;
/// `no_authorization` reads a Locked state as a `lock` that cancelled the authorization prompt.
fn refused(refusal: MigrationRefusal) -> AdminResponse {
    match refusal {
        MigrationRefusal::WrongState(state) => wrong_state(state),
        other => no_authorization(COMMAND, NoAuthorization(other)),
    }
}

fn wrong_state(state: ServiceState) -> AdminResponse {
    error(
        ErrorCode::WrongState,
        format!("`export` is allowed only while the service is Ready; it is {}", state_name(state)),
    )
}

fn locked_at_passphrase() -> AdminResponse {
    error(
        ErrorCode::MigrationUnavailable,
        "`export` was cancelled because a `lock` ran while it waited for the export passphrase; nothing was exported".to_owned(),
    )
}

fn export_failed(message: String) -> AdminResponse {
    error(ErrorCode::ExportFailed, format!("{message}; {NO_BUNDLE}"))
}

fn error(code: ErrorCode, message: String) -> AdminResponse {
    AdminResponse::Error { code, message }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_snapshot_with_no_software_approver_is_answered_approver_set_invalid() {
        let AdminResponse::Error { code, message } = check_failed(ExportError::Snapshot(SnapshotError::NoSoftwareApprover)) else {
            panic!("expected an error");
        };
        assert_eq!(code, ErrorCode::ApproverSetInvalid);
        assert!(
            message.contains("enroll a software approver first") && message.ends_with("nothing was exported"),
            "{message}"
        );
    }
}
