//! Runs the service's part of `export` ([migration bundle: Export](../../../../design/migration-bundle.md#export-1)):
//! step 3, the snapshot checks before any prompt, and steps 9 and 10, consuming the authorization and streaming the
//! snapshot.
//!
//! ```text
//!   step 3      check_export: the snapshot checks             export-failed (step `check`), naming the file
//!   steps 4-8   summary, migration authorization, export passphrase, in the admin exchange
//!   step 9      start_export: consume the authorization       migration-denied: nothing starts
//!   step 10     blocking task ──▶ FrameSink ──▶ chunks ──▶ exchange ──▶ bundle data frames
//!                     ◀── BrokenPipe once the exchange drops `chunks`
//! ```
//!
//! `check_export` and `start_export` read the state and config directories on the blocking pool with a clone of the
//! session's service-wide lock, so no writer can start while a read is under way, even if the exchange is dropped
//! meanwhile. The stream starts only from the witness that consuming the authorization returns, so no bundle leaves
//! without a consumed authorization. Export writes nothing to either directory and changes no counter.

use std::io::{self, Write};
use std::mem;
use std::sync::Arc;

use iron_vault_store::{
    ApprovalState, ExportPassphrase, ExportedBundle, SnapshotError, SnapshotSummary, StoreFs, VaultIdentity, check_export_snapshot,
    stream_export_snapshot,
};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::migration::MigrationSession;
use super::{Inner, ServiceContext};
use crate::admin::protocol::MAX_BODY_LEN;
use crate::audit::AuditEvent;
use crate::audit::migration::ExportFailed;
use crate::migration_authorization::{AuthorizedMigration, MigrationAuthorization, MigrationOperation, MigrationRefusal};
use crate::service_state::ServiceState;

/// The number of bundle data frames that may wait between the blocking task and the exchange. Two lets the store read
/// the next file while a frame is written, and bounds what an export holds in memory beyond the store's own reads.
const FRAMES_IN_FLIGHT: usize = 2;

/// Why an export's store work gave no result.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    /// The service no longer holds the vault identity or its approval state.
    #[error("the service no longer holds the vault identity")]
    WrongState(ServiceState),
    /// The snapshot checks or the stream failed; the error names the step and, for a file, the file.
    #[error(transparent)]
    Snapshot(SnapshotError),
    /// The blocking task ended without a result.
    #[error("the export task ended without a result")]
    Interrupted,
}

/// A started export: the bundle's bytes in chunks of at most one bundle data frame, and the task producing them.
pub struct ExportStream {
    /// The bundle's bytes in order. It ends when the task does; the task's result says whether the bundle is whole.
    pub chunks: mpsc::Receiver<Vec<u8>>,
    /// The blocking task streaming the snapshot. Once `chunks` is dropped its next write fails, so it ends soon after.
    pub task: JoinHandle<Result<ExportedBundle, SnapshotError>>,
}

impl<F: StoreFs + Send + Sync + 'static> ServiceContext<F> {
    /// Runs step 3, the snapshot checks, before any prompt or challenge. A failure is recorded as
    /// `migration.export-failed` (step `check`), naming the file.
    pub async fn check_export(&self, session: &MigrationSession<'_, F>) -> Result<SnapshotSummary, ExportError> {
        let (identity, held) = held_vault(&*self.inner.lock().await)?;
        let (locks, setup, lock) = (Arc::clone(&self.locks), Arc::clone(&self.setup), session.hold());
        let checked = tokio::task::spawn_blocking(move || {
            let _held = lock;
            check_export_snapshot(&locks.state, &locks.config, &setup.fs, &identity, &held)
        })
        .await;
        match checked {
            Ok(Ok(summary)) => Ok(summary),
            Ok(Err(error)) => {
                ExportFailed::of(&error).emit();
                Err(ExportError::Snapshot(error))
            }
            Err(_) => Err(ExportError::Interrupted),
        }
    }

    /// Runs steps 9 and 10: consumes `authorization` for `export`, then starts streaming the snapshot sealed to
    /// `passphrase` on the blocking pool. The caller relays the chunks and records how the stream ended. A refused
    /// authorization starts nothing.
    pub async fn start_export(
        &self,
        session: &MigrationSession<'_, F>,
        authorization: MigrationAuthorization,
        passphrase: ExportPassphrase,
    ) -> Result<ExportStream, MigrationRefusal> {
        let authorized = session.consume(authorization, &MigrationOperation::Export).await?;
        let (identity, held) = held_vault(&*self.inner.lock().await).map_err(|_| MigrationRefusal::Unavailable)?;
        let (sender, chunks) = mpsc::channel(FRAMES_IN_FLIGHT);
        let (locks, setup, lock) = (Arc::clone(&self.locks), Arc::clone(&self.setup), session.hold());
        let task = tokio::task::spawn_blocking(move || {
            // The witness travels with the stream, which cannot start without one.
            let (_held, _authorized): (_, AuthorizedMigration) = (lock, authorized);
            let mut sink = FrameSink::new(sender);
            let exported = stream_export_snapshot(&locks.state, &locks.config, &setup.fs, &identity, &held, passphrase, &mut sink)?;
            // The bytes still buffered: the bundle is whole only once they are queued too.
            sink.flush().map_err(SnapshotError::Transfer)?;
            Ok(exported)
        });
        Ok(ExportStream { chunks, task })
    }
}

/// Returns the vault identity and approval state the service holds, which the snapshot is checked against, or
/// [`ExportError::WrongState`] when it holds neither.
fn held_vault(inner: &Inner) -> Result<(Arc<VaultIdentity>, ApprovalState), ExportError> {
    match (&inner.identity, &inner.open) {
        (Some(identity), Some(open)) => Ok((Arc::clone(identity), open.approval.clone())),
        _ => Err(ExportError::WrongState(inner.state)),
    }
}

/// Gathers the bundle's bytes into chunks of one bundle data frame and hands each to the exchange, waiting while
/// [`FRAMES_IN_FLIGHT`] are queued. Once the exchange drops its receiver every write fails with `BrokenPipe`, so the
/// store stops at its next write and does not read the rest of the vault for nobody.
struct FrameSink {
    sender: mpsc::Sender<Vec<u8>>,
    buffer: Vec<u8>,
}

impl FrameSink {
    fn new(sender: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            sender,
            buffer: Vec::with_capacity(MAX_BODY_LEN),
        }
    }

    fn send_buffer(&mut self) -> io::Result<()> {
        let chunk = mem::replace(&mut self.buffer, Vec::with_capacity(MAX_BODY_LEN));
        self.sender
            .blocking_send(chunk)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "the export exchange ended"))
    }
}

impl Write for FrameSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.sender.is_closed() {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "the export exchange ended"));
        }
        let taken = bytes.len().min(MAX_BODY_LEN - self.buffer.len());
        self.buffer.extend_from_slice(&bytes[..taken]);
        if self.buffer.len() == MAX_BODY_LEN {
            self.send_buffer()?;
        }
        Ok(taken)
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.buffer.is_empty() {
            true => Ok(()),
            false => self.send_buffer(),
        }
    }
}
