//! Runs the service's part of `import`
//! ([specification §16](../../../../design/iron-vault-specification.md#16-administration-recovery-and-migration),
//! migration steps 4 and 5; [migration bundle: Import](../../../../design/migration-bundle.md#import-1)): the import
//! slot, opening and verifying a received bundle, and the writes once the owner has confirmed the recovery key.
//!
//! ```text
//!   step 1   take_import_slot            Busy while another import holds the slot
//!   step 2   (exchange) read and decode the bundle frames
//!   step 3-4 open_bundle                 export passphrase opens the identity envelope; verify with the vault identity
//!   step 5-7 (exchange) summary, new vault passphrase, recovery key confirmation
//!   step 8   import                      the write order, under the service-wide lock; the service stays Locked
//! ```
//!
//! Like `init`, the writes take the service-wide lock without waiting and check the service state again under the
//! context's mutex, and the service stays Locked throughout: import keeps no key it unwraps and runs no config check.

use std::sync::Arc;

use iron_vault_store::migration_bundle::DecodedBundle;
use iron_vault_store::{
    ExportPassphrase, ImportError, ImportFailure, ImportKeys, ImportProgress, ImportStep, ImportedVault, OpenBundleError, Passphrase,
    StoreFs, VerifiedBundle, import_vault, open_bundle, verify_bundle,
};
use tokio::sync::OwnedMutexGuard;
use tokio::task::JoinError;

use super::init::{directory_refusal, emit_discarded};
use super::{InitRefusal, ServiceContext};
use crate::audit::AuditEvent;
use crate::audit::migration::{ImportFailed, Imported};
use crate::service_state::AdminOperation;

/// The right to be the one import past its first step. It is held from the end of step 1 until the exchange ends, so
/// the bundle an import keeps in memory, and the scrypt runs it makes, are never doubled by a second import.
#[derive(Debug)]
pub struct ImportSlot {
    _held: OwnedMutexGuard<()>,
}

/// Why steps 3 and 4 gave no verified bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleRefusal {
    /// The export passphrase did not open the exported identity envelope, or the envelope is not one import opens, or a
    /// check with the vault identity failed.
    Open(OpenBundleError),
    /// The blocking task ended without a result.
    Interrupted,
}

impl<F: StoreFs + Send + Sync + 'static> ServiceContext<F> {
    /// Takes the import slot without waiting; another import past its first step ends this one with
    /// [`InitRefusal::Busy`].
    pub fn take_import_slot(&self) -> Result<ImportSlot, InitRefusal> {
        Arc::clone(&self.import_slot)
            .try_lock_owned()
            .map(|_held| ImportSlot { _held })
            .map_err(|_| InitRefusal::Busy)
    }

    /// Runs steps 3 and 4: opens the exported identity envelope with `passphrase`, then verifies the bundle with the
    /// vault identity it held, on the blocking pool since the envelope is a 256 MiB scrypt run. Nothing is written.
    pub async fn open_bundle(&self, decoded: DecodedBundle, passphrase: ExportPassphrase) -> Result<VerifiedBundle, BundleRefusal> {
        let opened = tokio::task::spawn_blocking(move || {
            open_bundle(decoded, &passphrase).and_then(|opened| verify_bundle(opened).map_err(OpenBundleError::from))
        })
        .await;
        opened.map_err(|_| BundleRefusal::Interrupted)?.map_err(BundleRefusal::Open)
    }

    /// Runs step 8, the write order for `bundle` on the blocking pool, since scrypt runs once and every file is
    /// fsynced. It takes the service-wide lock without waiting, so another holder ends it with [`InitRefusal::Busy`].
    ///
    /// The blocking task owns both guards and drops them only once the store has returned and the outcome is logged. If
    /// this future is dropped first, as `abort_all` does at shutdown, the task still runs to its end and logs how it
    /// ended, and no approval, vault write, unlock, init or second import can start while it writes.
    pub async fn import(
        &self,
        bundle: VerifiedBundle,
        (keys, passphrase): (ImportKeys, Passphrase),
        mut progress: impl ImportProgress + Send + 'static,
    ) -> Result<ImportedVault, InitRefusal> {
        let service_wide = Arc::clone(&self.service_wide).try_lock_owned().map_err(|_| InitRefusal::Busy)?;
        let inner = Arc::clone(&self.inner).lock_owned().await;
        if !inner.state.admin_allows(AdminOperation::Initialize) {
            return Err(InitRefusal::WrongState(inner.state));
        }
        let enrolled_at = self.clock.now().map_err(|error| InitRefusal::Clock(error.to_string()))?;
        let (locks, setup) = (Arc::clone(&self.locks), Arc::clone(&self.setup));
        let written = tokio::task::spawn_blocking(move || {
            let _held = (service_wide, inner);
            let written = import_vault(
                &locks.state,
                &locks.config,
                &setup.fs,
                bundle,
                (keys, passphrase),
                enrolled_at,
                &mut progress,
            );
            log_outcome(&written);
            written
        })
        .await;
        settled(written)
    }
}

/// Logs how the writes ended: the files a discard removed, then the new vault or the failed step. A refusal of the
/// directories is not a failure, since nothing was written, and its caller is told why.
fn log_outcome(written: &Result<ImportedVault, ImportError>) {
    emit_discarded(
        written
            .as_ref()
            .map_or_else(ImportError::discarded, |vault| vault.discarded.as_ref()),
    );
    match written {
        Ok(vault) => Imported { vault }.emit(),
        Err(error) if begin_refusal(error).is_none() => ImportFailed::Step {
            step: error.step(),
            cause: error.cause(),
        }
        .emit(),
        Err(_) => {}
    }
}

/// Turns how the writing task ended into `import`'s answer. Only a task that ended without a result is logged here; the
/// task logs every other outcome itself.
fn settled(written: Result<Result<ImportedVault, ImportError>, JoinError>) -> Result<ImportedVault, InitRefusal> {
    let Ok(written) = written else {
        ImportFailed::TaskEnded.emit();
        return Err(InitRefusal::Interrupted);
    };
    written.map_err(|error| begin_refusal(&error).unwrap_or(InitRefusal::Import(error)))
}

/// Returns step 1's refusal of the directories, which writes nothing, or `None` when `error` is a failed step.
fn begin_refusal(error: &ImportError) -> Option<InitRefusal> {
    match (error.step(), error.cause()) {
        (ImportStep::Begin, ImportFailure::State(refused)) => directory_refusal(refused),
        _ => None,
    }
}
