//! `init`'s side of the service context (specification §3.13; design/vault-initialization.md, "The exchange"): the
//! initialization state read before any prompt, and the writes once the owner has confirmed the recovery key.
//!
//! The prompts hold no lock, so the writes take the service-wide lock without waiting, check the service state again
//! under the context's mutex, and leave the store to read the initialization state again before its first write. The
//! service stays Locked throughout: init keeps no key it generates and runs no config check, so it makes no transition.

use std::sync::Arc;

use iron_vault_store::{
    InitError, InitFailure, InitPassphrases, InitStateError, InitStep, InitializationState, InitializedVault, SealingKeys, StoreFs,
    ensure_initializable, initialize,
};
use tokio::task::JoinError;

use super::ServiceContext;
use crate::audit::AuditEvent;
use crate::audit::vault::{InitDiscarded, InitFailed, VaultInitialized, emit_commit_uncertain};
use crate::service_state::{AdminOperation, ServiceState};

/// Why `init` wrote no vault, or may not have finished one. Each variant is one admin error code.
#[derive(Debug)]
pub enum InitRefusal {
    /// Another init, an approval, a vault write, a reload or a config check holds the service-wide lock.
    Busy,
    /// The service is not Locked.
    WrongState(ServiceState),
    /// The directories hold an initialized vault.
    Initialized,
    /// The directories hold files init did not write; the first of them.
    Unrecognized(Vec<String>),
    /// The initialization state could not be read, so nothing was written.
    Unreadable(String),
    /// A step of the write order, or the discard before it, failed.
    Failed(InitError),
    /// The task writing the vault ended without a result, so how far it got is unknown.
    Interrupted,
}

impl<F: StoreFs + Send + Sync + 'static> ServiceContext<F> {
    /// Whether init may write here, read on the blocking pool under the service's own directory locks: Uninitialized
    /// or Unfinished, or the refusal naming what is there.
    pub async fn initializable(&self) -> Result<InitializationState, InitRefusal> {
        let (locks, setup) = (Arc::clone(&self.locks), Arc::clone(&self.setup));
        let read = tokio::task::spawn_blocking(move || ensure_initializable(&locks.state, &locks.config, &setup.fs)).await;
        match read {
            Ok(Ok(state)) => Ok(state),
            Ok(Err(error)) => Err(directory_refusal(&error).unwrap_or_else(|| InitRefusal::Unreadable(error.to_string()))),
            Err(_) => Err(InitRefusal::Unreadable("the read did not finish".to_owned())),
        }
    }

    /// Writes the vault from `keys` and `passphrases` and approves the initial config as version 1, on the blocking
    /// pool, since scrypt runs three times. It takes the service-wide lock without waiting, so another holder ends it
    /// with [`InitRefusal::Busy`], and holds it and the context's mutex until the store returns.
    ///
    /// The approval's commit needs proof that admission is paused. In Locked the holder already refuses with `locked`,
    /// and the pause keeps that reason; its guard is dropped without ending the pause, so requests go on being refused
    /// with `locked`.
    ///
    /// The blocking task owns both guards and drops them only once the store has returned and the outcome is logged. If
    /// this future is dropped first, as `abort_all` does at shutdown, the task still runs to its end and logs how it
    /// ended, and no approval, vault write, unlock or second init can start while it writes.
    pub async fn initialize(&self, keys: SealingKeys, passphrases: InitPassphrases) -> Result<InitializedVault, InitRefusal> {
        let service_wide = Arc::clone(&self.service_wide).try_lock_owned().map_err(|_| InitRefusal::Busy)?;
        let inner = Arc::clone(&self.inner).lock_owned().await;
        if !inner.state.admin_allows(AdminOperation::Initialize) {
            return Err(InitRefusal::WrongState(inner.state));
        }
        let (locks, setup, holder) = (Arc::clone(&self.locks), Arc::clone(&self.setup), Arc::clone(&self.holder));
        let written = tokio::task::spawn_blocking(move || {
            let _held = (service_wide, inner);
            let paused = holder.pause();
            let written = initialize(&locks.state, &locks.config, &setup.fs, keys, passphrases, &paused);
            log_outcome(&written);
            written
        })
        .await;
        settled(written)
    }
}

/// A failed step's two names, from one place so they cannot drift apart: the log's (`3`, or `discard` for the discard of
/// an unfinished initialization) and the owner's (`step 3`, or `the discard`).
pub fn step_names(step: InitStep) -> (String, String) {
    step.number().map_or_else(
        || ("discard".to_owned(), "the discard".to_owned()),
        |number| (number.to_string(), format!("step {number}")),
    )
}

/// Logs how the writes ended: the files a discard removed, then the new vault or the failed step. A refusal of the
/// directories is not a failure, since nothing was written, and its caller is told why.
fn log_outcome(written: &Result<InitializedVault, InitError>) {
    let discarded = written
        .as_ref()
        .map_or_else(InitError::discarded, |vault| vault.discarded.as_slice());
    if !discarded.is_empty() {
        InitDiscarded { files: discarded }.emit();
    }
    match written {
        Ok(vault) => VaultInitialized { vault_id: vault.vault_id }.emit(),
        Err(error) if begin_refusal(error).is_none() => {
            InitFailed::Step {
                step: error.step(),
                cause: error.cause(),
            }
            .emit();
            if let InitFailure::Vault(vault_error) = error.cause() {
                emit_commit_uncertain(vault_error);
            }
        }
        Err(_) => {}
    }
}

/// Turns how the writing task ended into `init`'s answer. Only a task that ended without a result is logged here; the
/// task logs every other outcome itself.
fn settled(written: Result<Result<InitializedVault, InitError>, JoinError>) -> Result<InitializedVault, InitRefusal> {
    let Ok(written) = written else {
        InitFailed::TaskEnded.emit();
        return Err(InitRefusal::Interrupted);
    };
    written.map_err(|error| begin_refusal(&error).unwrap_or(InitRefusal::Failed(error)))
}

/// Step 1's refusal of the directories, which writes nothing; `None` for a failed step.
fn begin_refusal(error: &InitError) -> Option<InitRefusal> {
    match (error.step(), error.cause()) {
        (InitStep::Begin, InitFailure::State(refused)) => directory_refusal(refused),
        _ => None,
    }
}

/// The refusal for directories init must not write to; `None` for any other error.
fn directory_refusal(error: &InitStateError) -> Option<InitRefusal> {
    match error {
        InitStateError::AlreadyInitialized => Some(InitRefusal::Initialized),
        InitStateError::Unrecognized { files } => Some(InitRefusal::Unrecognized(files.clone())),
        _ => None,
    }
}
