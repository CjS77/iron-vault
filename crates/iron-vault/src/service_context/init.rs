//! `init`'s side of the service context (specification §16; design/vault-initialization.md, "The exchange"): the
//! initialization state read before any prompt, and the writes once the owner has confirmed the recovery key.
//!
//! The prompts hold no lock, so the writes take the service-wide lock without waiting, check the service state again
//! under the context's mutex, and leave the store to read the initialization state again before its first write. The
//! service stays Locked throughout: init keeps no key it generates and runs no config check, so it makes no transition.

use std::sync::Arc;

use iron_vault_store::{
    ConfigDigest, FirstApproval, INITIAL_CONFIG, InitError, InitFailure, InitPassphrases, InitStateError, InitStep, InitializationState,
    InitializedVault, RecipientIdentity, SOFTWARE_APPROVER_LABEL, SealingKeys, StoreFs, ensure_initializable, initialize,
};
use tokio::task::JoinError;

use super::ServiceContext;
use super::host_unlock::tries_host_unlock;
use crate::audit::config::{VersionReserved, record_commit_uncertain, record_failed_approval};
use crate::audit::vault::{InitDiscarded, InitFailed, VaultInitialized, emit_commit_uncertain};
use crate::audit::{ApprovalCompleted, AuditEvent, NamedApprover};
use crate::service_state::{AdminOperation, ServiceState};
use crate::unlock_handoff::{HandoffError, read_handoff};

/// Why `init` wrote no vault, or may not have finished one. Each variant is one admin error code.
#[derive(Debug)]
pub enum InitRefusal {
    /// Another init, an approval, a vault write, a reload or a config check holds the service-wide lock.
    Busy,
    /// The service is not Locked.
    WrongState(ServiceState),
    /// The directories hold an initialized vault.
    Initialized,
    /// A reset was interrupted; only the next reset finishes it.
    ResetUnfinished,
    /// The directories hold files init did not write; the first of them.
    Unrecognized(Vec<String>),
    /// The initialization state could not be read, so nothing was written.
    Unreadable(String),
    /// The service clock could not be read for the first approval's enrolment time, before any write.
    Clock(String),
    /// `init --host-unlock` found no identity to enrol, before any prompt.
    HostUnlock(HostUnlockUnavailable),
    /// A step of the write order, or the discard before it, failed.
    Failed(InitError),
    /// The task writing the vault ended without a result, so how far it got is unknown.
    Interrupted,
}

/// Why `init --host-unlock` has no host unlock identity to enrol. No variant carries the handoff's bytes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HostUnlockUnavailable {
    /// A Development service has no host unlock: it runs as the invoking user, with no root-owned handoff to trust.
    #[error("a development build has no host unlock")]
    Development,
    /// Nothing is at the handoff path.
    #[error("there is no unlock handoff")]
    Absent,
    /// The handoff was there and was refused.
    #[error(transparent)]
    Refused(#[from] HandoffError),
}

impl<F: StoreFs + Send + Sync + 'static> ServiceContext<F> {
    /// The host unlock identity in the unlock handoff, read on the blocking pool before `init` prompts for anything, so a
    /// missing or untrusted handoff ends the exchange with nothing written.
    pub async fn read_host_unlock(&self) -> Result<RecipientIdentity, InitRefusal> {
        let setup = Arc::clone(&self.setup);
        if !tries_host_unlock(setup.paths.profile) {
            return Err(InitRefusal::HostUnlock(HostUnlockUnavailable::Development));
        }
        let path = self.handoff.clone();
        let read = tokio::task::spawn_blocking(move || read_handoff(setup.paths.profile, setup.paths.owner, &path)).await;
        match read {
            Ok(Ok(Some(identity))) => Ok(identity),
            Ok(Ok(None)) => Err(InitRefusal::HostUnlock(HostUnlockUnavailable::Absent)),
            Ok(Err(refused)) => Err(InitRefusal::HostUnlock(refused.into())),
            Err(_) => Err(InitRefusal::Unreadable("the read did not finish".to_owned())),
        }
    }

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
        let enrolled_at = self.clock.now().map_err(|error| InitRefusal::Clock(error.to_string()))?;
        let approver = software_approver(&keys);
        let (locks, setup, holder) = (Arc::clone(&self.locks), Arc::clone(&self.setup), Arc::clone(&self.holder));
        let written = tokio::task::spawn_blocking(move || {
            let _held = (service_wide, inner);
            let paused = holder.pause();
            let written = initialize(&locks.state, &locks.config, &setup.fs, keys, passphrases, &paused, enrolled_at);
            log_outcome(&written, approver);
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

/// The software signer as `init` pins it, which signs version 1, named for the first approval's audit records.
fn software_approver(keys: &SealingKeys) -> NamedApprover<'static> {
    NamedApprover {
        id: keys.approver_id(),
        label: SOFTWARE_APPROVER_LABEL,
    }
}

/// Logs how the writes ended: the files a discard removed, then the new vault or the failed step. A refusal of the
/// directories is not a failure, since nothing was written, and its caller is told why.
fn log_outcome(written: &Result<InitializedVault, InitError>, approver: NamedApprover<'_>) {
    let discarded = written
        .as_ref()
        .map_or_else(InitError::discarded, |vault| vault.discarded.as_slice());
    if !discarded.is_empty() {
        InitDiscarded { files: discarded }.emit();
    }
    match written {
        Ok(vault) => {
            record_first_approval(&vault.approved(), approver);
            VaultInitialized {
                vault_id: vault.vault_id,
                recipients: &vault.recipients,
            }
            .emit();
        }
        Err(error) if begin_refusal(error).is_none() => {
            match error.approved() {
                Some(approved) => record_first_approval(approved, approver),
                None => record_uncertain_init_writes(error.cause(), approver),
            }
            InitFailed::Step {
                step: error.step(),
                cause: error.cause(),
            }
            .emit();
        }
        Err(_) => {}
    }
}

/// Records the uncertain writes behind a failed step before its `vault.init-failed`, the order a success records its
/// approval events in: the facts, then the outcome. Step 6's approval state creation fails as a vault error; step 8's
/// transaction as an approval error, whose reservation (if durable) is recorded too.
fn record_uncertain_init_writes(cause: &InitFailure, approver: NamedApprover<'_>) {
    match cause {
        InitFailure::Approval(approval) => record_failed_approval(approval, ConfigDigest::of(INITIAL_CONFIG), approver),
        InitFailure::Vault(vault_error) => emit_commit_uncertain(vault_error),
        _ => {}
    }
}

/// Init's version 1 is audited like any approval: reserved, uncertain if its commit was, then completed. The store ran
/// the transaction to its end before returning, so the events follow it in order. A later step's failure records them
/// too, before its own `vault.init-failed`.
fn record_first_approval(approved: &FirstApproval, approver: NamedApprover<'_>) {
    let FirstApproval {
        version,
        digest,
        commit_uncertain,
    } = approved;
    VersionReserved {
        version: *version,
        digest: *digest,
        approver,
    }
    .emit();
    commit_uncertain
        .iter()
        .for_each(|error_kind| record_commit_uncertain(*version, error_kind));
    ApprovalCompleted {
        version: *version,
        digest: *digest,
        summary: "initial config",
        approver,
    }
    .emit();
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
        InitStateError::ResetUnfinished => Some(InitRefusal::ResetUnfinished),
        InitStateError::Unrecognized { files } => Some(InitRefusal::Unrecognized(files.clone())),
        _ => None,
    }
}
