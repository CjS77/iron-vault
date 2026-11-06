//! `recovery check`'s side of the service context (design/recovery.md, "States and the service-wide lock").
//!
//! The checks before the prompt read the service state, the initialization state and the memory protection. After the
//! key has parsed, the check takes the service-wide lock without waiting (an approval holds it across its prompts for
//! minutes, longer than the CLI waits), reads the state again, and runs the store's check and the record write on the
//! blocking pool. It changes no service state, holds no vault identity beyond the store call, and never takes the
//! context's mutex for longer than a state read, so requests and `status` go on throughout.

use std::sync::Arc;
use std::time::SystemTime;

use iron_vault_store::{
    ErrorKindLabel, RecipientIdentity, RecoveryCheckError, RecoveryCheckRecord, StateDirLock, StoreFs, UtcSecond, VaultId, WriteError,
    WriteStep, check_recovery_key, read_recovery_check, require_initialized, write_recovery_check,
};

use super::unlock::memory_guard;
use super::{ServiceContext, ServiceLocks};
use crate::audit::AuditEvent;
use crate::audit::recovery::RecoveryChecked;
use crate::service_state::{AdminOperation, ServiceState};

/// Why a recovery check ended without proving the key. Each variant is one admin error code.
#[derive(Debug)]
pub enum RecoveryRefusal {
    /// Another operation holds the service-wide lock.
    Busy,
    /// The service is neither Locked nor Ready.
    WrongState(ServiceState),
    /// The vault is not Initialized; the text says which state it is in and what to do.
    NotInitialized(String),
    /// A protected install's memory is not locked, so the vault identity must not be unwrapped; the owner's message.
    MemoryUnprotected(String),
    /// The system clock is outside the range the check record can hold.
    ClockUnusable,
    /// The store check ended without opening the vault: the key was rejected, or a file could not be used.
    Check(RecoveryCheckError),
    /// The task running the check ended without a result.
    Interrupted,
}

/// A recovery key that opened the vault.
#[derive(Debug, Clone)]
pub struct RecoveryProof {
    /// The ID in the manifest the key opened.
    pub vault_id: VaultId,
    /// The time of the check, as written to the record.
    pub checked_at: UtcSecond,
    /// Why the check record was not written; `None` when it was.
    pub record_error: Option<ErrorKindLabel>,
}

impl<F: StoreFs + Send + Sync + 'static> ServiceContext<F> {
    /// The checks that come before the key prompt, in order: the service state, the initialization state, then memory.
    pub async fn recovery_check_allowed(&self) -> Result<(), RecoveryRefusal> {
        self.require_checkable().await?;
        self.require_locked_memory_for_check()
    }

    /// The memory rule `unlock` is held to (§3.11): the check unwraps the vault identity into memory. Every refusal
    /// `memory_guard` gives counts, so a refusal added to it later fails closed here.
    fn require_locked_memory_for_check(&self) -> Result<(), RecoveryRefusal> {
        memory_guard(self.setup.paths.profile, &self.setup.hardening.memory)
            .map_err(|refusal| RecoveryRefusal::MemoryUnprotected(refusal.to_string()))
    }

    /// Proves that `recipient`, parsed from the key the owner typed, opens the vault, and records the check.
    ///
    /// Fails with [`RecoveryRefusal::Busy`] at once if the service-wide lock is taken. Under it, the state and the
    /// initialization state are read again, since an `init`, `unlock` or `lock` may have run during the prompt. The
    /// blocking task owns the lock guard, so the record write cannot race a reminder evaluation even if this future is
    /// dropped. The memory rule is applied here too, before any file is read, so no caller can unwrap the identity in
    /// unprotected memory. It logs `recovery.checked` for every end of the store check; a task that ended without a
    /// result has no outcome to log.
    pub async fn check_recovery(&self, recipient: RecipientIdentity) -> Result<RecoveryProof, RecoveryRefusal> {
        let now = UtcSecond::from_system_time(SystemTime::now()).map_err(|_| RecoveryRefusal::ClockUnusable)?;
        let service_wide = Arc::clone(&self.service_wide).try_lock_owned().map_err(|_| RecoveryRefusal::Busy)?;
        self.require_checkable().await?;
        self.require_locked_memory_for_check()?;
        let (locks, setup) = (Arc::clone(&self.locks), Arc::clone(&self.setup));
        let ran = tokio::task::spawn_blocking(move || {
            let _held = service_wide;
            check_and_record(&locks, &setup.fs, &recipient, now)
        })
        .await
        .map_err(|_| RecoveryRefusal::Interrupted)?;
        log_end(&ran);
        ran.map_err(RecoveryRefusal::Check)
    }

    /// The service state is Locked or Ready and the vault is Initialized.
    async fn require_checkable(&self) -> Result<(), RecoveryRefusal> {
        let state = self.state().await;
        if !state.admin_allows(AdminOperation::RecoveryCheck) {
            return Err(RecoveryRefusal::WrongState(state));
        }
        let (locks, setup) = (Arc::clone(&self.locks), Arc::clone(&self.setup));
        tokio::task::spawn_blocking(move || require_initialized(&locks.state, &locks.config, &setup.fs))
            .await
            .map_err(|_| RecoveryRefusal::Interrupted)?
            .map(|_| ())
            .map_err(|error| RecoveryRefusal::NotInitialized(error.to_string()))
    }
}

/// Logs how a check that ran ended.
fn log_end(ran: &Result<RecoveryProof, RecoveryCheckError>) {
    match ran {
        Ok(proof) => RecoveryChecked::Opened {
            vault_id: proof.vault_id,
            record_error: proof.record_error.clone(),
        }
        .emit(),
        Err(error) if error.is_key_rejected() => RecoveryChecked::Failed(error).emit(),
        Err(error) => RecoveryChecked::Unavailable(error).emit(),
    }
}

/// Runs the store check, then records it. A failed record write does not fail a check that proved the key.
fn check_and_record(
    locks: &ServiceLocks,
    fs: &impl StoreFs,
    recipient: &RecipientIdentity,
    now: UtcSecond,
) -> Result<RecoveryProof, RecoveryCheckError> {
    let opened = check_recovery_key(&locks.state, fs, recipient)?;
    Ok(RecoveryProof {
        vault_id: opened.vault_id(),
        checked_at: now,
        record_error: record_check(&locks.state, fs, now).err(),
    })
}

/// Writes `last_checked = now`, keeping `since` from a readable record and starting it at `now` when the record is
/// missing or unusable. A clock that went backwards moves `since` back to `now` rather than refusing the record.
fn record_check(lock: &StateDirLock, fs: &impl StoreFs, now: UtcSecond) -> Result<(), ErrorKindLabel> {
    let since = read_recovery_check(lock, fs)
        .ok()
        .flatten()
        .map_or(now, |record| record.since().min(now));
    let record = RecoveryCheckRecord::new(since, Some(now)).map_err(|_| ErrorKindLabel::fixed("invalid_record"))?;
    write_recovery_check(lock, fs, &record)
        .or_else(synced_late)
        .map_err(|e| e.error_kind_label())
}

/// A failed directory fsync comes after the rename, so the record holds the new bytes: it counts as recorded.
fn synced_late(error: WriteError) -> Result<(), WriteError> {
    match error {
        WriteError::Io {
            step: WriteStep::SyncDir, ..
        } => Ok(()),
        other => Err(other),
    }
}
