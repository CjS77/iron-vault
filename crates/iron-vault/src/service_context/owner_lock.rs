//! The owner-lock file at the service's edge (design/tpm-unlock.md, "`lock` across restarts"): `lock` and `reset` write it,
//! a passphrase `unlock` removes it, and startup reads it before host unlock.
//!
//! Each caller already holds the service-wide lock, so the store's single-writer rule holds. A failed write or removal
//! never stops the command that asked for it: the owner's lock or unlock matters more than the file, so the failure is
//! logged at WARN with the error kind only and reported to the caller as `false`.

use std::sync::Arc;

use iron_vault_store::{ErrorKindLabel, StoreFs, WriteError, owner_lock_present, remove_owner_lock, write_owner_lock};

use super::ServiceContext;

impl<F: StoreFs + Send + Sync + 'static> ServiceContext<F> {
    /// Writes the owner-lock file on the blocking pool. Returns whether it is now durably there; a failure is logged.
    ///
    /// Not cancel-safe in one benign way: a future dropped while the write runs can leave the file beside a service
    /// that was not locked, which only makes the next start stay Locked until a passphrase `unlock`.
    pub(super) async fn write_owner_lock(&self) -> bool {
        let (locks, setup) = (Arc::clone(&self.locks), Arc::clone(&self.setup));
        let written = tokio::task::spawn_blocking(move || write_owner_lock(&locks.state, &setup.fs)).await;
        log_failure("write", written.unwrap_or_else(|_| Err(interrupted())))
    }

    /// Removes the owner-lock file on the blocking pool. Returns whether it is now gone, absent or removed; a failure is
    /// logged.
    pub(super) async fn remove_owner_lock(&self) -> bool {
        let (locks, setup) = (Arc::clone(&self.locks), Arc::clone(&self.setup));
        let removed = tokio::task::spawn_blocking(move || remove_owner_lock(&locks.state, &setup.fs).map(drop)).await;
        log_failure("removal", removed.unwrap_or_else(|_| Err(interrupted())))
    }

    /// Whether anything is at the owner-lock file's name. Read on the blocking pool; a task that does not finish counts
    /// as present, so the check fails closed like the store's.
    pub(super) async fn owner_lock_present(&self) -> bool {
        let (locks, setup) = (Arc::clone(&self.locks), Arc::clone(&self.setup));
        tokio::task::spawn_blocking(move || owner_lock_present(&locks.state, &setup.fs))
            .await
            .unwrap_or(true)
    }
}

/// Logs a failed owner-lock write or removal at WARN, by error kind only, and says whether `result` succeeded.
fn log_failure(what: &str, result: Result<(), WriteError>) -> bool {
    result
        .inspect_err(|error| {
            let error_kind: ErrorKindLabel = error.error_kind_label();
            tracing::warn!(%error_kind, "owner-lock file {what} failed");
        })
        .is_ok()
}

/// The error for a blocking task that did not finish, which the caller reports like any other failed file operation.
fn interrupted() -> WriteError {
    WriteError::ListStateDir {
        kind: std::io::ErrorKind::Interrupted,
    }
}
