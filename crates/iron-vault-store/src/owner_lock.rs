//! The owner-lock file: the empty state file `locked-by-owner` that makes an explicit `lock` outlast a crash, a restart
//! and a reboot ([`lock` across restarts](../../../design/tpm-unlock.md#lock-across-restarts)).
//!
//! The store only writes, removes and tests for the file. The service decides when: `lock` and `reset` write it, a
//! passphrase `unlock` removes it, and startup skips host unlock while it is there.

use std::ffi::OsStr;
use std::io;

use crate::{StateDirLock, StateFileName, StoreFs, WriteError, durable_remove, durable_replace};

/// Writes the empty owner-lock file, durably.
pub fn write_owner_lock(lock: &StateDirLock, fs: &impl StoreFs) -> Result<(), WriteError> {
    durable_replace(lock, fs, &StateFileName::owner_lock(), b"")
}

/// Removes the owner-lock file durably and says whether it was there. `unlock` and `init` call it.
pub fn remove_owner_lock(lock: &StateDirLock, fs: &impl StoreFs) -> Result<bool, WriteError> {
    match durable_remove(lock, fs, &StateFileName::owner_lock()) {
        Ok(()) => Ok(true),
        Err(WriteError::NotFound { .. }) => Ok(false),
        Err(error) => Err(error),
    }
}

/// Returns `true` if and only if anything is at the owner-lock file's name, whatever its type, so a directory or a
/// dangling symlink counts.
///
/// It fails closed: a state directory that cannot be listed counts as holding the file, since a service that cannot tell
/// must not host-unlock a vault the owner may have locked. Only a missing state directory holds nothing.
pub fn owner_lock_present(lock: &StateDirLock, fs: &impl StoreFs) -> bool {
    match fs.list_dir(lock.dir()) {
        Ok(names) => {
            let owner_lock = StateFileName::owner_lock();
            names.iter().any(|name| name.as_os_str() == OsStr::new(owner_lock.as_str()))
        }
        Err(error) => error.kind() != io::ErrorKind::NotFound,
    }
}

#[cfg(test)]
mod tests;
