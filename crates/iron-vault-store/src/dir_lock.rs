// SPDX-License-Identifier: MPL-2.0
//! Directory locks: the exclusive file lock that proves one process is the only writer of a directory.
//!
//! The state directory (lock file `lock`) and the config directory (lock file `config.toml.lock`) each take one through
//! [`StateDirLock`](crate::StateDirLock) and [`ConfigDirLock`](crate::ConfigDirLock). The lock is an advisory
//! `flock`-style lock on an open file, so the kernel releases it when the process exits, even after a crash, and a
//! restart never has to clean up a stale lock.

use std::fs::{File, OpenOptions, TryLockError};
use std::io;
use std::path::{Path, PathBuf};

/// Why a directory lock could not be taken.
#[derive(Debug, thiserror::Error)]
pub enum LockError {
    /// Another process, or another open of the lock file in this one, already holds the lock.
    #[error("{} is locked: a second Iron Vault instance is already running against this directory", path.display())]
    Held {
        /// The lock file path.
        path: PathBuf,
    },
    /// The lock path is a symlink, FIFO or other non-regular entry. Following or locking it could touch a file elsewhere.
    #[error("cannot lock {}: not a regular file", path.display())]
    NotRegularFile {
        /// The lock file path.
        path: PathBuf,
    },
    /// Opening or locking the lock file failed for another reason.
    #[error("cannot lock {}: {kind}", path.display())]
    Io {
        /// The lock file path.
        path: PathBuf,
        /// The underlying error kind.
        kind: io::ErrorKind,
    },
}

/// Opens or creates `dir/file_name` (mode `0600`) and takes an exclusive, non-blocking lock on it.
///
/// The lock lasts as long as the returned handle stays open. Fails with [`LockError::Held`] at once, without waiting,
/// if another holder has it.
pub(crate) fn lock_file(dir: &Path, file_name: &str) -> Result<File, LockError> {
    let path = dir.join(file_name);
    let file = open_lock_file(&path).map_err(|e| lock_open_error(e, &path))?;
    ensure_regular(&file, &path)?;
    file.try_lock().map_err(|e| match e {
        TryLockError::WouldBlock => LockError::Held { path: path.clone() },
        TryLockError::Error(e) => LockError::Io {
            path: path.clone(),
            kind: e.kind(),
        },
    })?;
    Ok(file)
}

fn open_lock_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // NOFOLLOW keeps a planted symlink from redirecting the create; NONBLOCK keeps a planted FIFO from hanging startup.
        // CLOEXEC keeps an exec'd child from holding the lock past its parent; std sets it already, so this states the
        // requirement rather than relying on that. A child still shares the fd between fork and exec, so a process that
        // holds a lock must not fork while it may drop and retake one.
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    options.open(path)
}

/// Refuses an open handle that is not a regular file.
///
/// A FIFO opened non-blocking still yields a handle, so this check on the handle is what refuses it.
fn ensure_regular(file: &File, path: &Path) -> Result<(), LockError> {
    match file.metadata() {
        Ok(meta) if meta.is_file() => Ok(()),
        Ok(_) => Err(LockError::NotRegularFile { path: path.to_path_buf() }),
        Err(e) => Err(LockError::Io {
            path: path.to_path_buf(),
            kind: e.kind(),
        }),
    }
}

/// Maps an open failure to a [`LockError`]. `O_NOFOLLOW` reports a symlink as `ELOOP`, which becomes
/// [`LockError::NotRegularFile`].
fn lock_open_error(e: io::Error, path: &Path) -> LockError {
    let path = path.to_path_buf();
    match is_eloop(&e) {
        true => LockError::NotRegularFile { path },
        false => LockError::Io { path, kind: e.kind() },
    }
}

#[cfg(unix)]
fn is_eloop(e: &io::Error) -> bool {
    e.raw_os_error() == Some(libc::ELOOP)
}

#[cfg(not(unix))]
fn is_eloop(_e: &io::Error) -> bool {
    false
}

#[cfg(all(test, unix))]
mod tests {
    use rustix::io::{FdFlags, fcntl_getfd};

    use super::*;
    use crate::test_dir::TestDir;

    #[test]
    fn the_lock_fd_is_closed_on_exec() {
        let dir = TestDir::new("lock-cloexec");
        let file = lock_file(dir.path(), "lock").unwrap();
        assert!(fcntl_getfd(&file).unwrap().contains(FdFlags::CLOEXEC));
    }
}
