//! The state-directory lock: proof that this process is the only writer of vault and control files
//! ([spec §13](../../../design/iron-vault-specification.md#13-vault-structure-and-durable-writes)).
//!
//! The service takes it at startup and holds it for its lifetime. Every function in this crate that reads or writes a
//! state file takes a `&StateDirLock`, so the type system rules out a write made without it. A second service started
//! against the same directory fails at once with [`LockError::Held`].

use std::fs::File;
use std::path::{Path, PathBuf};

use crate::LockError;
use crate::dir_lock::lock_file;

/// The name of the lock file inside the state directory.
pub(crate) const LOCK_FILE: &str = "lock";

/// An exclusive lock on a state directory, held until this guard drops.
///
/// Store reads and writes take a reference to this guard, so none can happen without the lock.
#[derive(Debug)]
pub struct StateDirLock {
    dir: PathBuf,
    // Keeping the file open keeps the lock; dropping it releases the lock.
    _file: File,
}

impl StateDirLock {
    /// Takes the exclusive lock on `dir`, or fails at once with [`LockError::Held`] if another instance holds it.
    pub fn acquire(dir: &Path) -> Result<Self, LockError> {
        Ok(Self {
            dir: dir.to_path_buf(),
            _file: lock_file(dir, LOCK_FILE)?,
        })
    }

    /// Returns the locked state directory. Every state-file path is resolved through it.
    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;
    use crate::test_dir::TestDir;

    #[test]
    fn second_acquire_is_held_and_names_path() {
        let dir = TestDir::new("lock-held");
        let _first = StateDirLock::acquire(dir.path()).unwrap();
        let err = StateDirLock::acquire(dir.path()).unwrap_err();
        assert!(matches!(err, LockError::Held { .. }));
        assert!(err.to_string().contains(&dir.path().join("lock").display().to_string()));
    }

    #[test]
    fn drop_releases_lock() {
        let dir = TestDir::new("lock-drop");
        drop(StateDirLock::acquire(dir.path()).unwrap());
        let lock = StateDirLock::acquire(dir.path()).unwrap();
        assert_eq!(lock.dir(), dir.path());
    }

    #[test]
    fn different_directories_do_not_conflict() {
        let (a, b) = (TestDir::new("lock-a"), TestDir::new("lock-b"));
        let _la = StateDirLock::acquire(a.path()).unwrap();
        assert!(StateDirLock::acquire(b.path()).is_ok());
    }

    #[test]
    fn missing_directory_is_io_error() {
        let dir = TestDir::new("lock-missing");
        let err = StateDirLock::acquire(&dir.path().join("absent")).unwrap_err();
        assert!(matches!(
            err,
            LockError::Io {
                kind: io::ErrorKind::NotFound,
                ..
            }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn lock_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TestDir::new("lock-mode");
        let _lock = StateDirLock::acquire(dir.path()).unwrap();
        let mode = std::fs::metadata(dir.path().join("lock")).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_lock_is_refused_and_not_followed() {
        let dir = TestDir::new("lock-symlink");
        let target = dir.path().join("elsewhere");
        std::os::unix::fs::symlink(&target, dir.path().join("lock")).unwrap();
        // The link dangles: following it would create the target, so its absence proves it was not followed.
        let err = StateDirLock::acquire(dir.path()).unwrap_err();
        assert!(matches!(err, LockError::NotRegularFile { .. }), "{err:?}");
        assert!(err.to_string().contains("lock"));
        assert!(!target.exists());
    }

    #[cfg(unix)]
    #[test]
    fn fifo_lock_is_refused_without_blocking() {
        let dir = TestDir::new("lock-fifo");
        let fifo = dir.path().join("lock");
        crate::test_dir::make_fifo(&fifo);
        let (sender, receiver) = std::sync::mpsc::channel();
        let state = dir.path().to_path_buf();
        std::thread::spawn(move || sender.send(StateDirLock::acquire(&state).map(|_| ())));
        let result = receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("acquiring a FIFO lock blocked");
        assert!(matches!(result, Err(LockError::NotRegularFile { .. })), "{result:?}");
    }
}
