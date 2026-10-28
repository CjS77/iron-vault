//! The state-directory lock: proof that this process is the only writer of vault and control files.

use std::fs::{File, OpenOptions, TryLockError};
use std::io;
use std::path::{Path, PathBuf};

/// Name of the lock file inside the state directory.
const LOCK_FILE: &str = "lock";

/// An exclusive lock on a state directory, held until this guard drops.
///
/// Store writes take a reference to this guard so a write cannot happen without the lock.
#[derive(Debug)]
pub struct StateDirLock {
    dir: PathBuf,
    // Keeping the file open keeps the lock; dropping it releases the lock.
    _file: File,
}

/// Why the state-directory lock could not be taken.
#[derive(Debug, thiserror::Error)]
pub enum LockError {
    /// Another process (or another open in this one) already holds the lock.
    #[error("{} is locked: a second Iron Vault instance is already running against this state directory", path.display())]
    Held {
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

impl StateDirLock {
    /// Takes the exclusive lock on `dir`, failing at once if another instance holds it.
    pub fn acquire(dir: &Path) -> Result<Self, LockError> {
        let path = dir.join(LOCK_FILE);
        let io_err = |e: io::Error| LockError::Io {
            path: path.clone(),
            kind: e.kind(),
        };
        let file = open_lock_file(&path).map_err(io_err)?;
        file.try_lock().map_err(|e| match e {
            TryLockError::WouldBlock => LockError::Held { path: path.clone() },
            TryLockError::Error(e) => io_err(e),
        })?;
        Ok(Self {
            dir: dir.to_path_buf(),
            _file: file,
        })
    }

    /// The locked state directory; later writes resolve their paths through it.
    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

fn open_lock_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}

#[cfg(test)]
mod tests {
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
}
