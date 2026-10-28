//! Durable replace, durable remove and bounded reads of state files.
//!
//! An atomic rename alone is not durable: after a power cut the rename can be lost, or the new name can point at an
//! empty file. Every store write goes through these functions so the file and directory fsyncs are right in one place.

use std::fmt;
use std::io;
use std::path::Path;

use crate::{StateDirLock, StateFileName, StoreFs};

/// The step of a durable write that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteStep {
    /// Creating the private temporary file.
    CreateTemp,
    /// Writing the new bytes to the temporary file.
    Write,
    /// Fsyncing the temporary file.
    SyncFile,
    /// Renaming the temporary file over the destination.
    Rename,
    /// Fsyncing the state directory after a rename or unlink.
    ///
    /// This failure comes after the change: the destination already holds the new bytes, or the file is already
    /// unlinked, but the change may not survive power loss. It is never "unchanged". On a platform without directory
    /// fsync, the durable functions report this step before changing anything.
    SyncDir,
    /// Unlinking the file.
    Remove,
}

impl fmt::Display for WriteStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CreateTemp => "create temporary file",
            Self::Write => "write",
            Self::SyncFile => "fsync file",
            Self::Rename => "rename",
            Self::SyncDir => "fsync directory",
            Self::Remove => "remove",
        })
    }
}

/// Why a durable replace or remove failed. It names the file but never carries its contents.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WriteError {
    /// A durable remove found no file; callers that only need the file gone may treat this as success.
    #[error("cannot remove state file {file}: it does not exist")]
    NotFound {
        /// The file that was to be removed.
        file: StateFileName,
    },
    /// Listing the state directory failed, so no file in it was examined.
    #[error("cannot list the state directory: {kind}")]
    ListStateDir {
        /// The underlying error kind.
        kind: io::ErrorKind,
    },
    /// A filesystem step failed.
    #[error("store file operation on state file {file} failed at {step}: {kind}")]
    Io {
        /// The step that failed.
        step: WriteStep,
        /// The state file being replaced or removed.
        file: StateFileName,
        /// The underlying error kind.
        kind: io::ErrorKind,
    },
}

/// Why a state file could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReadError {
    /// The file is longer than the caller's limit; it was not read in full.
    #[error("state file {file} is longer than {max_len} bytes")]
    TooLarge {
        /// The file that was read.
        file: StateFileName,
        /// The caller's limit.
        max_len: u64,
    },
    /// Opening or reading the file failed.
    #[error("cannot read state file {file}: {kind}")]
    Io {
        /// The file that was read.
        file: StateFileName,
        /// The underlying error kind.
        kind: io::ErrorKind,
    },
}

/// Replaces the state file `name` with exactly `bytes`, durably.
///
/// Writes a private `.<name>.tmp`, fsyncs it, renames it over `name` and fsyncs the state directory. A failure before
/// the rename removes the temporary file and leaves `name` untouched; the destination is never half-written. A stale
/// temporary file blocks the write with a [`WriteStep::CreateTemp`] error rather than being reused or followed.
///
/// A [`WriteStep::SyncDir`] failure comes after the rename: `name` already holds the new bytes and no temporary file is
/// left, but the replacement may not survive power loss. Callers must not treat that error as "unchanged". Where
/// directory fsync does not exist, this returns that error before touching the filesystem.
pub fn durable_replace(lock: &StateDirLock, fs: &impl StoreFs, name: &StateFileName, bytes: &[u8]) -> Result<(), WriteError> {
    ensure_dir_sync_supported(name)?;
    let dir = lock.dir();
    let temp = dir.join(name.temp_name());
    let file = fs.create_private(&temp).map_err(io_error(WriteStep::CreateTemp, name))?;
    fill_and_rename(fs, file, bytes, &temp, &dir.join(name.as_str()), name).inspect_err(|_| {
        // Best effort: the original error is the one worth reporting, and a leftover temp file blocks only this name.
        // No directory fsync follows: a lost unlink only leaves a stale temp file for the startup sweep.
        let _ = fs.remove_file(&temp);
    })?;
    fs.sync_dir(dir).map_err(io_error(WriteStep::SyncDir, name))
}

/// Removes the state file `name`, durably: unlinks it, then fsyncs the state directory.
///
/// A [`WriteStep::SyncDir`] failure comes after the unlink: the file is already gone, but the deletion may not
/// survive power loss. Where directory fsync does not exist, this returns that error before touching the filesystem.
pub fn durable_remove(lock: &StateDirLock, fs: &impl StoreFs, name: &StateFileName) -> Result<(), WriteError> {
    ensure_dir_sync_supported(name)?;
    fs.remove_file(&lock.dir().join(name.as_str())).map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => WriteError::NotFound { file: name.clone() },
        kind => WriteError::Io { step: WriteStep::Remove, file: name.clone(), kind },
    })?;
    fs.sync_dir(lock.dir()).map_err(io_error(WriteStep::SyncDir, name))
}

/// Reads the state file `name`, refusing one longer than `max_len` bytes without reading it whole.
pub fn read_state_file(lock: &StateDirLock, fs: &impl StoreFs, name: &StateFileName, max_len: u64) -> Result<Vec<u8>, ReadError> {
    fs.read_bounded(&lock.dir().join(name.as_str()), max_len).map_err(|e| match e.kind() {
        io::ErrorKind::FileTooLarge => ReadError::TooLarge { file: name.clone(), max_len },
        kind => ReadError::Io { file: name.clone(), kind },
    })
}

/// Writes and fsyncs the temporary file, closes it, then renames it over the destination.
fn fill_and_rename<F: StoreFs>(
    fs: &F,
    mut file: F::File,
    bytes: &[u8],
    temp: &Path,
    dest: &Path,
    name: &StateFileName,
) -> Result<(), WriteError> {
    fs.write_all(&mut file, bytes).map_err(io_error(WriteStep::Write, name))?;
    fs.sync_file(&file).map_err(io_error(WriteStep::SyncFile, name))?;
    // Close before renaming: some platforms refuse to rename an open file.
    drop(file);
    fs.rename(temp, dest).map_err(io_error(WriteStep::Rename, name))
}

/// Fails closed before any change on a platform with no directory fsync, so a write never claims durability it lacks.
pub(crate) fn ensure_dir_sync_supported(name: &StateFileName) -> Result<(), WriteError> {
    if cfg!(unix) {
        Ok(())
    } else {
        Err(WriteError::Io { step: WriteStep::SyncDir, file: name.clone(), kind: io::ErrorKind::Unsupported })
    }
}

pub(crate) fn io_error(step: WriteStep, file: &StateFileName) -> impl Fn(io::Error) -> WriteError + '_ {
    move |e| WriteError::Io { step, file: file.clone(), kind: e.kind() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OsFs;
    use crate::test_dir::TestDir;

    fn name(s: &str) -> StateFileName {
        StateFileName::new(s).unwrap()
    }

    fn temp_files(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with('.') && n.ends_with(".tmp"))
            .collect()
    }

    #[test]
    fn replace_creates_a_missing_file() {
        let dir = TestDir::new("dur-create");
        let lock = StateDirLock::acquire(dir.path()).unwrap();
        durable_replace(&lock, &OsFs, &name("rec"), b"new").unwrap();
        assert_eq!(std::fs::read(dir.path().join("rec")).unwrap(), b"new");
        assert!(temp_files(dir.path()).is_empty());
    }

    #[test]
    fn replace_overwrites_an_existing_file() {
        let dir = TestDir::new("dur-overwrite");
        let lock = StateDirLock::acquire(dir.path()).unwrap();
        std::fs::write(dir.path().join("rec"), b"a much longer old value").unwrap();
        durable_replace(&lock, &OsFs, &name("rec"), b"new").unwrap();
        assert_eq!(std::fs::read(dir.path().join("rec")).unwrap(), b"new");
        assert!(temp_files(dir.path()).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn replaced_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TestDir::new("dur-mode");
        let lock = StateDirLock::acquire(dir.path()).unwrap();
        durable_replace(&lock, &OsFs, &name("rec"), b"x").unwrap();
        let mode = std::fs::metadata(dir.path().join("rec")).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn stale_temp_file_blocks_replace_and_is_kept() {
        let dir = TestDir::new("dur-stale");
        let lock = StateDirLock::acquire(dir.path()).unwrap();
        std::fs::write(dir.path().join("rec"), b"old").unwrap();
        std::fs::write(dir.path().join(".rec.tmp"), b"stale").unwrap();
        let err = durable_replace(&lock, &OsFs, &name("rec"), b"new").unwrap_err();
        assert_eq!(err, WriteError::Io { step: WriteStep::CreateTemp, file: name("rec"), kind: io::ErrorKind::AlreadyExists });
        assert_eq!(std::fs::read(dir.path().join("rec")).unwrap(), b"old");
        assert_eq!(std::fs::read(dir.path().join(".rec.tmp")).unwrap(), b"stale");
    }

    #[test]
    fn failed_rename_removes_temp_and_keeps_destination() {
        let dir = TestDir::new("dur-rename");
        let lock = StateDirLock::acquire(dir.path()).unwrap();
        // A non-empty directory at the destination makes the rename fail after the temp file is written.
        std::fs::create_dir(dir.path().join("rec")).unwrap();
        std::fs::write(dir.path().join("rec").join("inner"), b"keep").unwrap();
        let err = durable_replace(&lock, &OsFs, &name("rec"), b"new").unwrap_err();
        assert!(matches!(err, WriteError::Io { step: WriteStep::Rename, .. }));
        assert!(temp_files(dir.path()).is_empty());
        assert_eq!(std::fs::read(dir.path().join("rec").join("inner")).unwrap(), b"keep");
    }

    #[test]
    fn error_names_step_and_file_but_not_contents() {
        let err = WriteError::Io { step: WriteStep::SyncDir, file: name("rec"), kind: io::ErrorKind::Unsupported };
        let text = err.to_string();
        assert!(text.contains("rec") && text.contains("fsync directory"), "{text}");
    }

    #[test]
    fn remove_deletes_the_file() {
        let dir = TestDir::new("dur-remove");
        let lock = StateDirLock::acquire(dir.path()).unwrap();
        std::fs::write(dir.path().join("rec"), b"x").unwrap();
        durable_remove(&lock, &OsFs, &name("rec")).unwrap();
        assert!(!dir.path().join("rec").exists());
    }

    #[test]
    fn removing_a_missing_file_is_not_found() {
        let dir = TestDir::new("dur-remove-missing");
        let lock = StateDirLock::acquire(dir.path()).unwrap();
        assert_eq!(durable_remove(&lock, &OsFs, &name("rec")), Err(WriteError::NotFound { file: name("rec") }));
    }

    #[test]
    fn read_returns_file_within_limit() {
        let dir = TestDir::new("dur-read");
        let lock = StateDirLock::acquire(dir.path()).unwrap();
        durable_replace(&lock, &OsFs, &name("rec"), b"1234").unwrap();
        assert_eq!(read_state_file(&lock, &OsFs, &name("rec"), 4).unwrap(), b"1234");
    }

    #[test]
    fn read_over_limit_is_refused() {
        let dir = TestDir::new("dur-read-big");
        let lock = StateDirLock::acquire(dir.path()).unwrap();
        durable_replace(&lock, &OsFs, &name("rec"), b"12345").unwrap();
        assert_eq!(read_state_file(&lock, &OsFs, &name("rec"), 4), Err(ReadError::TooLarge { file: name("rec"), max_len: 4 }));
    }

    #[test]
    fn reading_a_missing_file_is_io_not_found() {
        let dir = TestDir::new("dur-read-missing");
        let lock = StateDirLock::acquire(dir.path()).unwrap();
        let err = read_state_file(&lock, &OsFs, &name("rec"), 4).unwrap_err();
        assert_eq!(err, ReadError::Io { file: name("rec"), kind: io::ErrorKind::NotFound });
    }
}
