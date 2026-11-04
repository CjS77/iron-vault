//! Durable file operations on the config directory: the pending config, the staged approval, and publish.
//!
//! The approval transaction (design/config-approval.md) is built from these. They hold the same discipline as the
//! state directory's: a private temporary file, fsync, rename, directory fsync, and a single writer. None of them
//! decides anything; the transaction and recovery do.

use std::io;
use std::path::Path;

use crate::durable::{ReadFailure, StepFailure, dir_sync_supported, read_in, replace_in, unlink_in};
use crate::state_dir::lock_file;
use crate::{ConfigFileName, LockError, StoreFs, WriteStep};

/// Name of the lock file inside the config directory. It is not a [`ConfigFileName`]: no store call may write it.
const CONFIG_LOCK_FILE: &str = "config.toml.lock";

/// An exclusive lock on a config directory, held until this guard drops.
///
/// The state-directory lock alone does not give one writer per config directory, because the two directories come
/// from independent settings in development. Every config-directory write takes a reference to this guard.
#[derive(Debug)]
pub struct ConfigDirLock {
    dir: std::path::PathBuf,
    // Keeping the file open keeps the lock; dropping it releases the lock.
    _file: std::fs::File,
}

impl ConfigDirLock {
    /// Takes the exclusive lock on `dir`, failing at once if another instance holds it.
    pub fn acquire(dir: &Path) -> Result<Self, LockError> {
        Ok(Self {
            dir: dir.to_path_buf(),
            _file: lock_file(dir, CONFIG_LOCK_FILE)?,
        })
    }

    /// The locked config directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

/// Why a write to the config directory failed. It names the file but never carries its contents.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigWriteError {
    /// The bytes are longer than the file's limit; nothing was touched.
    #[error("config file {file} may hold at most {max_len} bytes")]
    TooLarge {
        /// The file that was to be written.
        file: ConfigFileName,
        /// The file's limit.
        max_len: usize,
    },
    /// Listing the config directory failed, so no file in it was examined.
    #[error("cannot list the config directory: {kind}")]
    ListConfigDir {
        /// The underlying error kind.
        kind: io::ErrorKind,
    },
    /// A filesystem step failed. For a rename, `file` is the file that was to be renamed. A
    /// [`WriteStep::SyncDir`] failure comes after the change: the change is visible, but may not survive power loss.
    #[error("config directory operation on {file} failed at {step}: {kind}")]
    Io {
        /// The step that failed.
        step: WriteStep,
        /// The file the step acted on.
        file: ConfigFileName,
        /// The underlying error kind.
        kind: io::ErrorKind,
    },
}

impl ConfigWriteError {
    fn io(file: ConfigFileName) -> impl Fn(StepFailure) -> Self {
        move |f| Self::Io {
            step: f.step,
            file,
            kind: f.kind,
        }
    }
}

/// Why a config file could not be read. Recovery treats every one of them as the file being absent.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigReadError {
    /// The file is longer than its limit; it was not read in full.
    #[error("config file {file} is longer than {max_len} bytes")]
    TooLarge {
        /// The file that was read.
        file: ConfigFileName,
        /// The file's limit.
        max_len: usize,
    },
    /// The entry is a symlink, directory, FIFO, socket or device, so it was not read.
    #[error("config file {file} is not a regular file")]
    NotARegularFile {
        /// The file that was to be read.
        file: ConfigFileName,
    },
    /// Opening or reading the file failed; a missing file is [`io::ErrorKind::NotFound`].
    #[error("cannot read config file {file}: {kind}")]
    Io {
        /// The file that was read.
        file: ConfigFileName,
        /// The underlying error kind.
        kind: io::ErrorKind,
    },
}

/// Which renames [`publish`] performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Published {
    /// The pending config was renamed to `config.toml`.
    pub config: bool,
    /// The staged approval was renamed to `config.toml.sig`.
    pub signature: bool,
}

/// Durably writes `bytes` as `config.toml.pending`. Step 1 of the approval transaction.
///
/// Bytes over [`ConfigFileName::max_len`] are refused before the filesystem is touched, so the file can always be read
/// back. See [`crate::durable_replace`] for what each failed step leaves behind.
pub fn write_pending(lock: &ConfigDirLock, fs: &impl StoreFs, bytes: &[u8]) -> Result<(), ConfigWriteError> {
    write_config_file(lock, fs, ConfigFileName::Pending, bytes)
}

/// Durably writes `bytes` as `config.toml.sig.staged`. Step 4 of the approval transaction.
pub fn write_staged(lock: &ConfigDirLock, fs: &impl StoreFs, bytes: &[u8]) -> Result<(), ConfigWriteError> {
    write_config_file(lock, fs, ConfigFileName::StagedSignature, bytes)
}

fn write_config_file(lock: &ConfigDirLock, fs: &impl StoreFs, name: ConfigFileName, bytes: &[u8]) -> Result<(), ConfigWriteError> {
    let max_len = name.max_len();
    if bytes.len() > max_len {
        return Err(ConfigWriteError::TooLarge { file: name, max_len });
    }
    replace_in(fs, lock.dir(), name.as_str(), bytes).map_err(ConfigWriteError::io(name))
}

/// Reads the config file `name`, refusing one longer than [`ConfigFileName::max_len`] without reading it whole.
///
/// A symlink, FIFO, device or other non-regular entry is refused before it is opened.
pub fn read_config_file(lock: &ConfigDirLock, fs: &impl StoreFs, name: ConfigFileName) -> Result<Vec<u8>, ConfigReadError> {
    let max_len = name.max_len();
    read_in(fs, lock.dir(), name.as_str(), u64::try_from(max_len).unwrap_or(u64::MAX)).map_err(|f| match f {
        ReadFailure::TooLarge => ConfigReadError::TooLarge { file: name, max_len },
        ReadFailure::NotRegular => ConfigReadError::NotARegularFile { file: name },
        ReadFailure::Io(kind) => ConfigReadError::Io { file: name, kind },
    })
}

/// Durably removes `config.toml.pending` and `config.toml.sig.staged`, then fsyncs the directory once. Returns the
/// files that existed and were removed, pending first.
///
/// A file that is already absent is not an error. Both removals are tried even if the first fails, and the directory
/// is fsynced if either one happened; the first failure is the one reported. A [`WriteStep::SyncDir`] failure comes
/// after the unlinks.
pub fn remove_pending_and_staged(lock: &ConfigDirLock, fs: &impl StoreFs) -> Result<Vec<ConfigFileName>, ConfigWriteError> {
    let dir = lock.dir();
    dir_sync_supported().map_err(ConfigWriteError::io(ConfigFileName::Pending))?;
    let attempts = [ConfigFileName::Pending, ConfigFileName::StagedSignature].map(|name| (name, unlink_in(fs, dir, name.as_str())));
    let removed: Vec<_> = attempts.iter().filter(|(_, r)| r.is_ok()).map(|(name, _)| *name).collect();
    let first_error = attempts.iter().find_map(|(name, r)| match r {
        Err(f) if f.kind != io::ErrorKind::NotFound => Some((*name, *f)),
        _ => None,
    });
    let synced = match removed.first() {
        Some(first) => fs
            .sync_dir(dir)
            .map_err(StepFailure::new(WriteStep::SyncDir))
            .map_err(ConfigWriteError::io(*first)),
        None => Ok(()),
    };
    match first_error {
        Some((name, failure)) => Err(ConfigWriteError::io(name)(failure)),
        None => synced.map(|()| removed),
    }
}

/// Publishes: renames `config.toml.pending` to `config.toml`, then `config.toml.sig.staged` to `config.toml.sig`,
/// then fsyncs the config directory once. Step 6 of the approval transaction.
///
/// The two renames are separate and the order is a convention only: until the directory fsync returns, power loss can
/// keep either rename, both or neither. A source file that is absent is skipped and reported in [`Published`], so the
/// same call finishes a half-published pair; a caller that needs both renames checks the report. The directory is
/// fsynced either way, which also makes durable a rename that landed in an earlier call whose fsync failed.
///
/// If the first rename fails nothing has changed. If the second fails, the new config is in place beside the old
/// signature, and the staged approval is still there for another call. A [`WriteStep::SyncDir`] failure, reported
/// against `config.toml.sig`, comes after the renames: they are visible but may not survive power loss.
///
/// # Reachable mixed states
///
/// Of the active config and signature, each is the old file or the new one, never torn. The mixed pairs that can be
/// on disk afterwards:
///
/// - new config, old signature: the second rename failed, or power was lost after the first rename reached disk but
///   not the second;
/// - old config, new signature: power was lost after the second rename reached disk but not the first. The
///   filesystem may persist directory changes in any order before the fsync, so the rename order does not rule this
///   out.
///
/// Both leave the staged or pending file that was not yet renamed in place, so recovery finishes them from the
/// committed approval alone.
pub fn publish(lock: &ConfigDirLock, fs: &impl StoreFs) -> Result<Published, ConfigWriteError> {
    let dir = lock.dir();
    dir_sync_supported().map_err(ConfigWriteError::io(ConfigFileName::ActiveSignature))?;
    let config = rename_if_present(fs, dir, ConfigFileName::Pending, ConfigFileName::Active)?;
    let signature = rename_if_present(fs, dir, ConfigFileName::StagedSignature, ConfigFileName::ActiveSignature)?;
    fs.sync_dir(dir)
        .map_err(StepFailure::new(WriteStep::SyncDir))
        .map_err(ConfigWriteError::io(ConfigFileName::ActiveSignature))?;
    Ok(Published { config, signature })
}

fn rename_if_present(fs: &impl StoreFs, dir: &Path, from: ConfigFileName, to: ConfigFileName) -> Result<bool, ConfigWriteError> {
    match fs.rename(&dir.join(from.as_str()), &dir.join(to.as_str())) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(ConfigWriteError::io(from)(StepFailure::new(WriteStep::Rename)(e))),
    }
}

/// Durably removes every stale temp file in the config directory and returns the files they belonged to, in
/// [`ConfigFileName::ALL`] order, for the audit log.
///
/// A durable replace cut short by a crash leaves `.<name>.tmp`, and the next replace of `name` refuses to reuse it.
/// The service runs this once after taking the config-directory lock and before any write. It removes only the four
/// temporary names a replace can produce; every other entry, including the lock file, is left alone. All removals
/// share one directory fsync, reported against the first file.
pub fn sweep_stale_config_temps(lock: &ConfigDirLock, fs: &impl StoreFs) -> Result<Vec<ConfigFileName>, ConfigWriteError> {
    let dir = lock.dir();
    let entries = fs.list_dir(dir).map_err(|e| ConfigWriteError::ListConfigDir { kind: e.kind() })?;
    let present: Vec<_> = entries.iter().filter_map(|n| n.to_str()).collect();
    let stale: Vec<_> = ConfigFileName::ALL
        .into_iter()
        .filter(|n| present.contains(&n.temp_name().as_str()))
        .collect();
    let Some(first) = stale.first() else {
        return Ok(stale);
    };
    dir_sync_supported().map_err(ConfigWriteError::io(*first))?;
    stale
        .iter()
        .try_for_each(|name| unlink_in(fs, dir, &name.temp_name()).map_err(ConfigWriteError::io(*name)))?;
    fs.sync_dir(dir)
        .map_err(StepFailure::new(WriteStep::SyncDir))
        .map_err(ConfigWriteError::io(*first))?;
    Ok(stale)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_dir::TestDir;
    use crate::{MAX_CONFIG_LEN, OsFs, StateDirLock};

    fn read(lock: &ConfigDirLock, name: ConfigFileName) -> Result<Vec<u8>, ConfigReadError> {
        read_config_file(lock, &OsFs, name)
    }

    #[test]
    fn every_file_round_trips() {
        let dir = TestDir::new("cfg-roundtrip");
        let lock = ConfigDirLock::acquire(dir.path()).unwrap();
        write_pending(&lock, &OsFs, b"[config]").unwrap();
        write_staged(&lock, &OsFs, b"signature").unwrap();
        assert_eq!(read(&lock, ConfigFileName::Pending).unwrap(), b"[config]");
        assert_eq!(read(&lock, ConfigFileName::StagedSignature).unwrap(), b"signature");
        let published = publish(&lock, &OsFs).unwrap();
        assert!(published.config && published.signature);
        assert_eq!(read(&lock, ConfigFileName::Active).unwrap(), b"[config]");
        assert_eq!(read(&lock, ConfigFileName::ActiveSignature).unwrap(), b"signature");
        assert!(read(&lock, ConfigFileName::Pending).is_err());
        assert_eq!(remove_pending_and_staged(&lock, &OsFs).unwrap(), []);
    }

    #[test]
    fn a_file_at_its_limit_reads_and_one_byte_more_is_refused_unread() {
        let dir = TestDir::new("cfg-limit");
        let lock = ConfigDirLock::acquire(dir.path()).unwrap();
        write_pending(&lock, &OsFs, &vec![b'a'; MAX_CONFIG_LEN]).unwrap();
        assert_eq!(read(&lock, ConfigFileName::Pending).unwrap().len(), MAX_CONFIG_LEN);
        // A sparse 1 TiB file: reading or buffering it would exhaust memory, so passing proves it was refused unread.
        std::fs::File::create(dir.path().join("config.toml"))
            .unwrap()
            .set_len(1 << 40)
            .unwrap();
        std::fs::File::create(dir.path().join("config.toml.sig.staged"))
            .unwrap()
            .set_len(u64::try_from(ConfigFileName::StagedSignature.max_len()).unwrap() + 1)
            .unwrap();
        assert_eq!(
            read(&lock, ConfigFileName::Active),
            Err(ConfigReadError::TooLarge {
                file: ConfigFileName::Active,
                max_len: MAX_CONFIG_LEN
            })
        );
        assert!(matches!(
            read(&lock, ConfigFileName::StagedSignature),
            Err(ConfigReadError::TooLarge { .. })
        ));
    }

    #[test]
    fn a_missing_file_is_not_found() {
        let dir = TestDir::new("cfg-missing");
        let lock = ConfigDirLock::acquire(dir.path()).unwrap();
        assert_eq!(
            read(&lock, ConfigFileName::Active),
            Err(ConfigReadError::Io {
                file: ConfigFileName::Active,
                kind: io::ErrorKind::NotFound
            })
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_config_is_refused_and_written_files_are_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TestDir::new("cfg-link");
        let lock = ConfigDirLock::acquire(dir.path()).unwrap();
        std::fs::write(dir.path().join("real"), b"x").unwrap();
        std::os::unix::fs::symlink(dir.path().join("real"), dir.path().join("config.toml")).unwrap();
        assert_eq!(
            read(&lock, ConfigFileName::Active),
            Err(ConfigReadError::NotARegularFile {
                file: ConfigFileName::Active
            })
        );
        write_pending(&lock, &OsFs, b"x").unwrap();
        let mode = |n: &str| std::fs::metadata(dir.path().join(n)).unwrap().permissions().mode() & 0o777;
        assert_eq!((mode("config.toml.pending"), mode("config.toml.lock")), (0o600, 0o600));
    }

    #[test]
    fn a_second_writer_is_refused_until_the_first_drops() {
        let dir = TestDir::new("cfg-lock");
        let first = ConfigDirLock::acquire(dir.path()).unwrap();
        let err = ConfigDirLock::acquire(dir.path()).unwrap_err();
        assert!(matches!(err, LockError::Held { .. }));
        assert!(err.to_string().contains("config.toml.lock"), "{err}");
        drop(first);
        assert!(ConfigDirLock::acquire(dir.path()).is_ok());
    }

    #[test]
    fn the_config_lock_and_the_state_lock_are_independent() {
        let dir = TestDir::new("cfg-both-locks");
        let _state = StateDirLock::acquire(dir.path()).unwrap();
        let _config = ConfigDirLock::acquire(dir.path()).unwrap();
    }

    #[test]
    fn a_stale_temp_sweeps_on_the_real_filesystem() {
        let dir = TestDir::new("cfg-sweep-real");
        let lock = ConfigDirLock::acquire(dir.path()).unwrap();
        std::fs::write(dir.path().join(".config.toml.pending.tmp"), b"stale").unwrap();
        assert!(write_pending(&lock, &OsFs, b"new").is_err());
        assert_eq!(sweep_stale_config_temps(&lock, &OsFs).unwrap(), [ConfigFileName::Pending]);
        write_pending(&lock, &OsFs, b"new").unwrap();
    }
}
