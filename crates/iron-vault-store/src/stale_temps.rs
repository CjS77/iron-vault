//! The stale temp sweep: clearing the temporary files that unfinished durable replaces left behind.

use crate::durable::{ensure_dir_sync_supported, io_error};
use crate::{StateDirLock, StateFileName, StoreFs, WriteError, WriteStep};

/// Durably removes every stale temp file in the state directory and returns the state files they belonged to, in
/// name order, for the audit log.
///
/// A durable replace cut short by a crash leaves `.<name>.tmp`, and the next replace of `name` refuses to reuse it.
/// The service runs this once after taking the state-directory lock and before any write. It removes only names that
/// [`StateFileName`]'s temporary naming can produce; every other entry, including other dotfiles and the lock file,
/// is left alone.
///
/// All removals share one directory fsync, whose failure is reported against the first name. If a removal fails, the
/// earlier ones may not survive power loss; that only leaves stale temps for the next sweep.
pub fn sweep_stale_temps(lock: &StateDirLock, fs: &impl StoreFs) -> Result<Vec<StateFileName>, WriteError> {
    let dir = lock.dir();
    let entries = fs.list_dir(dir).map_err(|e| WriteError::ListStateDir { kind: e.kind() })?;
    let stale: Vec<StateFileName> = entries.iter().filter_map(|n| n.to_str()).filter_map(StateFileName::from_temp_name).collect();
    let Some(first) = stale.first() else {
        return Ok(stale);
    };
    ensure_dir_sync_supported(first)?;
    stale.iter().try_for_each(|name| fs.remove_file(&dir.join(name.temp_name())).map_err(io_error(WriteStep::Remove, name)))?;
    fs.sync_dir(dir).map_err(io_error(WriteStep::SyncDir, first))?;
    Ok(stale)
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::path::Path;

    use super::*;
    use crate::fault_fs::{FaultFs, FsCall, FsOp};
    use crate::test_dir::TestDir;
    use crate::{OsFs, durable_replace};

    fn name(s: &str) -> StateFileName {
        StateFileName::new(s).unwrap()
    }

    fn entries(dir: &Path) -> Vec<String> {
        OsFs.list_dir(dir).unwrap().into_iter().map(|n| n.into_string().unwrap()).collect()
    }

    /// Entries a sweep must never touch: the lock, state files, other dotfiles and near-miss temp names.
    const BYSTANDERS: [&str; 9] = ["rec", "a.tmp", ".hidden", ".tmp", "..tmp", ".lock.tmp", ".LOCK.tmp", ".a.TMP", ".a.tmp~"];

    #[test]
    fn removes_stale_temps_and_nothing_else() {
        let dir = TestDir::new("sweep-mixed");
        let lock = StateDirLock::acquire(dir.path()).unwrap();
        BYSTANDERS.iter().chain(&[".rec.tmp", ".a.tmp.tmp"]).for_each(|n| std::fs::write(dir.path().join(n), n).unwrap());
        assert_eq!(sweep_stale_temps(&lock, &OsFs).unwrap(), [name("a.tmp"), name("rec")]);
        let mut expected: Vec<_> = BYSTANDERS.iter().chain(&["lock"]).map(|n| n.to_string()).collect();
        expected.sort();
        assert_eq!(entries(dir.path()), expected);
        BYSTANDERS.iter().for_each(|n| assert_eq!(std::fs::read(dir.path().join(n)).unwrap(), n.as_bytes()));
    }

    #[test]
    fn a_following_replace_succeeds() {
        let dir = TestDir::new("sweep-then-replace");
        let lock = StateDirLock::acquire(dir.path()).unwrap();
        std::fs::write(dir.path().join("rec"), b"old").unwrap();
        std::fs::write(dir.path().join(".rec.tmp"), b"stale").unwrap();
        assert!(durable_replace(&lock, &OsFs, &name("rec"), b"new").is_err());
        assert_eq!(sweep_stale_temps(&lock, &OsFs).unwrap(), [name("rec")]);
        durable_replace(&lock, &OsFs, &name("rec"), b"new").unwrap();
        assert_eq!(std::fs::read(dir.path().join("rec")).unwrap(), b"new");
    }

    #[test]
    fn a_clean_directory_needs_no_writes() {
        let dir = TestDir::new("sweep-clean");
        let lock = StateDirLock::acquire(dir.path()).unwrap();
        let fs = FaultFs::new().with_durable_file(&dir.path().join("rec"), b"x");
        assert_eq!(sweep_stale_temps(&lock, &fs).unwrap(), []);
        assert_eq!(fs.trace(), [FsCall::ListDir(dir.path().to_path_buf())]);
    }

    #[test]
    fn removals_are_durable() {
        let dir = TestDir::new("sweep-durable");
        let lock = StateDirLock::acquire(dir.path()).unwrap();
        let (temp, keep) = (dir.path().join(".rec.tmp"), dir.path().join(".hidden"));
        let fs = FaultFs::new().with_durable_file(&temp, b"stale").with_durable_file(&keep, b"k");
        sweep_stale_temps(&lock, &fs).unwrap();
        assert_eq!(fs.trace().last(), Some(&FsCall::SyncDir(dir.path().to_path_buf())));
        fs.crash();
        assert_eq!(fs.contents(&temp), None);
        assert_eq!(fs.contents(&keep).unwrap(), b"k");
    }

    #[test]
    fn failures_name_their_step() {
        let dir = TestDir::new("sweep-faults");
        let lock = StateDirLock::acquire(dir.path()).unwrap();
        let cases = [
            (FsOp::ListDir, WriteError::ListStateDir { kind: io::ErrorKind::PermissionDenied }),
            (FsOp::RemoveFile, WriteError::Io { step: WriteStep::Remove, file: name("rec"), kind: io::ErrorKind::PermissionDenied }),
            (FsOp::SyncDir, WriteError::Io { step: WriteStep::SyncDir, file: name("rec"), kind: io::ErrorKind::PermissionDenied }),
        ];
        cases.into_iter().for_each(|(op, expected)| {
            let fs = FaultFs::new().with_durable_file(&dir.path().join(".rec.tmp"), b"stale");
            fs.fail_first(op, io::ErrorKind::PermissionDenied);
            assert_eq!(sweep_stale_temps(&lock, &fs), Err(expected), "{op:?}");
        });
    }
}
