//! Fault-injection and power-loss tests for durable replace and durable remove, run against [`FaultFs`].

use std::io;
use std::path::{Path, PathBuf};

use crate::fault_fs::{FaultFs, FsCall, FsOp};
use crate::test_dir::TestDir;
use crate::{StateDirLock, StateFileName, WriteError, WriteStep, durable_remove, durable_replace, sweep_stale_temps};

const OLD: &[u8] = b"the old record, longer than the new one";
const NEW: &[u8] = b"the new record";

/// A locked scratch state directory; the lock is real, the files live in a [`FaultFs`] under the same path.
struct Setup {
    dir: TestDir,
    lock: StateDirLock,
}

impl Setup {
    fn new(label: &str) -> Self {
        let dir = TestDir::new(label);
        let lock = StateDirLock::acquire(dir.path()).unwrap();
        Self { dir, lock }
    }

    fn dest(&self) -> PathBuf {
        self.dir.path().join("rec")
    }

    fn temp(&self) -> PathBuf {
        self.dir.path().join(".rec.tmp")
    }

    /// A fresh filesystem holding `old` durably at the destination, or nothing there.
    fn fs(&self, old: Option<&[u8]>) -> FaultFs {
        old.into_iter()
            .fold(FaultFs::new(), |fs, bytes| fs.with_durable_file(&self.dest(), bytes))
    }

    fn replace(&self, fs: &FaultFs) -> Result<(), WriteError> {
        durable_replace(&self.lock, fs, &rec(), NEW)
    }

    fn remove(&self, fs: &FaultFs) -> Result<(), WriteError> {
        durable_remove(&self.lock, fs, &rec())
    }
}

fn rec() -> StateFileName {
    StateFileName::new("rec").unwrap()
}

/// The trace of an uninterrupted run of `op` on a fresh filesystem.
fn clean_trace(setup: &Setup, old: Option<&[u8]>, op: impl Fn(&Setup, &FaultFs) -> Result<(), WriteError>) -> Vec<FsCall> {
    let fs = setup.fs(old);
    op(setup, &fs).unwrap();
    fs.trace()
}

fn parent(path: &Path) -> PathBuf {
    path.parent().unwrap().to_path_buf()
}

/// Every rename and unlink is followed by an fsync of its directory, and every write is fsynced before the temp file
/// is renamed.
fn assert_trace_properties(trace: &[FsCall]) {
    let synced_dir_after = |i: usize, path: &Path| trace[i..].contains(&FsCall::SyncDir(parent(path)));
    trace.iter().enumerate().for_each(|(i, call)| match call {
        FsCall::Rename { to, .. } => assert!(synced_dir_after(i, to), "rename at {i} has no directory fsync: {trace:?}"),
        FsCall::RemoveFile(path) => assert!(synced_dir_after(i, path), "unlink at {i} has no directory fsync: {trace:?}"),
        FsCall::WriteAll(path) => {
            let rename = trace[i..]
                .iter()
                .position(|c| matches!(c, FsCall::Rename { from, .. } if from == path))
                .map(|j| i + j);
            let sync = trace[i..].iter().position(|c| *c == FsCall::SyncFile(path.clone())).map(|j| i + j);
            assert!(
                matches!((sync, rename), (Some(s), Some(r)) if s < r),
                "write at {i} is not fsynced before rename: {trace:?}"
            );
        }
        _ => {}
    });
}

fn write_step(op: FsOp) -> WriteStep {
    match op {
        FsOp::CreatePrivate => WriteStep::CreateTemp,
        FsOp::WriteAll => WriteStep::Write,
        FsOp::SyncFile => WriteStep::SyncFile,
        FsOp::Rename => WriteStep::Rename,
        FsOp::RemoveFile => WriteStep::Remove,
        FsOp::SyncDir => WriteStep::SyncDir,
        other => unreachable!("durable writes never call {other:?}"),
    }
}

/// The destination holds exactly the old bytes (or is absent when there were none) or exactly the new bytes.
fn assert_old_or_new(fs: &FaultFs, setup: &Setup, old: Option<&[u8]>, context: &str) {
    let now = fs.contents(&setup.dest());
    assert!(
        now.as_deref() == old || now.as_deref() == Some(NEW),
        "{context}: destination holds {now:?}"
    );
}

const OLD_STATES: [Option<&[u8]>; 2] = [Some(OLD), None];

#[test]
fn trace_properties_hold() {
    let setup = Setup::new("faults-trace");
    OLD_STATES
        .iter()
        .for_each(|&old| assert_trace_properties(&clean_trace(&setup, old, Setup::replace)));
    assert_trace_properties(&clean_trace(&setup, Some(OLD), Setup::remove));
    let fs = FaultFs::new().with_durable_file(&setup.temp(), b"stale");
    sweep_stale_temps(&setup.lock, &fs).unwrap();
    assert_trace_properties(&fs.trace());
}

#[test]
fn trace_properties_catch_a_missing_directory_fsync() {
    let (dir, file) = (PathBuf::from("/d"), PathBuf::from("/d/rec"));
    let temp = PathBuf::from("/d/.rec.tmp");
    let base = [
        FsCall::CreatePrivate(temp.clone()),
        FsCall::WriteAll(temp.clone()),
        FsCall::SyncFile(temp.clone()),
    ];
    let rename = FsCall::Rename { from: temp, to: file };
    let complete: Vec<_> = base.iter().cloned().chain([rename.clone(), FsCall::SyncDir(dir)]).collect();
    assert_trace_properties(&complete);
    let without_sync: Vec<_> = base.iter().cloned().chain([rename]).collect();
    assert!(std::panic::catch_unwind(|| assert_trace_properties(&without_sync)).is_err());
}

#[test]
fn replace_failure_at_each_step_reports_it_and_keeps_old_or_new() {
    let setup = Setup::new("faults-replace-steps");
    OLD_STATES.iter().for_each(|&old| {
        let trace = clean_trace(&setup, old, Setup::replace);
        let rename_at = trace.iter().position(|c| c.op() == FsOp::Rename).unwrap();
        trace.iter().enumerate().for_each(|(i, call)| {
            let fs = setup.fs(old);
            fs.fail_call(i, io::ErrorKind::StorageFull);
            let err = setup.replace(&fs).unwrap_err();
            let expected = WriteError::Io {
                step: write_step(call.op()),
                file: rec(),
                kind: io::ErrorKind::StorageFull,
            };
            assert_eq!(err, expected, "fault at call {i}");
            let expected_dest = if i <= rename_at { old } else { Some(NEW) };
            assert_eq!(fs.contents(&setup.dest()).as_deref(), expected_dest, "fault at call {i}");
            assert_eq!(fs.contents(&setup.temp()), None, "temp file left after fault at call {i}");
            fs.crash();
            assert_old_or_new(&fs, &setup, old, &format!("crash after fault at call {i}"));
        });
    });
}

#[test]
fn failed_cleanup_is_the_only_way_a_temp_file_stays() {
    let setup = Setup::new("faults-cleanup");
    let fs = setup.fs(Some(OLD));
    fs.fail_first(FsOp::Rename, io::ErrorKind::PermissionDenied);
    fs.fail_first(FsOp::RemoveFile, io::ErrorKind::PermissionDenied);
    let err = setup.replace(&fs).unwrap_err();
    assert_eq!(
        err,
        WriteError::Io {
            step: WriteStep::Rename,
            file: rec(),
            kind: io::ErrorKind::PermissionDenied
        }
    );
    assert_eq!(fs.contents(&setup.dest()).as_deref(), Some(OLD));
    assert_eq!(fs.contents(&setup.temp()).as_deref(), Some(NEW));
}

#[test]
fn replace_survives_a_crash_at_every_point() {
    let setup = Setup::new("faults-replace-crash");
    OLD_STATES.iter().for_each(|&old| {
        let len = clean_trace(&setup, old, Setup::replace).len();
        (0..=len).for_each(|k| {
            let fs = setup.fs(old);
            fs.cut_power_after(k);
            let result = setup.replace(&fs);
            fs.crash();
            assert_old_or_new(&fs, &setup, old, &format!("crash after {k} calls"));
            // With k equal to the full trace length the replace completes and returns Ok.
            if result.is_ok() {
                assert_eq!(
                    fs.contents(&setup.dest()).as_deref(),
                    Some(NEW),
                    "a replace that returned Ok was lost in a crash"
                );
            }
        });
    });
}

#[test]
fn remove_failure_at_each_step_reports_it() {
    let setup = Setup::new("faults-remove-steps");
    let trace = clean_trace(&setup, Some(OLD), Setup::remove);
    trace.iter().enumerate().for_each(|(i, call)| {
        let fs = setup.fs(Some(OLD));
        fs.fail_call(i, io::ErrorKind::StorageFull);
        let err = setup.remove(&fs).unwrap_err();
        assert_eq!(
            err,
            WriteError::Io {
                step: write_step(call.op()),
                file: rec(),
                kind: io::ErrorKind::StorageFull
            }
        );
        let expected = (call.op() == FsOp::RemoveFile).then_some(OLD);
        assert_eq!(fs.contents(&setup.dest()).as_deref(), expected, "fault at call {i}");
    });
}

#[test]
fn remove_survives_a_crash_at_every_point() {
    let setup = Setup::new("faults-remove-crash");
    let len = clean_trace(&setup, Some(OLD), Setup::remove).len();
    (0..=len).for_each(|k| {
        let fs = setup.fs(Some(OLD));
        fs.cut_power_after(k);
        let result = setup.remove(&fs);
        fs.crash();
        let now = fs.contents(&setup.dest());
        assert!(
            now.is_none() || now.as_deref() == Some(OLD),
            "crash after {k} calls: destination holds {now:?}"
        );
        assert!(result.is_err() || now.is_none(), "a remove that returned Ok was undone by a crash");
    });
}

#[test]
fn stale_temp_from_a_crash_is_swept_and_replace_then_succeeds() {
    let setup = Setup::new("faults-sweep");
    let fs = setup.fs(Some(OLD));
    // A replace of `rec` fails and cannot clean up; a replace of another file then fsyncs the directory, making the
    // leftover temp entry durable, and the power fails.
    fs.fail_first(FsOp::Rename, io::ErrorKind::PermissionDenied);
    fs.fail_first(FsOp::RemoveFile, io::ErrorKind::PermissionDenied);
    assert!(setup.replace(&fs).is_err());
    durable_replace(&setup.lock, &fs, &StateFileName::new("other").unwrap(), b"o").unwrap();
    fs.crash();
    assert_eq!(fs.contents(&setup.temp()).as_deref(), Some(NEW));
    let err = setup.replace(&fs).unwrap_err();
    assert_eq!(
        err,
        WriteError::Io {
            step: WriteStep::CreateTemp,
            file: rec(),
            kind: io::ErrorKind::AlreadyExists
        }
    );
    assert_eq!(sweep_stale_temps(&setup.lock, &fs).unwrap(), [rec()]);
    setup.replace(&fs).unwrap();
    assert_eq!(fs.contents(&setup.dest()).as_deref(), Some(NEW));
    assert_eq!(fs.contents(&setup.dir.path().join("other")).as_deref(), Some(&b"o"[..]));
}
