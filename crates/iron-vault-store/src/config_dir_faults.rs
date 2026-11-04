//! Fault-injection and power-loss tests for the config directory's file operations, run against [`FaultFs`].

use std::collections::BTreeSet;
use std::io;
use std::path::PathBuf;

use crate::ConfigFileName::{Active, ActiveSignature, Pending, StagedSignature};
use crate::durable_faults::assert_trace_properties;
use crate::fault_fs::{FaultFs, FsCall, FsOp};
use crate::test_dir::TestDir;
use crate::{
    ConfigDirLock, ConfigFileName, ConfigWriteError, PublishSet, StoreFs, WriteStep, publish, remove_pending_and_staged,
    sweep_stale_config_temps, write_pending, write_staged,
};

const OLD_CONFIG: &[u8] = b"old config, longer than the new one";
const NEW_CONFIG: &[u8] = b"new config";
const OLD_SIG: &[u8] = b"old signature, longer than the new one";
const NEW_SIG: &[u8] = b"new signature";

/// A locked scratch config directory; the lock is real, the files live in a [`FaultFs`] under the same path.
struct Setup {
    dir: TestDir,
    lock: ConfigDirLock,
}

impl Setup {
    fn new(label: &str) -> Self {
        let dir = TestDir::new(label);
        let lock = ConfigDirLock::acquire(dir.path()).unwrap();
        Self { dir, lock }
    }

    fn path(&self, name: ConfigFileName) -> PathBuf {
        self.dir.path().join(name.as_str())
    }

    fn temp(&self, name: ConfigFileName) -> PathBuf {
        self.dir.path().join(name.temp_name())
    }

    /// A filesystem where a transaction has staged a new pair beside the published old pair, all durable.
    fn staged_fs(&self) -> FaultFs {
        [
            (Active, OLD_CONFIG),
            (ActiveSignature, OLD_SIG),
            (Pending, NEW_CONFIG),
            (StagedSignature, NEW_SIG),
        ]
        .into_iter()
        .fold(FaultFs::new(), |fs, (name, bytes)| fs.with_durable_file(&self.path(name), bytes))
    }

    fn contents(&self, fs: &FaultFs, name: ConfigFileName) -> Option<Vec<u8>> {
        fs.contents(&self.path(name))
    }

    /// Which generation each of the active config and signature holds. Panics on any other bytes, which is a torn file.
    fn active_pair(&self, fs: &FaultFs) -> (Gen, Gen) {
        let gen_of = |name, old: &[u8], new: &[u8]| match self.contents(fs, name) {
            Some(b) if b == old => Gen::Old,
            Some(b) if b == new => Gen::New,
            other => panic!("{name} holds neither generation: {other:?}"),
        };
        (gen_of(Active, OLD_CONFIG, NEW_CONFIG), gen_of(ActiveSignature, OLD_SIG, NEW_SIG))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Gen {
    Old,
    New,
}

type Writer = fn(&ConfigDirLock, &FaultFs, &[u8]) -> Result<(), ConfigWriteError>;

fn writers() -> [(ConfigFileName, Writer); 2] {
    [
        (Pending, |l, f, b| write_pending(l, f, b)),
        (StagedSignature, |l, f, b| write_staged(l, f, b)),
    ]
}

fn write_step(op: FsOp) -> WriteStep {
    match op {
        FsOp::CreatePrivate => WriteStep::CreateTemp,
        FsOp::WriteAll => WriteStep::Write,
        FsOp::SyncFile => WriteStep::SyncFile,
        FsOp::Rename => WriteStep::Rename,
        FsOp::RemoveFile => WriteStep::Remove,
        FsOp::SyncDir => WriteStep::SyncDir,
        other => unreachable!("config writes never call {other:?}"),
    }
}

/// A filesystem holding `old` durably at `name`, or nothing there.
fn fs_with(setup: &Setup, name: ConfigFileName, old: Option<&[u8]>) -> FaultFs {
    old.into_iter()
        .fold(FaultFs::new(), |fs, b| fs.with_durable_file(&setup.path(name), b))
}

const NEW_BYTES: &[u8] = b"the replacement";
const OLD_BYTES: &[u8] = b"the previous file, longer than its replacement";
const OLD_STATES: [Option<&[u8]>; 2] = [Some(OLD_BYTES), None];

#[test]
fn writes_follow_the_durable_discipline() {
    let setup = Setup::new("cfg-trace");
    writers().into_iter().for_each(|(name, write)| {
        let fs = fs_with(&setup, name, Some(OLD_BYTES));
        write(&setup.lock, &fs, NEW_BYTES).unwrap();
        assert_trace_properties(&fs.trace());
        assert_eq!(fs.contents(&setup.path(name)).as_deref(), Some(NEW_BYTES));
    });
}

#[test]
fn write_failure_at_each_call_names_the_step_and_keeps_old_or_new() {
    let setup = Setup::new("cfg-write-steps");
    writers().into_iter().for_each(|(name, write)| {
        OLD_STATES.iter().for_each(|&old| {
            let clean = fs_with(&setup, name, old);
            write(&setup.lock, &clean, NEW_BYTES).unwrap();
            let trace = clean.trace();
            let rename_at = trace.iter().position(|c| c.op() == FsOp::Rename).unwrap();
            trace.iter().enumerate().for_each(|(i, call)| {
                let fs = fs_with(&setup, name, old);
                fs.fail_call(i, io::ErrorKind::StorageFull);
                let expected = ConfigWriteError::Io {
                    step: write_step(call.op()),
                    file: name,
                    kind: io::ErrorKind::StorageFull,
                };
                assert_eq!(
                    write(&setup.lock, &fs, NEW_BYTES).unwrap_err(),
                    expected,
                    "{name}, fault at call {i}"
                );
                let expected_dest = if i <= rename_at { old } else { Some(NEW_BYTES) };
                assert_eq!(
                    fs.contents(&setup.path(name)).as_deref(),
                    expected_dest,
                    "{name}, fault at call {i}"
                );
                assert_eq!(
                    fs.contents(&setup.temp(name)),
                    None,
                    "{name}: temp file left after fault at call {i}"
                );
            });
        });
    });
}

#[test]
fn write_survives_a_crash_at_every_point() {
    let setup = Setup::new("cfg-write-crash");
    writers().into_iter().for_each(|(name, write)| {
        OLD_STATES.iter().for_each(|&old| {
            let clean = fs_with(&setup, name, old);
            write(&setup.lock, &clean, NEW_BYTES).unwrap();
            (0..=clean.trace().len()).for_each(|k| {
                let fs = fs_with(&setup, name, old);
                fs.cut_power_after(k);
                let result = write(&setup.lock, &fs, NEW_BYTES);
                fs.crash();
                let now = fs.contents(&setup.path(name));
                assert!(
                    now.as_deref() == old || now.as_deref() == Some(NEW_BYTES),
                    "{name}, crash after {k}: {now:?}"
                );
                assert!(
                    result.is_err() || now.as_deref() == Some(NEW_BYTES),
                    "{name}: an Ok write was lost in a crash"
                );
            });
        });
    });
}

#[test]
fn an_oversized_write_is_refused_before_the_filesystem_is_touched() {
    let setup = Setup::new("cfg-write-big");
    writers().into_iter().for_each(|(name, write)| {
        let fs = FaultFs::new();
        let big = vec![0; name.max_len() + 1];
        let expected = ConfigWriteError::TooLarge {
            file: name,
            max_len: name.max_len(),
        };
        assert_eq!(write(&setup.lock, &fs, &big), Err(expected));
        assert_eq!(fs.trace(), []);
        write(&setup.lock, &fs, &big[1..]).unwrap();
    });
}

#[test]
fn publish_lists_then_renames_config_then_signature_then_syncs_once() {
    let setup = Setup::new("cfg-publish-trace");
    let fs = setup.staged_fs();
    publish(&setup.lock, &fs, PublishSet::Both).unwrap();
    let rename = |from, to| FsCall::Rename {
        from: setup.path(from),
        to: setup.path(to),
    };
    let dir = setup.dir.path().to_path_buf();
    let expected = [
        FsCall::ListDir(dir.clone()),
        rename(Pending, Active),
        rename(StagedSignature, ActiveSignature),
        FsCall::SyncDir(dir),
    ];
    assert_eq!(fs.trace(), expected);
    assert_trace_properties(&fs.trace());
    assert_eq!(setup.active_pair(&fs), (Gen::New, Gen::New));
    assert_eq!((setup.contents(&fs, Pending), setup.contents(&fs, StagedSignature)), (None, None));
}

#[test]
fn publish_failure_at_each_call_names_the_file_and_leaves_a_resumable_pair() {
    let setup = Setup::new("cfg-publish-steps");
    let io = |step, file| ConfigWriteError::Io {
        step,
        file,
        kind: io::ErrorKind::StorageFull,
    };
    let list = ConfigWriteError::ListConfigDir {
        kind: io::ErrorKind::StorageFull,
    };
    // For each call: the error, the active pair left behind, and the set that finishes the publish (None if done).
    let cases = [
        (list, (Gen::Old, Gen::Old), Some(PublishSet::Both)),
        (io(WriteStep::Rename, Pending), (Gen::Old, Gen::Old), Some(PublishSet::Both)),
        (
            io(WriteStep::Rename, StagedSignature),
            (Gen::New, Gen::Old),
            Some(PublishSet::SignatureOnly),
        ),
        (io(WriteStep::SyncDir, ActiveSignature), (Gen::New, Gen::New), None),
    ];
    cases.into_iter().enumerate().for_each(|(i, (error, pair, retry))| {
        let fs = setup.staged_fs();
        fs.fail_call(i, io::ErrorKind::StorageFull);
        assert_eq!(publish(&setup.lock, &fs, PublishSet::Both), Err(error), "fault at call {i}");
        assert_eq!(setup.active_pair(&fs), pair, "fault at call {i}");
        if let Some(set) = retry {
            publish(&setup.lock, &fs, set).unwrap();
        }
        assert_eq!(setup.active_pair(&fs), (Gen::New, Gen::New), "after retry of fault at call {i}");
    });
}

#[test]
fn publish_survives_a_crash_at_every_point() {
    let setup = Setup::new("cfg-publish-crash");
    let calls = 4;
    (0..=calls).for_each(|k| {
        let fs = setup.staged_fs();
        fs.cut_power_after(k);
        let result = publish(&setup.lock, &fs, PublishSet::Both);
        fs.crash();
        let pair = setup.active_pair(&fs);
        assert!(result.is_err() || pair == (Gen::New, Gen::New), "an Ok publish was lost in a crash");
        // Without an fsync, the filesystem keeps none of the renames; with it, both.
        assert_eq!(
            pair,
            if k == calls { (Gen::New, Gen::New) } else { (Gen::Old, Gen::Old) },
            "crash after {k}"
        );
    });
}

/// Every pair of active files on disk after a publish that failed, or lost power with the filesystem persisting any
/// subset of the two renames. The recovery ticket relies on this list.
fn reachable_pairs(setup: &Setup) -> BTreeSet<(Gen, Gen)> {
    let renames = [(Pending, Active), (StagedSignature, ActiveSignature)];
    let power_loss = (0..4u8).map(|keep| {
        let fs = setup.staged_fs();
        // Power is lost just before the directory fsync: after the listing and both renames.
        fs.cut_power_after(3);
        assert!(publish(&setup.lock, &fs, PublishSet::Both).is_err());
        let kept: Vec<PathBuf> = renames
            .iter()
            .enumerate()
            .filter(|(i, _)| keep >> i & 1 == 1)
            .flat_map(|(_, (from, to))| [setup.path(*from), setup.path(*to)])
            .collect();
        fs.crash_keeping(&kept.iter().map(PathBuf::as_path).collect::<Vec<_>>());
        setup.active_pair(&fs)
    });
    let failed = (0..4).map(|i| {
        let fs = setup.staged_fs();
        fs.fail_call(i, io::ErrorKind::StorageFull);
        assert!(publish(&setup.lock, &fs, PublishSet::Both).is_err());
        setup.active_pair(&fs)
    });
    power_loss.chain(failed).collect()
}

#[test]
fn the_reachable_mixed_states_are_new_config_old_signature_and_the_reverse() {
    let setup = Setup::new("cfg-publish-mixed");
    let pairs = reachable_pairs(&setup);
    let expected = [
        (Gen::Old, Gen::Old),
        (Gen::New, Gen::Old),
        (Gen::Old, Gen::New),
        (Gen::New, Gen::New),
    ];
    assert_eq!(pairs, expected.into_iter().collect());
}

#[test]
fn a_mixed_state_keeps_the_file_that_finishes_it_and_the_matching_set_completes_it() {
    let setup = Setup::new("cfg-publish-resume");
    // New config + old signature keeps the staged signature; old config + new signature keeps the pending config.
    let cases = [
        (Pending, Active, StagedSignature, (Gen::New, Gen::Old), PublishSet::SignatureOnly),
        (
            StagedSignature,
            ActiveSignature,
            Pending,
            (Gen::Old, Gen::New),
            PublishSet::ConfigOnly,
        ),
    ];
    cases.into_iter().for_each(|(from, to, kept, pair, set)| {
        let fs = setup.staged_fs();
        fs.rename(&setup.path(from), &setup.path(to)).unwrap();
        assert_eq!(setup.active_pair(&fs), pair);
        assert!(setup.contents(&fs, kept).is_some(), "{kept} is gone");
        publish(&setup.lock, &fs, set).unwrap();
        assert_eq!(setup.active_pair(&fs), (Gen::New, Gen::New));
    });
}

#[test]
fn a_missing_requested_source_fails_with_not_found_before_anything_is_renamed() {
    let setup = Setup::new("cfg-publish-missing");
    // (set, the source removed first, the source the error names)
    let cases = [
        (PublishSet::Both, Pending, Pending),
        (PublishSet::Both, StagedSignature, StagedSignature),
        (PublishSet::ConfigOnly, Pending, Pending),
        (PublishSet::SignatureOnly, StagedSignature, StagedSignature),
    ];
    cases.into_iter().for_each(|(set, removed, named)| {
        let fs = setup.staged_fs();
        fs.remove_file(&setup.path(removed)).unwrap();
        let before = fs.trace().len();
        let expected = ConfigWriteError::Io {
            step: WriteStep::Rename,
            file: named,
            kind: io::ErrorKind::NotFound,
        };
        assert_eq!(publish(&setup.lock, &fs, set), Err(expected), "{set:?} without {removed}");
        assert_eq!(
            fs.trace()[before..],
            [FsCall::ListDir(setup.dir.path().to_path_buf())],
            "{set:?} without {removed}"
        );
        assert_eq!(setup.active_pair(&fs), (Gen::Old, Gen::Old), "{set:?} without {removed}");
    });
}

#[test]
fn signature_only_leaves_a_leftover_pending_config_and_the_active_config_alone() {
    let setup = Setup::new("cfg-publish-sig-only");
    // Recovery row 2 with an uncommitted pending config from a later approval beside it.
    let fs = setup.staged_fs();
    publish(&setup.lock, &fs, PublishSet::SignatureOnly).unwrap();
    assert_eq!(setup.active_pair(&fs), (Gen::Old, Gen::New));
    assert_eq!(setup.contents(&fs, Active).as_deref(), Some(OLD_CONFIG));
    assert_eq!(setup.contents(&fs, Pending).as_deref(), Some(NEW_CONFIG));
    assert_eq!(setup.contents(&fs, StagedSignature), None);
    assert_eq!(renames(&fs), [setup.path(StagedSignature)]);
}

#[test]
fn config_only_leaves_a_leftover_staged_signature_and_the_active_signature_alone() {
    let setup = Setup::new("cfg-publish-config-only");
    // Recovery row 3 with an uncommitted staged signature from a later approval beside it.
    let fs = setup.staged_fs();
    publish(&setup.lock, &fs, PublishSet::ConfigOnly).unwrap();
    assert_eq!(setup.active_pair(&fs), (Gen::New, Gen::Old));
    assert_eq!(setup.contents(&fs, ActiveSignature).as_deref(), Some(OLD_SIG));
    assert_eq!(setup.contents(&fs, StagedSignature).as_deref(), Some(NEW_SIG));
    assert_eq!(setup.contents(&fs, Pending), None);
    assert_eq!(renames(&fs), [setup.path(Pending)]);
}

/// The sources of every rename in the trace.
fn renames(fs: &FaultFs) -> Vec<PathBuf> {
    fs.trace()
        .into_iter()
        .filter_map(|c| match c {
            FsCall::Rename { from, .. } => Some(from),
            _ => None,
        })
        .collect()
}

#[test]
fn remove_pending_and_staged_is_durable_and_tolerates_absence() {
    let setup = Setup::new("cfg-remove");
    let fs = setup.staged_fs();
    assert_eq!(remove_pending_and_staged(&setup.lock, &fs).unwrap(), [Pending, StagedSignature]);
    assert_trace_properties(&fs.trace());
    fs.crash();
    assert_eq!((setup.contents(&fs, Pending), setup.contents(&fs, StagedSignature)), (None, None));
    assert_eq!(setup.active_pair(&fs), (Gen::Old, Gen::Old));
    assert_eq!(remove_pending_and_staged(&setup.lock, &fs).unwrap(), []);
}

#[test]
fn remove_failure_at_each_call_names_the_step_and_the_file_and_tries_the_rest() {
    let setup = Setup::new("cfg-remove-steps");
    let io = |step, file| ConfigWriteError::Io {
        step,
        file,
        kind: io::ErrorKind::PermissionDenied,
    };
    // For each call: the error, then whether the pending config and the staged approval are left on disk.
    let cases = [
        (io(WriteStep::Remove, Pending), true, false),
        (io(WriteStep::Remove, StagedSignature), false, true),
        (io(WriteStep::SyncDir, Pending), false, false),
    ];
    cases.into_iter().enumerate().for_each(|(i, (error, pending_left, staged_left))| {
        let fs = setup.staged_fs();
        fs.fail_call(i, io::ErrorKind::PermissionDenied);
        assert_eq!(remove_pending_and_staged(&setup.lock, &fs), Err(error), "fault at call {i}");
        assert_eq!(setup.contents(&fs, Pending).is_some(), pending_left, "fault at call {i}");
        assert_eq!(setup.contents(&fs, StagedSignature).is_some(), staged_left, "fault at call {i}");
        assert_eq!(setup.active_pair(&fs), (Gen::Old, Gen::Old), "fault at call {i}");
        // Every attempt reaches the directory fsync, so the unlink that did happen is made durable.
        assert_eq!(fs.trace().len(), 3, "fault at call {i}");
    });
}

#[test]
fn remove_survives_a_crash_at_every_point() {
    let setup = Setup::new("cfg-remove-crash");
    (0..=3).for_each(|k| {
        let fs = setup.staged_fs();
        fs.cut_power_after(k);
        let result = remove_pending_and_staged(&setup.lock, &fs);
        fs.crash();
        assert_eq!(setup.active_pair(&fs), (Gen::Old, Gen::Old));
        let gone = (setup.contents(&fs, Pending), setup.contents(&fs, StagedSignature)) == (None, None);
        assert!(result.is_err() || gone, "an Ok remove was undone by a crash at {k}");
    });
}

#[test]
fn sweep_removes_only_the_pending_and_staged_temp_names_durably() {
    let setup = Setup::new("cfg-sweep");
    // The active files are written only by rename, so their temp names are never produced and never swept.
    let bystanders = [
        ".config.toml.tmp",
        ".config.toml.sig.tmp",
        ".config.toml.lock.tmp",
        "config.toml.tmp",
        ".hidden",
        "config.toml.lock",
        ".config.toml.sig.staged.tmp~",
    ];
    let fs = [Pending, StagedSignature]
        .iter()
        .map(|n| setup.temp(*n))
        .chain(bystanders.iter().map(|n| setup.dir.path().join(n)))
        .fold(FaultFs::new(), |fs, path| fs.with_durable_file(&path, b"x"));
    assert_eq!(sweep_stale_config_temps(&setup.lock, &fs).unwrap(), [Pending, StagedSignature]);
    assert_trace_properties(&fs.trace());
    fs.crash();
    [Pending, StagedSignature]
        .iter()
        .for_each(|n| assert_eq!(fs.contents(&setup.temp(*n)), None));
    bystanders
        .iter()
        .for_each(|n| assert!(fs.contents(&setup.dir.path().join(n)).is_some(), "{n}"));
}

#[test]
fn sweep_failures_name_their_step_and_a_clean_directory_needs_no_writes() {
    let setup = Setup::new("cfg-sweep-faults");
    let clean = FaultFs::new().with_durable_file(&setup.path(Active), b"x");
    assert_eq!(sweep_stale_config_temps(&setup.lock, &clean).unwrap(), []);
    assert_eq!(clean.trace(), [FsCall::ListDir(setup.dir.path().to_path_buf())]);
    let io = |step| ConfigWriteError::Io {
        step,
        file: Pending,
        kind: io::ErrorKind::PermissionDenied,
    };
    let cases = [
        (
            FsOp::ListDir,
            ConfigWriteError::ListConfigDir {
                kind: io::ErrorKind::PermissionDenied,
            },
        ),
        (FsOp::RemoveFile, io(WriteStep::Remove)),
        (FsOp::SyncDir, io(WriteStep::SyncDir)),
    ];
    cases.into_iter().for_each(|(op, expected)| {
        let fs = FaultFs::new().with_durable_file(&setup.temp(Pending), b"stale");
        fs.fail_first(op, io::ErrorKind::PermissionDenied);
        assert_eq!(sweep_stale_config_temps(&setup.lock, &fs), Err(expected), "{op:?}");
    });
}

#[test]
fn a_stale_temp_blocks_a_write_until_it_is_swept() {
    let setup = Setup::new("cfg-sweep-then-write");
    let fs = FaultFs::new().with_durable_file(&setup.temp(Pending), b"stale");
    let err = write_pending(&setup.lock, &fs, NEW_CONFIG).unwrap_err();
    let expected = ConfigWriteError::Io {
        step: WriteStep::CreateTemp,
        file: Pending,
        kind: io::ErrorKind::AlreadyExists,
    };
    assert_eq!(err, expected);
    assert_eq!(sweep_stale_config_temps(&setup.lock, &fs).unwrap(), [Pending]);
    write_pending(&setup.lock, &fs, NEW_CONFIG).unwrap();
    assert_eq!(setup.contents(&fs, Pending).as_deref(), Some(NEW_CONFIG));
}
