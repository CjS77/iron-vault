// SPDX-License-Identifier: MPL-2.0
//! The unfinished import: its classification, its discard by either command and the marker swap.

use super::*;

const RECORD: &str = "record-7c9e6679-7425-40de-944b-e07fc1f90ae7.age";
const OTHER_RECORD: &str = "record-1b4e28ba-2fa1-41d2-883f-0016d3cca427.age";
const TPM_BLOB: &str = "approver-8d1c6f0e-2b7a-4c59-9e3d-5a4b3c2d1e0f.tpm";

const INIT: UnfinishedKind = UnfinishedKind::Initialization;
const IMPORT: UnfinishedKind = UnfinishedKind::Import;

/// Lists every file an import writes, and the leftovers a discard sweeps with them, in the order the discard removes
/// them.
const IMPORT_FILES: [&str; 12] = [
    "recovery.toml",
    "locked-by-owner",
    "approval.age",
    "manifest.age",
    OTHER_RECORD,
    RECORD,
    OTHER_APPROVER_KEY,
    APPROVER_KEY,
    "operational.age",
    "recipients.age",
    "identity.age",
    "config.toml",
];

impl Dirs {
    /// Builds the directory a crash leaves in the middle of an import: the marker and every file an import writes, any
    /// number of record and approver key files, and a `config.toml` that is the bundle's, not the initial config.
    fn crashed_import(&self, fs: &impl StoreFs) {
        self.put_bytes(fs, "import.unfinished", b"");
        IMPORT_FILES
            .iter()
            .filter(|name| **name != "config.toml")
            .for_each(|name| self.put(fs, name));
        self.put_config(fs, Active, b"[listeners.a]\naddress = \"127.0.0.1:1\"\n");
    }

    /// Builds the directory a crash leaves in the middle of `kind`'s run.
    fn crashed(&self, fs: &impl StoreFs, kind: UnfinishedKind) {
        match kind {
            INIT => self.crashed_after(fs, PUBLISHED),
            IMPORT => self.crashed_import(fs),
        }
    }

    fn begin_as(&self, fs: &impl StoreFs, own: UnfinishedKind) -> Result<Option<Discarded>, BeginError> {
        match own {
            INIT => begin_initialization(&self.state, &self.config, fs),
            IMPORT => begin_import(&self.state, &self.config, fs),
        }
    }

    /// Asserts that only `own`'s marker and the lock files are left.
    fn assert_only_marker(&self, fs: &impl StoreFs, own: UnfinishedKind, context: &str) {
        let mut expected = [own.marker().to_string(), "lock".to_owned()];
        expected.sort();
        assert_eq!(self.state_names(fs), expected, "{context}");
        assert_eq!(self.config_names(fs), ["config.toml.lock"], "{context}");
    }
}

#[test]
fn every_file_an_import_writes_beside_its_marker_is_unfinished_import() {
    let dirs = Dirs::new("import-classify");
    dirs.crashed_import(&OsFs);
    assert_eq!(dirs.read(&OsFs), InitializationState::Unfinished(IMPORT));
    let marker_alone = Dirs::new("import-marker");
    marker_alone.put_bytes(&OsFs, "import.unfinished", b"");
    assert_eq!(marker_alone.read(&OsFs), InitializationState::Unfinished(IMPORT));
}

#[test]
fn a_config_file_but_config_toml_makes_an_unfinished_import_unrecognized() {
    [ActiveSignature, Pending, StagedSignature].into_iter().for_each(|file| {
        let dirs = Dirs::new("import-config");
        dirs.crashed_import(&OsFs);
        dirs.put_config(&OsFs, file, b"x");
        assert_eq!(dirs.read(&OsFs), InitializationState::Unrecognized, "{file}");
        let expected = InitStateError::Unrecognized {
            files: vec![file.to_string()],
        };
        assert_eq!(dirs.begin_as(&OsFs, IMPORT).map_err(|e| e.cause), Err(expected));
    });
}

#[test]
fn foreign_staged_and_tpm_files_and_both_markers_make_an_unfinished_import_unrecognized() {
    ["notes.txt", "recipients.age.staged", TPM_BLOB, "init.unfinished"]
        .into_iter()
        .for_each(|name| {
            let dirs = Dirs::new("import-unrecognized");
            dirs.crashed_import(&OsFs);
            dirs.put(&OsFs, name);
            assert_eq!(dirs.read(&OsFs), InitializationState::Unrecognized, "{name}");
            let before = (dirs.state_names(&OsFs), dirs.config_names(&OsFs));
            let error = dirs.begin_as(&OsFs, IMPORT).unwrap_err();
            assert!(
                matches!(error.cause, InitStateError::Unrecognized { .. }) && error.discarded.is_none(),
                "{name}"
            );
            assert_eq!((dirs.state_names(&OsFs), dirs.config_names(&OsFs)), before, "{name}");
        });
}

#[test]
fn the_reset_marker_beside_either_marker_is_unfinished_reset() {
    [INIT, IMPORT].into_iter().for_each(|kind| {
        let dirs = Dirs::new("import-reset-marker");
        dirs.crashed(&OsFs, kind);
        dirs.put(&OsFs, "reset.unfinished");
        assert_eq!(dirs.read(&OsFs), InitializationState::UnfinishedReset);
        [INIT, IMPORT].into_iter().for_each(|own| {
            assert_eq!(dirs.begin_as(&OsFs, own).map_err(|e| e.cause), Err(InitStateError::ResetUnfinished));
        });
    });
}

#[test]
fn either_command_discards_either_kind_and_keeps_only_its_own_marker() {
    [INIT, IMPORT].into_iter().for_each(|found| {
        [INIT, IMPORT].into_iter().for_each(|own| {
            let dirs = Dirs::new("import-swap");
            dirs.crashed(&OsFs, found);
            let discarded = dirs.begin_as(&OsFs, own).unwrap().unwrap();
            assert_eq!(discarded.kind, found);
            assert_eq!(
                discarded.files.contains(&found.marker().to_string()),
                found != own,
                "{found:?} by {own:?}"
            );
            dirs.assert_only_marker(&OsFs, own, &format!("{found:?} by {own:?}"));
            assert_eq!(dirs.read(&OsFs), InitializationState::Unfinished(own));
        });
    });
}

#[test]
fn the_discard_of_an_import_removes_what_is_there_in_order_and_config_toml_whatever_its_bytes() {
    let dirs = Dirs::new("import-order");
    dirs.crashed_import(&OsFs);
    let discarded = dirs.begin_as(&OsFs, IMPORT).unwrap().unwrap();
    let mut expected = vec!["config.toml".to_owned()];
    expected.extend(
        IMPORT_FILES
            .iter()
            .filter(|name| **name != "config.toml")
            .map(|name| (*name).to_owned()),
    );
    assert_eq!(discarded.files, expected);
    let partial = Dirs::new("import-order-partial");
    partial.put_bytes(&OsFs, "import.unfinished", b"");
    partial.put(&OsFs, "identity.age");
    assert_eq!(partial.begin_as(&OsFs, IMPORT).unwrap().unwrap().files, ["identity.age"]);
}

#[test]
fn the_import_discard_names_are_all_store_owned() {
    let listing: Vec<_> = IMPORT_FILES
        .iter()
        .filter(|name| **name != "config.toml")
        .map(|name| StateFileName::new(name).unwrap())
        .collect();
    let files = import_files(&listing);
    assert_eq!(files.len(), IMPORT_FILES.len() - 1);
    files.iter().for_each(|name| assert!(is_store_owned(name), "{name}"));
}

#[test]
fn a_leftover_recovery_record_and_owner_lock_go_before_the_marker_is_written() {
    let dirs = Dirs::new("import-leftover");
    let fs = dirs.fault_fs();
    dirs.put(&fs, "recovery.toml");
    dirs.put(&fs, "locked-by-owner");
    assert_eq!(dirs.read(&fs), InitializationState::Uninitialized);
    let base = fs.trace().len();
    assert_eq!(begin_import(&dirs.state, &dirs.config, &fs).unwrap(), None);
    let ops: Vec<_> = fs.trace()[base..].iter().map(FsCall::op).collect();
    let (first_remove, first_rename) = (
        ops.iter().position(|op| *op == FsOp::RemoveFile),
        ops.iter().position(|op| *op == FsOp::Rename),
    );
    assert!(first_remove < first_rename, "{ops:?}");
    dirs.assert_only_marker(&fs, IMPORT, "uninitialized");
}

/// Checks that a failed or interrupted discard leaves a directory a second run completes from: Unfinished of either
/// kind, or Uninitialized once the other marker is gone; never Unrecognized or Initialized.
fn assert_resumable(dirs: &Dirs, fs: &FaultFs, own: UnfinishedKind, context: &str) {
    let state = dirs.read(fs);
    assert!(
        matches!(state, InitializationState::Uninitialized | InitializationState::Unfinished(_)),
        "{context}: {state:?}"
    );
    dirs.begin_as(fs, own).unwrap_or_else(|e| panic!("{context}: {e:?}"));
    dirs.assert_only_marker(fs, own, context);
}

#[test]
fn a_discard_or_marker_swap_failing_at_any_call_leaves_a_state_a_second_run_completes() {
    [INIT, IMPORT].into_iter().for_each(|found| {
        [INIT, IMPORT].into_iter().for_each(|own| {
            let dirs = Dirs::new("import-fault");
            let probe = dirs.fault_fs();
            dirs.crashed(&probe, found);
            let base = probe.trace().len();
            dirs.begin_as(&probe, own).unwrap();
            let calls = probe.trace().len() - base;
            assert!(calls >= 10, "{calls}");
            (0..calls).for_each(|i| {
                let context = format!("{found:?} by {own:?}, call {i}");
                let fs = dirs.fault_fs();
                dirs.crashed(&fs, found);
                fs.fail_call(fs.trace().len() + i, io::ErrorKind::Other);
                assert!(dirs.begin_as(&fs, own).is_err(), "{context}");
                assert_resumable(&dirs, &fs, own, &context);
            });
        });
    });
}

#[test]
fn a_power_cut_during_a_discard_or_marker_swap_leaves_a_state_a_second_run_completes() {
    [INIT, IMPORT].into_iter().for_each(|found| {
        [INIT, IMPORT].into_iter().for_each(|own| {
            let dirs = Dirs::new("import-cut");
            let probe = dirs.fault_fs();
            dirs.crashed(&probe, found);
            let base = probe.trace().len();
            dirs.begin_as(&probe, own).unwrap();
            (0..probe.trace().len() - base).for_each(|cut| {
                let context = format!("{found:?} by {own:?}, cut {cut}");
                let fs = dirs.fault_fs();
                dirs.crashed(&fs, found);
                fs.cut_power_after(fs.trace().len() + cut);
                assert!(dirs.begin_as(&fs, own).is_err(), "{context}");
                fs.crash();
                assert_resumable(&dirs, &fs, own, &context);
            });
        });
    });
}

#[test]
fn a_discard_failing_part_way_names_its_kind_and_the_files_it_removed() {
    let dirs = Dirs::new("import-fail-names");
    let fs = dirs.fault_fs();
    dirs.crashed_import(&fs);
    fs.fail_first(FsOp::RemoveFile, io::ErrorKind::Other);
    let error = dirs.begin_as(&fs, INIT).unwrap_err();
    assert_eq!(
        error.discarded,
        Some(Discarded {
            kind: IMPORT,
            files: Vec::new()
        })
    );
}

#[test]
fn unlock_refuses_an_unfinished_import_by_name_before_reading_anything() {
    let dirs = Dirs::new("import-unlock");
    let fs = FaultFs::new();
    dirs.crashed_import(&fs);
    let base = fs.trace().len();
    let error = unlock_with_passphrase(&dirs.state, &fs, &passphrase()).unwrap_err();
    assert_eq!(error, UnlockError::ImportUnfinished);
    let text = error.to_string();
    assert!(
        text.contains("unfinished") && text.contains("iron-vault import") && text.contains("iron-vault init"),
        "{text}"
    );
    assert_eq!(fs.trace()[base..], [FsCall::ListDir(dirs.state_dir.path().to_path_buf())]);
    assert_eq!(
        require_initialized(&dirs.state, &dirs.config, &fs),
        Err(UnlockError::ImportUnfinished)
    );
}

#[test]
fn finish_import_removes_the_marker_and_reports_a_failed_directory_fsync_as_uncertain() {
    let dirs = Dirs::new("import-finish");
    let outcomes = fail_each_call(
        &dirs,
        |fs| dirs.put_import_marker_and_manifest(fs),
        |fs| finish_import(&dirs.state, fs),
    );
    assert_eq!(outcomes.len(), 2, "{outcomes:?}");
    assert!(matches!(
        &outcomes[0],
        (0, InitStateError::State(_), InitializationState::Unfinished(IMPORT))
    ));
    assert!(matches!(
        &outcomes[1],
        (1, InitStateError::ImportFinishUncertain { .. }, InitializationState::Initialized)
    ));
}

impl Dirs {
    fn put_import_marker_and_manifest(&self, fs: &impl StoreFs) {
        self.put_bytes(fs, "import.unfinished", b"");
        self.put(fs, "manifest.age");
    }
}
