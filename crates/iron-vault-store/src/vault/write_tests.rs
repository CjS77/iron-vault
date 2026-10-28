//! Vault writes end to end, and under an injected failure or a power cut at every file-system step.

use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;

use iron_vault_policy::Port;
use secrecy::ExposeSecret;
use tracing::Level;

use super::tests::{assert_no_secret_logged, capture_logs, identity, init_test_tracing, n, record, sealed, secret};
use super::*;
use crate::fault_fs::{FaultFs, FsCall, FsOp};
use crate::test_dir::TestDir;
use crate::{OsFs, PermittedOrigins, RecordId, StateGeneration, WriteStep, durable_remove, durable_replace};

/// The credentials every vault under test starts with.
const SEEDED: [&str; 2] = ["keep", "target"];

/// Credential name to stored key: what a reopened vault holds, compared across crash points whatever the record IDs.
type State = BTreeMap<String, String>;

/// One vault write under test, run against a vault seeded with [`SEEDED`].
type Op = fn(&Setup, &FaultFs, &mut Vault) -> Result<(), VaultError>;

/// The key `name` holds at `version`; it starts with [`secret`], so log checks find it.
fn key(name: &str, version: u32) -> String {
    format!("{}-v{version}", secret(name))
}

fn material(name: &str, version: u32) -> CredentialMaterial {
    CredentialMaterial::Static {
        key: key(name, version).into(),
    }
}

fn origins(name: &str) -> PermittedOrigins {
    let host = format!("api.{}.example", name.replace('_', "-"));
    PermittedOrigins::new([(n(&host), Port::HTTPS)].into()).unwrap()
}

fn state(vault: &Vault) -> State {
    let key_of = |record: &CredentialRecord| match record.material() {
        CredentialMaterial::Static { key } => key.expose_secret().to_owned(),
        CredentialMaterial::Basic { .. } => unreachable!("tests store static keys only"),
    };
    vault
        .healthy
        .iter()
        .map(|(name, record)| (name.as_str().to_owned(), key_of(record)))
        .collect()
}

fn expected(pairs: &[(&str, u32)]) -> State {
    pairs
        .iter()
        .map(|(name, version)| (name.to_string(), key(name, *version)))
        .collect()
}

/// Everything a failed write must leave exactly as it was.
fn snapshot(vault: &Vault) -> (VaultManifest, State) {
    (vault.manifest.clone(), state(vault))
}

/// The calls since call `from` that changed a directory entry: created, renamed or removed a file.
fn mutations(fs: &FaultFs, from: usize) -> Vec<FsCall> {
    let changes = [FsOp::CreatePrivate, FsOp::Rename, FsOp::RemoveFile];
    fs.trace()
        .split_off(from)
        .into_iter()
        .filter(|call| changes.contains(&call.op()))
        .collect()
}

/// A locked state directory whose files live in a [`FaultFs`] under the same path.
struct Setup {
    dir: TestDir,
    lock: StateDirLock,
}

impl Setup {
    fn new(label: &str) -> Self {
        init_test_tracing();
        let dir = TestDir::new(label);
        let lock = StateDirLock::acquire(dir.path()).unwrap();
        Self { dir, lock }
    }

    fn path(&self, file: &StateFileName) -> PathBuf {
        self.dir.path().join(file.as_str())
    }

    fn record_path(&self, id: RecordId) -> PathBuf {
        self.path(&StateFileName::record(&id))
    }

    fn manifest_path(&self) -> PathBuf {
        self.path(&StateFileName::manifest())
    }

    fn open(&self, fs: &impl StoreFs) -> Result<(Vault, OpenReport), VaultError> {
        Vault::open(&self.lock, fs, identity())
    }

    fn add(&self, fs: &impl StoreFs, vault: &mut Vault, name: &str, version: u32) -> Result<(RecordId, WriteReport), VaultError> {
        vault.add(&self.lock, fs, None, n(name), material(name, version), origins(name))
    }

    fn replace(&self, fs: &impl StoreFs, vault: &mut Vault, name: &str, version: u32) -> Result<(RecordId, WriteReport), VaultError> {
        vault.replace(&self.lock, fs, None, n(name), material(name, version), origins(name))
    }

    /// A fresh vault holding version 1 of each of `names`, all durable.
    fn seeded(&self, names: &[&str]) -> (FaultFs, Vault) {
        let fs = FaultFs::new();
        let mut vault = Vault::create(&self.lock, &fs, identity()).unwrap();
        names.iter().for_each(|name| {
            self.add(&fs, &mut vault, name, 1).unwrap();
        });
        (fs, vault)
    }

    /// The calls `op` makes on a freshly seeded vault, numbered from 0.
    fn op_trace(&self, op: Op) -> Vec<FsCall> {
        let (fs, mut vault) = self.seeded(&SEEDED);
        let base = fs.trace().len();
        op(self, &fs, &mut vault).unwrap();
        fs.trace().split_off(base)
    }

    /// The index in `trace` of the commit point: the rename of the new manifest into place.
    fn commit_index(&self, trace: &[FsCall]) -> usize {
        let manifest = self.manifest_path();
        trace
            .iter()
            .position(|c| matches!(c, FsCall::Rename { to, .. } if *to == manifest))
            .unwrap()
    }

    /// Reopens after an interrupted write and checks the vault is whole: no record the manifest lists is damaged, at
    /// most one unindexed file remains, and the next write removes it. Returns what the reopened vault held.
    fn reopen_whole(&self, fs: &FaultFs, context: &str) -> State {
        let (mut vault, report) = self.open(fs).unwrap_or_else(|e| panic!("{context}: {e}"));
        assert!(report.damaged().is_empty(), "{context}: {report:?}");
        assert!(report.unindexed().len() <= 1, "{context}: {report:?}");
        let state = state(&vault);
        let (_, written) = self.add(fs, &mut vault, "probe", 1).unwrap();
        assert_eq!(written.removed_unindexed(), report.unindexed(), "{context}");
        let (_, after) = self.open(fs).unwrap();
        assert_eq!(after, OpenReport::default(), "{context}");
        state
    }
}

fn add_fresh(setup: &Setup, fs: &FaultFs, vault: &mut Vault) -> Result<(), VaultError> {
    setup.add(fs, vault, "fresh", 1).map(|_| ())
}

fn replace_target(setup: &Setup, fs: &FaultFs, vault: &mut Vault) -> Result<(), VaultError> {
    setup.replace(fs, vault, "target", 2).map(|_| ())
}

fn remove_target(setup: &Setup, fs: &FaultFs, vault: &mut Vault) -> Result<(), VaultError> {
    vault.remove(&setup.lock, fs, None, &n("target")).map(|_| ())
}

/// Each operation, with the state it starts from and the state it commits.
fn operations() -> [(&'static str, Op, State, State); 3] {
    let old = expected(&[("keep", 1), ("target", 1)]);
    [
        (
            "add",
            add_fresh as Op,
            old.clone(),
            expected(&[("fresh", 1), ("keep", 1), ("target", 1)]),
        ),
        ("replace", replace_target, old.clone(), expected(&[("keep", 1), ("target", 2)])),
        ("remove", remove_target, old, expected(&[("keep", 1)])),
    ]
}

#[test]
fn add_replace_and_remove_work_end_to_end_on_disk() {
    let setup = Setup::new("write-e2e");
    let fs = OsFs;
    let mut vault = Vault::create(&setup.lock, &fs, identity()).unwrap();
    let (fx_v1, _) = setup.add(&fs, &mut vault, "fx_key", 1).unwrap();
    setup.add(&fs, &mut vault, "brave", 1).unwrap();
    let (opened, _) = setup.open(&fs).unwrap();
    assert_eq!(state(&opened), expected(&[("brave", 1), ("fx_key", 1)]));

    let (fx_v2, report) = setup.replace(&fs, &mut vault, "fx_key", 2).unwrap();
    assert_eq!(report, WriteReport::default());
    assert_ne!(fx_v1, fx_v2);
    assert!(!setup.record_path(fx_v1).exists() && setup.record_path(fx_v2).exists());
    assert_eq!(vault.remove(&setup.lock, &fs, None, &n("brave")).unwrap(), WriteReport::default());

    let (opened, report) = setup.open(&fs).unwrap();
    assert_eq!(report, OpenReport::default());
    assert_eq!(state(&opened), expected(&[("fx_key", 2)]));
    assert_eq!(state(&vault), state(&opened));
    assert_eq!(opened.manifest(), vault.manifest());
    assert_eq!(opened.manifest().state_generation(), StateGeneration::new(5).unwrap());
    let on_disk: BTreeSet<String> = fs
        .list_dir(setup.dir.path())
        .unwrap()
        .into_iter()
        .map(|f| f.into_string().unwrap())
        .collect();
    let wanted: BTreeSet<String> = ["lock", "manifest.age", StateFileName::record(&fx_v2).as_str()]
        .map(str::to_owned)
        .into();
    assert_eq!(on_disk, wanted);
}

#[test]
fn create_writes_an_empty_manifest_at_the_first_state_generation() {
    let setup = Setup::new("write-create");
    let fs = FaultFs::new();
    let vault = Vault::create(&setup.lock, &fs, identity()).unwrap();
    let manifest = vault.manifest();
    assert_eq!(
        (manifest.state_generation(), manifest.peer_generation(), manifest.entries().len()),
        (StateGeneration::FIRST, None, 0)
    );
    fs.crash();
    let (opened, report) = setup.open(&fs).unwrap();
    assert_eq!((opened.manifest(), report), (vault.manifest(), OpenReport::default()));
}

#[test]
fn create_refuses_a_state_directory_with_a_manifest_or_record_files() {
    let setup = Setup::new("write-create-existing");
    let (fs, _) = setup.seeded(&[]);
    assert_eq!(
        Vault::create(&setup.lock, &fs, identity()).unwrap_err(),
        VaultError::AlreadyInitialized
    );

    let stray = record("stray");
    let fs = FaultFs::new().with_durable_file(&setup.record_path(stray.id()), &sealed(&stray));
    let damage = SharedStateDamage::MissingWithRecords;
    let refused = VaultError::SharedStateDamaged {
        file: StateFileName::manifest(),
        damage,
    };
    assert_eq!(Vault::create(&setup.lock, &fs, identity()).unwrap_err(), refused);
    assert!(fs.trace().iter().all(|call| call.op() == FsOp::ListDir), "{:?}", fs.trace());
}

#[test]
fn create_refuses_a_state_directory_with_leftover_approval_state() {
    let setup = Setup::new("write-create-approval");
    let approval = setup.dir.path().join(StateFileName::approval_state().as_str());
    let fs = FaultFs::new().with_durable_file(&approval, b"leftover");
    let refused = VaultError::SharedStateDamaged {
        file: StateFileName::manifest(),
        damage: SharedStateDamage::MissingWithApprovalState,
    };
    assert_eq!(Vault::create(&setup.lock, &fs, identity()).unwrap_err(), refused);
    assert!(fs.trace().iter().all(|call| call.op() == FsOp::ListDir), "{:?}", fs.trace());
}

#[test]
fn adding_an_existing_name_fails_and_touches_no_file() {
    let setup = Setup::new("write-name-taken");
    let (fs, mut vault) = setup.seeded(&SEEDED);
    let before = (fs.trace().len(), snapshot(&vault));
    assert_eq!(
        setup.add(&fs, &mut vault, "target", 2).unwrap_err(),
        VaultError::NameTaken(n("target"))
    );
    assert_eq!((fs.trace().len(), snapshot(&vault)), before);
}

#[test]
fn a_damaged_name_is_taken_and_replace_repairs_it() {
    let setup = Setup::new("write-repair");
    let (fs, vault) = setup.seeded(&SEEDED);
    let target = vault.record_id_of(&n("target")).unwrap();
    fs.remove_file(&setup.record_path(target)).unwrap();
    let (mut vault, report) = setup.open(&fs).unwrap();
    assert_eq!(report.damaged().get(&n("target")), Some(&RecordDamage::Missing));

    assert_eq!(
        setup.add(&fs, &mut vault, "target", 2).unwrap_err(),
        VaultError::NameTaken(n("target"))
    );
    let (repaired, report) = setup.replace(&fs, &mut vault, "target", 2).unwrap();
    assert_eq!(report, WriteReport::default());
    assert_ne!(repaired, target);
    let (opened, report) = setup.open(&fs).unwrap();
    assert_eq!(report, OpenReport::default());
    assert_eq!(state(&opened), expected(&[("keep", 1), ("target", 2)]));
}

#[test]
fn replace_and_remove_refuse_an_unknown_name_and_touch_no_file() {
    let setup = Setup::new("write-unknown");
    let (fs, mut vault) = setup.seeded(&SEEDED);
    let before = (fs.trace().len(), snapshot(&vault));
    assert_eq!(
        setup.replace(&fs, &mut vault, "venice", 1).unwrap_err(),
        VaultError::UnknownName(n("venice"))
    );
    assert_eq!(
        vault.remove(&setup.lock, &fs, None, &n("venice")).unwrap_err(),
        VaultError::UnknownName(n("venice"))
    );
    assert_eq!((fs.trace().len(), snapshot(&vault)), before);
}

#[test]
fn invalid_material_touches_no_file() {
    let setup = Setup::new("write-invalid");
    let (fs, mut vault) = setup.seeded(&SEEDED);
    let before = (fs.trace().len(), snapshot(&vault));
    let material = CredentialMaterial::Basic {
        username: "a:b".into(),
        password: "p".into(),
    };
    let error = vault
        .add(&setup.lock, &fs, None, n("basic"), material, origins("basic"))
        .unwrap_err();
    assert!(matches!(error, VaultError::InvalidMaterial(_)), "{error}");
    assert_eq!((fs.trace().len(), snapshot(&vault)), before);
}

#[test]
fn a_write_first_removes_unindexed_files_and_reports_them() {
    let setup = Setup::new("write-unindexed");
    let (fs, _) = setup.seeded(&SEEDED);
    let planted = record("planted");
    let file = StateFileName::record(&planted.id());
    let fs = fs.with_durable_file(&setup.path(&file), &sealed(&planted));
    let (mut vault, report) = setup.open(&fs).unwrap();
    assert_eq!(report.unindexed(), &[file.clone()].into());

    let (written, events) = capture_logs(|| setup.add(&fs, &mut vault, "fresh", 1));
    let (_, written) = written.unwrap();
    assert_eq!(written.removed_unindexed(), &[file.clone()].into());
    assert_eq!(fs.contents(&setup.path(&file)), None);
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!((events[0].level, events[0].field("file")), (Level::WARN, file.as_str()));
    assert_no_secret_logged(&events, &["planted", "fresh"]);
    let (_, report) = setup.open(&fs).unwrap();
    assert_eq!(report, OpenReport::default());
}

#[test]
fn a_superseded_file_that_cannot_be_removed_is_reported_and_removed_by_the_next_write() {
    let setup = Setup::new("write-left");
    let (fs, mut vault) = setup.seeded(&SEEDED);
    let old = StateFileName::record(&vault.record_id_of(&n("target")).unwrap());
    fs.fail_first(FsOp::RemoveFile, io::ErrorKind::PermissionDenied);
    let (written, events) = capture_logs(|| setup.replace(&fs, &mut vault, "target", 2));
    let (_, written) = written.unwrap();
    assert_eq!(written.left_unindexed(), Some(&old));
    assert_eq!(state(&vault), expected(&[("keep", 1), ("target", 2)]));
    assert_eq!(
        (events.len(), events[0].level, events[0].field("file")),
        (1, Level::WARN, old.as_str())
    );
    assert_no_secret_logged(&events, &SEEDED);

    let (_, next) = setup.add(&fs, &mut vault, "fresh", 1).unwrap();
    assert_eq!(next.removed_unindexed(), &[old].into());
    let (_, report) = setup.open(&fs).unwrap();
    assert_eq!(report, OpenReport::default());
}

#[test]
fn an_uncertain_commit_leaves_memory_unchanged_and_blocks_writes_until_reopen() {
    let setup = Setup::new("write-uncertain");
    operations().into_iter().for_each(|(label, op, old, new)| {
        let trace = setup.op_trace(op);
        let sync = setup.commit_index(&trace) + 1;
        assert_eq!(trace[sync].op(), FsOp::SyncDir, "{label}");

        let (fs, mut vault) = setup.seeded(&SEEDED);
        let before = snapshot(&vault);
        fs.fail_call(fs.trace().len() + sync, io::ErrorKind::StorageFull);
        let (result, events) = capture_logs(|| op(&setup, &fs, &mut vault));
        assert!(
            matches!(
                result,
                Err(VaultError::CommitUncertain(WriteError::Io {
                    step: WriteStep::SyncDir,
                    ..
                }))
            ),
            "{label}"
        );
        assert_eq!(events.iter().filter(|e| e.level == Level::ERROR).count(), 1, "{label}: {events:?}");
        assert_eq!(snapshot(&vault), (before.0, old), "{label}");
        let calls = fs.trace().len();
        assert_eq!(
            setup.add(&fs, &mut vault, "other", 1).unwrap_err(),
            VaultError::ReopenRequired,
            "{label}"
        );
        assert_eq!(mutations(&fs, calls), [], "{label}");
        // The rename happened, so a reopen without a crash sees the new vault.
        assert_eq!(setup.reopen_whole(&fs, label), new, "{label}");
    });
}

#[test]
fn a_failure_at_every_step_leaves_the_old_or_the_new_vault() {
    let setup = Setup::new("write-faults");
    operations().into_iter().for_each(|(label, op, old, new)| {
        (0..setup.op_trace(op).len()).for_each(|i| {
            let context = format!("{label}, fault at call {i}");
            let (fs, mut vault) = setup.seeded(&SEEDED);
            let before = snapshot(&vault);
            fs.fail_call(fs.trace().len() + i, io::ErrorKind::StorageFull);
            let result = op(&setup, &fs, &mut vault);
            let on_disk = match &result {
                Ok(()) => {
                    assert_eq!(state(&vault), new, "{context}");
                    &new
                }
                Err(VaultError::CommitUncertain(_)) => {
                    assert_eq!(snapshot(&vault), (before.0.clone(), old.clone()), "{context}");
                    &new
                }
                Err(_) => {
                    assert_eq!(snapshot(&vault), before, "{context}");
                    &old
                }
            };
            let (reopened, _) = setup.open(&fs).unwrap();
            assert_eq!(&state(&reopened), on_disk, "{context}");
            fs.crash();
            let after_crash = setup.reopen_whole(&fs, &context);
            assert!(after_crash == old || after_crash == new, "{context}: {after_crash:?}");
        });
    });
}

#[test]
fn a_crash_at_every_point_leaves_the_old_or_the_new_vault() {
    let setup = Setup::new("write-crash");
    operations().into_iter().for_each(|(label, op, old, new)| {
        (0..=setup.op_trace(op).len()).for_each(|k| {
            let context = format!("{label}, power cut after {k} calls");
            let (fs, mut vault) = setup.seeded(&SEEDED);
            fs.cut_power_after(fs.trace().len() + k);
            let result = op(&setup, &fs, &mut vault);
            fs.crash();
            let state = setup.reopen_whole(&fs, &context);
            assert!(state == old || state == new, "{context}: {state:?}");
            assert!(result.is_err() || state == new, "{context}: a write that returned Ok was lost");
        });
    });
}

#[test]
fn a_crash_during_create_or_the_first_add_never_loses_the_manifest() {
    let setup = Setup::new("write-create-crash");
    let run = |fs: &FaultFs| Vault::create(&setup.lock, fs, identity()).and_then(|mut vault| setup.add(fs, &mut vault, "fx_key", 1));
    let len = {
        let fs = FaultFs::new();
        run(&fs).unwrap();
        fs.trace().len()
    };
    (0..=len).for_each(|k| {
        let context = format!("power cut after {k} calls");
        let fs = FaultFs::new();
        fs.cut_power_after(k);
        let result = run(&fs);
        fs.crash();
        match setup.open(&fs) {
            Err(VaultError::NotInitialized) => assert!(result.is_err(), "{context}"),
            Ok(_) => {
                let state = setup.reopen_whole(&fs, &context);
                assert!(state.is_empty() || state == expected(&[("fx_key", 1)]), "{context}: {state:?}");
                assert!(result.is_err() || !state.is_empty(), "{context}: an add that returned Ok was lost");
            }
            Err(other) => panic!("{context}: {other}"),
        }
    });
}

#[test]
fn record_files_are_written_before_the_commit_and_removed_after_it() {
    let setup = Setup::new("write-order");
    operations().into_iter().for_each(|(label, op, _, _)| {
        let trace = setup.op_trace(op);
        let commit = setup.commit_index(&trace);
        trace.iter().enumerate().for_each(|(i, call)| match call {
            FsCall::Rename { .. } => assert!(i <= commit, "{label}: a file was renamed into place after the commit"),
            FsCall::RemoveFile(_) => assert!(i > commit, "{label}: a file was removed before the commit"),
            _ => {}
        });
    });
}

#[test]
fn a_stale_vault_on_the_same_lock_removes_no_record_file() {
    let setup = Setup::new("write-stale");
    let (fs, mut current) = setup.seeded(&SEEDED);
    let (mut stale, _) = setup.open(&fs).unwrap();
    let (fresh, _) = setup.add(&fs, &mut current, "fresh", 1).unwrap();

    // The stale vault's manifest does not list `fresh`, so without the disk check its cleanup would remove it.
    let calls = fs.trace().len();
    assert_eq!(setup.add(&fs, &mut stale, "other", 1).unwrap_err(), VaultError::ReopenRequired);
    assert_eq!(setup.replace(&fs, &mut stale, "target", 2).unwrap_err(), VaultError::ReopenRequired);
    assert_eq!(
        stale.remove(&setup.lock, &fs, None, &n("keep")).unwrap_err(),
        VaultError::ReopenRequired
    );
    assert_eq!(mutations(&fs, calls), []);
    assert!(fs.contents(&setup.record_path(fresh)).is_some());
    let (opened, report) = setup.open(&fs).unwrap();
    assert_eq!(report, OpenReport::default());
    assert_eq!(state(&opened), expected(&[("fresh", 1), ("keep", 1), ("target", 1)]));
}

#[test]
fn a_write_refuses_when_the_disk_manifest_is_gone_or_damaged() {
    let setup = Setup::new("write-disk-manifest");
    let manifest = StateFileName::manifest();
    [true, false].into_iter().for_each(|gone| {
        let (fs, mut vault) = setup.seeded(&SEEDED);
        match gone {
            true => durable_remove(&setup.lock, &fs, &manifest).unwrap(),
            false => {
                let mut bytes = fs.contents(&setup.manifest_path()).unwrap();
                let last = bytes.len() - 1;
                bytes[last] ^= 1;
                durable_replace(&setup.lock, &fs, &manifest, &bytes).unwrap();
            }
        }
        let calls = fs.trace().len();
        assert_eq!(
            setup.add(&fs, &mut vault, "fresh", 1).unwrap_err(),
            VaultError::ReopenRequired,
            "gone: {gone}"
        );
        assert_eq!(mutations(&fs, calls), [], "gone: {gone}");
    });
}

#[test]
fn a_vault_given_another_directorys_lock_touches_no_file() {
    let (ours, theirs) = (Setup::new("write-dir-ours"), Setup::new("write-dir-theirs"));
    let fs = FaultFs::new();
    let mut vault = Vault::create(&ours.lock, &fs, identity()).unwrap();
    let mut other = Vault::create(&theirs.lock, &fs, identity()).unwrap();
    let (theirs_keep, _) = theirs.add(&fs, &mut other, "keep", 1).unwrap();

    let calls = fs.trace().len();
    let wrong = VaultError::WrongStateDir {
        vault_dir: ours.dir.path().to_path_buf(),
        lock_dir: theirs.dir.path().to_path_buf(),
    };
    // `theirs` is the Setup whose lock is passed; `ours` built the vault.
    assert_eq!(theirs.add(&fs, &mut vault, "fresh", 1).unwrap_err(), wrong);
    assert_eq!(theirs.replace(&fs, &mut vault, "keep", 2).unwrap_err(), wrong);
    assert_eq!(vault.remove(&theirs.lock, &fs, None, &n("keep")).unwrap_err(), wrong);
    assert_eq!(fs.trace().len(), calls);
    assert!(fs.contents(&theirs.record_path(theirs_keep)).is_some());
    assert!(wrong.to_string().contains(&theirs.dir.path().display().to_string()), "{wrong}");
}

#[test]
fn a_short_secret_is_written_and_warned_about_without_its_value() {
    let setup = Setup::new("write-short-secret");
    let (fs, mut vault) = setup.seeded(&SEEDED);
    let short = CredentialMaterial::Static { key: "q7z".into() };
    let (added, events) = capture_logs(|| vault.add(&setup.lock, &fs, None, n("stripe"), short, origins("stripe")));
    added.unwrap();
    let warnings: Vec<_> = events.iter().filter(|event| event.level == Level::WARN).collect();
    assert_eq!(warnings.len(), 1, "{events:?}");
    assert_eq!((warnings[0].field("credential"), warnings[0].field("field")), ("stripe", "API key"));
    assert_eq!(warnings[0].field("len"), "3");
    assert!(
        warnings[0]
            .field("message")
            .contains("credential `stripe`: the API key is 3 bytes long")
    );
    assert!(!format!("{events:?}").contains("q7z"), "{events:?}");

    let password = CredentialMaterial::Basic {
        username: "long-username".into(),
        password: "z9q".into(),
    };
    let (replaced, events) = capture_logs(|| vault.replace(&setup.lock, &fs, None, n("stripe"), password, origins("stripe")));
    replaced.unwrap();
    let fields: Vec<_> = events.iter().filter(|e| e.level == Level::WARN).map(|e| e.field("field")).collect();
    assert_eq!(fields, ["password"]);
    assert!(!format!("{events:?}").contains("z9q"), "{events:?}");
}

#[test]
fn a_long_secret_logs_no_warning() {
    let setup = Setup::new("write-long-secret");
    let (fs, mut vault) = setup.seeded(&SEEDED);
    let (added, events) = capture_logs(|| setup.add(&fs, &mut vault, "fx_key", 1));
    added.unwrap();
    assert!(events.iter().all(|event| event.level != Level::WARN), "{events:?}");
}
