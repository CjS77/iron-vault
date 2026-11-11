use std::io;
use std::path::Path;

use secrecy::{ExposeSecret, SecretString};

use super::*;
use crate::export_snapshot::tests::Fixture;
use crate::fault_fs::{FaultFs, FsOp};
use crate::import_check::tests::{Parts, verify_encoded};
use crate::test_dir::TestDir;
use crate::{
    OsFs, RecipientSet, StanzaKind, UnfinishedKind, Vault, read_identity_envelope, read_recipient_inventory, stanza_kinds,
    unlock_with_passphrase, unwrap_identity, write_owner_lock,
};

/// The passphrase work factor the tests seal at, so a run does not spend seconds in scrypt.
const TEST_WORK_FACTOR: u8 = 2;

const VAULT_PASSPHRASE: &str = "correct horse battery";

/// Locked destination state and config directories. The locks are real; the files live wherever the `fs` passed puts
/// them.
struct Dirs {
    state_dir: TestDir,
    config_dir: TestDir,
    state: StateDirLock,
    config: ConfigDirLock,
}

/// What a test hears from the write order.
#[derive(Debug, Default)]
struct Recorded {
    steps: Vec<ImportStep>,
    records: Vec<(ImportStep, usize, usize)>,
}

impl ImportProgress for Recorded {
    fn step(&mut self, step: ImportStep) {
        self.steps.push(step);
    }

    fn records(&mut self, step: ImportStep, done: usize, total: usize) {
        self.records.push((step, done, total));
    }
}

/// One import's outcome, with the recovery key it enrolled and the recipient set `identity.age` was wrapped for.
struct Run {
    result: Result<ImportedVault, ImportError>,
    recovery: RecipientIdentity,
    wrapped_for: RecipientSet,
    progress: Recorded,
}

impl Dirs {
    fn new(label: &str) -> Self {
        let state_dir = TestDir::new(&format!("{label}-state"));
        let config_dir = TestDir::new(&format!("{label}-config"));
        Self {
            state: StateDirLock::acquire(state_dir.path()).unwrap(),
            config: ConfigDirLock::acquire(config_dir.path()).unwrap(),
            state_dir,
            config_dir,
        }
    }

    /// A [`FaultFs`] that shows the two lock files, which are real files the fault filesystem does not see.
    fn fault_fs(&self) -> FaultFs {
        FaultFs::new()
            .with_durable_file(&self.state_dir.path().join("lock"), b"")
            .with_durable_file(&self.config_dir.path().join("config.toml.lock"), b"")
    }

    fn import(&self, fs: &impl StoreFs, encoded: &[u8]) -> Result<ImportedVault, ImportError> {
        self.import_with(fs, encoded, None).result
    }

    fn import_with(&self, fs: &impl StoreFs, encoded: &[u8], host: Option<RecipientIdentity>) -> Run {
        let (keys, secret) = ImportKeys::generate();
        let recovery = RecipientIdentity::from_secret_text(secret.expose_secret().as_bytes()).unwrap();
        let host_key = host.as_ref().map(RecipientIdentity::recipient_key);
        let wrapped_for = RecipientSet::new(
            [keys.operational.recipient_key(), recovery.recipient_key()]
                .into_iter()
                .chain(host_key),
        )
        .unwrap();
        let keys = host.into_iter().fold(keys, ImportKeys::with_host_unlock);
        let mut progress = Recorded::default();
        let result = import_vault_at(
            (&self.state, &self.config),
            fs,
            (verify_encoded(encoded).unwrap(), keys, vault_passphrase()),
            (UtcSecond::EPOCH, TEST_WORK_FACTOR),
            &mut progress,
        );
        Run {
            result,
            recovery,
            wrapped_for,
            progress,
        }
    }

    fn read(&self, fs: &impl StoreFs) -> InitializationState {
        InitializationState::read(&self.state, &self.config, fs).unwrap()
    }

    fn state_file(&self, fs: &impl StoreFs, name: &StateFileName) -> Vec<u8> {
        file(fs, self.state_dir.path(), name.as_str())
    }

    fn names(&self, fs: &impl StoreFs, dir: &Path) -> Vec<String> {
        let mut names: Vec<_> = fs.list_dir(dir).unwrap().iter().map(|n| n.to_string_lossy().into_owned()).collect();
        names.sort();
        names
    }

    /// Every file in both directories with its contents, sorted, read through `fs`.
    fn snapshot(&self, fs: &impl StoreFs) -> Vec<(String, Vec<u8>)> {
        [self.state_dir.path(), self.config_dir.path()]
            .into_iter()
            .flat_map(|dir| self.names(fs, dir).into_iter().map(move |name| (dir, name)))
            .map(|(dir, name)| {
                let bytes = fs.read_bounded(&dir.join(&name), 1 << 20).unwrap_or_default();
                (name, bytes)
            })
            .collect()
    }
}

fn file(fs: &impl StoreFs, dir: &Path, name: &str) -> Vec<u8> {
    fs.read_bounded(&dir.join(name), 1 << 20).unwrap()
}

fn vault_passphrase() -> Passphrase {
    Passphrase::new(SecretString::from(VAULT_PASSPHRASE)).unwrap()
}

/// The fixture's vault, exported as a bundle.
fn source() -> (Fixture, Vec<u8>) {
    let fixture = Fixture::new();
    let encoded = Parts::of(&fixture).encode();
    (fixture, encoded)
}

/// The vault opens with the identity the new vault passphrase unwraps, the recovery key opens the same identity, and
/// the inventory names exactly the recipients `identity.age` was wrapped for, labelled by role.
fn assert_opens(dirs: &Dirs, fs: &impl StoreFs, run: &Run, imported: &ImportedVault) {
    assert_eq!(dirs.read(fs), InitializationState::Initialized);
    let identity = unlock_with_passphrase(&dirs.state, fs, &vault_passphrase()).unwrap();
    let envelope = read_identity_envelope(&dirs.state, fs).unwrap();
    assert_eq!(
        unwrap_identity(&envelope, &run.recovery).unwrap().public_key(),
        identity.public_key()
    );
    let inventory = read_recipient_inventory(&dirs.state, fs, &identity).unwrap();
    assert_eq!(inventory.vault_id(), imported.vault_id);
    assert_eq!(inventory.recipient_set(), run.wrapped_for);
    let labels: Vec<_> = inventory.entries().map(|e| (e.role(), e.label().as_str().to_owned())).collect();
    let expected: Vec<_> = [
        (RecipientRole::Operational, "vault passphrase"),
        (RecipientRole::Recovery, "recovery key"),
        (RecipientRole::HostUnlock, "host unlock"),
    ]
    .into_iter()
    .filter(|(role, _)| imported.recipients.contains(role))
    .map(|(role, label)| (role, label.to_owned()))
    .collect();
    assert_eq!(labels.len(), expected.len());
    expected.iter().for_each(|entry| assert!(labels.contains(entry), "{labels:?}"));
    let (vault, report) = Vault::open(&dirs.state, fs, identity).unwrap();
    assert_eq!(report, Default::default());
    assert_eq!(vault.manifest().vault_id(), imported.vault_id);
}

#[test]
fn a_bundle_imports_into_an_empty_directory_byte_for_byte() {
    let (fixture, encoded) = source();
    let dirs = Dirs::new("import-run");
    let run = dirs.import_with(&OsFs, &encoded, None);
    let imported = run.result.as_ref().unwrap();
    assert_opens(&dirs, &OsFs, &run, imported);
    assert_eq!(imported.recipients, [RecipientRole::Operational, RecipientRole::Recovery]);
    assert_eq!(imported.discarded, None);
    let copied = fixture
        .records
        .iter()
        .map(StateFileName::record)
        .chain([StateFileName::approval_state(), StateFileName::manifest()]);
    copied.for_each(|name| assert_eq!(dirs.state_file(&OsFs, &name), fixture.file(&name), "{name}"));
    let bundle = verify_encoded(&encoded).unwrap();
    bundle
        .approver_keys()
        .iter()
        .for_each(|(id, envelope)| assert_eq!(&dirs.state_file(&OsFs, &StateFileName::approver_key(*id)), envelope));
    assert_eq!(file(&OsFs, dirs.config_dir.path(), "config.toml"), bundle.config());
    assert_eq!(dirs.names(&OsFs, dirs.config_dir.path()), ["config.toml", "config.toml.lock"]);
    let stanzas = stanza_kinds(&dirs.state_file(&OsFs, &StateFileName::identity_envelope())).unwrap();
    assert_eq!(stanzas.iter().filter(|k| **k == StanzaKind::X25519).count(), 2, "{stanzas:?}");
    assert!(stanzas.iter().all(StanzaKind::is_x25519_or_grease), "{stanzas:?}");
}

#[test]
fn the_counters_are_the_sources() {
    let (fixture, encoded) = source();
    let dirs = Dirs::new("import-counters");
    let imported = dirs.import(&OsFs, &encoded).unwrap();
    let (committed, digest) = fixture.held.committed().unwrap();
    assert_eq!(
        (imported.committed_version, imported.highest_reserved, imported.config_digest),
        (committed, fixture.held.highest_reserved(), digest)
    );
    assert_eq!((imported.records, imported.approvers), (3, 2));
    let identity = unlock_with_passphrase(&dirs.state, &OsFs, &vault_passphrase()).unwrap();
    let (vault, _) = Vault::open(&dirs.state, &OsFs, identity).unwrap();
    let approval = vault.load_approval_state(&dirs.state, &OsFs).unwrap();
    assert_eq!(approval.committed(), Some((committed, digest)));
    assert_eq!(approval.highest_reserved(), fixture.held.highest_reserved());
}

#[test]
fn a_host_unlock_identity_is_a_third_recipient() {
    let (_fixture, encoded) = source();
    let dirs = Dirs::new("import-host-unlock");
    let host = RecipientIdentity::generate();
    let host_copy = RecipientIdentity::from_secret_text(host.secret_text().expose_secret().as_bytes()).unwrap();
    let run = dirs.import_with(&OsFs, &encoded, Some(host));
    let imported = run.result.as_ref().unwrap();
    assert_eq!(
        imported.recipients,
        [RecipientRole::Operational, RecipientRole::Recovery, RecipientRole::HostUnlock]
    );
    assert_opens(&dirs, &OsFs, &run, imported);
    let envelope = read_identity_envelope(&dirs.state, &OsFs).unwrap();
    let identity = unlock_with_passphrase(&dirs.state, &OsFs, &vault_passphrase()).unwrap();
    assert_eq!(unwrap_identity(&envelope, &host_copy).unwrap().public_key(), identity.public_key());
}

#[test]
fn progress_is_told_of_every_step_and_every_record() {
    let (_fixture, encoded) = source();
    let dirs = Dirs::new("import-progress");
    let run = dirs.import_with(&OsFs, &encoded, None);
    run.result.unwrap();
    let numbers: Vec<_> = run.progress.steps.iter().map(|step| step.number()).collect();
    assert_eq!(numbers, (1..=10).map(Some).collect::<Vec<_>>());
    let per_record = |step| (1..=3).map(move |done| (step, done, 3));
    let expected: Vec<_> = per_record(ImportStep::Records).chain(per_record(ImportStep::Check)).collect();
    assert_eq!(run.progress.records, expected);
}

#[test]
fn leftovers_of_an_earlier_vault_are_removed_first() {
    let (_fixture, encoded) = source();
    let dirs = Dirs::new("import-leftovers");
    durable_replace(&dirs.state, &OsFs, &StateFileName::recovery_check_record(), b"left over").unwrap();
    write_owner_lock(&dirs.state, &OsFs).unwrap();
    let imported = dirs.import(&OsFs, &encoded).unwrap();
    assert_eq!(imported.discarded, None);
    let names = dirs.names(&OsFs, dirs.state_dir.path());
    assert!(!names.contains(&"recovery.toml".to_owned()), "{names:?}");
    assert!(!names.contains(&"locked-by-owner".to_owned()), "{names:?}");
}

#[test]
fn an_unfinished_initialization_is_discarded_first() {
    let (_fixture, encoded) = source();
    let dirs = Dirs::new("import-discards-init");
    durable_replace(&dirs.state, &OsFs, &StateFileName::unfinished_initialization(), b"").unwrap();
    durable_replace(&dirs.state, &OsFs, &StateFileName::identity_envelope(), b"half written").unwrap();
    let run = dirs.import_with(&OsFs, &encoded, None);
    let imported = run.result.as_ref().unwrap();
    let discarded = imported.discarded.as_ref().unwrap();
    assert_eq!(discarded.kind, UnfinishedKind::Initialization);
    assert_eq!(discarded.files, ["identity.age", "init.unfinished"]);
    assert_opens(&dirs, &OsFs, &run, imported);
}

/// Fails the unlink of `import.unfinished`, the last unlink of an import into an empty directory.
fn fail_finish_unlink(dirs: &Dirs, fs: &FaultFs, encoded: &[u8]) {
    let probe = dirs.fault_fs();
    dirs.import(&probe, encoded).unwrap();
    let last = probe.trace().iter().rposition(|call| call.op() == FsOp::RemoveFile).unwrap();
    fs.fail_call(fs.trace().len() + last, io::ErrorKind::Other);
}

#[test]
fn an_unfinished_import_is_discarded_first() {
    let (_fixture, encoded) = source();
    let dirs = Dirs::new("import-discards-import");
    let fs = dirs.fault_fs();
    fail_finish_unlink(&dirs, &fs, &encoded);
    assert_eq!(dirs.import(&fs, &encoded).unwrap_err().step(), ImportStep::Finish);
    assert_eq!(dirs.read(&fs), InitializationState::Unfinished(UnfinishedKind::Import));
    let run = dirs.import_with(&fs, &encoded, None);
    let imported = run.result.as_ref().unwrap();
    let discarded = imported.discarded.as_ref().unwrap();
    assert_eq!(discarded.kind, UnfinishedKind::Import);
    assert_eq!(discarded.files.first().map(String::as_str), Some("config.toml"));
    // config.toml, the three records, the two approver keys, and the five fixed state files an import writes.
    assert_eq!(discarded.files.len(), 1 + 3 + 2 + 5, "{discarded:?}");
    assert_opens(&dirs, &fs, &run, imported);
}

/// A directory a refused import starts from, and the refusal it expects.
type Refusal = (fn(&Dirs, &[u8]), fn(&InitStateError) -> bool);

#[test]
fn directories_import_must_not_write_to_are_refused_unchanged() {
    let (_fixture, encoded) = source();
    let cases: [Refusal; 3] = [
        (
            |dirs, encoded| drop(dirs.import(&OsFs, encoded).unwrap()),
            |e| *e == InitStateError::AlreadyInitialized,
        ),
        (
            |dirs, _| std::fs::write(dirs.state_dir.path().join("stray"), b"x").unwrap(),
            |e| matches!(e, InitStateError::Unrecognized { .. }),
        ),
        (
            |dirs, _| std::fs::write(dirs.state_dir.path().join("reset.unfinished"), b"").unwrap(),
            |e| *e == InitStateError::ResetUnfinished,
        ),
    ];
    cases.iter().for_each(|(setup, refused)| {
        let dirs = Dirs::new("import-refused");
        setup(&dirs, &encoded);
        let before = dirs.snapshot(&OsFs);
        let error = dirs.import(&OsFs, &encoded).unwrap_err();
        assert_eq!(error.step(), ImportStep::Begin);
        assert!(matches!(error.cause(), ImportFailure::State(cause) if refused(cause)), "{error:?}");
        assert_eq!(dirs.snapshot(&OsFs), before);
    });
}

#[test]
fn a_failed_directory_fsync_at_the_commit_point_names_step_10() {
    let (_fixture, encoded) = source();
    let dirs = Dirs::new("import-finish-uncertain");
    let probe = dirs.fault_fs();
    dirs.import(&probe, &encoded).unwrap();
    let unlink = probe.trace().iter().rposition(|call| call.op() == FsOp::RemoveFile).unwrap();
    let fs = dirs.fault_fs();
    fs.fail_call(unlink + 1, io::ErrorKind::Other);
    let error = dirs.import(&fs, &encoded).unwrap_err();
    assert_eq!(error.step().number(), Some(10));
    assert!(
        matches!(error.cause(), ImportFailure::State(InitStateError::ImportFinishUncertain { .. })),
        "{error:?}"
    );
    assert_eq!(dirs.read(&fs), InitializationState::Initialized);
}

/// The state a failure at `error`'s step must leave: Uninitialized or Unfinished before the marker is durable, and
/// Unfinished after it.
fn assert_left_by(dirs: &Dirs, fs: &FaultFs, error: &ImportError, call: usize) {
    let state = dirs.read(fs);
    let unfinished = InitializationState::Unfinished(UnfinishedKind::Import);
    let expected: &[InitializationState] = match error.step() {
        ImportStep::Discard | ImportStep::Begin => &[InitializationState::Uninitialized, unfinished],
        ImportStep::Finish if matches!(error.cause(), ImportFailure::State(InitStateError::ImportFinishUncertain { .. })) => {
            &[InitializationState::Initialized]
        }
        _ => &[unfinished],
    };
    assert!(expected.contains(&state), "call {call}: {error} left {state:?}");
}

/// A fault at each call of an import into an empty directory, steps 1 to 10, leaves a directory the next import
/// discards and completes.
#[test]
fn a_fault_at_any_call_is_recoverable() {
    let (_fixture, encoded) = source();
    let dirs = Dirs::new("import-faults");
    let probe = dirs.fault_fs();
    dirs.import(&probe, &encoded).unwrap();
    let calls = probe.trace().len();
    let failed: Vec<_> = (0..calls)
        .filter_map(|call| {
            let fs = dirs.fault_fs();
            fs.fail_call(call, io::ErrorKind::Other);
            let error = dirs.import(&fs, &encoded).err()?;
            assert_left_by(&dirs, &fs, &error, call);
            if dirs.read(&fs) != InitializationState::Initialized {
                dirs.import(&fs, &encoded).unwrap();
                assert_eq!(dirs.read(&fs), InitializationState::Initialized, "call {call}");
            }
            Some(error.step())
        })
        .collect();
    (1..=10).for_each(|n| {
        assert!(
            failed.iter().any(|step| step.number() == Some(n)),
            "no fault failed step {n}: {failed:?}"
        )
    });
}
