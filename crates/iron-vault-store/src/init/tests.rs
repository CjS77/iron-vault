use std::io;
use std::path::Path;

use secrecy::{ExposeSecret, SecretString};

use super::*;
use crate::fault_fs::{FaultFs, FsOp};
use crate::test_dir::TestDir;
use crate::vault::tests::capture_logs;
use crate::{
    ConfigDigest, OsFs, RecoveryKeySecret, StanzaKind, StateFileName, read_passphrase_envelope, recover_approval, stanza_kinds,
    unlock_with_passphrase,
};

/// The passphrase work factor the tests seal at, so a run does not spend seconds in scrypt.
const TEST_WORK_FACTOR: u8 = 2;

const VAULT_PASSPHRASE: &str = "correct horse battery";
const APPROVAL_PASSPHRASE: &str = "staple approval words";

struct Paused;

impl AdmissionPaused for Paused {}

/// Locked state and config directories. The locks are real; the files live wherever the `fs` passed puts them.
struct Dirs {
    state_dir: TestDir,
    config_dir: TestDir,
    state: StateDirLock,
    config: ConfigDirLock,
}

/// What the owner and the test know after the keys are generated: the recovery key's text, taken before sealing,
/// and the operational identity's text, kept only to search the files for it.
struct Secrets {
    recovery: String,
    operational: String,
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

    fn init(&self, fs: &impl StoreFs) -> Result<InitializedVault, InitError> {
        self.init_keeping(fs).0
    }

    fn init_keeping(&self, fs: &impl StoreFs) -> (Result<InitializedVault, InitError>, Secrets) {
        let keys = NewVaultKeys::generate().unwrap();
        let recovery = keys.recovery_secret().expose_secret().to_owned();
        let sealing = keys.into_sealing();
        let operational = sealing.operational.secret_text().expose_secret().to_owned();
        let result = initialize_at(&self.state, &self.config, fs, (sealing, passphrases()), &Paused, TEST_WORK_FACTOR);
        (result, Secrets { recovery, operational })
    }

    fn read(&self, fs: &impl StoreFs) -> InitializationState {
        InitializationState::read(&self.state, &self.config, fs).unwrap()
    }

    /// Every file in both directories with its contents, sorted, read through `fs`.
    fn snapshot(&self, fs: &impl StoreFs) -> Vec<(String, Vec<u8>)> {
        let mut files: Vec<_> = [self.state_dir.path(), self.config_dir.path()]
            .into_iter()
            .flat_map(|dir| files_in(fs, dir))
            .collect();
        files.sort();
        files
    }

    fn file(&self, fs: &impl StoreFs, dir: &Path, name: &str) -> Vec<u8> {
        fs.read_bounded(&dir.join(name), 1 << 20).unwrap()
    }
}

fn files_in(fs: &impl StoreFs, dir: &Path) -> Vec<(String, Vec<u8>)> {
    fs.list_dir(dir)
        .unwrap()
        .into_iter()
        .map(|name| name.to_string_lossy().into_owned())
        .map(|name| {
            let bytes = fs.read_bounded(&dir.join(&name), 1 << 20).unwrap_or_default();
            (name, bytes)
        })
        .collect()
}

fn vault_passphrase() -> Passphrase {
    Passphrase::new(SecretString::from(VAULT_PASSPHRASE)).unwrap()
}

fn approval_passphrase(text: &str) -> ApprovalPassphrase {
    ApprovalPassphrase::new(SecretString::from(text)).unwrap()
}

fn passphrases() -> InitPassphrases {
    InitPassphrases::new(vault_passphrase(), approval_passphrase(APPROVAL_PASSPHRASE)).unwrap()
}

/// Checks the vault opens by both recovery paths to the same identity, and that its approval state committed version
/// 1 on the initial config with a published pair that verifies.
fn assert_initialized(dirs: &Dirs, fs: &impl StoreFs, initialized: &InitializedVault, recovery: &str) {
    assert_eq!(dirs.read(fs), InitializationState::Initialized);
    assert_eq!(initialized.version, ApprovalVersion::FIRST);
    let identity = unlock_with_passphrase(&dirs.state, fs, &vault_passphrase()).unwrap();
    let recovery = RecoveryKeySecret::parse(SecretString::from(recovery)).unwrap();
    let recovered = unwrap_identity(&read_identity_envelope(&dirs.state, fs).unwrap(), &recovery).unwrap();
    assert_eq!(recovered.public_key(), identity.public_key());
    let (vault, report) = Vault::open(&dirs.state, fs, identity).unwrap();
    assert_eq!(report, Default::default());
    assert_eq!(vault.manifest().vault_id(), initialized.vault_id);
    let approval = vault.load_approval_state(&dirs.state, fs).unwrap();
    assert_eq!(approval.highest_reserved(), 1);
    assert_eq!(
        approval.committed(),
        Some((ApprovalVersion::FIRST, ConfigDigest::of(INITIAL_CONFIG)))
    );
    let recovered = recover_approval(&dirs.config, fs, &approval).unwrap();
    assert_eq!(recovered.published().approval().version(), ApprovalVersion::FIRST);
    assert_eq!(recovered.published().config(), INITIAL_CONFIG);
}

#[test]
fn a_fresh_directory_initializes_to_version_1() {
    let dirs = Dirs::new("init-run");
    let (result, secrets) = dirs.init_keeping(&OsFs);
    let initialized = result.unwrap();
    assert!(initialized.discarded.is_empty(), "{initialized:?}");
    assert_initialized(&dirs, &OsFs, &initialized, &secrets.recovery);
    assert_eq!(dirs.file(&OsFs, dirs.config_dir.path(), "config.toml"), INITIAL_CONFIG);
}

/// The no-mixed-recipient check: the identity envelope is X25519 for exactly the two recipients plus grease, and the
/// two passphrase-protected files are one scrypt stanza each.
#[test]
fn no_file_mixes_recipient_kinds() {
    let dirs = Dirs::new("init-stanzas");
    dirs.init(&OsFs).unwrap();
    let kinds = |name: &str| stanza_kinds(&dirs.file(&OsFs, dirs.state_dir.path(), name)).unwrap();
    let identity = kinds(StateFileName::identity_envelope().as_str());
    assert_eq!(identity.iter().filter(|k| **k == StanzaKind::X25519).count(), 2, "{identity:?}");
    assert_eq!(identity.iter().filter(|k| **k == StanzaKind::Grease).count(), 1, "{identity:?}");
    assert!(identity.iter().all(StanzaKind::is_x25519_or_grease), "{identity:?}");
    [StateFileName::passphrase_envelope(), StateFileName::approver_key()]
        .iter()
        .for_each(|file| assert_eq!(kinds(file.as_str()), [StanzaKind::Scrypt], "{file}"));
}

#[test]
fn no_secret_reaches_a_file_or_the_log() {
    let dirs = Dirs::new("init-leaks");
    let ((result, secrets), events) = capture_logs(|| dirs.init_keeping(&OsFs));
    result.unwrap();
    assert!(!events.is_empty(), "the approval's audit events were not captured");
    let logged = format!("{events:?}");
    let files = dirs.snapshot(&OsFs);
    [
        secrets.recovery.as_str(),
        &secrets.operational,
        VAULT_PASSPHRASE,
        APPROVAL_PASSPHRASE,
    ]
    .iter()
    .flat_map(|secret| [secret.to_string(), secret.to_lowercase()])
    .for_each(|needle| {
        assert!(!logged.contains(&needle), "a secret was logged: {logged}");
        files.iter().for_each(|(name, bytes)| {
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle.as_bytes()),
                "a secret is in {name}"
            );
        });
    });
}

#[test]
fn an_initialized_directory_is_refused_unchanged() {
    let dirs = Dirs::new("init-twice");
    dirs.init(&OsFs).unwrap();
    let before = dirs.snapshot(&OsFs);
    let error = dirs.init(&OsFs).unwrap_err();
    assert_eq!(error.step(), InitStep::Begin);
    assert_eq!(error.cause(), &InitFailure::State(InitStateError::AlreadyInitialized));
    assert_eq!(dirs.snapshot(&OsFs), before);
}

#[test]
fn an_unrecognized_directory_is_refused_unchanged() {
    let stray_state = |dirs: &Dirs| std::fs::write(dirs.state_dir.path().join("stray"), b"x").unwrap();
    let owner_config = |dirs: &Dirs| std::fs::write(dirs.config_dir.path().join("config.toml"), b"schema_version = 1\n# mine\n").unwrap();
    [stray_state, owner_config].iter().for_each(|setup| {
        let dirs = Dirs::new("init-unrecognized");
        setup(&dirs);
        let before = dirs.snapshot(&OsFs);
        let error = dirs.init(&OsFs).unwrap_err();
        assert_eq!(error.step(), InitStep::Begin);
        assert!(
            matches!(error.cause(), InitFailure::State(InitStateError::Unrecognized { .. })),
            "{error:?}"
        );
        assert_eq!(dirs.snapshot(&OsFs), before);
    });
}

#[test]
fn an_unfinished_initialization_is_discarded_and_started_over() {
    let dirs = Dirs::new("init-discard");
    let fs = dirs.fault_fs();
    fs.fail_first(FsOp::RemoveFile, io::ErrorKind::Other);
    let error = dirs.init(&fs).unwrap_err();
    assert_eq!(error.step(), InitStep::Finish);
    assert_eq!(dirs.read(&fs), InitializationState::Unfinished);
    let (result, secrets) = dirs.init_keeping(&fs);
    let initialized = result.unwrap();
    assert_eq!(initialized.discarded, DISCARDED);
    assert_initialized(&dirs, &fs, &initialized, &secrets.recovery);
}

/// What the discard of a run that failed only at its commit point removes, in order.
const DISCARDED: [&str; 7] = [
    "config.toml.sig",
    "config.toml",
    "approval.age",
    "manifest.age",
    "approver.age",
    "operational.age",
    "identity.age",
];

#[test]
fn a_step_failing_after_a_discard_still_names_the_discarded_files() {
    let dirs = Dirs::new("init-discard-then-fail");
    let fs = dirs.fault_fs();
    fs.fail_first(FsOp::RemoveFile, io::ErrorKind::Other);
    assert!(dirs.init(&fs).unwrap_err().discarded().is_empty());
    fs.fail_first(FsOp::Rename, io::ErrorKind::Other);
    let error = dirs.init(&fs).unwrap_err();
    assert_eq!(error.step(), InitStep::IdentityEnvelope);
    assert_eq!(error.discarded(), DISCARDED);
}

#[test]
fn the_first_approval_is_audited_as_completed_with_the_initial_config_digest() {
    let dirs = Dirs::new("init-audit");
    let (result, events) = capture_logs(|| dirs.init(&OsFs));
    result.unwrap();
    let logged = format!("{events:?}");
    let digest = ConfigDigest::of(INITIAL_CONFIG).to_string();
    assert!(
        logged.contains("config.approval-completed") && logged.contains(&digest) && logged.contains("initial config"),
        "{logged}"
    );
}

/// The state a failure at `error`'s step must leave: untouched before the marker is durable, Unfinished after it, and
/// Initialized only once the marker's unlink has landed.
fn assert_left_by(dirs: &Dirs, fs: &FaultFs, error: &InitError, call: usize) {
    let state = dirs.read(fs);
    let expected: &[InitializationState] = match (error.step(), error.cause()) {
        (InitStep::Begin, _) => &[InitializationState::Uninitialized, InitializationState::Unfinished],
        (InitStep::Finish, InitFailure::State(InitStateError::FinishUncertain { .. })) => &[InitializationState::Initialized],
        _ => &[InitializationState::Unfinished],
    };
    assert!(expected.contains(&state), "call {call}: {error} left {state:?}");
}

/// The number of file-system calls `run` makes on the directory `setup` leaves.
fn calls_of(dirs: &Dirs, setup: &impl Fn(&FaultFs), run: impl FnOnce(&FaultFs)) -> usize {
    let probe = dirs.fault_fs();
    setup(&probe);
    let base = probe.trace().len();
    run(&probe);
    probe.trace().len() - base
}

/// Fails call `call` of an initialization from the directory `setup` leaves, checks what the failure left, and that
/// the next initialization, with fresh keys, finishes. Returns the failed step, or `None` when the fault was passed
/// over, as a failed directory fsync after publishing is.
fn fail_call(dirs: &Dirs, setup: &impl Fn(&FaultFs), call: usize) -> Option<InitStep> {
    let fs = dirs.fault_fs();
    setup(&fs);
    fs.fail_call(fs.trace().len() + call, io::ErrorKind::Other);
    let failed = dirs.init(&fs).err();
    failed.iter().for_each(|error| assert_left_by(dirs, &fs, error, call));
    if dirs.read(&fs) != InitializationState::Initialized {
        dirs.init(&fs).unwrap();
        assert_eq!(dirs.read(&fs), InitializationState::Initialized, "call {call}");
    }
    failed.map(|error| error.step())
}

/// [`fail_call`] for each of the first `calls` calls, spread over threads because every run seals and opens three
/// envelopes and signs an approval. Returns the steps that failed.
fn fail_each_call(dirs: &Dirs, setup: impl Fn(&FaultFs) + Sync, calls: usize) -> Vec<InitStep> {
    let workers = std::thread::available_parallelism().map_or(4, usize::from);
    let indices: Vec<usize> = (0..calls).collect();
    std::thread::scope(|scope| {
        let setup = &setup;
        let handles: Vec<_> = indices
            .chunks(calls.div_ceil(workers).max(1))
            .map(|chunk| scope.spawn(move || chunk.iter().filter_map(|&call| fail_call(dirs, setup, call)).collect::<Vec<_>>()))
            .collect();
        handles.into_iter().flat_map(|handle| handle.join().unwrap()).collect()
    })
}

fn assert_every_step_failed(failed: &[InitStep], steps: &[InitStep]) {
    steps
        .iter()
        .for_each(|step| assert!(failed.contains(step), "no fault failed {step}: {failed:?}"));
}

#[test]
fn a_fault_at_any_call_of_a_fresh_initialization_is_recoverable() {
    let dirs = Dirs::new("init-faults");
    let fresh = |_: &FaultFs| {};
    let calls = calls_of(&dirs, &fresh, |fs| drop(dirs.init(fs).unwrap()));
    let failed = fail_each_call(&dirs, fresh, calls);
    let steps = [
        InitStep::Begin,
        InitStep::IdentityEnvelope,
        InitStep::PassphraseEnvelope,
        InitStep::ApproverKey,
        InitStep::Manifest,
        InitStep::ApprovalState,
        InitStep::OpenSigner,
        InitStep::FirstApproval,
        InitStep::Finish,
    ];
    assert_every_step_failed(&failed, &steps);
}

/// Every call of the discard; the steps after it are the fresh case's.
#[test]
fn a_fault_while_discarding_an_unfinished_initialization_is_recoverable() {
    let dirs = Dirs::new("init-faults-unfinished");
    let unfinished = |fs: &FaultFs| {
        fs.fail_first(FsOp::RemoveFile, io::ErrorKind::Other);
        assert_eq!(dirs.init(fs).unwrap_err().step(), InitStep::Finish);
    };
    let calls = calls_of(&dirs, &unfinished, |fs| drop(begin(&dirs.state, &dirs.config, fs).unwrap()));
    let failed = fail_each_call(&dirs, unfinished, calls);
    assert_every_step_failed(&failed, &[InitStep::Discard]);
}

#[test]
fn the_passphrase_envelope_opens_only_with_the_vault_passphrase() {
    let dirs = Dirs::new("init-passphrases");
    dirs.init(&OsFs).unwrap();
    let envelope = read_passphrase_envelope(&dirs.state, &OsFs).unwrap();
    let approval_as_vault = Passphrase::new(SecretString::from(APPROVAL_PASSPHRASE)).unwrap();
    assert!(crate::open_passphrase_envelope(&envelope, &approval_as_vault).is_err());
    assert!(crate::open_passphrase_envelope(&envelope, &vault_passphrase()).is_ok());
}

#[test]
fn short_passphrases_are_refused() {
    let eleven = "ééééééééééé";
    let twelve = "éééééééééééé";
    let refused = |vault: &str, approval: &str| {
        InitPassphrases::new(Passphrase::new(SecretString::from(vault)).unwrap(), approval_passphrase(approval)).unwrap_err()
    };
    assert_eq!(
        refused(eleven, APPROVAL_PASSPHRASE),
        InitPassphrasesError::TooShort {
            which: WhichPassphrase::Vault
        }
    );
    assert_eq!(
        refused(VAULT_PASSPHRASE, eleven),
        InitPassphrasesError::TooShort {
            which: WhichPassphrase::Approval
        }
    );
    let accepted = InitPassphrases::new(
        Passphrase::new(SecretString::from(twelve)).unwrap(),
        approval_passphrase(APPROVAL_PASSPHRASE),
    );
    assert!(accepted.is_ok());
}

#[test]
fn identical_passphrases_are_refused() {
    let same = InitPassphrases::new(vault_passphrase(), approval_passphrase(VAULT_PASSPHRASE)).unwrap_err();
    assert_eq!(same, InitPassphrasesError::Same);
    let shown = format!("{same} {same:?}");
    assert!(!shown.contains(VAULT_PASSPHRASE), "{shown}");
}
