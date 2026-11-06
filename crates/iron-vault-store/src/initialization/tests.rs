use std::io;
use std::path::Path;

use ed25519_dalek::SigningKey;
use secrecy::SecretString;

use super::*;
use crate::ConfigFileName::{Active, ActiveSignature, Pending, StagedSignature};
use crate::fault_fs::{FaultFs, FsCall, FsOp};
use crate::test_dir::TestDir;
use crate::{
    OperationalIdentity, OsFs, Passphrase, PinnedApprover, PublishSet, RecipientIdentity, RecipientSet, Vault, VaultIdentity, publish,
    unlock_with_passphrase, wrap_identity, write_pending, write_staged,
};

/// Locked state and config directories. The locks are real; the files live wherever the `fs` passed to each call puts them.
struct Dirs {
    state_dir: TestDir,
    config_dir: TestDir,
    state: StateDirLock,
    config: ConfigDirLock,
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

    fn read(&self, fs: &impl StoreFs) -> InitializationState {
        InitializationState::read(&self.state, &self.config, fs).unwrap()
    }

    fn begin(&self, fs: &impl StoreFs) -> Result<Vec<String>, InitStateError> {
        begin_initialization(&self.state, &self.config, fs).map_err(|e| e.cause)
    }

    /// The names in both directories, sorted, for comparing what a discard removed.
    fn all_names(&self, fs: &impl StoreFs) -> Vec<String> {
        let mut all: Vec<_> = self.state_names(fs).into_iter().chain(self.config_names(fs)).collect();
        all.sort();
        all
    }

    fn put(&self, fs: &impl StoreFs, name: &str) {
        self.put_bytes(fs, name, b"x");
    }

    fn put_bytes(&self, fs: &impl StoreFs, name: &str, bytes: &[u8]) {
        durable_replace(&self.state, fs, &StateFileName::new(name).unwrap(), bytes).unwrap();
    }

    /// Puts `bytes` at the config file `name` through the store's own writers: staged, then published.
    fn put_config(&self, fs: &impl StoreFs, name: ConfigFileName, bytes: &[u8]) {
        match name {
            Pending => write_pending(&self.config, fs, bytes).unwrap(),
            StagedSignature => write_staged(&self.config, fs, bytes).unwrap(),
            Active => {
                write_pending(&self.config, fs, bytes).unwrap();
                publish(&self.config, fs, PublishSet::ConfigOnly).unwrap();
            }
            ActiveSignature => {
                write_staged(&self.config, fs, bytes).unwrap();
                publish(&self.config, fs, PublishSet::SignatureOnly).unwrap();
            }
        }
    }

    /// The directory after the write-order step `step` (0 to 7) is durable, with every earlier step. Step 8 is the
    /// publish, and its three outcomes are `PUBLISHED` (both renames), `ONLY_CONFIG_PUBLISHED` (`config.toml` beside
    /// the staged signature) and `ONLY_SIGNATURE_PUBLISHED` (the pending config beside `config.toml.sig`).
    fn crashed_after(&self, fs: &impl StoreFs, step: usize) {
        (0..=step.min(7)).for_each(|s| match s {
            0 => self.put_bytes(fs, "init.unfinished", b""),
            1 => self.put(fs, "identity.age"),
            2 => self.put(fs, "operational.age"),
            3 => self.put(fs, "approver.age"),
            4 => self.put(fs, "manifest.age"),
            5 => self.put(fs, "approval.age"),
            6 => self.put_config(fs, Pending, INITIAL_CONFIG),
            _ => self.put_config(fs, StagedSignature, b"signature"),
        });
        let published = match step {
            PUBLISHED => Some(PublishSet::Both),
            ONLY_CONFIG_PUBLISHED => Some(PublishSet::ConfigOnly),
            ONLY_SIGNATURE_PUBLISHED => Some(PublishSet::SignatureOnly),
            _ => None,
        };
        published.into_iter().for_each(|set| publish(&self.config, fs, set).unwrap());
    }

    /// A [`FaultFs`] that shows the two lock files, which are real files the fault filesystem does not see.
    fn fault_fs(&self) -> FaultFs {
        FaultFs::new()
            .with_durable_file(&self.state_dir.path().join("lock"), b"")
            .with_durable_file(&self.config_dir.path().join("config.toml.lock"), b"")
    }

    fn state_names(&self, fs: &impl StoreFs) -> Vec<String> {
        names(fs, self.state_dir.path())
    }

    fn config_names(&self, fs: &impl StoreFs) -> Vec<String> {
        names(fs, self.config_dir.path())
    }

    fn marker_path(&self) -> std::path::PathBuf {
        self.state_dir.path().join("init.unfinished")
    }
}

const PUBLISHED: usize = 8;
const ONLY_CONFIG_PUBLISHED: usize = 9;
const ONLY_SIGNATURE_PUBLISHED: usize = 10;
const LAST_STEP: usize = ONLY_SIGNATURE_PUBLISHED;

fn names(fs: &impl StoreFs, dir: &Path) -> Vec<String> {
    fs.list_dir(dir)
        .unwrap()
        .into_iter()
        .map(|n| n.to_string_lossy().into_owned())
        .collect()
}

fn passphrase() -> Passphrase {
    Passphrase::new(SecretString::from("correct horse")).unwrap()
}

#[test]
fn a_fresh_directory_is_uninitialized() {
    let dirs = Dirs::new("init-fresh");
    assert_eq!(dirs.read(&OsFs), InitializationState::Uninitialized);
}

#[test]
fn only_the_marker_is_unfinished() {
    let dirs = Dirs::new("init-marker");
    dirs.crashed_after(&OsFs, 0);
    assert_eq!(dirs.read(&OsFs), InitializationState::Unfinished);
}

#[test]
fn every_crash_point_is_unfinished() {
    (0..=LAST_STEP).for_each(|step| {
        let dirs = Dirs::new("init-points");
        dirs.crashed_after(&OsFs, step);
        assert_eq!(dirs.read(&OsFs), InitializationState::Unfinished, "after step {step}");
    });
}

#[test]
fn a_created_vault_with_approval_state_is_initialized() {
    let dirs = Dirs::new("init-created");
    let mut vault = Vault::create(&dirs.state, &OsFs, VaultIdentity::generate()).unwrap();
    let approver = PinnedApprover::from_signing_key(&SigningKey::from_bytes(&[1; 32]));
    vault.create_approval_state(&dirs.state, &OsFs, approver).unwrap();
    assert_eq!(dirs.read(&OsFs), InitializationState::Initialized);
}

#[test]
fn a_manifest_beside_the_marker_is_still_unfinished() {
    let dirs = Dirs::new("init-both");
    Vault::create(&dirs.state, &OsFs, VaultIdentity::generate()).unwrap();
    dirs.put_bytes(&OsFs, "init.unfinished", b"");
    assert_eq!(dirs.read(&OsFs), InitializationState::Unfinished);
}

#[test]
fn vault_files_without_the_marker_or_a_manifest_are_unrecognized() {
    [
        "identity.age",
        "operational.age",
        "approver.age",
        "approval.age",
        "record-7c9e6679-7425-40de-944b-e07fc1f90ae7.age",
    ]
    .iter()
    .for_each(|file| {
        let dirs = Dirs::new("init-orphans");
        dirs.put(&OsFs, file);
        assert_eq!(dirs.read(&OsFs), InitializationState::Unrecognized, "{file}");
    });
}

#[test]
fn a_config_file_beside_an_empty_state_directory_is_unrecognized() {
    [Active, ActiveSignature, Pending, StagedSignature].into_iter().for_each(|file| {
        let dirs = Dirs::new("init-config-only");
        dirs.put_config(&OsFs, file, INITIAL_CONFIG);
        assert_eq!(dirs.read(&OsFs), InitializationState::Unrecognized, "{file}");
    });
}

#[test]
fn a_foreign_file_beside_a_manifest_is_still_initialized() {
    let dirs = Dirs::new("init-foreign-ok");
    Vault::create(&dirs.state, &OsFs, VaultIdentity::generate()).unwrap();
    ["notes.txt", "manifest.age.bak", ".hidden"].iter().for_each(|file| {
        std::fs::write(dirs.state_dir.path().join(file), b"x").unwrap();
    });
    dirs.put_config(&OsFs, Active, b"any bytes at all");
    assert_eq!(dirs.read(&OsFs), InitializationState::Initialized);
}

#[test]
fn the_recovery_record_is_never_a_foreign_file() {
    let dirs = Dirs::new("init-recovery-record");
    Vault::create(&dirs.state, &OsFs, VaultIdentity::generate()).unwrap();
    dirs.put(&OsFs, "recovery.toml");
    assert_eq!(dirs.read(&OsFs), InitializationState::Initialized);
    assert_eq!(require_initialized(&dirs.state, &dirs.config, &OsFs), Ok(Vec::new()));
}

#[test]
fn a_leftover_recovery_record_leaves_the_state_uninitialized() {
    let dirs = Dirs::new("init-recovery-leftover");
    dirs.put(&OsFs, "recovery.toml");
    assert_eq!(dirs.read(&OsFs), InitializationState::Uninitialized);
    dirs.put(&OsFs, "identity.age");
    assert_eq!(dirs.read(&OsFs), InitializationState::Unrecognized);
}

#[test]
fn a_recovery_record_beside_the_marker_is_discarded() {
    let dirs = Dirs::new("init-recovery-discard");
    dirs.crashed_after(&OsFs, 2);
    dirs.put(&OsFs, "recovery.toml");
    assert_eq!(dirs.read(&OsFs), InitializationState::Unfinished);
    let removed = dirs.begin(&OsFs).unwrap();
    assert!(removed.contains(&"recovery.toml".to_owned()), "{removed:?}");
    assert_eq!(dirs.state_names(&OsFs), ["init.unfinished", "lock"]);
}

#[test]
fn require_initialized_returns_the_sorted_foreign_names_beside_a_manifest() {
    let dirs = Dirs::new("init-require-foreign");
    Vault::create(&dirs.state, &OsFs, VaultIdentity::generate()).unwrap();
    assert_eq!(require_initialized(&dirs.state, &dirs.config, &OsFs), Ok(Vec::new()));
    ["notes.txt", "backup~", "lost+found", ".stale.tmp"].iter().for_each(|file| {
        std::fs::write(dirs.state_dir.path().join(file), b"x").unwrap();
    });
    assert_eq!(
        require_initialized(&dirs.state, &dirs.config, &OsFs),
        Ok(vec!["backup~".to_owned(), "notes.txt".to_owned()])
    );
}

#[test]
fn require_initialized_refuses_every_other_state_by_name() {
    let fresh = Dirs::new("init-require-fresh");
    assert_eq!(
        require_initialized(&fresh.state, &fresh.config, &OsFs),
        Err(UnlockError::NotInitialized)
    );
    let unfinished = Dirs::new("init-require-unfinished");
    unfinished.crashed_after(&OsFs, 3);
    assert_eq!(
        require_initialized(&unfinished.state, &unfinished.config, &OsFs),
        Err(UnlockError::InitializationUnfinished)
    );
    let alone = Dirs::new("init-require-alone");
    alone.put(&OsFs, "operational.age");
    let error = require_initialized(&alone.state, &alone.config, &OsFs).unwrap_err();
    assert_eq!(
        error,
        UnlockError::Unrecognized {
            files: vec!["operational.age".to_owned()]
        }
    );
    assert!(error.to_string().contains("operational.age"));
}

#[test]
fn a_foreign_file_beside_the_marker_or_without_a_manifest_is_unrecognized() {
    let beside_marker = Dirs::new("init-foreign-marker");
    beside_marker.crashed_after(&OsFs, 3);
    beside_marker.put(&OsFs, "notes.txt");
    assert_eq!(beside_marker.read(&OsFs), InitializationState::Unrecognized);
    let alone = Dirs::new("init-foreign-alone");
    alone.put(&OsFs, "notes.txt");
    assert_eq!(alone.read(&OsFs), InitializationState::Unrecognized);
}

#[test]
fn a_record_file_beside_the_marker_is_unrecognized() {
    let dirs = Dirs::new("init-record");
    dirs.crashed_after(&OsFs, 4);
    dirs.put(&OsFs, "record-7c9e6679-7425-40de-944b-e07fc1f90ae7.age");
    assert_eq!(dirs.read(&OsFs), InitializationState::Unrecognized);
}

#[test]
fn lost_and_found_and_temp_files_are_ignored() {
    let dirs = Dirs::new("init-ignored");
    let (lost, temp) = (dirs.state_dir.path().join("lost+found"), dirs.state_dir.path().join(".stale.tmp"));
    std::fs::create_dir(&lost).unwrap();
    std::fs::write(temp, b"stale").unwrap();
    assert_eq!(dirs.read(&OsFs), InitializationState::Uninitialized);
    dirs.crashed_after(&OsFs, 2);
    assert_eq!(dirs.read(&OsFs), InitializationState::Unfinished);
    dirs.put(&OsFs, "manifest.age");
    std::fs::remove_file(dirs.marker_path()).unwrap();
    assert_eq!(dirs.read(&OsFs), InitializationState::Initialized);
}

#[test]
fn only_the_initial_config_passes_the_config_test_beside_the_marker() {
    let owners = [
        b"schema_version = 2\n".to_vec(),
        b"schema_version = 1\n\n".to_vec(),
        Vec::new(),
        vec![b'a'; 4096],
    ];
    [Active, Pending].into_iter().for_each(|file| {
        owners.iter().for_each(|bytes| {
            let dirs = Dirs::new("init-config-owner");
            dirs.crashed_after(&OsFs, 0);
            dirs.put_config(&OsFs, file, bytes);
            assert_eq!(dirs.read(&OsFs), InitializationState::Unrecognized, "{file} {} bytes", bytes.len());
        });
    });
}

#[test]
fn a_signature_is_judged_by_the_config_beside_it() {
    let alone = Dirs::new("init-sig-alone");
    alone.crashed_after(&OsFs, 0);
    alone.put_config(&OsFs, ActiveSignature, b"signature");
    assert_eq!(alone.read(&OsFs), InitializationState::Unrecognized);
    let staged_alone = Dirs::new("init-staged-alone");
    staged_alone.crashed_after(&OsFs, 0);
    staged_alone.put_config(&OsFs, StagedSignature, b"signature");
    assert_eq!(staged_alone.read(&OsFs), InitializationState::Unrecognized);
    let beside = Dirs::new("init-sig-beside");
    beside.crashed_after(&OsFs, 0);
    beside.put_config(&OsFs, Active, INITIAL_CONFIG);
    beside.put_config(&OsFs, ActiveSignature, b"signature");
    assert_eq!(beside.read(&OsFs), InitializationState::Unfinished);
}

#[test]
fn begin_on_a_fresh_directory_writes_only_the_empty_marker() {
    let dirs = Dirs::new("init-begin-fresh");
    assert_eq!(dirs.begin(&OsFs), Ok(Vec::new()));
    assert_eq!(dirs.state_names(&OsFs), ["init.unfinished", "lock"]);
    assert_eq!(std::fs::read(dirs.marker_path()).unwrap(), b"");
    assert_eq!(dirs.read(&OsFs), InitializationState::Unfinished);
}

#[test]
fn begin_removes_a_leftover_recovery_record_without_reporting_it() {
    let dirs = Dirs::new("init-begin-leftover");
    dirs.put(&OsFs, "recovery.toml");
    assert_eq!(dirs.begin(&OsFs), Ok(Vec::new()));
    assert_eq!(dirs.state_names(&OsFs), ["init.unfinished", "lock"]);
}

#[test]
fn begin_leaves_no_marker_when_the_leftover_record_cannot_be_removed() {
    let dirs = Dirs::new("init-begin-leftover-fault");
    let fs = dirs.fault_fs();
    dirs.put(&fs, "recovery.toml");
    fs.fail_first(FsOp::RemoveFile, io::ErrorKind::Other);
    assert!(matches!(dirs.begin(&fs), Err(InitStateError::LeftoverRecoveryCheck(_))));
    assert_eq!(dirs.state_names(&fs), ["lock", "recovery.toml"]);
    assert_eq!(dirs.read(&fs), InitializationState::Uninitialized);
}

#[test]
fn begin_after_every_crash_point_leaves_only_the_marker() {
    (0..=LAST_STEP).for_each(|step| {
        let dirs = Dirs::new("init-begin-unfinished");
        dirs.crashed_after(&OsFs, step);
        let removed = dirs.begin(&OsFs).unwrap();
        assert_eq!(dirs.state_names(&OsFs), ["init.unfinished", "lock"], "after step {step}");
        assert_eq!(dirs.config_names(&OsFs), ["config.toml.lock"], "after step {step}");
        assert_eq!(removed.len(), [0, 1, 2, 3, 4, 5, 6, 7, 7, 7, 7][step], "after step {step}");
    });
}

#[test]
fn begin_names_what_it_removed_config_first() {
    let dirs = Dirs::new("init-begin-names");
    dirs.crashed_after(&OsFs, PUBLISHED);
    assert_eq!(
        dirs.begin(&OsFs).unwrap(),
        [
            "config.toml.sig",
            "config.toml",
            "approval.age",
            "manifest.age",
            "approver.age",
            "operational.age",
            "identity.age"
        ]
    );
}

#[test]
fn begin_refuses_and_writes_nothing_on_initialized_and_unrecognized() {
    let initialized = Dirs::new("init-begin-done");
    Vault::create(&initialized.state, &OsFs, VaultIdentity::generate()).unwrap();
    let unrecognized = Dirs::new("init-begin-unrec");
    unrecognized.crashed_after(&OsFs, 4);
    unrecognized.put(&OsFs, "record-7c9e6679-7425-40de-944b-e07fc1f90ae7.age");
    let owner_config = Dirs::new("init-begin-owner");
    owner_config.put_config(&OsFs, Active, b"[listener.a]\n");
    let cases = [
        (&initialized, InitStateError::AlreadyInitialized),
        (
            &unrecognized,
            InitStateError::Unrecognized {
                files: vec!["record-7c9e6679-7425-40de-944b-e07fc1f90ae7.age".to_owned()],
            },
        ),
        (
            &owner_config,
            InitStateError::Unrecognized {
                files: vec!["config.toml".to_owned()],
            },
        ),
    ];
    cases.into_iter().for_each(|(dirs, expected)| {
        let before = (dirs.state_names(&OsFs), dirs.config_names(&OsFs));
        assert_eq!(ensure_initializable(&dirs.state, &dirs.config, &OsFs), Err(expected.clone()));
        assert_eq!(dirs.begin(&OsFs), Err(expected));
        assert_eq!((dirs.state_names(&OsFs), dirs.config_names(&OsFs)), before);
    });
}

#[test]
fn an_initializable_directory_is_named_and_left_as_it_was() {
    let fresh = Dirs::new("init-ensure-fresh");
    let unfinished = Dirs::new("init-ensure-unfinished");
    unfinished.crashed_after(&OsFs, PUBLISHED);
    [
        (&fresh, InitializationState::Uninitialized),
        (&unfinished, InitializationState::Unfinished),
    ]
    .into_iter()
    .for_each(|(dirs, expected)| {
        let before = (dirs.state_names(&OsFs), dirs.config_names(&OsFs));
        assert_eq!(ensure_initializable(&dirs.state, &dirs.config, &OsFs), Ok(expected));
        assert_eq!((dirs.state_names(&OsFs), dirs.config_names(&OsFs)), before);
    });
}

#[test]
fn an_unrecognized_error_names_files_only_and_at_most_five() {
    let dirs = Dirs::new("init-begin-many");
    (0..8).for_each(|i| dirs.put(&OsFs, &format!("stray-{i}")));
    let error = dirs.begin(&OsFs).unwrap_err();
    assert!(
        matches!(&error, InitStateError::Unrecognized { files } if files.len() == MAX_NAMED),
        "{error}"
    );
    assert!(
        error.to_string().contains("stray-0") && !error.to_string().contains("stray-7"),
        "{error}"
    );
}

/// The discard unlinks every signature before any config, so a crash after any call reads Unfinished again and never
/// Unrecognized, from each state the publish step can leave, the half-published ones included.
#[test]
fn a_crash_during_the_discard_reads_unfinished() {
    [PUBLISHED, ONLY_CONFIG_PUBLISHED, ONLY_SIGNATURE_PUBLISHED]
        .into_iter()
        .for_each(|step| {
            let dirs = Dirs::new("init-discard-crash");
            let probe = dirs.fault_fs();
            dirs.crashed_after(&probe, step);
            let base = probe.trace().len();
            dirs.begin(&probe).unwrap();
            let calls = probe.trace().len() - base;
            (0..calls).for_each(|cut| {
                let fs = dirs.fault_fs();
                dirs.crashed_after(&fs, step);
                fs.cut_power_after(fs.trace().len() + cut);
                assert!(dirs.begin(&fs).is_err(), "step {step} cut {cut}");
                fs.crash();
                assert_eq!(dirs.read(&fs), InitializationState::Unfinished, "step {step} cut {cut}");
                dirs.begin(&fs).unwrap();
                assert_eq!(dirs.state_names(&fs), ["init.unfinished", "lock"], "step {step} cut {cut}");
                assert_eq!(dirs.config_names(&fs), ["config.toml.lock"], "step {step} cut {cut}");
            });
        });
}

/// Fails each call of `run` in turn and checks that it reports the failure, then returns the state it left.
fn fail_each_call<T: std::fmt::Debug>(
    dirs: &Dirs,
    setup: impl Fn(&FaultFs),
    run: impl Fn(&FaultFs) -> Result<T, InitStateError>,
) -> Vec<(usize, InitStateError, InitializationState)> {
    let clean = FaultFs::new();
    setup(&clean);
    let base = clean.trace().len();
    run(&clean).unwrap();
    (0..clean.trace().len() - base)
        .map(|i| {
            let fs = FaultFs::new();
            setup(&fs);
            fs.fail_call(fs.trace().len() + i, io::ErrorKind::Other);
            let error = run(&fs).unwrap_err();
            (i, error, dirs.read(&fs))
        })
        .collect()
}

#[test]
fn begin_on_a_fresh_directory_fails_cleanly_at_every_call() {
    let dirs = Dirs::new("init-fault-fresh");
    let outcomes = fail_each_call(&dirs, |_| {}, |fs| dirs.begin(fs));
    assert!(outcomes.len() >= 5, "{outcomes:?}");
    outcomes.iter().for_each(|(i, _, state)| {
        // Only a failed directory fsync leaves the marker behind, and then init reads Unfinished and goes on.
        assert!(
            matches!(state, InitializationState::Uninitialized | InitializationState::Unfinished),
            "call {i}: {state:?}"
        );
    });
}

#[test]
fn begin_on_an_unfinished_directory_fails_cleanly_at_every_call() {
    let dirs = Dirs::new("init-fault-unfinished");
    let outcomes = fail_each_call(&dirs, |fs| dirs.crashed_after(fs, ONLY_CONFIG_PUBLISHED), |fs| dirs.begin(fs));
    assert!(outcomes.len() >= 10, "{outcomes:?}");
    outcomes
        .iter()
        .for_each(|(i, _, state)| assert_eq!(*state, InitializationState::Unfinished, "call {i}"));
}

/// A discard that fails at any call still names every file it unlinked first, so `vault.init-discarded` can log them.
#[test]
fn a_discard_failing_part_way_names_the_files_it_removed() {
    let dirs = Dirs::new("init-fault-discard-names");
    let probe = dirs.fault_fs();
    dirs.crashed_after(&probe, PUBLISHED);
    let base = probe.trace().len();
    dirs.begin(&probe).unwrap();
    let partial = (0..probe.trace().len() - base)
        .filter(|&i| {
            let fs = dirs.fault_fs();
            dirs.crashed_after(&fs, PUBLISHED);
            let before = dirs.all_names(&fs);
            fs.fail_call(fs.trace().len() + i, io::ErrorKind::Other);
            let error = begin_initialization(&dirs.state, &dirs.config, &fs).unwrap_err();
            let after = dirs.all_names(&fs);
            let mut named = error.discarded.clone();
            named.sort();
            let gone: Vec<_> = before.into_iter().filter(|name| !after.contains(name)).collect();
            assert_eq!(named, gone, "call {i}: {error:?}");
            !named.is_empty()
        })
        .count();
    assert!(partial >= 5, "only {partial} failures came after a removal");
}

#[test]
fn finish_removes_the_marker_and_fails_cleanly_at_every_call() {
    let dirs = Dirs::new("init-fault-finish");
    let setup = |fs: &FaultFs| dirs.crashed_after(fs, 5);
    let outcomes = fail_each_call(&dirs, setup, |fs| finish_initialization(&dirs.state, fs));
    assert_eq!(outcomes.len(), 2, "{outcomes:?}");
    assert!(matches!(
        &outcomes[0],
        (
            0,
            InitStateError::State(WriteError::Io {
                step: WriteStep::Remove,
                ..
            }),
            InitializationState::Unfinished
        )
    ));
    assert!(matches!(
        &outcomes[1],
        (1, InitStateError::FinishUncertain { .. }, InitializationState::Initialized)
    ));
    let fs = FaultFs::new();
    setup(&fs);
    finish_initialization(&dirs.state, &fs).unwrap();
    assert_eq!(dirs.read(&fs), InitializationState::Initialized);
}

#[test]
fn unlock_refuses_while_unfinished_even_when_the_envelopes_would_open() {
    let dirs = Dirs::new("init-unlock-open");
    let vault = VaultIdentity::generate();
    let (operational, operational_key) = OperationalIdentity::generate();
    let envelope = wrap_identity(
        &vault,
        &RecipientSet::new([operational_key, RecipientIdentity::generate().recipient_key()]).unwrap(),
    )
    .unwrap();
    crate::write_identity_envelope(&dirs.state, &OsFs, &envelope).unwrap();
    let sealed = crate::passphrase::seal_at(&operational, &passphrase(), 2).unwrap();
    crate::write_passphrase_envelope(&dirs.state, &OsFs, &sealed).unwrap();
    assert!(unlock_with_passphrase(&dirs.state, &OsFs, &passphrase()).is_ok());
    dirs.put_bytes(&OsFs, "init.unfinished", b"");
    assert_eq!(
        unlock_with_passphrase(&dirs.state, &OsFs, &passphrase()).unwrap_err(),
        UnlockError::InitializationUnfinished
    );
}

#[test]
fn unlock_refuses_before_reading_any_envelope() {
    let dirs = Dirs::new("init-unlock-noread");
    let fs = FaultFs::new();
    dirs.crashed_after(&fs, 2);
    let base = fs.trace().len();
    assert_eq!(
        unlock_with_passphrase(&dirs.state, &fs, &passphrase()).unwrap_err(),
        UnlockError::InitializationUnfinished
    );
    // Reading an envelope is a ReadBounded call, and scrypt runs only on bytes read.
    let state_dir = dirs.state_dir.path().to_path_buf();
    assert_eq!(fs.trace()[base..], [FsCall::ListDir(state_dir)]);
}

#[test]
fn unlock_on_an_empty_directory_says_to_run_init() {
    let dirs = Dirs::new("init-unlock-empty");
    let error = unlock_with_passphrase(&dirs.state, &OsFs, &passphrase()).unwrap_err();
    assert_eq!(error, UnlockError::NotInitialized);
    assert!(error.to_string().contains("iron-vault init"));
    assert!(UnlockError::InitializationUnfinished.to_string().contains("iron-vault init"));
}
