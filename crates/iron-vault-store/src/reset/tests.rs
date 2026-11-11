use std::io;
use std::path::Path;

use iron_vault_kinds::CredentialMaterial;
use iron_vault_policy::Port;
use secrecy::SecretString;

use super::*;
use crate::fault_fs::{FaultFs, FsOp};
use crate::init::initialize_at;
use crate::test_dir::TestDir;
use crate::test_request::HOST;
use crate::{
    AdmissionPaused, ApprovalPassphrase, InitPassphrases, NewVaultKeys, OsFs, Passphrase, PermittedOrigins, RecoveryCheckRecord,
    UnlockError, UtcSecond, Vault, begin_initialization, durable_replace, ensure_initializable, require_initialized,
    unlock_with_passphrase, write_pending, write_recovery_check, write_staged,
};

const VAULT_PASSPHRASE: &str = "correct horse battery";

/// A second approver's key envelope, beside the one `init` writes.
const OTHER_APPROVER_KEY: &str = "approver-3f2a9b1c-7d4e-4a8b-b6c5-0e1d2c3b4a59.age";

/// A TPM approver's key blob.
const TPM_KEY_BLOB: &str = "approver-5b0e9a1c-7d2f-4e83-b6a4-0c1d2e3f4a5b.tpm";

struct Paused;

impl AdmissionPaused for Paused {}

/// Locked state and config directories. The locks are real; the files live wherever the `fs` passed puts them.
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

    /// A [`FaultFs`] that shows the two lock files, which are real files the fault filesystem does not see.
    fn fault_fs(&self) -> FaultFs {
        FaultFs::new()
            .with_durable_file(&self.state_dir.path().join("lock"), b"")
            .with_durable_file(&self.config_dir.path().join("config.toml.lock"), b"")
    }

    /// Initializes a vault and returns its ID.
    fn init(&self, fs: &impl StoreFs) -> VaultId {
        let passphrases = InitPassphrases::new(
            Passphrase::new(SecretString::from(VAULT_PASSPHRASE)).unwrap(),
            ApprovalPassphrase::new(SecretString::from("staple approval words")).unwrap(),
        )
        .unwrap();
        let keys = NewVaultKeys::generate().unwrap().into_sealing();
        initialize_at(&self.state, &self.config, fs, (keys, passphrases), &Paused, (UtcSecond::EPOCH, 2))
            .unwrap()
            .vault_id
    }

    /// An initialized vault with everything a used one holds beyond `init`'s files: a record, a second approver key
    /// envelope, a TPM key blob, a staged inventory, a recovery check record, the owner-lock file, a pending config and a
    /// staged signature.
    fn full_vault(&self, fs: &impl StoreFs) -> VaultId {
        let vault_id = self.init(fs);
        let passphrase = Passphrase::new(SecretString::from(VAULT_PASSPHRASE)).unwrap();
        let identity = unlock_with_passphrase(&self.state, fs, &passphrase).unwrap();
        let (mut vault, _) = Vault::open(&self.state, fs, identity).unwrap();
        let origins = PermittedOrigins::new([(HOST.parse().unwrap(), Port::HTTPS)].into()).unwrap();
        let material = CredentialMaterial::Static {
            key: SecretString::from("SECRET-reset-key"),
        };
        vault.add(&self.state, fs, "fx_key".parse().unwrap(), material, origins).unwrap();
        self.put(fs, OTHER_APPROVER_KEY);
        self.put(fs, TPM_KEY_BLOB);
        self.put(fs, "recipients.age.staged");
        write_recovery_check(&self.state, fs, &RecoveryCheckRecord::new(UtcSecond::EPOCH, None).unwrap()).unwrap();
        crate::write_owner_lock(&self.state, fs).unwrap();
        write_pending(&self.config, fs, b"schema_version = 1\n# next\n").unwrap();
        write_staged(&self.config, fs, b"signature").unwrap();
        vault_id
    }

    fn put(&self, fs: &impl StoreFs, name: &str) {
        durable_replace(&self.state, fs, &StateFileName::new(name).unwrap(), b"x").unwrap();
    }

    fn read(&self, fs: &impl StoreFs) -> InitializationState {
        InitializationState::read(&self.state, &self.config, fs).unwrap()
    }

    fn discard(&self, fs: &impl StoreFs) -> Result<DiscardedVault, DiscardError> {
        discard_vault(&self.state, &self.config, fs)
    }

    fn scope(&self, fs: &impl StoreFs) -> ResetScope {
        reset_scope(&self.state, &self.config, fs).unwrap()
    }

    /// Every file in both directories with its contents, sorted, read through `fs`.
    fn snapshot(&self, fs: &FaultFs) -> Vec<(String, Option<Vec<u8>>)> {
        [self.state_dir.path(), self.config_dir.path()]
            .into_iter()
            .flat_map(|dir| files_in(fs, dir))
            .collect()
    }

    fn names(&self, fs: &impl StoreFs) -> (Vec<String>, Vec<String>) {
        (names_in(fs, self.state_dir.path()), names_in(fs, self.config_dir.path()))
    }
}

fn files_in(fs: &FaultFs, dir: &Path) -> Vec<(String, Option<Vec<u8>>)> {
    names_in(fs, dir)
        .into_iter()
        .map(|name| {
            let bytes = fs.contents(&dir.join(&name));
            (name, bytes)
        })
        .collect()
}

fn names_in(fs: &impl StoreFs, dir: &Path) -> Vec<String> {
    fs.list_dir(dir)
        .unwrap()
        .into_iter()
        .map(|name| name.to_string_lossy().into_owned())
        .collect()
}

fn lock_files_only() -> (Vec<String>, Vec<String>) {
    (vec!["lock".to_owned()], vec!["config.toml.lock".to_owned()])
}

#[test]
fn discarding_a_full_vault_leaves_uninitialized_and_init_makes_a_new_vault() {
    let dirs = Dirs::new("reset-full");
    let fs = dirs.fault_fs();
    let old = dirs.full_vault(&fs);
    let discarded = dirs.discard(&fs).unwrap();
    assert_eq!(dirs.names(&fs), lock_files_only());
    assert_eq!(dirs.read(&fs), InitializationState::Uninitialized);
    assert_eq!(discarded.foreign, Vec::<String>::new());
    assert_eq!(discarded.finish_uncertain, None);
    assert_eq!(discarded.removed.first().map(String::as_str), Some("manifest.age"));
    assert_eq!(discarded.removed.get(1).map(String::as_str), Some("identity.age"));
    let config_files = ["config.toml.sig", "config.toml.sig.staged", "config.toml", "config.toml.pending"];
    assert_eq!(discarded.removed[discarded.removed.len() - 4..], config_files);
    assert_eq!(discarded.removed.len(), 16, "{:?}", discarded.removed);
    assert!(discarded.removed.contains(&"locked-by-owner".to_owned()), "{:?}", discarded.removed);
    fs.crash();
    assert_eq!(dirs.names(&fs), lock_files_only(), "every removal is durable");
    assert_ne!(dirs.init(&fs), old);
}

#[test]
fn the_scope_describes_the_vault_without_its_identity() {
    let dirs = Dirs::new("reset-scope");
    let fs = dirs.fault_fs();
    let vault_id = dirs.full_vault(&fs);
    dirs.put(&fs, "notes.txt");
    assert_eq!(
        dirs.scope(&fs),
        ResetScope {
            state: InitializationState::Initialized,
            has_vault_file: true,
            record_files: 1,
            config_files: ConfigFileName::ALL.to_vec(),
            foreign: vec!["notes.txt".to_owned()],
        }
    );
    assert_eq!(read_unverified_vault_id(&dirs.state, &fs), Ok(vault_id));
}

#[test]
fn a_foreign_file_survives_and_is_reported() {
    let dirs = Dirs::new("reset-foreign");
    let fs = dirs.fault_fs();
    dirs.full_vault(&fs);
    dirs.put(&fs, "notes.txt");
    let discarded = dirs.discard(&fs).unwrap();
    assert_eq!(discarded.foreign, ["notes.txt"]);
    assert_eq!(fs.contents(&dirs.state_dir.path().join("notes.txt")).unwrap(), b"x");
    assert_eq!(dirs.read(&fs), InitializationState::Unrecognized);
    assert!(!dirs.scope(&fs).has_vault_file);
}

#[test]
fn files_that_are_no_vault_leave_nothing_to_reset() {
    let only = |label: &str, put: &dyn Fn(&Dirs, &FaultFs)| {
        let dirs = Dirs::new(label);
        let fs = dirs.fault_fs();
        put(&dirs, &fs);
        let before = dirs.snapshot(&fs);
        assert!(!dirs.scope(&fs).has_vault_file, "{label}");
        assert_eq!(dirs.discard(&fs), Err(DiscardFailure::NothingToReset.into()), "{label}");
        assert_eq!(dirs.snapshot(&fs), before, "{label}");
    };
    only("reset-none-empty", &|_, _| {});
    only("reset-none-recovery", &|dirs, fs| dirs.put(fs, "recovery.toml"));
    // The owner-lock file is store-owned but no vault file: a directory holding only it has nothing to reset.
    only("reset-none-owner-lock", &|dirs, fs| dirs.put(fs, "locked-by-owner"));
    only("reset-none-temps", &|dirs, fs| {
        [".manifest.age.tmp", ".identity.age.tmp"].iter().for_each(|temp| {
            fs.create_private(&dirs.state_dir.path().join(temp)).unwrap();
        });
    });
    only("reset-none-config", &|dirs, fs| write_pending(&dirs.config, fs, b"mine").unwrap());
}

#[test]
fn stale_temp_files_of_store_owned_names_go_and_others_stay() {
    let dirs = Dirs::new("reset-temps");
    let fs = dirs.fault_fs();
    dirs.put(&fs, "manifest.age");
    [".identity.age.tmp", ".notes.txt.tmp", ".config.toml.pending.tmp"]
        .iter()
        .zip([dirs.state_dir.path(), dirs.state_dir.path(), dirs.config_dir.path()])
        .for_each(|(temp, dir)| {
            fs.create_private(&dir.join(temp)).unwrap();
        });
    let discarded = dirs.discard(&fs).unwrap();
    assert_eq!(discarded.removed, ["manifest.age", ".identity.age.tmp", ".config.toml.pending.tmp"]);
    assert_eq!(dirs.names(&fs).0, [".notes.txt.tmp", "lock"]);
}

#[test]
fn every_failure_leaves_the_intact_vault_or_an_unfinished_reset() {
    let reference = Dirs::new("reset-faults-reference");
    let fs = reference.fault_fs();
    reference.full_vault(&fs);
    let start = fs.trace().len();
    reference.discard(&fs).unwrap();
    let calls = fs.trace().len() - start;
    let failing: Vec<_> = (0..calls)
        .filter(|call| matches!(fs.trace()[start + call].op(), FsOp::RemoveFile | FsOp::SyncDir))
        .collect();
    assert!(failing.len() > 30, "{failing:?}");
    failing.iter().for_each(|&call| fail_and_resume(call));
}

/// Fails the `call`th filesystem call of a discard, then cuts the power, and checks the state each time.
fn fail_and_resume(call: usize) {
    let dirs = Dirs::new("reset-faults");
    let fs = dirs.fault_fs();
    dirs.full_vault(&fs);
    let intact = dirs.snapshot(&fs);
    fs.fail_call(fs.trace().len() + call, io::ErrorKind::Other);
    let first = dirs.discard(&fs);
    assert_safe(&dirs, &fs, &intact, &format!("call {call}, after {first:?}"));
    fs.crash();
    assert_safe(&dirs, &fs, &intact, &format!("call {call}, after power loss"));
    dirs.discard(&fs).unwrap();
    assert_eq!(dirs.names(&fs), lock_files_only(), "call {call}");
    assert_eq!(dirs.read(&fs), InitializationState::Uninitialized, "call {call}");
}

/// The directories hold the intact vault, read Unfinished reset, or are empty (a failed final fsync leaves the marker
/// gone until the power is cut); never a vault with files missing.
fn assert_safe(dirs: &Dirs, fs: &FaultFs, intact: &[(String, Option<Vec<u8>>)], context: &str) {
    match dirs.read(fs) {
        InitializationState::Initialized => assert_eq!(dirs.snapshot(fs), intact, "{context}"),
        InitializationState::Uninitialized => assert_eq!(dirs.names(fs), lock_files_only(), "{context}"),
        state => assert_eq!(state, InitializationState::UnfinishedReset, "{context}"),
    }
}

#[test]
fn a_reset_marker_over_empty_directories_is_finished_by_the_next_discard() {
    let dirs = Dirs::new("reset-marker-only");
    let fs = dirs.fault_fs();
    dirs.put(&fs, "reset.unfinished");
    assert_eq!(dirs.read(&fs), InitializationState::UnfinishedReset);
    assert_eq!(dirs.discard(&fs).unwrap().removed, Vec::<String>::new());
    assert_eq!(dirs.names(&fs), lock_files_only());
}

#[test]
fn a_failed_final_fsync_is_a_success_with_a_warning() {
    let dirs = Dirs::new("reset-finish-uncertain");
    let fs = dirs.fault_fs();
    dirs.put(&fs, "manifest.age");
    let start = fs.trace().len();
    dirs.discard(&fs).unwrap();
    let last = fs.trace().len() - 1 - start;
    let dirs = Dirs::new("reset-finish-uncertain-again");
    let fs = dirs.fault_fs();
    dirs.put(&fs, "manifest.age");
    fs.fail_call(fs.trace().len() + last, io::ErrorKind::Other);
    let discarded = dirs.discard(&fs).unwrap();
    assert_eq!(discarded.finish_uncertain, Some(ErrorKindLabel::from(io::ErrorKind::Other)));
    assert_eq!(dirs.read(&fs), InitializationState::Uninitialized);
}

#[test]
fn a_store_owned_name_that_is_not_a_regular_file_stops_the_discard_before_any_write() {
    let dirs = Dirs::new("reset-not-regular");
    let outside = TestDir::new("reset-not-regular-outside");
    std::fs::write(dirs.state_dir.path().join("manifest.age"), b"m").unwrap();
    std::fs::write(outside.path().join("target"), b"t").unwrap();
    std::os::unix::fs::symlink(outside.path().join("target"), dirs.state_dir.path().join("identity.age")).unwrap();
    std::fs::create_dir(dirs.config_dir.path().join("config.toml")).unwrap();
    assert_eq!(
        dirs.discard(&OsFs),
        Err(DiscardFailure::NotARegularFile {
            file: "identity.age".to_owned()
        }
        .into())
    );
    assert_eq!(names_in(&OsFs, dirs.state_dir.path()), ["identity.age", "lock", "manifest.age"]);
    assert_eq!(std::fs::read(outside.path().join("target")).unwrap(), b"t");
}

#[test]
fn the_reset_marker_decides_the_state_whatever_else_is_there() {
    let dirs = Dirs::new("reset-check-zero");
    let fs = dirs.fault_fs();
    dirs.full_vault(&fs);
    ["reset.unfinished", "init.unfinished", "notes.txt"].iter().for_each(|name| {
        dirs.put(&fs, name);
        assert_eq!(dirs.read(&fs), InitializationState::UnfinishedReset, "beside {name}");
    });
}

#[test]
fn an_unfinished_reset_refuses_unlock_and_init() {
    let dirs = Dirs::new("reset-refusals");
    let fs = dirs.fault_fs();
    dirs.full_vault(&fs);
    dirs.put(&fs, "reset.unfinished");
    let before = dirs.snapshot(&fs);
    let passphrase = Passphrase::new(SecretString::from(VAULT_PASSPHRASE)).unwrap();
    assert_eq!(
        unlock_with_passphrase(&dirs.state, &fs, &passphrase).err(),
        Some(UnlockError::ResetUnfinished)
    );
    assert_eq!(
        require_initialized(&dirs.state, &dirs.config, &fs),
        Err(UnlockError::ResetUnfinished)
    );
    assert_eq!(
        ensure_initializable(&dirs.state, &dirs.config, &fs),
        Err(InitStateError::ResetUnfinished)
    );
    assert_eq!(
        begin_initialization(&dirs.state, &dirs.config, &fs).map_err(|e| e.cause),
        Err(InitStateError::ResetUnfinished)
    );
    assert_eq!(dirs.snapshot(&fs), before);
    assert!(UnlockError::ResetUnfinished.to_string().contains("iron-vault reset"));
}
