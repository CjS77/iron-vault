//! Partial restore end to end: a control file copied back from an older copy, or deleted, after real writes is refused
//! at open, at approval state load and by every write; a history written normally, or cut short by a failure at any
//! step, never is.

use std::io;

use tracing::Level;

use super::tests::{capture_logs, identity, init_test_tracing, n};
use super::write_tests::{material, mutations, origins};
use super::*;
use crate::fault_fs::FaultFs;
use crate::test_dir::TestDir;
use crate::{ApprovalVersion, ConfigDigest, OsFs, PinnedApprover, VaultId, durable_remove, durable_replace};

/// The bytes of the two control files on disk: the manifest, and the approval state or `None` while it does not exist.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Disk {
    manifest: Vec<u8>,
    approval: Option<Vec<u8>>,
}

/// The disk after each step of a history, by step label.
type History = Vec<(&'static str, Disk)>;

/// One write cut short by a failure, run against a vault and approval state [`Fixture::book`] builds.
type Op = fn(&Fixture, &FaultFs, &mut Vault, &mut ApprovalState);

fn approver(seed: u8) -> PinnedApprover {
    PinnedApprover::from_signing_key(&ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
}

fn g(value: u64) -> StateGeneration {
    StateGeneration::new(value).unwrap()
}

/// The disk `history` recorded after the step labelled `label`.
fn after<'a>(history: &'a History, label: &str) -> &'a Disk {
    history
        .iter()
        .find(|(step, _)| *step == label)
        .map(|(_, disk)| disk)
        .unwrap_or_else(|| panic!("no step {label}"))
}

/// The error an open, and a vault write, returns for `restore`.
fn refused(restore: PartialRestore) -> VaultError {
    VaultError::SharedStateDamaged {
        file: restore.file(),
        damage: SharedStateDamage::PartialRestore(restore),
    }
}

fn behind(file: StateFileName, expected: Option<u64>, found: Option<u64>) -> PartialRestore {
    PartialRestore::Behind {
        file,
        expected: expected.map(g),
        found: found.map(g),
    }
}

/// A locked state directory.
struct Fixture {
    /// Held so the directory outlives the lock and the test.
    _dir: TestDir,
    lock: StateDirLock,
}

impl Fixture {
    fn new(label: &str) -> Self {
        init_test_tracing();
        let dir = TestDir::new(label);
        let lock = StateDirLock::acquire(dir.path()).unwrap();
        Self { _dir: dir, lock }
    }

    fn open(&self, fs: &impl StoreFs) -> Result<(Vault, OpenReport), VaultError> {
        Vault::open(&self.lock, fs, identity())
    }

    fn load(&self, fs: &impl StoreFs, vault_id: VaultId) -> Result<ApprovalState, ApprovalStateError> {
        ApprovalState::load(&self.lock, fs, &identity(), vault_id)
    }

    fn create_approval(&self, fs: &impl StoreFs) -> Result<ApprovalState, ApprovalStateError> {
        ApprovalState::create(&self.lock, fs, &identity(), approver(1))
    }

    fn add(&self, fs: &impl StoreFs, vault: &mut Vault, name: &str) {
        vault.add(&self.lock, fs, n(name), material(name, 1), origins(name)).unwrap();
    }

    fn reserve(&self, fs: &impl StoreFs, approval: &mut ApprovalState) -> ApprovalVersion {
        approval.reserve(&self.lock, fs, &identity()).unwrap()
    }

    fn commit(&self, fs: &impl StoreFs, approval: &mut ApprovalState, version: ApprovalVersion) {
        let digest = ConfigDigest::of(format!("config {version}").as_bytes());
        approval.commit(&self.lock, fs, &identity(), version, digest).unwrap();
    }

    fn read(&self, fs: &impl StoreFs, file: &StateFileName) -> Option<Vec<u8>> {
        match read_state_file(&self.lock, fs, file, MAX_MANIFEST_LEN as u64) {
            Ok(bytes) => Some(bytes),
            Err(ReadError::Io {
                kind: io::ErrorKind::NotFound,
                ..
            }) => None,
            Err(error) => panic!("reading {file}: {error}"),
        }
    }

    fn disk(&self, fs: &impl StoreFs) -> Disk {
        Disk {
            manifest: self.read(fs, &StateFileName::manifest()).unwrap(),
            approval: self.read(fs, &StateFileName::approval_state()),
        }
    }

    /// Puts `disk` on disk, as a restore from a copy of the state directory would.
    fn put(&self, fs: &impl StoreFs, disk: &Disk) {
        let approval = StateFileName::approval_state();
        durable_replace(&self.lock, fs, &StateFileName::manifest(), &disk.manifest).unwrap();
        match (&disk.approval, self.read(fs, &approval)) {
            (Some(bytes), _) => durable_replace(&self.lock, fs, &approval, bytes).unwrap(),
            (None, Some(_)) => durable_remove(&self.lock, fs, &approval).unwrap(),
            (None, None) => {}
        }
    }

    /// Checks the vault opens, and the approval state loads if it exists, as a history of real writes leaves them.
    fn assert_opens(&self, fs: &impl StoreFs, context: &str) {
        let (vault, _) = self.open(fs).unwrap_or_else(|e| panic!("{context}: {e}"));
        if self.read(fs, &StateFileName::approval_state()).is_some() {
            self.load(fs, vault.manifest().vault_id())
                .unwrap_or_else(|e| panic!("{context}: {e}"));
        }
    }

    /// Runs a history of interleaved vault and approval state writes, checking the vault opens after every step, and
    /// returns the disk after each. Its state generations run 1 to 10; the vault is unapproved for the first two.
    fn history(&self, fs: &impl StoreFs) -> History {
        let mut history = Vec::new();
        let mut step = |label: &'static str| {
            self.assert_opens(fs, label);
            history.push((label, self.disk(fs)));
        };
        let mut vault = Vault::create(&self.lock, fs, identity()).unwrap();
        step("create");
        self.add(fs, &mut vault, "keep");
        step("add keep");
        let mut approval = self.create_approval(fs).unwrap();
        step("create approval");
        self.add(fs, &mut vault, "fx_key");
        step("add fx_key");
        let first = self.reserve(fs, &mut approval);
        step("reserve");
        self.commit(fs, &mut approval, first);
        step("commit");
        self.add(fs, &mut vault, "brave");
        step("add brave");
        self.reserve(fs, &mut approval);
        step("reserve again");
        vault
            .replace(&self.lock, fs, n("fx_key"), material("fx_key", 2), origins("fx_key"))
            .unwrap();
        step("replace fx_key");
        vault.remove(&self.lock, fs, &n("keep")).unwrap();
        step("remove keep");
        history
    }

    /// A vault holding `keep` and an approval state with version 1 reserved: state generation 4 on the manifest.
    fn book(&self, fs: &FaultFs) -> (Vault, ApprovalState) {
        let mut vault = Vault::create(&self.lock, fs, identity()).unwrap();
        self.add(fs, &mut vault, "keep");
        let mut approval = self.create_approval(fs).unwrap();
        self.add(fs, &mut vault, "fx_key");
        self.reserve(fs, &mut approval);
        (vault, approval)
    }
}

#[test]
fn an_older_control_file_copied_back_or_a_deleted_approval_state_is_refused_at_open_and_load() {
    let fixture = Fixture::new("restore-open");
    let history = fixture.history(&OsFs);
    let current = after(&history, "remove keep").clone();
    let vault_id = fixture.open(&OsFs).unwrap().0.manifest().vault_id();
    let manifest_of = |label| Disk {
        manifest: after(&history, label).manifest.clone(),
        ..current.clone()
    };
    let approval_of = |label: &str| Disk {
        approval: after(&history, label).approval.clone(),
        ..current.clone()
    };
    // The manifest is at 10 recording 8; the approval state is at 8 recording 7.
    let cases = [
        (
            "approval state from reserve",
            approval_of("reserve"),
            behind(StateFileName::approval_state(), Some(8), Some(5)),
        ),
        (
            "approval state deleted",
            approval_of("add keep"),
            behind(StateFileName::approval_state(), Some(8), None),
        ),
        (
            "manifest from add fx_key",
            manifest_of("add fx_key"),
            behind(StateFileName::manifest(), Some(7), Some(4)),
        ),
    ];
    cases.into_iter().for_each(|(label, restored, restore)| {
        fixture.put(&OsFs, &restored);
        let (opened, events) = capture_logs(|| fixture.open(&OsFs));
        assert_eq!(opened.unwrap_err(), refused(restore.clone()), "{label}");
        assert_eq!(events.len(), 1, "{label}: {events:?}");
        assert_eq!(
            (events[0].level, events[0].field("file")),
            (Level::ERROR, restore.file().as_str()),
            "{label}"
        );
        let damage = events[0].field("damage");
        assert!(
            damage.contains("restored from an older copy") && damage.contains("recovery key or reset"),
            "{label}: {damage}"
        );
        if restored.approval.is_some() {
            assert_eq!(
                fixture.load(&OsFs, vault_id),
                Err(ApprovalStateError::PartialRestore(restore)),
                "{label}"
            );
        }
        fixture.put(&OsFs, &current);
        fixture.assert_opens(&OsFs, label);
    });
}

/// Every older copy of one control file beside the current other: refused exactly when the two were never on disk
/// together, which is what a partial restore is. A pair that once was on disk cannot be told from the current one.
#[test]
fn a_single_file_restore_is_refused_unless_the_pair_was_once_on_disk() {
    let fixture = Fixture::new("restore-every-copy");
    let history = fixture.history(&OsFs);
    let current = after(&history, "remove keep").clone();
    let restores = history.iter().flat_map(|(label, older)| {
        [
            (
                format!("manifest from {label}"),
                Disk {
                    manifest: older.manifest.clone(),
                    ..current.clone()
                },
            ),
            (
                format!("approval state from {label}"),
                Disk {
                    approval: older.approval.clone(),
                    ..current.clone()
                },
            ),
        ]
    });
    restores.for_each(|(label, restored)| {
        let once_on_disk = history.iter().any(|(_, disk)| *disk == restored);
        fixture.put(&OsFs, &restored);
        match fixture.open(&OsFs) {
            Ok(_) => assert!(once_on_disk, "{label}: accepted a pair never on disk"),
            Err(VaultError::SharedStateDamaged {
                damage: SharedStateDamage::PartialRestore(_),
                ..
            }) => assert!(!once_on_disk, "{label}: refused a pair a history left"),
            Err(error) => panic!("{label}: {error}"),
        }
    });
}

fn add_fresh(fixture: &Fixture, fs: &FaultFs, vault: &mut Vault, _: &mut ApprovalState) {
    let _ = vault.add(&fixture.lock, fs, n("fresh"), material("fresh", 1), origins("fresh"));
}

fn reserve_next(fixture: &Fixture, fs: &FaultFs, _: &mut Vault, approval: &mut ApprovalState) {
    let _ = approval.reserve(&fixture.lock, fs, &identity());
}

fn commit_first(fixture: &Fixture, fs: &FaultFs, _: &mut Vault, approval: &mut ApprovalState) {
    let _ = approval.commit(&fixture.lock, fs, &identity(), ApprovalVersion::FIRST, ConfigDigest::of(b"config"));
}

/// A way to cut a write short at file-system call `n`.
type Cut = fn(&FaultFs, usize);

fn fail_at(fs: &FaultFs, n: usize) {
    fs.fail_call(n, io::ErrorKind::StorageFull);
}

fn cut_power_after(fs: &FaultFs, n: usize) {
    fs.cut_power_after(n);
}

/// A failure or a power cut at any step of one write leaves the old or the new file, and either agrees with the other
/// file: the vault still opens and the approval state still loads.
#[test]
fn a_write_cut_short_at_any_step_still_opens() {
    let fixture = Fixture::new("restore-crash");
    let ops: [(&str, Op); 3] = [
        ("vault add", add_fresh),
        ("approval reserve", reserve_next),
        ("approval commit", commit_first),
    ];
    ops.into_iter().for_each(|(label, op)| {
        let calls = {
            let fs = FaultFs::new();
            let (mut vault, mut approval) = fixture.book(&fs);
            let base = fs.trace().len();
            op(&fixture, &fs, &mut vault, &mut approval);
            fs.trace().len() - base
        };
        (0..=calls).for_each(|k| {
            let cuts: [(&str, Cut); 2] = [("failure", fail_at), ("power cut", cut_power_after)];
            cuts.into_iter().for_each(|(cut, inject)| {
                let fs = FaultFs::new();
                let (mut vault, mut approval) = fixture.book(&fs);
                inject(&fs, fs.trace().len() + k);
                op(&fixture, &fs, &mut vault, &mut approval);
                fs.crash();
                fixture.assert_opens(&fs, &format!("{label}, {cut} at call {k}"));
            });
        });
    });
}

/// Writing over a partial restore would record the restored file, or no approval state, as the peer and make the pair
/// agree again; every vault write refuses instead.
#[test]
fn a_vault_write_refuses_a_deleted_or_restored_approval_state_and_touches_no_file() {
    let fixture = Fixture::new("restore-vault-write");
    let fs = FaultFs::new();
    let (mut vault, mut approval) = fixture.book(&fs);
    let older = fixture.disk(&fs);
    fixture.reserve(&fs, &mut approval);
    fixture.add(&fs, &mut vault, "brave");
    let current = fixture.disk(&fs);
    // The manifest is at 7 recording the approval state at 6, which was at 5 in `older`.
    let cases = [
        ("deleted", None, behind(StateFileName::approval_state(), Some(6), None)),
        (
            "restored",
            older.approval,
            behind(StateFileName::approval_state(), Some(6), Some(5)),
        ),
    ];
    cases.into_iter().for_each(|(label, approval_bytes, restore)| {
        fixture.put(
            &fs,
            &Disk {
                approval: approval_bytes,
                ..current.clone()
            },
        );
        let (calls, before) = (fs.trace().len(), vault.manifest().clone());
        let expected = refused(restore);
        let add = vault.add(&fixture.lock, &fs, n("fresh"), material("fresh", 1), origins("fresh"));
        assert_eq!(add.unwrap_err(), expected, "{label}");
        let replace = vault.replace(&fixture.lock, &fs, n("keep"), material("keep", 2), origins("keep"));
        assert_eq!(replace.unwrap_err(), expected, "{label}");
        assert_eq!(vault.remove(&fixture.lock, &fs, &n("keep")).unwrap_err(), expected, "{label}");
        assert_eq!((mutations(&fs, calls), vault.manifest()), (vec![], &before), "{label}");
    });
}

#[test]
fn an_approval_state_write_refuses_a_restored_manifest_and_touches_no_file() {
    let fixture = Fixture::new("restore-approval-write");
    let fs = FaultFs::new();
    let (mut vault, mut approval) = fixture.book(&fs);
    let older = fixture.disk(&fs);
    fixture.add(&fs, &mut vault, "brave");
    fixture.reserve(&fs, &mut approval);
    // The approval state is at 7 recording the manifest at 6; the manifest copied back is at 4.
    fixture.put(
        &fs,
        &Disk {
            approval: fixture.disk(&fs).approval,
            ..older
        },
    );
    let (calls, before) = (fs.trace().len(), approval.clone());
    let expected = Err(ApprovalStateError::PartialRestore(behind(
        StateFileName::manifest(),
        Some(6),
        Some(4),
    )));
    assert_eq!(approval.reserve(&fixture.lock, &fs, &identity()).map(|_| ()), expected);
    assert_eq!(
        approval.commit(&fixture.lock, &fs, &identity(), ApprovalVersion::FIRST, ConfigDigest::of(b"c")),
        expected
    );
    assert_eq!(approval.replace_approver(&fixture.lock, &fs, &identity(), approver(9)), expected);
    assert_eq!((mutations(&fs, calls), &approval), (vec![], &before));
}

/// An approval state has existed, so creating one again would reset its version counters (spec §3.9).
#[test]
fn creating_an_approval_state_the_manifest_records_is_refused_and_touches_no_file() {
    let fixture = Fixture::new("restore-approval-create");
    let fs = FaultFs::new();
    let (mut vault, _) = fixture.book(&fs);
    fixture.add(&fs, &mut vault, "brave");
    durable_remove(&fixture.lock, &fs, &StateFileName::approval_state()).unwrap();
    let calls = fs.trace().len();
    // The manifest is at 6 recording the approval state at 5.
    let expected = ApprovalStateError::PartialRestore(behind(StateFileName::approval_state(), Some(5), None));
    assert_eq!(fixture.create_approval(&fs).unwrap_err(), expected);
    assert_eq!(mutations(&fs, calls), []);
}
