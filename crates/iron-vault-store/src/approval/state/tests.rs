// SPDX-License-Identifier: MPL-2.0
//! Approval state operations end to end, and under an injected failure or a power cut at every filesystem step.

use std::io;
use std::path::PathBuf;

use super::*;
use crate::fault_fs::{FaultFs, FsCall, FsOp};
use crate::manifest::tests::KAT_IDENTITY;
use crate::test_dir::TestDir;
use crate::{ManifestError, OsFs, VaultManifest, durable_replace};

/// One operation under test, run against the state [`Setup::seeded`] builds.
type Op = fn(&Setup, &FaultFs, &mut ApprovalState) -> Result<(), ApprovalStateError>;

fn approver(seed: u8) -> PinnedApprover {
    PinnedApprover::from_seed(seed)
}

/// `seeds`' approvers, in the approver ID order the state keeps them in.
fn approvers(seeds: &[u8]) -> Vec<PinnedApprover> {
    let mut approvers: Vec<_> = seeds.iter().copied().map(approver).collect();
    approvers.sort_by_key(PinnedApprover::id);
    approvers
}

fn version(v: u64) -> ApprovalVersion {
    ApprovalVersion::new(v).unwrap()
}

/// The state generation of the manifest [`Setup::fs`] holds, which every write here records as its peer.
const MANIFEST: StateGeneration = StateGeneration::FIRST;

fn generation(value: u64) -> StateGeneration {
    StateGeneration::new(value).unwrap()
}

/// The state generation the write after `state` takes.
fn after(state: &ApprovalState) -> StateGeneration {
    StateGeneration::new(state.state_generation().get() + 1).unwrap()
}

/// The digest of the config approved as version `v`.
fn digest(v: u64) -> ConfigDigest {
    ConfigDigest::of(format!("config approved as version {v}").as_bytes())
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

/// A locked state directory whose files live in a [`FaultFs`] under the same path, and the vault's identity and ID.
struct Setup {
    dir: TestDir,
    lock: StateDirLock,
    identity: VaultIdentity,
    vault_id: VaultId,
}

impl Setup {
    fn new(label: &str) -> Self {
        let dir = TestDir::new(label);
        let lock = StateDirLock::acquire(dir.path()).unwrap();
        Self {
            dir,
            lock,
            identity: VaultIdentity::from_secret(KAT_IDENTITY),
            vault_id: VaultId::new_random(),
        }
    }

    fn path(&self) -> PathBuf {
        self.dir.path().join(StateFileName::approval_state().as_str())
    }

    fn manifest_path(&self) -> PathBuf {
        self.dir.path().join(StateFileName::manifest().as_str())
    }

    /// The sealed manifest of this vault at `state_generation` recording `peer`, with no records.
    fn manifest(&self, state_generation: StateGeneration, peer: Option<StateGeneration>) -> Vec<u8> {
        let manifest = VaultManifest::new(self.vault_id, state_generation, peer, Default::default()).unwrap();
        crate::seal_manifest(&self.identity, &manifest).unwrap()
    }

    /// A file system holding this vault's manifest at [`MANIFEST`], as `Vault::create` leaves it.
    fn fs(&self) -> FaultFs {
        FaultFs::new().with_durable_file(&self.manifest_path(), &self.manifest(MANIFEST, None))
    }

    /// Durably writes this vault's manifest at `state_generation` recording `peer`, as a vault write would.
    fn plant_manifest(&self, fs: &impl StoreFs, state_generation: StateGeneration, peer: Option<StateGeneration>) {
        durable_replace(&self.lock, fs, &StateFileName::manifest(), &self.manifest(state_generation, peer)).unwrap();
    }

    fn create(&self, fs: &impl StoreFs) -> Result<ApprovalState, ApprovalStateError> {
        ApprovalState::create(&self.lock, fs, &self.identity, approver(1))
    }

    fn load(&self, fs: &impl StoreFs) -> Result<ApprovalState, ApprovalStateError> {
        ApprovalState::load(&self.lock, fs, &self.identity, self.vault_id)
    }

    fn reserve(&self, fs: &impl StoreFs, state: &mut ApprovalState) -> Result<ApprovalVersion, ApprovalStateError> {
        state.reserve(&self.lock, fs, &self.identity)
    }

    fn commit(&self, fs: &impl StoreFs, state: &mut ApprovalState, v: u64) -> Result<(), ApprovalStateError> {
        state.commit(&self.lock, fs, &self.identity, version(v), digest(v))
    }

    fn enroll(&self, fs: &impl StoreFs, state: &mut ApprovalState, seed: u8) -> Result<(), ApprovalStateError> {
        state.enroll_approver(&self.lock, fs, &self.identity, approver(seed))
    }

    fn remove(&self, fs: &impl StoreFs, state: &mut ApprovalState, seed: u8) -> Result<(), ApprovalStateError> {
        state.remove_approver(&self.lock, fs, &self.identity, approver(seed).id())
    }

    /// Writes `state` as the durable file with any counters, which only a test can do.
    fn plant(&self, fs: &impl StoreFs, state: &ApprovalState) {
        durable_replace(
            &self.lock,
            fs,
            &StateFileName::approval_state(),
            &seal_approval_state(&self.identity, state).unwrap(),
        )
        .unwrap();
    }

    /// A created state with approvers 1 and 2 pinned, versions 1 and 2 reserved and version 1 committed, all durable.
    fn seeded(&self) -> (FaultFs, ApprovalState) {
        let fs = self.fs();
        let mut state = self.create(&fs).unwrap();
        self.enroll(&fs, &mut state, 2).unwrap();
        self.reserve(&fs, &mut state).unwrap();
        self.commit(&fs, &mut state, 1).unwrap();
        self.reserve(&fs, &mut state).unwrap();
        (fs, state)
    }

    /// The calls `op` makes on a freshly seeded state, numbered from 0.
    fn op_len(&self, op: Op) -> usize {
        let (fs, mut state) = self.seeded();
        let base = fs.trace().len();
        op(self, &fs, &mut state).unwrap();
        fs.trace().len() - base
    }

    /// Reloads after an interrupted operation and checks the state still works: the next reservation succeeds and is
    /// one above the reloaded counter. Returns the reloaded state.
    fn reload_working(&self, fs: &FaultFs, context: &str) -> ApprovalState {
        let state = self.load(fs).unwrap_or_else(|e| panic!("{context}: {e}"));
        let mut probe = state.clone();
        let next = self.reserve(fs, &mut probe).unwrap_or_else(|e| panic!("{context}: {e}"));
        assert_eq!(next.get(), state.highest_reserved() + 1, "{context}");
        state
    }
}

fn reserve_next(setup: &Setup, fs: &FaultFs, state: &mut ApprovalState) -> Result<(), ApprovalStateError> {
    setup.reserve(fs, state).map(|_| ())
}

fn commit_two(setup: &Setup, fs: &FaultFs, state: &mut ApprovalState) -> Result<(), ApprovalStateError> {
    setup.commit(fs, state, 2)
}

fn enroll_nine(setup: &Setup, fs: &FaultFs, state: &mut ApprovalState) -> Result<(), ApprovalStateError> {
    setup.enroll(fs, state, 9)
}

fn remove_two(setup: &Setup, fs: &FaultFs, state: &mut ApprovalState) -> Result<(), ApprovalStateError> {
    setup.remove(fs, state, 2)
}

/// Each operation, with the state it starts from and the state it commits.
fn operations(setup: &Setup) -> [(&'static str, Op, ApprovalState, ApprovalState); 4] {
    let (_, old) = setup.seeded();
    [
        (
            "reserve",
            reserve_next as Op,
            old.clone(),
            ApprovalState {
                highest_reserved: 3,
                state_generation: after(&old),
                ..old.clone()
            },
        ),
        (
            "commit",
            commit_two,
            old.clone(),
            ApprovalState {
                committed: Some((version(2), digest(2))),
                state_generation: after(&old),
                ..old.clone()
            },
        ),
        (
            "enroll approver",
            enroll_nine,
            old.clone(),
            ApprovalState {
                approvers: approvers(&[1, 2, 9]),
                state_generation: after(&old),
                ..old.clone()
            },
        ),
        (
            "remove approver",
            remove_two,
            old.clone(),
            ApprovalState {
                approvers: approvers(&[1]),
                state_generation: after(&old),
                ..old
            },
        ),
    ]
}

#[test]
fn reserve_counts_up_from_one_across_reopen_and_never_resets() {
    let setup = Setup::new("approval-count");
    let fs = setup.fs();
    let created = setup.create(&fs).unwrap();
    assert_eq!(
        (created.highest_reserved(), created.committed(), created.approvers()),
        (0, None, &approvers(&[1])[..])
    );
    (1..=3).for_each(|expected| {
        fs.crash();
        let mut state = setup.load(&fs).unwrap();
        assert_eq!(setup.reserve(&fs, &mut state).unwrap().get(), expected);
    });
    fs.crash();
    assert_eq!(setup.load(&fs).unwrap().highest_reserved(), 3);
}

#[test]
fn reserve_commit_and_approver_rotation_work_end_to_end_on_disk() {
    let setup = Setup::new("approval-e2e");
    let fs = OsFs;
    setup.plant_manifest(&fs, MANIFEST, None);
    let mut state = setup.create(&fs).unwrap();
    assert_eq!(setup.reserve(&fs, &mut state).unwrap(), ApprovalVersion::FIRST);
    setup.commit(&fs, &mut state, 1).unwrap();
    assert_eq!(setup.load(&fs).unwrap(), state);

    // A failed signing attempt still consumes its version: version 2 is reserved, never committed, and not reused.
    assert_eq!(setup.reserve(&fs, &mut state).unwrap().get(), 2);
    let mut state = setup.load(&fs).unwrap();
    assert_eq!(setup.reserve(&fs, &mut state).unwrap().get(), 3);
    setup.commit(&fs, &mut state, 3).unwrap();
    // Signing-key rotation: enroll the new approver, then remove the old one.
    setup.enroll(&fs, &mut state, 9).unwrap();
    setup.remove(&fs, &mut state, 1).unwrap();

    let reloaded = setup.load(&fs).unwrap();
    assert_eq!(reloaded, state);
    assert_eq!(
        (reloaded.highest_reserved(), reloaded.committed(), reloaded.approvers()),
        (3, Some((version(3), digest(3))), &approvers(&[9])[..])
    );
}

#[test]
fn enroll_then_remove_keeps_both_counters_across_reopen() {
    let setup = Setup::new("approval-rotate");
    let (fs, mut state) = setup.seeded();
    setup.enroll(&fs, &mut state, 9).unwrap();
    fs.crash();
    let mut reloaded = setup.load(&fs).unwrap();
    assert_eq!(
        (reloaded.highest_reserved(), reloaded.committed(), reloaded.approvers()),
        (2, Some((version(1), digest(1))), &approvers(&[1, 2, 9])[..])
    );
    setup.remove(&fs, &mut reloaded, 1).unwrap();
    fs.crash();
    let mut reloaded = setup.load(&fs).unwrap();
    assert_eq!(
        (reloaded.highest_reserved(), reloaded.committed(), reloaded.approvers()),
        (2, Some((version(1), digest(1))), &approvers(&[2, 9])[..])
    );
    assert_eq!(reloaded.approver(approver(9).id()), Some(&approver(9)));
    assert_eq!(reloaded.approver(approver(1).id()), None);
    assert_eq!(setup.reserve(&fs, &mut reloaded).unwrap().get(), 3);
}

#[test]
fn enroll_refuses_a_duplicate_id_a_pinned_key_and_a_seventeenth_approver_and_touches_no_file() {
    let setup = Setup::new("approval-enroll-refused");
    let (fs, mut state) = setup.seeded();
    let (calls, before) = (fs.trace().len(), state.clone());
    let two = approver(2);
    let same_id = PinnedApprover::software_for_tests(two.id(), *approver(9).public_key(), two.label().clone(), two.enrolled_at());
    let same_key = PinnedApprover::software_for_tests(approver(9).id(), *two.public_key(), two.label().clone(), two.enrolled_at());
    let mut enroll = |approver| state.enroll_approver(&setup.lock, &fs, &setup.identity, approver);
    assert_eq!(enroll(same_id), Err(ApprovalStateError::DuplicateApproverId(two.id())));
    assert_eq!(enroll(same_key), Err(ApprovalStateError::DuplicateApproverKey));
    assert_eq!((fs.trace().len(), &state), (calls, &before));

    (3..=MAX_APPROVERS as u8).for_each(|seed| setup.enroll(&fs, &mut state, seed).unwrap());
    assert_eq!(state.approvers(), approvers(&(1..=16).collect::<Vec<_>>()));
    let (calls, full) = (fs.trace().len(), state.clone());
    assert_eq!(setup.enroll(&fs, &mut state, 17), Err(ApprovalStateError::TooManyApprovers));
    assert_eq!((fs.trace().len(), &state), (calls, &full));
    assert_eq!(setup.load(&fs).unwrap(), full);
}

#[test]
fn remove_refuses_an_unknown_id_and_the_last_approver_and_touches_no_file() {
    let setup = Setup::new("approval-remove-refused");
    let (fs, mut state) = setup.seeded();
    let (calls, before) = (fs.trace().len(), state.clone());
    assert_eq!(
        setup.remove(&fs, &mut state, 9),
        Err(ApprovalStateError::UnknownApprover(approver(9).id()))
    );
    assert_eq!((fs.trace().len(), &state), (calls, &before));
    setup.remove(&fs, &mut state, 2).unwrap();
    let (calls, last) = (fs.trace().len(), state.clone());
    assert_eq!(setup.remove(&fs, &mut state, 1), Err(ApprovalStateError::LastApprover));
    assert_eq!((fs.trace().len(), &state), (calls, &last));
    assert_eq!(setup.load(&fs).unwrap().approvers(), approvers(&[1]));
}

#[test]
fn create_refuses_an_existing_file_and_never_resets_the_counter() {
    let setup = Setup::new("approval-create-existing");
    let (fs, state) = setup.seeded();
    let calls = fs.trace().len();
    assert_eq!(setup.create(&fs), Err(ApprovalStateError::AlreadyExists));
    let fs = fs.with_durable_file(&setup.path(), b"not an approval state");
    assert_eq!(setup.create(&fs), Err(ApprovalStateError::AlreadyExists));
    assert_eq!(mutations(&fs, calls), []);
    let fs = setup
        .fs()
        .with_durable_file(&setup.path(), &seal_approval_state(&setup.identity, &state).unwrap());
    assert_eq!(setup.create(&fs), Err(ApprovalStateError::AlreadyExists));
    assert_eq!(setup.load(&fs).unwrap().highest_reserved(), 2);
}

#[test]
fn reserve_at_u64_max_is_exhausted_and_touches_no_file() {
    let setup = Setup::new("approval-exhausted");
    let (fs, state) = setup.seeded();
    let mut last = ApprovalState {
        highest_reserved: u64::MAX,
        ..state
    };
    setup.plant(&fs, &last);
    let (calls, before) = (fs.trace().len(), last.clone());
    assert_eq!(setup.reserve(&fs, &mut last), Err(ApprovalStateError::Exhausted));
    assert_eq!((fs.trace().len(), &last), (calls, &before));
    assert_eq!(setup.load(&fs).unwrap(), before);
    // The last version can still be committed.
    setup.commit(&fs, &mut last, u64::MAX).unwrap();
    assert_eq!(setup.reserve(&fs, &mut last), Err(ApprovalStateError::Exhausted));
}

#[test]
fn every_write_takes_the_next_state_generation_and_records_the_manifest_on_disk() {
    let setup = Setup::new("approval-generations");
    let fs = FaultFs::new();
    setup.plant_manifest(&fs, generation(4), None);
    let mut state = setup.create(&fs).unwrap();
    assert_eq!(
        (state.vault_id(), state.state_generation(), state.peer_generation()),
        (setup.vault_id, generation(5), generation(4))
    );
    setup.reserve(&fs, &mut state).unwrap();
    assert_eq!((state.state_generation(), state.peer_generation()), (generation(6), generation(4)));
    // A vault write since: the next write is one above the manifest, not above this state, and records it.
    setup.plant_manifest(&fs, generation(9), Some(generation(6)));
    setup.commit(&fs, &mut state, 1).unwrap();
    assert_eq!((state.state_generation(), state.peer_generation()), (generation(10), generation(9)));
    setup.enroll(&fs, &mut state, 2).unwrap();
    assert_eq!((state.state_generation(), state.peer_generation()), (generation(11), generation(9)));
    setup.remove(&fs, &mut state, 2).unwrap();
    assert_eq!((state.state_generation(), state.peer_generation()), (generation(12), generation(9)));
    assert_eq!(setup.load(&fs).unwrap(), state);
}

/// A label, a way to break the manifest, and whether an error is the refusal that break causes.
type ManifestBreak<'a> = (&'a str, &'a dyn Fn(&FaultFs), &'a dyn Fn(&ApprovalStateError) -> bool);

#[test]
fn a_missing_damaged_or_foreign_manifest_refuses_every_write_and_touches_no_file() {
    let setup = Setup::new("approval-no-manifest");
    let foreign = VaultManifest::first(VaultId::new_random()).unwrap();
    let damaged = |fs: &FaultFs| {
        let mut bytes = fs.contents(&setup.manifest_path()).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        bytes
    };
    let missing = |fs: &FaultFs| crate::durable_remove(&setup.lock, fs, &StateFileName::manifest()).unwrap();
    let flip = |fs: &FaultFs| durable_replace(&setup.lock, fs, &StateFileName::manifest(), &damaged(fs)).unwrap();
    let other = |fs: &FaultFs| {
        let bytes = crate::seal_manifest(&setup.identity, &foreign).unwrap();
        durable_replace(&setup.lock, fs, &StateFileName::manifest(), &bytes).unwrap();
    };
    let not_found = |e: &ApprovalStateError| {
        matches!(
            e,
            ApprovalStateError::ManifestUnreadable(ReadError::Io {
                kind: io::ErrorKind::NotFound,
                ..
            })
        )
    };
    let is_damaged = |e: &ApprovalStateError| *e == ApprovalStateError::ManifestDamaged(ManifestError::Damaged);
    let mismatch = |e: &ApprovalStateError| *e == ApprovalStateError::ManifestDamaged(ManifestError::VaultIdMismatch);
    let breaks: [ManifestBreak<'_>; 3] = [
        ("missing", &missing, &not_found),
        ("damaged", &flip, &is_damaged),
        ("foreign", &other, &mismatch),
    ];
    breaks.into_iter().for_each(|(label, break_manifest, expected)| {
        let (fs, mut state) = setup.seeded();
        break_manifest(&fs);
        let (calls, before) = (fs.trace().len(), state.clone());
        let errors = [
            setup.reserve(&fs, &mut state).map(|_| ()).unwrap_err(),
            setup.commit(&fs, &mut state, 2).unwrap_err(),
            setup.enroll(&fs, &mut state, 9).unwrap_err(),
            setup.remove(&fs, &mut state, 2).unwrap_err(),
        ];
        errors.iter().for_each(|error| assert!(expected(error), "{label}: {error:?}"));
        assert_eq!((mutations(&fs, calls), &state), (vec![], &before), "{label}");
        // `load` refuses without a manifest of this vault to check against, so read the file alone.
        let on_disk = ApprovalState::read(&setup.lock, &fs, &setup.identity, setup.vault_id).unwrap();
        assert_eq!(on_disk, before, "{label}");
    });
    let created = ApprovalState::create(&setup.lock, &FaultFs::new(), &setup.identity, approver(1));
    assert!(created.as_ref().is_err_and(not_found), "{created:?}");
}

#[test]
fn every_write_at_state_generation_u64_max_is_exhausted_and_touches_no_file() {
    let setup = Setup::new("approval-generation-exhausted");
    let (fs, state) = setup.seeded();
    let last = generation(u64::MAX);
    let mut at_max = ApprovalState {
        state_generation: last,
        ..state.clone()
    };
    setup.plant(&fs, &at_max);
    let (calls, before) = (fs.trace().len(), at_max.clone());
    let exhausted = Err(ApprovalStateError::StateGenerationExhausted);
    assert_eq!(setup.reserve(&fs, &mut at_max).map(|_| ()), exhausted);
    assert_eq!(setup.commit(&fs, &mut at_max, 2), exhausted);
    assert_eq!(setup.enroll(&fs, &mut at_max, 9), exhausted);
    assert_eq!(setup.remove(&fs, &mut at_max, 2), exhausted);
    assert_eq!((mutations(&fs, calls), &at_max), (vec![], &before));

    // A manifest at u64::MAX exhausts the approval state's next write and its creation just the same.
    setup.plant(&fs, &state);
    setup.plant_manifest(&fs, last, Some(state.state_generation()));
    let (calls, mut current) = (fs.trace().len(), state.clone());
    assert_eq!(setup.reserve(&fs, &mut current).map(|_| ()), exhausted);
    assert_eq!((mutations(&fs, calls), &current), (vec![], &state));
    let fresh = FaultFs::new().with_durable_file(&setup.manifest_path(), &setup.manifest(last, None));
    assert_eq!(setup.create(&fresh).map(|_| ()), exhausted);
    assert_eq!(mutations(&fresh, 0), []);
}

#[test]
fn commit_refuses_unreserved_and_not_newer_versions_and_touches_no_file() {
    let setup = Setup::new("approval-commit-refused");
    let (fs, mut state) = setup.seeded();
    let (calls, before) = (fs.trace().len(), state.clone());
    let refusals = [
        (
            3,
            ApprovalStateError::NotReserved {
                version: version(3),
                highest_reserved: 2,
            },
        ),
        (
            u64::MAX,
            ApprovalStateError::NotReserved {
                version: version(u64::MAX),
                highest_reserved: 2,
            },
        ),
        (
            1,
            ApprovalStateError::NotNewer {
                version: version(1),
                committed: version(1),
            },
        ),
    ];
    refusals
        .into_iter()
        .for_each(|(v, error)| assert_eq!(setup.commit(&fs, &mut state, v), Err(error), "{v}"));
    assert_eq!((fs.trace().len(), &state), (calls, &before));

    // A newer reserved version commits, and then the one it replaced is refused as not newer.
    setup.commit(&fs, &mut state, 2).unwrap();
    assert_eq!(
        setup.commit(&fs, &mut state, 2),
        Err(ApprovalStateError::NotNewer {
            version: version(2),
            committed: version(2)
        })
    );
    assert_eq!(
        setup.commit(&fs, &mut state, 1),
        Err(ApprovalStateError::NotNewer {
            version: version(1),
            committed: version(2)
        })
    );
}

#[test]
fn the_first_commit_may_skip_versions_whose_signing_failed() {
    let setup = Setup::new("approval-first-commit");
    let fs = setup.fs();
    let mut state = setup.create(&fs).unwrap();
    assert_eq!(
        setup.commit(&fs, &mut state, 1),
        Err(ApprovalStateError::NotReserved {
            version: version(1),
            highest_reserved: 0
        })
    );
    (0..3).for_each(|_| {
        setup.reserve(&fs, &mut state).unwrap();
    });
    setup.commit(&fs, &mut state, 3).unwrap();
    assert_eq!(setup.load(&fs).unwrap().committed(), Some((version(3), digest(3))));
}

#[test]
fn a_stale_state_writes_nothing_and_never_lowers_the_counter() {
    let setup = Setup::new("approval-stale");
    let (fs, mut current) = setup.seeded();
    let mut stale = setup.load(&fs).unwrap();
    setup.reserve(&fs, &mut current).unwrap();

    // The stale state still has highest reserved 2, so without the disk check it would hand out version 3 again.
    let calls = fs.trace().len();
    assert_eq!(setup.reserve(&fs, &mut stale), Err(ApprovalStateError::ReloadRequired));
    assert_eq!(setup.commit(&fs, &mut stale, 2), Err(ApprovalStateError::ReloadRequired));
    assert_eq!(setup.enroll(&fs, &mut stale, 9), Err(ApprovalStateError::ReloadRequired));
    assert_eq!(setup.remove(&fs, &mut stale, 2), Err(ApprovalStateError::ReloadRequired));
    assert_eq!(mutations(&fs, calls), []);
    assert_eq!(setup.load(&fs).unwrap(), current);
}

#[test]
fn a_missing_or_damaged_file_blocks_writes_and_loads() {
    let setup = Setup::new("approval-damaged");
    [true, false].into_iter().for_each(|gone| {
        let (fs, mut state) = setup.seeded();
        match gone {
            true => crate::durable_remove(&setup.lock, &fs, &StateFileName::approval_state()).unwrap(),
            false => {
                let mut bytes = fs.contents(&setup.path()).unwrap();
                let last = bytes.len() - 1;
                bytes[last] ^= 1;
                durable_replace(&setup.lock, &fs, &StateFileName::approval_state(), &bytes).unwrap();
            }
        }
        let calls = fs.trace().len();
        assert_eq!(
            setup.reserve(&fs, &mut state),
            Err(ApprovalStateError::ReloadRequired),
            "gone: {gone}"
        );
        assert_eq!(mutations(&fs, calls), [], "gone: {gone}");
        let loaded = setup.load(&fs);
        assert!(
            matches!(loaded, Err(ApprovalStateError::Read(_) | ApprovalStateError::Damaged)),
            "gone: {gone}: {loaded:?}"
        );
    });
}

#[test]
fn a_state_for_another_vault_id_is_refused_on_load() {
    let setup = Setup::new("approval-other-vault");
    let (fs, _) = setup.seeded();
    let other = ApprovalState::load(&setup.lock, &fs, &setup.identity, VaultId::new_random());
    assert_eq!(other, Err(ApprovalStateError::VaultIdMismatch));
}

#[test]
fn an_uncertain_write_leaves_memory_unchanged_and_blocks_writes_until_reload() {
    let setup = Setup::new("approval-uncertain");
    operations(&setup).into_iter().for_each(|(label, op, old, new)| {
        let (fs, mut state) = setup.seeded();
        fs.fail_call(fs.trace().len() + setup.op_len(op) - 1, io::ErrorKind::StorageFull);
        let result = op(&setup, &fs, &mut state);
        assert!(
            matches!(
                result,
                Err(ApprovalStateError::WriteUncertain(WriteError::Io {
                    step: WriteStep::SyncDir,
                    ..
                }))
            ),
            "{label}"
        );
        assert_eq!(state, old, "{label}");
        assert!(state.is_unsettled(), "{label}");
        let calls = fs.trace().len();
        assert_eq!(setup.reserve(&fs, &mut state), Err(ApprovalStateError::ReloadRequired), "{label}");
        assert_eq!(mutations(&fs, calls), [], "{label}");
        // The rename happened, so a reload without a crash sees the new state.
        assert_eq!(setup.reload_working(&fs, label), new, "{label}");
        assert!(!setup.load(&fs).unwrap().is_unsettled(), "{label}");
    });
}

#[test]
fn a_failure_at_every_step_leaves_the_old_or_the_new_state() {
    let setup = Setup::new("approval-faults");
    operations(&setup).into_iter().for_each(|(label, op, old, new)| {
        (0..setup.op_len(op)).for_each(|i| {
            let context = format!("{label}, fault at call {i}");
            let (fs, mut state) = setup.seeded();
            fs.fail_call(fs.trace().len() + i, io::ErrorKind::StorageFull);
            let result = op(&setup, &fs, &mut state);
            let on_disk = match &result {
                Ok(()) => &new,
                Err(ApprovalStateError::WriteUncertain(_)) => &new,
                Err(_) => &old,
            };
            assert_eq!(&state, if result.is_ok() { &new } else { &old }, "{context}");
            assert_eq!(&setup.load(&fs).unwrap(), on_disk, "{context}");
            fs.crash();
            let after_crash = setup.reload_working(&fs, &context);
            assert!(after_crash == old || after_crash == new, "{context}: {after_crash:?}");
        });
    });
}

#[test]
fn a_crash_at_every_point_leaves_the_old_or_the_new_state() {
    let setup = Setup::new("approval-crash");
    operations(&setup).into_iter().for_each(|(label, op, old, new)| {
        (0..=setup.op_len(op)).for_each(|k| {
            let context = format!("{label}, power cut after {k} calls");
            let (fs, mut state) = setup.seeded();
            fs.cut_power_after(fs.trace().len() + k);
            let result = op(&setup, &fs, &mut state);
            fs.crash();
            let reloaded = setup.reload_working(&fs, &context);
            assert!(reloaded == old || reloaded == new, "{context}: {reloaded:?}");
            assert!(
                result.is_err() || reloaded == new,
                "{context}: an operation that returned Ok was lost"
            );
        });
    });
}

#[test]
fn a_reserved_version_returned_as_ok_is_never_handed_out_again_after_a_crash() {
    let setup = Setup::new("approval-no-reuse");
    (0..=setup.op_len(reserve_next)).for_each(|k| {
        let (fs, mut state) = setup.seeded();
        fs.cut_power_after(fs.trace().len() + k);
        let returned = setup.reserve(&fs, &mut state);
        fs.crash();
        let mut reloaded = setup.load(&fs).unwrap();
        let next = setup.reserve(&fs, &mut reloaded).unwrap();
        match returned {
            Ok(returned) => assert!(next > returned, "power cut after {k} calls: {next} handed out after {returned}"),
            Err(_) => assert!(next.get() >= 3, "power cut after {k} calls: {next}"),
        }
    });
}

#[test]
fn the_state_is_written_only_by_one_durable_replace_per_operation() {
    let setup = Setup::new("approval-trace");
    let path = setup.path();
    operations(&setup).into_iter().for_each(|(label, op, _, _)| {
        let (fs, mut state) = setup.seeded();
        let base = fs.trace().len();
        op(&setup, &fs, &mut state).unwrap();
        let renames: Vec<FsCall> = fs.trace().split_off(base).into_iter().filter(|c| c.op() == FsOp::Rename).collect();
        assert!(
            matches!(renames.as_slice(), [FsCall::Rename { to, .. }] if *to == path),
            "{label}: {renames:?}"
        );
        assert_eq!(fs.trace().last().map(FsCall::op), Some(FsOp::SyncDir), "{label}");
    });
}
