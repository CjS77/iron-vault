//! The approval transaction end to end, and under an injected failure or a power cut at every filesystem call.
//!
//! Every failure is checked against the split spec §3.9 requires: a transaction that fails before its commit leaves
//! the previous committed approval and the published pair that verifies as it; one that fails after leaves the new
//! committed approval and files that recovery rows 1 to 4 of design/config-approval.md finish.

use std::io;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey};

use super::*;
use crate::ConfigFileName::{Active, ActiveSignature, Pending, StagedSignature};
use crate::fault_fs::{FaultFs, FsCall, FsOp};
use crate::manifest::tests::KAT_IDENTITY;
use crate::test_dir::TestDir;
use crate::{
    ApprovalEnvelope, ConfigFileName, PinnedApprover, SignatureAlgorithm, StateFileName, StateGeneration, VaultId, VaultManifest,
    durable_replace, read_config_file, seal_approval_state,
};

const OLD_CONFIG: &[u8] = b"# version 1\n[listener.agent]\nbind = \"127.0.0.1:8080\"\n";
const NEW_CONFIG: &[u8] = b"# version 2\n[listener.agent]\nbind = \"127.0.0.1:8081\"\n";
const OLD: ApprovalVersion = ApprovalVersion::FIRST;

fn version(v: u64) -> ApprovalVersion {
    ApprovalVersion::new(v).unwrap()
}

/// The pause guard's stand-in: the store cannot see the service's snapshot holder.
struct Paused;

impl AdmissionPaused for Paused {}

/// An Ed25519 signer that can be told to fail, as a TPM signer authorizing inside step 3 would.
struct TestSigner {
    key: SigningKey,
    fail: Option<SignError>,
}

impl TestSigner {
    fn pinned() -> Self {
        Self::with_seed(7)
    }

    fn with_seed(seed: u8) -> Self {
        Self {
            key: SigningKey::from_bytes(&[seed; 32]),
            fail: None,
        }
    }

    fn failing(fail: SignError) -> Self {
        Self {
            fail: Some(fail),
            ..Self::pinned()
        }
    }
}

impl ApprovalSigner for TestSigner {
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Ed25519
    }

    fn pinned(&self) -> PinnedApprover {
        PinnedApprover::from_signing_key(&self.key)
    }

    fn sign(&self, payload: &ApprovalPayload) -> Result<ApprovalEnvelope, SignError> {
        if let Some(fail) = &self.fail {
            return Err(fail.clone());
        }
        let signature = self.key.sign(&payload.encode()).to_bytes().to_vec();
        ApprovalEnvelope::new(SignatureAlgorithm::Ed25519, *payload, signature).map_err(SignError::Signature)
    }
}

/// A signer that must never be asked to sign.
struct UnusableSigner;

impl ApprovalSigner for UnusableSigner {
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Ed25519
    }

    fn pinned(&self) -> PinnedApprover {
        TestSigner::pinned().pinned()
    }

    fn sign(&self, _: &ApprovalPayload) -> Result<ApprovalEnvelope, SignError> {
        panic!("nothing may be signed")
    }
}

/// Locked state and config directories whose files live in a [`FaultFs`] under the same paths.
struct Setup {
    state_dir: TestDir,
    config_dir: TestDir,
    state_lock: StateDirLock,
    config_lock: ConfigDirLock,
    identity: VaultIdentity,
    vault_id: VaultId,
}

/// Where recovery finds a file of the committed approval: in place, or waiting as the pending or staged file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Place {
    InPlace,
    Waiting,
}

impl Setup {
    fn new(label: &str) -> Self {
        let state_dir = TestDir::new(&format!("{label}-state"));
        let config_dir = TestDir::new(&format!("{label}-config"));
        Self {
            state_lock: StateDirLock::acquire(state_dir.path()).unwrap(),
            config_lock: ConfigDirLock::acquire(config_dir.path()).unwrap(),
            state_dir,
            config_dir,
            identity: VaultIdentity::from_secret(KAT_IDENTITY),
            vault_id: VaultId::new_random(),
        }
    }

    fn storage<'a>(&'a self, fs: &'a FaultFs) -> ApprovalStorage<'a, FaultFs> {
        ApprovalStorage {
            state_dir: &self.state_lock,
            config_dir: &self.config_lock,
            identity: &self.identity,
            fs,
        }
    }

    fn config_path(&self, name: ConfigFileName) -> PathBuf {
        self.config_dir.path().join(name.as_str())
    }

    fn state_path(&self) -> PathBuf {
        self.state_dir.path().join(StateFileName::approval_state().as_str())
    }

    /// A vault with `OLD_CONFIG` approved, committed and published as version 1, everything durable.
    fn seeded(&self) -> (FaultFs, ApprovalState) {
        let manifest = VaultManifest::new(self.vault_id, StateGeneration::FIRST, None, Default::default()).unwrap();
        let manifest_path = self.state_dir.path().join(StateFileName::manifest().as_str());
        let fs = FaultFs::new().with_durable_file(&manifest_path, &crate::seal_manifest(&self.identity, &manifest).unwrap());
        let mut state = ApprovalState::create(&self.state_lock, &fs, &self.identity, TestSigner::pinned().pinned()).unwrap();
        let committed = approve(self, &fs, &mut state, OLD_CONFIG, TestSigner::pinned()).unwrap();
        assert_eq!(committed.approval().version(), OLD);
        (fs, state)
    }

    fn load(&self, fs: &FaultFs) -> ApprovalState {
        ApprovalState::load(&self.state_lock, fs, &self.identity, self.vault_id).unwrap()
    }

    fn read(&self, fs: &FaultFs, name: ConfigFileName) -> Option<Vec<u8>> {
        read_config_file(&self.config_lock, fs, name).ok()
    }

    /// Where the committed approval's config and approval are, as the recovery table looks for them.
    fn locate(&self, fs: &FaultFs, state: &ApprovalState) -> (Option<Place>, Option<Place>) {
        let (_, digest) = state.committed().unwrap();
        let holds_config = |name| self.read(fs, name).filter(|b| ConfigDigest::of(b) == digest);
        let config = holds_config(Active)
            .map(|b| (Place::InPlace, b))
            .or_else(|| holds_config(Pending).map(|b| (Place::Waiting, b)));
        let Some((config_place, bytes)) = config else {
            return (None, None);
        };
        let verifies = |name| self.read(fs, name).is_some_and(|sig| verify_approval(state, &bytes, &sig).is_ok());
        let approval = [(ActiveSignature, Place::InPlace), (StagedSignature, Place::Waiting)]
            .into_iter()
            .find_map(|(name, place)| verifies(name).then_some(place));
        (Some(config_place), approval)
    }

    /// The previous approval is untouched: version 1 is committed, and the published pair is `OLD_CONFIG` verifying as it.
    fn assert_previous(&self, fs: &FaultFs, context: &str) {
        let state = self.load(fs);
        assert_eq!(state.committed().map(|(v, _)| v), Some(OLD), "{context}");
        assert_eq!(self.locate(fs, &state), (Some(Place::InPlace), Some(Place::InPlace)), "{context}");
        assert_eq!(self.read(fs, Active).as_deref(), Some(OLD_CONFIG), "{context}");
    }

    /// The new approval is committed, and its files are where recovery rows 1 to 4 find them. Returns their places.
    fn assert_new_committed(&self, fs: &FaultFs, context: &str) -> (Option<Place>, Option<Place>) {
        let state = self.load(fs);
        assert_eq!(state.committed(), Some((version(2), ConfigDigest::of(NEW_CONFIG))), "{context}");
        let places = self.locate(fs, &state);
        assert!(
            places.0.is_some() && places.1.is_some(),
            "{context}: recovery cannot finish {places:?}"
        );
        places
    }

    fn assert_nothing_staged(&self, fs: &FaultFs, context: &str) {
        assert_eq!((self.read(fs, Pending), self.read(fs, StagedSignature)), (None, None), "{context}");
    }
}

/// Runs the whole transaction for `config`.
fn approve(
    setup: &Setup,
    fs: &FaultFs,
    state: &mut ApprovalState,
    config: &[u8],
    signer: impl ApprovalSigner,
) -> Result<CommittedApproval, ApprovalError> {
    let storage = setup.storage(fs);
    let pending = PendingConfig::write(&storage, config.to_vec())?;
    pending.prepare(&storage, state, signer)?.commit(&storage, &Paused)
}

/// Approves `NEW_CONFIG` on a seeded vault, after `inject` has set up faults counted from the approval's first call.
fn approve_new(setup: &Setup, inject: impl FnOnce(&FaultFs, usize)) -> (FaultFs, ApprovalState, Result<CommittedApproval, ApprovalError>) {
    let (fs, mut state) = setup.seeded();
    inject(&fs, fs.trace().len());
    let result = approve(setup, &fs, &mut state, NEW_CONFIG, TestSigner::pinned());
    (fs, state, result)
}

/// The calls a clean approval of `NEW_CONFIG` makes, from its first.
fn clean_calls(setup: &Setup) -> Vec<FsCall> {
    let (fs, _, result) = approve_new(setup, |_, _| ());
    result.unwrap();
    let base = setup.seeded().0.trace().len();
    fs.trace().split_off(base)
}

/// Whether the approval reached its commit, by its result.
fn committed(result: &Result<CommittedApproval, ApprovalError>) -> Option<bool> {
    match result.as_ref().map_err(ApprovalError::progress) {
        Ok(_) | Err(ApprovalProgress::Committed(_)) => Some(true),
        Err(ApprovalProgress::NothingReserved | ApprovalProgress::Reserved(_)) => Some(false),
        Err(ApprovalProgress::CommitUncertain(_)) => None,
    }
}

#[test]
fn a_clean_approval_commits_and_publishes_the_next_version() {
    let setup = Setup::new("txn-happy");
    let (fs, state, result) = approve_new(&setup, |_, _| ());
    let committed = result.unwrap();
    assert_eq!(committed.approval().version(), version(2));
    assert_eq!(committed.approval().digest(), ConfigDigest::of(NEW_CONFIG));
    assert_eq!(committed.config(), NEW_CONFIG);
    assert_eq!((state.highest_reserved(), state.committed().map(|(v, _)| v)), (2, Some(version(2))));
    assert_eq!(setup.load(&fs), state);
    assert_eq!(
        setup.assert_new_committed(&fs, "clean"),
        (Some(Place::InPlace), Some(Place::InPlace))
    );
    assert_eq!(setup.read(&fs, Active).as_deref(), Some(NEW_CONFIG));
    setup.assert_nothing_staged(&fs, "clean");
}

#[test]
fn the_steps_run_in_order_each_durable_before_the_next_and_nothing_is_read_back() {
    let setup = Setup::new("txn-order");
    let calls = clean_calls(&setup);
    let renamed: Vec<PathBuf> = calls
        .iter()
        .filter_map(|c| match c {
            FsCall::Rename { to, .. } => Some(to.clone()),
            _ => None,
        })
        .collect();
    let (state, config) = (setup.state_path(), |n| setup.config_path(n));
    assert_eq!(
        renamed,
        [
            config(Pending),
            state.clone(),
            config(StagedSignature),
            state,
            config(Active),
            config(ActiveSignature)
        ]
    );
    // Each step's rename is followed by an fsync of its directory before the next step's rename.
    let renames: Vec<usize> = (0..calls.len()).filter(|&i| calls[i].op() == FsOp::Rename).collect();
    let steps = [renames[0], renames[1], renames[2], renames[3], renames[5]];
    steps.windows(2).for_each(|w| {
        let synced = calls[w[0]..w[1]].iter().any(|c| c.op() == FsOp::SyncDir);
        assert!(synced, "no directory fsync between calls {} and {}", w[0], w[1]);
    });
    let pending_read = calls
        .iter()
        .any(|c| matches!(c, FsCall::ReadBounded(p) if *p == setup.config_path(Pending)));
    assert!(!pending_read, "the pending config was read back");
}

#[test]
fn a_failure_at_every_call_leaves_the_previous_approval_or_a_finishable_new_one() {
    let setup = Setup::new("txn-faults");
    (0..clean_calls(&setup).len()).for_each(|i| {
        let context = format!("fault at call {i}");
        let (fs, _, result) = approve_new(&setup, |fs, base| fs.fail_call(base + i, io::ErrorKind::StorageFull));
        match committed(&result) {
            Some(false) => {
                setup.assert_previous(&fs, &context);
                setup.assert_nothing_staged(&fs, &context);
            }
            Some(true) => {
                let places = setup.assert_new_committed(&fs, &context);
                if result.is_ok() {
                    assert_eq!(places, (Some(Place::InPlace), Some(Place::InPlace)), "{context}");
                }
            }
            None => panic!("{context}: one fault cannot leave the commit uncertain, since settling runs: {result:?}"),
        }
        fs.crash();
        match committed(&result) {
            Some(false) => setup.assert_previous(&fs, &format!("{context}, after reboot")),
            _ => {
                setup.assert_new_committed(&fs, &format!("{context}, after reboot"));
            }
        }
    });
}

/// The paths of each rename that ran before call `cut`, counted from `base`, and that no fsync of its directory
/// followed before the cut: the renames a crash may keep or lose. A synced rename is durable already, and keeping its
/// paths again would undo half of a later rename of one of them.
fn unsynced_renames(fs: &FaultFs, base: usize, cut: usize) -> Vec<Vec<PathBuf>> {
    let trace = fs.trace();
    let ran = &trace[base..(base + cut).min(trace.len())];
    let synced_after = |i: usize, dir: &Path| ran[i + 1..].iter().any(|c| matches!(c, FsCall::SyncDir(d) if d == dir));
    ran.iter()
        .enumerate()
        .filter_map(|(i, c)| match c {
            FsCall::Rename { from, to } if !to.parent().is_some_and(|dir| synced_after(i, dir)) => Some(vec![from.clone(), to.clone()]),
            _ => None,
        })
        .collect()
}

#[test]
fn power_loss_after_every_call_leaves_the_previous_approval_or_a_finishable_new_one() {
    let setup = Setup::new("txn-crash");
    (0..=clean_calls(&setup).len()).for_each(|k| {
        let (probe, _, _) = approve_new(&setup, |fs, base| fs.cut_power_after(base + k));
        let base = setup.seeded().0.trace().len();
        let renames = unsynced_renames(&probe, base, k);
        // Lose every unsynced rename, keep all of them, or keep each one alone.
        let keeps: Vec<Vec<PathBuf>> = [Vec::new(), renames.concat()].into_iter().chain(renames).collect();
        keeps.iter().for_each(|keep| {
            let context = format!("power cut after {k} calls, keeping {keep:?}");
            let (fs, _, result) = approve_new(&setup, |fs, base| fs.cut_power_after(base + k));
            fs.crash_keeping(&keep.iter().map(PathBuf::as_path).collect::<Vec<&Path>>());
            let reloaded = setup.load(&fs);
            match (committed(&result), reloaded.committed().map(|(v, _)| v)) {
                (Some(false), _) | (None, Some(OLD)) => setup.assert_previous(&fs, &context),
                (Some(true), _) | (None, _) => {
                    setup.assert_new_committed(&fs, &context);
                }
            }
        });
    });
}

/// The index, from the approval's first call, of step 5's directory fsync: the one after the second rename of
/// `approval.age`.
fn commit_sync_index(setup: &Setup, calls: &[FsCall]) -> usize {
    let state = setup.state_path();
    let commit_rename = calls
        .iter()
        .enumerate()
        .filter(|(_, c)| matches!(c, FsCall::Rename { to, .. } if *to == state))
        .nth(1)
        .map(|(i, _)| i)
        .unwrap();
    commit_rename + 1 + calls[commit_rename + 1..].iter().position(|c| c.op() == FsOp::SyncDir).unwrap()
}

#[test]
fn an_uncertain_commit_is_settled_by_a_second_durable_write_before_publishing() {
    let setup = Setup::new("txn-settle");
    let sync = commit_sync_index(&setup, &clean_calls(&setup));
    let (fs, state, result) = approve_new(&setup, |fs, base| fs.fail_call(base + sync, io::ErrorKind::StorageFull));
    assert_eq!(result.unwrap().approval().version(), version(2));
    let state_writes = fs
        .trace()
        .iter()
        .filter(|c| matches!(c, FsCall::Rename { to, .. } if *to == setup.state_path()))
        .count();
    // Creation, version 1's reservation and commit, version 2's reservation, and its commit written twice.
    assert_eq!(state_writes, 6);
    assert_eq!(setup.load(&fs), state);
    fs.crash();
    assert_eq!(
        setup.assert_new_committed(&fs, "settled"),
        (Some(Place::InPlace), Some(Place::InPlace))
    );
}

#[test]
fn a_commit_that_cannot_be_settled_is_uncertain_and_leaves_its_files_in_place() {
    let setup = Setup::new("txn-unsettled");
    let sync = commit_sync_index(&setup, &clean_calls(&setup));
    let (probe, _, _) = approve_new(&setup, |fs, base| fs.fail_call(base + sync, io::ErrorKind::StorageFull));
    let base = setup.seeded().0.trace().len();
    let settle_len = probe.trace()[base + sync + 1..]
        .iter()
        .position(|c| c.op() == FsOp::ListDir)
        .unwrap();
    (1..=settle_len).for_each(|j| {
        let context = format!("settling fails at its call {j}");
        let (fs, mut state, result) = approve_new(&setup, |fs, base| {
            fs.fail_call(base + sync, io::ErrorKind::StorageFull);
            fs.fail_call(base + sync + j, io::ErrorKind::StorageFull);
        });
        let error = result.unwrap_err();
        assert_eq!(
            (error.step(), error.progress()),
            (ApprovalStep::Commit, ApprovalProgress::CommitUncertain(version(2))),
            "{context}"
        );
        assert_eq!(
            setup.assert_new_committed(&fs, &context),
            (Some(Place::Waiting), Some(Place::Waiting)),
            "{context}"
        );
        let refused = state.reserve(&setup.state_lock, &fs, &setup.identity);
        assert_eq!(refused, Err(ApprovalStateError::ReloadRequired), "{context}");
        fs.crash();
        match setup.load(&fs).committed().map(|(v, _)| v) {
            Some(OLD) => setup.assert_previous(&fs, &context),
            _ => {
                setup.assert_new_committed(&fs, &context);
            }
        }
    });
}

#[test]
fn a_failed_signer_consumes_its_version_and_stages_nothing() {
    let setup = Setup::new("txn-signer");
    let signers = [
        (
            TestSigner::failing(SignError::WrongPassphrase),
            ApprovalFailure::Sign(SignError::WrongPassphrase),
        ),
        (
            TestSigner::failing(SignError::KeyMismatch),
            ApprovalFailure::Sign(SignError::KeyMismatch),
        ),
        (TestSigner::with_seed(9), ApprovalFailure::BadApproval(VerifyError::BadSignature)),
    ];
    signers.into_iter().for_each(|(signer, cause)| {
        let context = format!("{cause:?}");
        let (fs, mut state) = setup.seeded();
        let error = approve(&setup, &fs, &mut state, NEW_CONFIG, signer).unwrap_err();
        let expected = (ApprovalStep::Sign, ApprovalProgress::Reserved(version(2)), &cause);
        assert_eq!((error.step(), error.progress(), error.cause()), expected, "{context}");
        setup.assert_nothing_staged(&fs, &context);
        setup.assert_previous(&fs, &context);
        assert_eq!(setup.load(&fs).highest_reserved(), 2, "{context}");
        let next = approve(&setup, &fs, &mut state, NEW_CONFIG, TestSigner::pinned()).unwrap();
        assert_eq!(next.approval().version(), version(3), "{context}");
    });
}

#[test]
fn an_exhausted_counter_fails_before_signing_and_stages_nothing() {
    let setup = Setup::new("txn-exhausted");
    let (fs, state) = setup.seeded();
    let mut last = state.with_highest_reserved(u64::MAX);
    let sealed = seal_approval_state(&setup.identity, &last).unwrap();
    durable_replace(&setup.state_lock, &fs, &StateFileName::approval_state(), &sealed).unwrap();
    let error = approve(&setup, &fs, &mut last, NEW_CONFIG, UnusableSigner).unwrap_err();
    let expected = (
        ApprovalStep::Reserve,
        ApprovalProgress::NothingReserved,
        &ApprovalFailure::State(ApprovalStateError::Exhausted),
    );
    assert_eq!((error.step(), error.progress(), error.cause()), expected);
    setup.assert_nothing_staged(&fs, "exhausted");
    setup.assert_previous(&fs, "exhausted");
}

#[test]
fn what_is_signed_is_the_buffer_written_in_step_1_not_the_file() {
    let setup = Setup::new("txn-bytes");
    let (fs, mut state) = setup.seeded();
    let storage = setup.storage(&fs);
    let pending = PendingConfig::write(&storage, NEW_CONFIG.to_vec()).unwrap();
    let edited = [NEW_CONFIG, b" "].concat();
    write_pending(&setup.config_lock, &fs, &edited).unwrap();
    let prepared = pending.prepare(&storage, &mut state, TestSigner::pinned()).unwrap();
    let staged = ApprovalEnvelope::decode(&setup.read(&fs, StagedSignature).unwrap()).unwrap();
    assert_eq!(staged.payload().digest(), ConfigDigest::of(NEW_CONFIG));
    assert_eq!(prepared.digest(), ConfigDigest::of(NEW_CONFIG));
    let committed = prepared.commit(&storage, &Paused).unwrap();
    assert_eq!(committed.config(), NEW_CONFIG);
    // The edited file was published, so the config check refuses it rather than serving what was not signed.
    let (config, sig) = (setup.read(&fs, Active).unwrap(), setup.read(&fs, ActiveSignature).unwrap());
    assert_eq!(config, edited);
    assert_eq!(verify_approval(&state, &config, &sig), Err(VerifyError::ConfigChanged));
}
