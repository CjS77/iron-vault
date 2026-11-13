// SPDX-License-Identifier: MPL-2.0
//! Approver changes against the fault filesystem: each failing step, the read-back and the orphan sweep.

use std::io;
use std::path::PathBuf;

use iron_vault_tpm_protocol::TpmKeyBlob;
use secrecy::SecretString;

use super::*;
use crate::fault_fs::{FaultFs, FsCall, FsOp};
use crate::manifest::tests::KAT_IDENTITY;
use crate::test_dir::TestDir;
use crate::{SignatureAlgorithm, VaultId, VaultManifest, WriteStep, durable_replace};

const PASSPHRASE: &str = "a new approval passphrase";

fn passphrase(text: &str) -> ApprovalPassphrase {
    ApprovalPassphrase::new(SecretString::from(text)).unwrap()
}

fn label(text: &str) -> ApproverLabel {
    ApproverLabel::new(text).unwrap()
}

/// A locked state directory whose files live in a [`FaultFs`] under the same path, with a vault whose one pinned approver
/// is [`PinnedApprover::from_seed`] 1, which has no key file.
struct Setup {
    dir: TestDir,
    lock: StateDirLock,
    identity: VaultIdentity,
    fs: FaultFs,
    state: ApprovalState,
}

impl Setup {
    fn new() -> Self {
        let dir = TestDir::new("approver-change");
        let lock = StateDirLock::acquire(dir.path()).unwrap();
        let identity = VaultIdentity::from_secret(KAT_IDENTITY);
        let manifest = VaultManifest::new(VaultId::new_random(), crate::StateGeneration::FIRST, None, Default::default()).unwrap();
        let manifest_path = dir.path().join(StateFileName::manifest().as_str());
        let fs = FaultFs::new().with_durable_file(&manifest_path, &crate::seal_manifest(&identity, &manifest).unwrap());
        let state = ApprovalState::create(&lock, &fs, &identity, PinnedApprover::from_seed(1)).unwrap();
        Self {
            dir,
            lock,
            identity,
            fs,
            state,
        }
    }

    fn changes(&self) -> ApproverChanges<'_, FaultFs> {
        ApproverChanges::new(&self.lock, &self.fs, &self.identity)
    }

    fn enroll(&mut self) -> Result<PinnedApprover, ApproverChangeError> {
        let changes = ApproverChanges::new(&self.lock, &self.fs, &self.identity);
        changes.enroll_software_approver_for_tests(&mut self.state, label("second"), &passphrase(PASSPHRASE), UtcSecond::EPOCH)
    }

    fn remove(&mut self, id: ApproverId) -> Result<KeyFileOutcome, ApproverChangeError> {
        ApproverChanges::new(&self.lock, &self.fs, &self.identity).remove_approver(&mut self.state, id)
    }

    fn key_path(&self, id: ApproverId) -> PathBuf {
        self.dir.path().join(StateFileName::approver_key(id).as_str())
    }

    fn has_key_file(&self, id: ApproverId) -> bool {
        self.fs.contents(&self.key_path(id)).is_some()
    }

    /// The approval state on disk.
    fn load(&self) -> ApprovalState {
        ApprovalState::load(&self.lock, &self.fs, &self.identity, self.state.vault_id()).unwrap()
    }

    /// Plants `bytes` as the key file of `id`, as a failed enrollment or a failed removal leaves one.
    fn plant_key_file(&self, id: ApproverId) {
        write_signer_key(&self.lock, &self.fs, id, b"leftover").unwrap();
    }

    /// The IDs whose key files exist, in file name order.
    fn key_file_ids(&self) -> Vec<ApproverId> {
        let names = self.fs.list_dir(self.lock.dir()).unwrap();
        names.iter().filter_map(|n| StateFileName::approver_key_id(n.to_str()?)).collect()
    }

    /// The directory-changing calls since call `from`.
    fn mutations(&self, from: usize) -> Vec<FsCall> {
        let changes = [FsOp::CreatePrivate, FsOp::Rename, FsOp::RemoveFile];
        self.fs
            .trace()
            .split_off(from)
            .into_iter()
            .filter(|c| changes.contains(&c.op()))
            .collect()
    }

    fn read_back(&mut self) -> Result<ReadBack, ApproverChangeError> {
        ApproverChanges::new(&self.lock, &self.fs, &self.identity).read_back_approval_state(&mut self.state)
    }

    /// Reads the approval state back and sweeps the orphans against it, as a command's step 3 does.
    fn settle(&mut self) -> Vec<ApproverId> {
        let changes = ApproverChanges::new(&self.lock, &self.fs, &self.identity);
        let read = changes.read_back_approval_state(&mut self.state).unwrap();
        changes.remove_orphan_key_files(&read).unwrap()
    }

    /// Plants key files for two new orphans and returns their IDs in file name order.
    fn plant_two_orphans(&self) -> [ApproverId; 2] {
        let mut orphans = [ApproverId::generate(), ApproverId::generate()];
        orphans.sort();
        orphans.iter().for_each(|id| self.plant_key_file(*id));
        orphans
    }
}

/// The indices, from the end of `prepare`, of the calls of `op` that `act` makes on a fresh [`Setup`], so a test fails a
/// call by what it is and not by a count that changes with the implementation. `prepare` and `act` make the same calls
/// whenever they run and with any IDs.
fn calls_of<T>(op: FsOp, prepare: impl Fn(&mut Setup) -> T, act: impl Fn(&mut Setup, T)) -> Vec<usize> {
    let mut setup = Setup::new();
    let prepared = prepare(&mut setup);
    let from = setup.fs.trace().len();
    act(&mut setup, prepared);
    let calls = setup.fs.trace().split_off(from);
    (0..calls.len()).filter(|i| calls[*i].op() == op).collect()
}

/// The calls a clean enrollment makes on a fresh [`Setup`].
fn enroll_calls() -> usize {
    let mut setup = Setup::new();
    let base = setup.fs.trace().len();
    setup.enroll().unwrap();
    setup.fs.trace().len() - base
}

#[test]
fn an_enrolled_approver_opens_with_its_passphrase_and_is_pinned() {
    let mut setup = Setup::new();

    let approver = setup.enroll().unwrap();

    assert_eq!(setup.state.approver(approver.id()), Some(&approver));
    assert_eq!(setup.load(), setup.state);
    assert_eq!((approver.kind(), approver.label().as_str()), (SignerKind::Software, "second"));
    let envelope = read_signer_key(&setup.lock, &setup.fs, approver.id()).unwrap();
    let signer = open_signer_key(&envelope, &passphrase(PASSPHRASE), setup.state.approvers()).unwrap();
    assert_eq!(crate::ApprovalSigner::public_key(&signer), *approver.public_key());
    let wrong = open_signer_key(&envelope, &passphrase("another passphrase"), setup.state.approvers());
    assert!(matches!(wrong, Err(SignError::WrongPassphrase)));
}

#[test]
fn every_enrollment_gets_a_new_approver_id_and_key_file() {
    let mut setup = Setup::new();
    let ids: Vec<_> = (0..3).map(|_| setup.enroll().unwrap().id()).collect();

    let mut sorted = ids.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), 3);
    assert_eq!(setup.key_file_ids(), sorted);
}

#[test]
fn removing_an_approver_unpins_it_and_deletes_its_key_file() {
    let mut setup = Setup::new();
    let id = setup.enroll().unwrap().id();

    assert_eq!(setup.remove(id), Ok(KeyFileOutcome::Removed));

    assert!(!setup.has_key_file(id));
    assert!(setup.state.approver(id).is_none());
    assert_eq!(setup.load(), setup.state);
}

#[test]
fn a_failure_at_every_step_before_the_commit_leaves_the_state_unchanged_and_at_most_an_orphan() {
    let calls = enroll_calls();
    let steps: Vec<_> = (0..calls)
        .map(|i| {
            let mut setup = Setup::new();
            let before = setup.state.clone();
            setup.fs.fail_call(setup.fs.trace().len() + i, io::ErrorKind::StorageFull);

            let error = setup.enroll().unwrap_err();

            let unknown = i == calls - 1;
            assert_eq!(
                error.may_have_committed() == MayHaveCommitted::Unknown,
                unknown,
                "call {i}: {error}"
            );
            assert_eq!(setup.state, before, "call {i}");
            assert_eq!(setup.load().approvers().len(), if unknown { 2 } else { 1 }, "call {i}");
            assert!(setup.key_file_ids().len() <= 1, "call {i}");
            (error.step(), setup.settle().len() + usize::from(unknown))
        })
        .collect();
    let seen = |step| steps.iter().any(|(s, _)| *s == step);
    assert!(
        [
            ApproverChangeStep::KeyFile,
            ApproverChangeStep::KeyCheck,
            ApproverChangeStep::ApprovalState
        ]
        .into_iter()
        .all(seen)
    );
    assert!(steps.iter().all(|(_, left_or_pinned)| *left_or_pinned <= 1));
}

#[test]
fn a_failed_directory_fsync_after_the_rename_reports_unknown_and_the_read_back_settles_it() {
    let mut setup = Setup::new();
    let last = setup.fs.trace().len() + enroll_calls() - 1;
    setup.fs.fail_call(last, io::ErrorKind::StorageFull);

    let error = setup.enroll().unwrap_err();

    assert_eq!(error.may_have_committed(), MayHaveCommitted::Unknown);
    assert_eq!(error.step(), ApproverChangeStep::ApprovalState);
    assert!(matches!(
        &error,
        ApproverChangeError::ApprovalState(ApprovalStateError::WriteUncertain(_))
    ));
    assert!(setup.state.is_unsettled());
    assert_eq!(setup.state.approvers().len(), 1);
    let refused = setup.enroll().unwrap_err();
    assert_eq!(refused, ApproverChangeError::ApprovalState(ApprovalStateError::ReloadRequired));
    assert_eq!(refused.may_have_committed(), MayHaveCommitted::No);

    let enrolled_by_the_failed_commit = setup.key_file_ids();
    assert_eq!(enrolled_by_the_failed_commit.len(), 1);
    assert_eq!(setup.settle(), []);
    assert_eq!(setup.key_file_ids(), enrolled_by_the_failed_commit);
    assert!(!setup.state.is_unsettled());
    assert_eq!(setup.state.approvers().len(), 2);
    assert!(setup.enroll().is_ok());
}

#[test]
fn a_read_back_of_an_older_approval_state_restored_while_unsettled_is_refused_and_keeps_every_key_file() {
    let mut setup = Setup::new();
    let older = setup
        .fs
        .contents(&setup.dir.path().join(StateFileName::approval_state().as_str()))
        .unwrap();
    let last = setup.fs.trace().len() + enroll_calls() - 1;
    setup.fs.fail_call(last, io::ErrorKind::StorageFull);
    setup.enroll().unwrap_err();
    assert!(setup.state.is_unsettled());
    let enrolled = setup.key_file_ids();
    assert_eq!(enrolled.len(), 1, "the premise: a key file only the newer state pins");
    // A write that follows the enrollment records its approval state generation in the manifest.
    let newer = setup.load();
    let generation = |n| crate::StateGeneration::new(n).unwrap();
    let manifest = VaultManifest::new(newer.vault_id(), generation(4), Some(newer.state_generation()), Default::default()).unwrap();
    durable_replace(
        &setup.lock,
        &setup.fs,
        &StateFileName::manifest(),
        &crate::seal_manifest(&setup.identity, &manifest).unwrap(),
    )
    .unwrap();
    durable_replace(&setup.lock, &setup.fs, &StateFileName::approval_state(), &older).unwrap();
    let vault_id = setup.state.vault_id();
    let adopted = ApprovalState::read(&setup.lock, &setup.fs, &setup.identity, vault_id).unwrap();
    assert_eq!(
        adopted.approvers().len(),
        1,
        "the premise: a read without the manifest check would adopt it"
    );
    let unsettled = setup.state.clone();
    let from = setup.fs.trace().len();

    let error = setup.read_back().unwrap_err();

    assert!(
        matches!(
            &error,
            ApproverChangeError::ReadBackUnreadable(ApprovalStateError::PartialRestore(_))
        ),
        "{error}"
    );
    assert!(error.to_string().contains("nothing was changed"), "{error}");
    assert_eq!(
        (error.step(), error.may_have_committed()),
        (ApproverChangeStep::ReadBack, MayHaveCommitted::No)
    );
    assert!(setup.state.is_unsettled());
    assert_eq!(setup.state, unsettled);
    assert_eq!(setup.mutations(from), []);
    assert_eq!(setup.key_file_ids(), enrolled);
}

#[test]
fn a_read_back_that_differs_from_a_settled_state_is_refused_and_deletes_nothing() {
    let mut setup = Setup::new();
    let orphan = ApproverId::generate();
    setup.plant_key_file(orphan);
    let mut other = setup.state.clone();
    other
        .enroll_approver(&setup.lock, &setup.fs, &setup.identity, PinnedApprover::from_seed(7))
        .unwrap();
    let stale = setup.state.clone();
    let from = setup.fs.trace().len();

    let error = setup.read_back().unwrap_err();

    assert_eq!(error, ApproverChangeError::ReadBackDiffers);
    assert_eq!(
        (error.step(), error.may_have_committed()),
        (ApproverChangeStep::ReadBack, MayHaveCommitted::No)
    );
    assert_eq!(setup.state, stale);
    assert_eq!(setup.mutations(from), []);
    assert!(setup.has_key_file(orphan));
}

#[test]
fn a_read_back_of_a_file_that_does_not_open_or_is_missing_is_refused_and_deletes_nothing() {
    let mut setup = Setup::new();
    let orphan = ApproverId::generate();
    setup.plant_key_file(orphan);
    let damaged = [Some(&b"not an approval state"[..]), None];
    damaged.into_iter().for_each(|file| {
        match file {
            Some(bytes) => durable_replace(&setup.lock, &setup.fs, &StateFileName::approval_state(), bytes).unwrap(),
            None => crate::durable_remove(&setup.lock, &setup.fs, &StateFileName::approval_state()).unwrap(),
        }
        let error = setup.read_back().unwrap_err();

        assert!(matches!(error, ApproverChangeError::ReadBackUnreadable(_)), "{error}");
        assert_eq!(
            (error.step(), error.may_have_committed()),
            (ApproverChangeStep::ReadBack, MayHaveCommitted::No)
        );
        assert!(setup.has_key_file(orphan));
    });
}

#[test]
fn the_sweep_removes_only_ids_the_read_back_state_does_not_pin() {
    let mut setup = Setup::new();
    let pinned = setup.enroll().unwrap().id();
    let orphans = setup.plant_two_orphans();
    let others = ["approver-NOT-A-UUID.age", "record-1.age", "notes.txt"];
    others
        .iter()
        .for_each(|name| durable_replace(&setup.lock, &setup.fs, &StateFileName::new(name).unwrap(), b"x").unwrap());

    let mut removed = setup.settle();

    removed.sort();
    assert_eq!(removed, orphans);
    assert_eq!(setup.key_file_ids(), [pinned]);
    let names = setup.fs.list_dir(setup.lock.dir()).unwrap();
    assert!(others.iter().all(|other| names.iter().any(|n| n == other)));
    assert_eq!(setup.settle(), []);
}

#[test]
fn a_sweep_that_fails_partway_reports_the_orphans_it_already_deleted() {
    let prepare = |setup: &mut Setup| {
        setup.plant_two_orphans();
        setup.read_back().unwrap()
    };
    let act = |setup: &mut Setup, read: ReadBack| drop(setup.changes().remove_orphan_key_files(&read));
    let second_unlink = calls_of(FsOp::RemoveFile, prepare, act)[1];
    let mut setup = Setup::new();
    let orphans = setup.plant_two_orphans();
    let read = setup.read_back().unwrap();
    setup
        .fs
        .fail_call(setup.fs.trace().len() + second_unlink, io::ErrorKind::PermissionDenied);

    let error = setup.changes().remove_orphan_key_files(&read).unwrap_err();

    assert!(
        matches!(&error, ApproverChangeError::OrphanSweep { error: WriteError::Io { step: WriteStep::Remove, .. }, removed } if *removed == [orphans[0]]),
        "{error:?}"
    );
    assert_eq!(
        (error.step(), error.may_have_committed()),
        (ApproverChangeStep::ReadBack, MayHaveCommitted::No)
    );
    assert_eq!(setup.key_file_ids(), [orphans[1]]);
}

#[test]
fn a_seventeenth_approver_the_last_approver_and_an_unknown_id_are_refused_before_any_file_changes() {
    let mut setup = Setup::new();
    let id = setup.state.approvers()[0].id();
    let from = setup.fs.trace().len();
    assert_eq!(
        setup.remove(id),
        Err(ApproverChangeError::ApprovalState(ApprovalStateError::LastApprover))
    );
    let unknown = ApproverId::generate();
    assert_eq!(
        setup.remove(unknown),
        Err(ApproverChangeError::ApprovalState(ApprovalStateError::UnknownApprover(unknown)))
    );
    assert_eq!(setup.mutations(from), []);
    (2..=MAX_APPROVERS as u8).for_each(|seed| {
        let approver = PinnedApprover::from_seed(seed);
        setup
            .state
            .enroll_approver(&setup.lock, &setup.fs, &setup.identity, approver)
            .unwrap();
    });
    let full = setup.state.clone();
    let before_enroll = setup.fs.trace().len();

    let error = setup.enroll().unwrap_err();

    assert_eq!(error, ApproverChangeError::ApprovalState(ApprovalStateError::TooManyApprovers));
    assert_eq!(error.may_have_committed(), MayHaveCommitted::No);
    assert_eq!(setup.state, full);
    assert_eq!(setup.mutations(before_enroll), []);
    assert_eq!(setup.key_file_ids(), []);
}

#[test]
fn a_key_file_that_cannot_be_deleted_after_the_removal_is_left_and_the_removal_still_succeeds() {
    let mut setup = Setup::new();
    let id = setup.enroll().unwrap().id();
    setup.fs.fail_first(FsOp::RemoveFile, io::ErrorKind::PermissionDenied);

    let outcome = setup.remove(id).unwrap();

    assert!(
        matches!(
            outcome,
            KeyFileOutcome::Left(WriteError::Io {
                step: WriteStep::Remove,
                ..
            })
        ),
        "{outcome:?}"
    );
    assert!(setup.state.approver(id).is_none());
    assert!(setup.has_key_file(id));
    assert_eq!(setup.settle(), [id]);
    assert!(!setup.has_key_file(id));
}

#[test]
fn a_directory_fsync_failing_after_the_key_file_unlink_leaves_the_removal_successful() {
    let prepare = |setup: &mut Setup| setup.enroll().unwrap().id();
    let act = |setup: &mut Setup, id| drop(setup.remove(id));
    let unlink_sync = *calls_of(FsOp::SyncDir, prepare, act).last().unwrap();
    let mut setup = Setup::new();
    let id = prepare(&mut setup);
    setup.fs.fail_call(setup.fs.trace().len() + unlink_sync, io::ErrorKind::StorageFull);

    let outcome = setup.remove(id).unwrap();

    assert!(
        matches!(
            outcome,
            KeyFileOutcome::Left(WriteError::Io {
                step: WriteStep::SyncDir,
                ..
            })
        ),
        "{outcome:?}"
    );
    assert!(setup.state.approver(id).is_none());
    assert!(!setup.has_key_file(id));
}

#[test]
fn a_removal_whose_commit_fsync_fails_reports_unknown_and_keeps_the_key_file_for_the_sweep() {
    let mut setup = Setup::new();
    let id = setup.enroll().unwrap().id();
    setup.fs.fail_first(FsOp::SyncDir, io::ErrorKind::StorageFull);

    let error = setup.remove(id).unwrap_err();

    assert_eq!(
        (error.step(), error.may_have_committed()),
        (ApproverChangeStep::ApprovalState, MayHaveCommitted::Unknown)
    );
    assert!(setup.has_key_file(id));
    assert_eq!(setup.settle(), [id]);
    assert!(setup.state.approver(id).is_none());
}

/// A stand-in for the TPM signing helper that holds a P-256 key in memory and can be told to fail.
struct FakeHelper {
    key: p256::ecdsa::SigningKey,
    fail_create: bool,
    fail_sign: bool,
    wrong_signer: bool,
}

impl FakeHelper {
    fn new() -> Self {
        Self {
            key: p256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap(),
            fail_create: false,
            fail_sign: false,
            wrong_signer: false,
        }
    }
}

impl TpmHelper for FakeHelper {
    fn create(&mut self, id: ApproverId) -> Result<CreatedTpmKey, TpmHelperFailure> {
        if self.fail_create {
            return Err(TpmHelperFailure::new("dictionary-attack settings too weak"));
        }
        let parts = iron_vault_tpm_protocol::TpmKeyParts {
            primary_name: vec![1; 34],
            public: vec![2; 90],
            private: vec![3; 100],
        };
        let public_key = self.key.verifying_key().to_encoded_point(false).as_bytes().try_into().unwrap();
        Ok(CreatedTpmKey {
            blob: TpmKeyBlob::new(*id.as_bytes(), parts),
            public_key,
        })
    }

    fn sign(&mut self, _: &TpmKeyBlob, _: &[u8; 65], message: &[u8]) -> Result<[u8; 64], TpmHelperFailure> {
        if self.fail_sign {
            return Err(TpmHelperFailure::locked_out("locked out", 60));
        }
        let key = match self.wrong_signer {
            true => p256::ecdsa::SigningKey::from_slice(&[9; 32]).unwrap(),
            false => self.key.clone(),
        };
        let signature: p256::ecdsa::Signature = p256::ecdsa::signature::Signer::sign(&key, message);
        Ok(signature.normalize_s().unwrap_or(signature).to_bytes().into())
    }
}

impl Setup {
    fn enroll_tpm(&mut self, helper: &mut FakeHelper) -> Result<PinnedApprover, ApproverChangeError> {
        ApproverChanges::new(&self.lock, &self.fs, &self.identity).enroll_tpm_approver(
            &mut self.state,
            label("laptop TPM"),
            UtcSecond::EPOCH,
            helper,
        )
    }

    fn tpm_blob_ids(&self) -> Vec<ApproverId> {
        let names = self.fs.list_dir(self.lock.dir()).unwrap();
        names.iter().filter_map(|n| StateFileName::tpm_key_blob_id(n.to_str()?)).collect()
    }
}

#[test]
fn an_enrolled_tpm_approver_is_pinned_with_a_blob_and_removal_deletes_the_blob() {
    let mut setup = Setup::new();
    let counters = (setup.state.highest_reserved(), setup.state.committed());

    let approver = setup.enroll_tpm(&mut FakeHelper::new()).unwrap();

    assert_eq!(
        (approver.kind(), approver.algorithm()),
        (SignerKind::Tpm, SignatureAlgorithm::EcdsaP256)
    );
    assert_eq!(setup.load(), setup.state);
    assert_eq!(setup.tpm_blob_ids(), [approver.id()]);
    assert_eq!(counters, (setup.state.highest_reserved(), setup.state.committed()));
    assert_eq!(setup.remove(approver.id()).unwrap(), KeyFileOutcome::Removed);
    assert!(setup.tpm_blob_ids().is_empty());
}

#[test]
fn a_helper_refusal_at_create_writes_nothing() {
    let mut setup = Setup::new();
    let before = setup.fs.trace().len();

    let failed = setup
        .enroll_tpm(&mut FakeHelper {
            fail_create: true,
            ..FakeHelper::new()
        })
        .unwrap_err();

    assert!(matches!(failed, ApproverChangeError::TpmHelper(_)));
    assert_eq!(failed.step(), ApproverChangeStep::TpmHelper);
    assert!(setup.mutations(before).is_empty());
    assert_eq!(setup.load().approvers().len(), 1);
}

#[test]
fn a_failed_read_back_signature_leaves_an_orphan_blob_the_next_sweep_removes() {
    let refusals = [
        FakeHelper {
            fail_sign: true,
            ..FakeHelper::new()
        },
        FakeHelper {
            wrong_signer: true,
            ..FakeHelper::new()
        },
    ];
    for mut helper in refusals {
        let mut setup = Setup::new();

        let failed = setup.enroll_tpm(&mut helper).unwrap_err();

        assert_eq!(failed.may_have_committed(), MayHaveCommitted::No);
        assert_eq!(setup.load().approvers().len(), 1);
        let orphans = setup.tpm_blob_ids();
        assert_eq!(orphans.len(), 1);
        assert_eq!(setup.settle(), orphans);
        assert!(setup.tpm_blob_ids().is_empty());
    }
}
