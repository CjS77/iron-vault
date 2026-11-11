//! Approver changes: enrolling and removing one software approver, and the checks that keep `approval.age` and the
//! `approver-<approver ID>.age` key files consistent (`design/approval-signers.md`, "Approver changes").
//!
//! The approval state write is each change's single commit point. An enrollment writes and checks the key file first, so
//! a failure before the commit leaves the approval state as it was and at most an orphan key file. A removal commits
//! first and deletes the key file after, so a file it cannot delete is an orphan and never fails the removal. Before
//! either change the caller reads the approval state back and sweeps the orphans against the state that read returned.
//! The caller holds the service-wide lock and has the owner's authorization; nothing here asks for either.

#[cfg(test)]
mod tests;
mod tpm;

use thiserror::Error;

pub use tpm::{CreatedTpmKey, TpmHelper, TpmHelperFailure};

use super::{
    ApprovalPassphrase, ApprovalState, ApprovalStateError, ApproverId, ApproverLabel, MAX_APPROVERS, PinnedApprover, SignError, SignerKind,
    SoftwareSigner, open_signer_key, read_signer_key, seal_signer_key_at, write_signer_key,
};
use crate::durable::{ReadError, WriteError, durable_remove};
use crate::{ErrorKindLabel, PASSPHRASE_WORK_FACTOR, StateDirLock, StateFileName, StoreFs, UtcSecond, VaultIdentity};

/// The step of an approver change that failed, as `approver.change-failed` records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApproverChangeStep {
    /// Step 3 of the commands: reading `approval.age` back, and the orphan sweep that follows. Nothing is ever committed.
    ReadBack,
    /// The TPM signing helper creating or using the new TPM approver's key.
    TpmHelper,
    /// Generating, sealing or writing the approver's key file.
    KeyFile,
    /// Reading the new key file back and opening it as the approver about to be pinned.
    KeyCheck,
    /// The durable replace of `approval.age`, the commit point.
    ApprovalState,
}

impl ApproverChangeStep {
    /// The snake_case label `approver.change-failed` records in its `step` field.
    pub fn label(self) -> &'static str {
        match self {
            Self::ReadBack => "read_back",
            Self::TpmHelper => "tpm_helper",
            Self::KeyFile => "key_file",
            Self::KeyCheck => "key_check",
            Self::ApprovalState => "approval_state",
        }
    }
}

/// Whether a failed approver change may have committed.
///
/// There is no "yes": a failure after the commit point is not a failure. A removal that cannot delete its key file still
/// succeeds ([`KeyFileOutcome::Left`]), and an enrollment ends at its commit point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MayHaveCommitted {
    /// The approval state on disk is as it was.
    No,
    /// The rename of `approval.age` landed but the directory fsync failed, so the disk holds the change but it may not
    /// survive power loss. The owner finds out with `approver list`.
    Unknown,
}

impl MayHaveCommitted {
    /// The label `approver.change-failed` records in its `committed` field, as `recipient.change-failed` does.
    pub fn label(self) -> &'static str {
        match self {
            Self::No => "no",
            Self::Unknown => "unknown",
        }
    }
}

/// What a removal did with the removed approver's key file, which is no longer a pinned approver's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyFileOutcome {
    /// The file is gone: deleted and the directory fsync succeeded, or it was not there to delete (no fsync runs then).
    Removed,
    /// The file could not be deleted, or its deletion may not survive power loss. It is an orphan the next sweep removes.
    Left(WriteError),
}

/// Why the key file written for a new approver does not pass the check that follows the write.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum KeyCheckError {
    /// The file just written cannot be read back.
    #[error("it cannot be read back: {0}")]
    Read(ReadError),
    /// The file does not open with the passphrase as the key of the approver about to be pinned.
    #[error("it does not open as the new approver's key: {0}")]
    Open(SignError),
    /// The blob read back is not a well-formed key blob for the approver about to be pinned.
    #[error("it is not a key blob for the new approver")]
    Blob,
    /// The helper's signature over a fresh presence payload does not verify against the key about to be pinned.
    #[error("the helper's signature does not verify against the new key")]
    Signature,
    /// The operating system gave no random bytes for the check's presence payload.
    #[error("the check's presence payload could not be made: no random bytes")]
    Randomness,
}

/// An approver change or the checks before it failed. Every variant says whether the change may have committed
/// ([`Self::may_have_committed`]) and at which step ([`Self::step`]). No variant carries key material or a passphrase.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ApproverChangeError {
    /// `approval.age` cannot be read or opened, or is one half of a partial restore against the manifest
    /// ([`ApprovalStateError::PartialRestore`]). Nothing was changed and no key file was deleted.
    #[error("the approval state cannot be read back ({0}); nothing was changed")]
    ReadBackUnreadable(ApprovalStateError),
    /// `approval.age` differs from a settled in-memory state: another writer changed it, or the file was replaced.
    /// Nothing was changed and no key file was deleted.
    #[error("the approval state on disk differs from the one in memory; nothing was changed")]
    ReadBackDiffers,
    /// An orphan key file could not be listed or deleted, which ends the sweep. `removed` are the IDs it deleted before
    /// that, in the order of its file names, for the caller to log. No approver change was made.
    #[error("cannot remove orphan approver key files ({error}); no approver change was made")]
    OrphanSweep {
        /// What stopped the sweep.
        error: WriteError,
        /// The orphans deleted before it stopped.
        removed: Vec<ApproverId>,
    },
    /// The generated key does not make a valid approver. Nothing was written.
    #[error("the generated approver is invalid: {0}; nothing was written")]
    ApproverInvalid(ApprovalStateError),
    /// The TPM signing helper refused or could not be reached while creating the key or signing the read-back check.
    /// The approval state is as it was; a key blob may be left as an orphan.
    #[error("the TPM signing helper cannot enroll the key: {0}; nothing was committed")]
    TpmHelper(TpmHelperFailure),
    /// The key could not be generated or sealed. Nothing was written.
    #[error("cannot generate or seal the approver key ({0}); nothing was committed")]
    KeySeal(SignError),
    /// The key file could not be written. The approval state is as it was, and a file may be left as an orphan.
    #[error("cannot write the approver key file ({0}); nothing was committed")]
    KeyFile(WriteError),
    /// The key file was written but does not pass the check. The approval state is as it was; the file is an orphan.
    #[error("the approver key file fails its check: {0}; nothing was committed")]
    KeyCheck(KeyCheckError),
    /// The approval state refused the change or could not write it. Unless it is
    /// [`ApprovalStateError::WriteUncertain`], the approval state is as it was.
    #[error("the approval state change failed: {0}")]
    ApprovalState(ApprovalStateError),
}

impl ApproverChangeError {
    /// The step that failed.
    pub fn step(&self) -> ApproverChangeStep {
        match self {
            Self::ReadBackUnreadable(_) | Self::ReadBackDiffers | Self::OrphanSweep { .. } => ApproverChangeStep::ReadBack,
            Self::TpmHelper(_) => ApproverChangeStep::TpmHelper,
            Self::ApproverInvalid(_) | Self::KeySeal(_) | Self::KeyFile(_) => ApproverChangeStep::KeyFile,
            Self::KeyCheck(_) => ApproverChangeStep::KeyCheck,
            Self::ApprovalState(_) => ApproverChangeStep::ApprovalState,
        }
    }

    /// Whether the change may have committed: only a directory fsync that failed after the rename of `approval.age` leaves
    /// that open.
    pub fn may_have_committed(&self) -> MayHaveCommitted {
        match self {
            Self::ApprovalState(ApprovalStateError::WriteUncertain(_)) => MayHaveCommitted::Unknown,
            _ => MayHaveCommitted::No,
        }
    }

    /// The failure as a label that holds no file name, key or error text, for `approver.change-failed`'s `error_kind`.
    pub fn error_kind_label(&self) -> ErrorKindLabel {
        match self {
            Self::ReadBackUnreadable(ApprovalStateError::PartialRestore(_)) => ErrorKindLabel::fixed("partial_restore"),
            Self::ReadBackUnreadable(_) => ErrorKindLabel::fixed("unreadable"),
            Self::ReadBackDiffers => ErrorKindLabel::fixed("differs"),
            Self::OrphanSweep { error, .. } | Self::KeyFile(error) => error.error_kind_label(),
            Self::ApproverInvalid(_) => ErrorKindLabel::fixed("approver_invalid"),
            Self::TpmHelper(_) => ErrorKindLabel::fixed("tpm_helper"),
            Self::KeySeal(_) => ErrorKindLabel::fixed("key_seal"),
            Self::KeyCheck(KeyCheckError::Read(_)) => ErrorKindLabel::fixed("read_failed"),
            Self::KeyCheck(KeyCheckError::Open(_) | KeyCheckError::Blob | KeyCheckError::Signature | KeyCheckError::Randomness) => {
                ErrorKindLabel::fixed("key_mismatch")
            }
            Self::ApprovalState(ApprovalStateError::Write(error) | ApprovalStateError::WriteUncertain(error)) => error.error_kind_label(),
            Self::ApprovalState(ApprovalStateError::TooManyApprovers) => ErrorKindLabel::fixed("too_many_approvers"),
            Self::ApprovalState(_) => ErrorKindLabel::fixed("approval_state"),
        }
    }
}

/// The state directory an approver change runs in: the lock that makes the service its only writer, the filesystem and
/// the vault identity the approval state is sealed to.
#[derive(Debug)]
pub struct ApproverChanges<'a, F> {
    lock: &'a StateDirLock,
    fs: &'a F,
    identity: &'a VaultIdentity,
}

impl<'a, F: StoreFs> ApproverChanges<'a, F> {
    /// The approver changes of the state directory `lock` holds.
    pub fn new(lock: &'a StateDirLock, fs: &'a F, identity: &'a VaultIdentity) -> Self {
        Self { lock, fs, identity }
    }

    /// Enrolls a new software approver named `label`, sealing its key to `passphrase`, and returns the pinned approver.
    ///
    /// Generates an Ed25519 key and a new approver ID, durably writes `approver-<id>.age`, reads it back and opens it with
    /// `passphrase` as the approver about to be pinned, and only then enrolls the approver in `approval.age`: the commit
    /// point, after which `state` holds the new approver. A failure before it leaves `state` as it was and at most an
    /// orphan key file. The key is dropped before this returns.
    pub fn enroll_software_approver(
        &self,
        state: &mut ApprovalState,
        label: ApproverLabel,
        passphrase: &ApprovalPassphrase,
        now: UtcSecond,
    ) -> Result<PinnedApprover, ApproverChangeError> {
        self.enroll_at(state, (label, now), passphrase, PASSPHRASE_WORK_FACTOR)
    }

    /// [`Self::enroll_software_approver`] sealing at work factor 2 instead of [`PASSPHRASE_WORK_FACTOR`], so a test that
    /// opens the key spends no seconds in scrypt. Only the `test-support` feature exposes it.
    #[cfg(any(test, feature = "test-support"))]
    pub fn enroll_software_approver_for_tests(
        &self,
        state: &mut ApprovalState,
        label: ApproverLabel,
        passphrase: &ApprovalPassphrase,
        now: UtcSecond,
    ) -> Result<PinnedApprover, ApproverChangeError> {
        self.enroll_at(state, (label, now), passphrase, 2)
    }

    fn enroll_at(
        &self,
        state: &mut ApprovalState,
        (label, now): (ApproverLabel, UtcSecond),
        passphrase: &ApprovalPassphrase,
        log_n: u8,
    ) -> Result<PinnedApprover, ApproverChangeError> {
        self.refuse_before_any_file(state)?;
        let (key, public_key) = SoftwareSigner::generate().map_err(ApproverChangeError::KeySeal)?;
        let approver = PinnedApprover::new(ApproverId::generate(), SignerKind::Software, public_key, label, now)
            .map_err(ApproverChangeError::ApproverInvalid)?;
        let sealed = seal_signer_key_at(&key, passphrase, log_n).map_err(ApproverChangeError::KeySeal)?;
        drop(key);
        write_signer_key(self.lock, self.fs, approver.id(), &sealed).map_err(ApproverChangeError::KeyFile)?;
        self.check_key_file(&approver, passphrase)?;
        state
            .enroll_approver(self.lock, self.fs, self.identity, approver.clone())
            .map_err(ApproverChangeError::ApprovalState)?;
        Ok(approver)
    }

    /// The refusals the approval state write would make after the key file is written, made before so they leave no
    /// orphan: a seventeenth approver, and a state that is unsettled or no longer the one on disk.
    fn refuse_before_any_file(&self, state: &ApprovalState) -> Result<(), ApproverChangeError> {
        if state.approvers().len() >= MAX_APPROVERS {
            return Err(ApproverChangeError::ApprovalState(ApprovalStateError::TooManyApprovers));
        }
        state
            .ensure_disk_matches(self.lock, self.fs, self.identity)
            .map_err(ApproverChangeError::ApprovalState)
    }

    /// Reads the new key file back and opens it with `passphrase` as `approver`, so a pinned software approver always has a
    /// key file that opens. The opened signer is dropped at once.
    fn check_key_file(&self, approver: &PinnedApprover, passphrase: &ApprovalPassphrase) -> Result<(), ApproverChangeError> {
        let envelope =
            read_signer_key(self.lock, self.fs, approver.id()).map_err(|e| ApproverChangeError::KeyCheck(KeyCheckError::Read(e)))?;
        open_signer_key(&envelope, passphrase, std::slice::from_ref(approver))
            .map(drop)
            .map_err(|e| ApproverChangeError::KeyCheck(KeyCheckError::Open(e)))
    }

    /// Unpins the approver `id` and then deletes its key file, which is the order that keeps a pinned approver's key.
    ///
    /// The approval state write is the commit point; the refusals (an unknown ID, the last approver, a stale state) come
    /// before it and change nothing. After it, a key file that cannot be deleted is reported as [`KeyFileOutcome::Left`]
    /// and never fails the removal: the approver is gone and the file is an orphan the next sweep deletes.
    pub fn remove_approver(&self, state: &mut ApprovalState, id: ApproverId) -> Result<KeyFileOutcome, ApproverChangeError> {
        let kind = state.approver(id).map(PinnedApprover::kind);
        // `remove_approver` below fails for an unknown ID, so on success `kind` is always `Some`; the default is never used.
        state
            .remove_approver(self.lock, self.fs, self.identity, id)
            .map_err(ApproverChangeError::ApprovalState)?;
        Ok(
            match durable_remove(self.lock, self.fs, &key_file_name(kind.unwrap_or(SignerKind::Software), id)) {
                Ok(()) | Err(WriteError::NotFound { .. }) => KeyFileOutcome::Removed,
                Err(error) => KeyFileOutcome::Left(error),
            },
        )
    }

    /// Loads `approval.age` from disk, opening it and checking it against the manifest as every approval does, and
    /// returns the state read.
    ///
    /// When `state` is unsettled the state read replaces it, as the next approval does after such a reservation.
    /// Otherwise the two must be equal, the check the store makes before every approval state write. A file that cannot
    /// be read or opened, that differs, or that is one half of a partial restore (an older `approval.age` put back
    /// beside a newer manifest) is an error and nothing was changed, so the caller deletes no key file. The manifest pair
    /// check applies to an unsettled state too: it is what stops a restored older `approval.age` from being adopted and
    /// the key of an approver it does not pin from looking like an orphan.
    pub fn read_back_approval_state(&self, state: &mut ApprovalState) -> Result<ReadBack, ApproverChangeError> {
        let on_disk =
            ApprovalState::load(self.lock, self.fs, self.identity, state.vault_id()).map_err(ApproverChangeError::ReadBackUnreadable)?;
        match (state.is_unsettled(), on_disk == *state) {
            (true, _) => *state = on_disk.clone(),
            (false, true) => {}
            (false, false) => return Err(ApproverChangeError::ReadBackDiffers),
        }
        Ok(ReadBack(on_disk))
    }

    /// Deletes every `approver-<id>.age` and `approver-<id>.tpm` whose ID no approver pinned in `read_back` has, and
    /// returns the IDs removed in ascending order of file name.
    ///
    /// Only the state [`Self::read_back_approval_state`] returned is accepted, never the in-memory state: an in-memory
    /// state that missed a committed enrollment would make that approver's key file look like an orphan, and this would
    /// delete the only key of a pinned approver. A failure ends the sweep and still reports the IDs deleted so far
    /// ([`ApproverChangeError::OrphanSweep`]).
    pub fn remove_orphan_key_files(&self, read_back: &ReadBack) -> Result<Vec<ApproverId>, ApproverChangeError> {
        let names = self.fs.list_dir(self.lock.dir()).map_err(|e| ApproverChangeError::OrphanSweep {
            error: WriteError::ListStateDir { kind: e.kind() },
            removed: Vec::new(),
        })?;
        let mut removed = Vec::new();
        let swept = names
            .iter()
            .filter_map(|name| orphan_candidate(name.to_str()?))
            .filter(|(id, _)| read_back.state().approver(*id).is_none())
            .try_for_each(|(id, file)| durable_remove(self.lock, self.fs, &file).map(|()| removed.push(id)));
        match swept {
            Ok(()) => Ok(removed),
            Err(error) => Err(ApproverChangeError::OrphanSweep { error, removed }),
        }
    }
}

/// The state file that holds a `kind` approver's key: the software approver's `approver-<id>.age`, or the TPM approver's key
/// blob `approver-<id>.tpm`.
fn key_file_name(kind: SignerKind, id: ApproverId) -> StateFileName {
    match kind {
        SignerKind::Software => StateFileName::approver_key(id),
        SignerKind::Tpm => StateFileName::tpm_key_blob(id),
    }
}

/// The approver ID and file when `name` is exactly an approver's key file of either kind.
fn orphan_candidate(name: &str) -> Option<(ApproverId, StateFileName)> {
    let software = StateFileName::approver_key_id(name).map(|id| (id, key_file_name(SignerKind::Software, id)));
    software.or_else(|| StateFileName::tpm_key_blob_id(name).map(|id| (id, key_file_name(SignerKind::Tpm, id))))
}

/// The approval state [`ApproverChanges::read_back_approval_state`] read from disk and checked. Only that call builds
/// one, so the orphan sweep cannot be given any other state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadBack(ApprovalState);

impl ReadBack {
    /// The state read back.
    pub fn state(&self) -> &ApprovalState {
        &self.0
    }
}
