//! The approval transaction's durable steps: the six steps of spec §3.9, each durable before the next starts
//! (design/config-approval.md, "The transaction").
//!
//! The types follow the steps, so they cannot be run out of order or skipped:
//!
//! - [`PendingConfig::write`] is step 1. It keeps the one owned buffer that is validated, summarized, digested, signed
//!   and published. The file is never read back.
//! - [`PendingConfig::prepare`] is steps 2 to 4: reserve, sign, stage. The service has already shown the approval
//!   summary, had it confirmed and opened the signer, so the store prompts for nothing.
//! - [`PreparedApproval::commit`] is steps 5 and 6: commit, then publish. It takes proof that admission is paused, so
//!   the service cannot commit while requests are still being admitted under the old policy.
//!
//! Each failure says which step failed and how far the transaction got ([`ApprovalProgress`]), so audit can tell a
//! reserved version from a completed approval. Uncommitted files are removed on failure, best effort: a file left
//! behind is a leftover the next config check discards.

#[cfg(test)]
mod tests;

use std::fmt;

use thiserror::Error;

use super::verify::verify_signed;
use super::{ApprovalPayload, ApprovalSigner, ApprovalState, ApprovalVersion, ConfigDigest, SignError, VerifiedApproval, VerifyError};
use crate::{
    ApprovalStateError, ConfigDirLock, ConfigWriteError, PublishSet, StateDirLock, StoreFs, VaultIdentity, WriteStep, publish,
    remove_pending_and_staged, verify_approval, write_pending, write_staged,
};

/// Proof that no request is being admitted: the service's admission pause guard implements this.
///
/// [`PreparedApproval::commit`] takes it by reference, so a commit cannot run unless the caller holds the pause
/// (spec §3.9: "pause new admissions before committing"). Implement it only for a guard whose existence means the
/// snapshot holder refuses every new request.
pub trait AdmissionPaused {}

/// Everything the transaction's durable steps act on: the two locked directories, the vault identity that seals the
/// approval state, and the filesystem.
pub struct ApprovalStorage<'a, F> {
    /// The state directory, which holds `approval.age`.
    pub state_dir: &'a StateDirLock,
    /// The config directory, which holds the pending, staged and active files.
    pub config_dir: &'a ConfigDirLock,
    /// The unlocked vault identity.
    pub identity: &'a VaultIdentity,
    /// The filesystem every step goes through.
    pub fs: &'a F,
}

/// One of the transaction's durable steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalStep {
    /// Step 1: durably write `config.toml.pending`.
    WritePending,
    /// Step 2: durably reserve the next approval version.
    Reserve,
    /// Step 3: sign the approval payload, and check the signer's envelope against the pinned approver.
    Sign,
    /// Step 4: durably write `config.toml.sig.staged`.
    Stage,
    /// Step 5: durably commit the version and digest, settling the commit if its directory fsync failed.
    Commit,
    /// Step 6: publish the pending config and the staged approval.
    Publish,
}

impl fmt::Display for ApprovalStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::WritePending => "step 1, writing the pending config",
            Self::Reserve => "step 2, reserving the approval version",
            Self::Sign => "step 3, signing the approval",
            Self::Stage => "step 4, staging the approval",
            Self::Commit => "step 5, committing the approval",
            Self::Publish => "step 6, publishing the approved config",
        })
    }
}

/// How far a failed approval got: what audit records, and what the service does next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalProgress {
    /// No version was reserved: step 1 failed, or the reservation failed before its rename.
    NothingReserved,
    /// The version is consumed and nothing was committed. The committed approval and the published pair are unchanged.
    Reserved(ApprovalVersion),
    /// Step 5's rename landed, but its directory fsync failed and so did the write that settles it: the commit is
    /// visible but may not survive power loss. The service goes Unavailable with `RecoveryNeeded`. The pending config
    /// and staged approval are left in place.
    CommitUncertain(ApprovalVersion),
    /// The commit is durable, but publishing failed. The config check's recovery finishes the publish.
    Committed(ApprovalVersion),
}

/// A failed approval: the step that failed, how far it got, and why.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("config approval failed at {step}: {cause}")]
pub struct ApprovalError {
    step: ApprovalStep,
    progress: ApprovalProgress,
    cause: ApprovalFailure,
}

impl ApprovalError {
    /// The step that failed.
    pub fn step(&self) -> ApprovalStep {
        self.step
    }

    /// How far the approval got.
    pub fn progress(&self) -> ApprovalProgress {
        self.progress
    }

    /// Why the step failed.
    pub fn cause(&self) -> &ApprovalFailure {
        &self.cause
    }
}

/// Why a step of the transaction failed. No variant carries config bytes, key material or signature bytes.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ApprovalFailure {
    /// A write to the config directory failed.
    #[error(transparent)]
    ConfigDir(#[from] ConfigWriteError),
    /// The approval state could not be reserved, committed or settled; [`ApprovalStateError::Exhausted`] means no
    /// version is left to reserve.
    #[error(transparent)]
    State(#[from] ApprovalStateError),
    /// The signer refused or failed to sign.
    #[error(transparent)]
    Sign(#[from] SignError),
    /// The signer's envelope does not verify against the pinned approver for this vault and config.
    #[error("the signed approval does not verify: {0}")]
    BadApproval(VerifyError),
    /// The signer's envelope verifies but carries another version from the one reserved.
    #[error("the signer signed another approval version from the one reserved")]
    WrongVersion,
}

/// Step 1 done: the pending config is durable, and this buffer is the one copy of its bytes.
pub struct PendingConfig {
    bytes: Box<[u8]>,
    digest: ConfigDigest,
}

impl PendingConfig {
    /// Step 1: durably writes `bytes` as `config.toml.pending` and keeps them as the buffer every later step uses.
    ///
    /// On failure the pending file is removed and nothing is reserved.
    pub fn write<F: StoreFs>(storage: &ApprovalStorage<'_, F>, bytes: Vec<u8>) -> Result<Self, ApprovalError> {
        let bytes = bytes.into_boxed_slice();
        write_pending(storage.config_dir, storage.fs, &bytes).map_err(|e| fail(storage, ApprovalStep::WritePending, None, e.into()))?;
        let digest = ConfigDigest::of(&bytes);
        Ok(Self { bytes, digest })
    }

    /// The proposed bytes, exactly as written: what the service validates, activates and summarizes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The digest of [`bytes`](Self::bytes), the one the approval signs.
    pub fn digest(&self) -> ConfigDigest {
        self.digest
    }

    /// Ends the approval before anything is reserved (the config is invalid, or the owner declined): removes the
    /// pending config, best effort.
    pub fn abandon<F: StoreFs>(self, storage: &ApprovalStorage<'_, F>) {
        discard_uncommitted(storage);
    }

    /// Steps 2 to 4: durably reserves the next version, signs it with `signer` (dropped once it has signed), checks
    /// the envelope against the pinned approver, and durably stages it.
    ///
    /// The `&mut` borrow of `state` lasts until the approval is committed or abandoned, so approvals are serialized.
    /// On failure the pending config and any staged approval are removed. A failure after the reservation leaves its
    /// version consumed.
    pub fn prepare<'s, F: StoreFs, S: ApprovalSigner>(
        self,
        storage: &ApprovalStorage<'_, F>,
        state: &'s mut ApprovalState,
        signer: S,
    ) -> Result<PreparedApproval<'s>, ApprovalError> {
        let version = reserve(storage, state)?;
        let payload = ApprovalPayload::new(state.vault_id(), version, self.digest);
        let envelope = sign(state, &payload, signer).map_err(|e| fail(storage, ApprovalStep::Sign, Some(version), e))?;
        write_staged(storage.config_dir, storage.fs, &envelope).map_err(|e| fail(storage, ApprovalStep::Stage, Some(version), e.into()))?;
        Ok(PreparedApproval {
            state,
            config: self.bytes,
            envelope,
            payload,
        })
    }
}

/// Steps 1 to 4 done: the pending config and its staged approval are durable, and its version is reserved but not
/// committed. Nothing is changed for requests until [`commit`](Self::commit).
pub struct PreparedApproval<'s> {
    state: &'s mut ApprovalState,
    config: Box<[u8]>,
    envelope: Vec<u8>,
    payload: ApprovalPayload,
}

impl PreparedApproval<'_> {
    /// The reserved version this approval commits.
    pub fn version(&self) -> ApprovalVersion {
        self.payload.version()
    }

    /// The digest of the approved config.
    pub fn digest(&self) -> ConfigDigest {
        self.payload.digest()
    }

    /// Ends the approval before the commit (the serving dry run failed): removes the pending config and the staged
    /// approval, best effort, and returns the version it consumed.
    pub fn abandon<F: StoreFs>(self, storage: &ApprovalStorage<'_, F>) -> ApprovalVersion {
        discard_uncommitted(storage);
        self.version()
    }

    /// Steps 5 and 6: durably commits the approval, then publishes the pending config and the staged approval, and
    /// returns the approval verified over the bytes it published.
    ///
    /// `_paused` is the proof that admission is paused, which must be in place before the commit. A commit whose
    /// directory fsync fails is settled by a second durable write of the approval state before anything is published.
    /// A failed directory fsync after the publish renames is logged and passed over, because the commit, not the
    /// published files, is the durable record of the approval.
    pub fn commit<F: StoreFs>(
        self,
        storage: &ApprovalStorage<'_, F>,
        _paused: &impl AdmissionPaused,
    ) -> Result<CommittedApproval, ApprovalError> {
        let (version, digest) = (self.version(), self.digest());
        commit(storage, &mut *self.state, version, digest)?;
        let committed = |cause| ApprovalError {
            step: ApprovalStep::Publish,
            progress: ApprovalProgress::Committed(version),
            cause,
        };
        publish_both(storage).map_err(|e| committed(e.into()))?;
        let approval = verify_approval(self.state, &self.config, &self.envelope).map_err(|e| committed(ApprovalFailure::BadApproval(e)))?;
        Ok(CommittedApproval {
            approval,
            config: self.config,
        })
    }
}

/// Steps 1 to 6 done: the approval is committed and published, and its config is the one to activate.
pub struct CommittedApproval {
    approval: VerifiedApproval,
    config: Box<[u8]>,
}

impl CommittedApproval {
    /// The committed approval, verified over the published bytes.
    pub fn approval(&self) -> VerifiedApproval {
        self.approval
    }

    /// The published config bytes, the same buffer step 1 wrote.
    pub fn config(&self) -> &[u8] {
        &self.config
    }
}

/// Shows the config's length and digest, never its bytes, which the approval summary is the place to describe.
impl fmt::Debug for PendingConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingConfig")
            .field("len", &self.bytes.len())
            .field("digest", &self.digest)
            .finish()
    }
}

/// Shows the payload only: no config bytes or signature bytes.
impl fmt::Debug for PreparedApproval<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedApproval")
            .field("payload", &self.payload)
            .finish_non_exhaustive()
    }
}

/// Shows the approval only: no config bytes.
impl fmt::Debug for CommittedApproval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommittedApproval")
            .field("approval", &self.approval)
            .finish_non_exhaustive()
    }
}

/// Step 2. Exhaustion and a failure before the rename reserve nothing; a failed directory fsync after the rename
/// leaves the version consumed, because the next reservation reads it from disk.
fn reserve<F: StoreFs>(storage: &ApprovalStorage<'_, F>, state: &mut ApprovalState) -> Result<ApprovalVersion, ApprovalError> {
    let next = state.highest_reserved().checked_add(1).and_then(ApprovalVersion::new);
    state.reserve(storage.state_dir, storage.fs, storage.identity).map_err(|e| {
        let consumed = matches!(e, ApprovalStateError::WriteUncertain(_)).then_some(next).flatten();
        fail(storage, ApprovalStep::Reserve, consumed, e.into())
    })
}

/// Step 3: signs `payload`, then checks the encoded envelope as the config check later will, so a misbehaving signer
/// fails here and not after the commit. The signer is dropped on return.
fn sign<S: ApprovalSigner>(state: &ApprovalState, payload: &ApprovalPayload, signer: S) -> Result<Vec<u8>, ApprovalFailure> {
    let envelope = signer.sign(payload)?.encode();
    let signed = verify_signed(state, payload.digest(), &envelope).map_err(ApprovalFailure::BadApproval)?;
    match signed == *payload {
        true => Ok(envelope),
        false => Err(ApprovalFailure::WrongVersion),
    }
}

/// Step 5, settling an uncertain commit with a second durable write. Only a failure before the rename of
/// `approval.age` removes the pending config and staged approval: after it, they may belong to the committed approval.
fn commit<F: StoreFs>(
    storage: &ApprovalStorage<'_, F>,
    state: &mut ApprovalState,
    version: ApprovalVersion,
    digest: ConfigDigest,
) -> Result<(), ApprovalError> {
    match state.commit(storage.state_dir, storage.fs, storage.identity, version, digest) {
        Ok(()) => Ok(()),
        Err(ApprovalStateError::WriteUncertain(error)) => {
            tracing::warn!(event = "config.commit-uncertain", %version, %error, "the commit landed but its directory fsync failed; settling it");
            state
                .settle_commit(storage.state_dir, storage.fs, storage.identity, (version, digest))
                .map_err(|e| ApprovalError {
                    step: ApprovalStep::Commit,
                    progress: ApprovalProgress::CommitUncertain(version),
                    cause: e.into(),
                })
        }
        Err(other) => Err(fail(storage, ApprovalStep::Commit, Some(version), other.into())),
    }
}

/// Step 6's file change. A directory fsync failure comes after both renames, so it is logged and passed over.
fn publish_both<F: StoreFs>(storage: &ApprovalStorage<'_, F>) -> Result<(), ConfigWriteError> {
    match publish(storage.config_dir, storage.fs, PublishSet::Both) {
        Err(ConfigWriteError::Io {
            step: WriteStep::SyncDir,
            kind,
            ..
        }) => {
            tracing::warn!(
                ?kind,
                "the approved config was published but the config directory fsync failed; recovery finishes it if power loss undoes it"
            );
            Ok(())
        }
        other => other,
    }
}

/// A failure before the commit: removes the uncommitted files, then reports `step` with `reserved` consumed.
fn fail<F: StoreFs>(
    storage: &ApprovalStorage<'_, F>,
    step: ApprovalStep,
    reserved: Option<ApprovalVersion>,
    cause: ApprovalFailure,
) -> ApprovalError {
    discard_uncommitted(storage);
    let progress = reserved.map_or(ApprovalProgress::NothingReserved, ApprovalProgress::Reserved);
    ApprovalError { step, progress, cause }
}

/// Removes the pending config and the staged approval, best effort: the next config check discards a leftover.
fn discard_uncommitted<F: StoreFs>(storage: &ApprovalStorage<'_, F>) {
    if let Err(error) = remove_pending_and_staged(storage.config_dir, storage.fs) {
        tracing::warn!(%error, "cannot remove the uncommitted pending config and staged approval; the next config check discards them");
    }
}
