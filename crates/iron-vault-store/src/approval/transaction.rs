//! Runs the durable steps of a config approval: the six steps of
//! [spec §12](../../../../design/iron-vault-specification.md#12-configuration-approval-and-reload), each durable before
//! the next starts ([config approval, "The transaction"](../../../../design/config-approval.md#the-transaction)). The
//! service's `config approve` handler drives it.
//!
//! Each step returns a type that only the next step accepts, so the steps cannot run out of order or be skipped:
//!
//! ```text
//!  config bytes
//!       │ PendingConfig::write          step 1: config.toml.pending
//!       ▼
//!  PendingConfig ── abandon ──→ pending file removed, nothing reserved
//!       │ reserve                       step 2: approval.age reserves N
//!       ▼
//!  ReservedApproval
//!       │ sign                          step 3: sign; step 4: config.toml.sig.staged
//!       ▼
//!  PreparedApproval
//!       │ commit(&admission paused)     step 5: approval.age commits (N, digest)
//!       ▼                               step 6: publish config.toml + config.toml.sig, read back, verify
//!  CommittedApproval
//! ```
//!
//! - [`PendingConfig::write`] is step 1. It keeps the one owned buffer that the service validates, summarizes,
//!   digests and signs. Nothing reads the pending file back.
//! - [`PendingConfig::reserve`] is step 2 and [`ReservedApproval::sign`] steps 3 and 4: sign, then stage.
//!   [`PendingConfig::prepare`] runs steps 2 to 4 in one call. The service has already shown the approval summary, had
//!   it confirmed and opened the signer, so the store prompts for nothing.
//! - [`PreparedApproval::commit`] is steps 5 and 6: commit, then publish and verify the published pair as read back.
//!   It takes proof that admission is paused, so the service cannot commit while it still admits requests under the
//!   old policy.
//!
//! Each failure names the step that failed and how far the transaction got ([`ApprovalProgress`]), so audit can tell a
//! reserved version from a completed approval. A failure before the commit removes the uncommitted files, best effort;
//! the next config check discards any file left behind.

#[cfg(test)]
pub(super) mod tests;

use std::fmt;

use thiserror::Error;

use super::verify::verify_signed;
use super::{ApprovalPayload, ApprovalSigner, ApprovalState, ApprovalVersion, ConfigDigest, SignError, VerifiedApproval, VerifyError};
use crate::{
    ApprovalStateError, ConfigDirLock, ConfigFileName, ConfigReadError, ConfigWriteError, ErrorKindLabel, PublishSet, StateDirLock,
    StoreFs, VaultIdentity, WriteStep, publish, read_config_file, remove_pending_and_staged, verify_approval, write_pending, write_staged,
};

/// Proof that the service admits no request: the service's admission pause guard implements this.
///
/// [`PreparedApproval::commit`] takes it by reference, so a commit cannot run unless the caller holds the pause
/// ([spec §12](../../../../design/iron-vault-specification.md#12-configuration-approval-and-reload): "pause new admissions before
/// committing"). The one production implementation is the service's `AdmissionPause` guard, returned by
/// `SnapshotHolder::pause`; while it exists, the snapshot holder refuses every new request. Any other implementation
/// could commit while requests are still admitted, so adding one needs review.
pub trait AdmissionPaused {}

/// What the transaction's durable steps act on: the two locked directories, the vault identity that seals the approval
/// state, and the filesystem.
pub struct ApprovalStorage<'a, F> {
    /// The state directory, which holds `approval.age`.
    pub state_dir: &'a StateDirLock,
    /// The config directory, which holds `config.toml.pending`, `config.toml.sig.staged`, `config.toml` and
    /// `config.toml.sig`.
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
    /// Step 3: sign the approval payload, and check the signer's envelope against the pinned approver it names.
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

/// How far a failed approval got. Audit records it, and it decides what the service does next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalProgress {
    /// No version was reserved: step 1 failed, or step 2 failed before its rename.
    NothingReserved,
    /// The version is consumed and nothing was committed. The committed approval and the published pair are unchanged.
    Reserved(ApprovalVersion),
    /// Step 5's rename landed, but its directory fsync failed and so did the write that settles it: the commit is
    /// visible but may not survive power loss. The service goes Unavailable with `RecoveryNeeded`. The pending config
    /// and staged approval stay in place.
    CommitUncertain(ApprovalVersion),
    /// The commit is durable, but step 6 failed. The approval recovery of the next config check finishes the publish.
    Committed(ApprovalVersion),
}

impl fmt::Display for ApprovalProgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NothingReserved => f.write_str("no version reserved"),
            Self::Reserved(v) => write!(f, "version {v} reserved, not committed"),
            Self::CommitUncertain(v) => write!(f, "version {v} committed, but the commit may not survive power loss"),
            Self::Committed(v) => write!(f, "version {v} committed"),
        }
    }
}

/// A failed approval: the step that failed, how far it got, and why.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("config approval failed at {step} ({progress}): {cause}")]
pub struct ApprovalError {
    step: ApprovalStep,
    progress: ApprovalProgress,
    cause: ApprovalFailure,
    commit_uncertain: Option<Box<ErrorKindLabel>>,
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

    /// The kind of the directory fsync failure that made step 5's commit uncertain, whether or not a later write settled
    /// it. `None` when the commit's rename and fsync both succeeded, or never ran.
    pub fn commit_uncertain(&self) -> Option<&ErrorKindLabel> {
        self.commit_uncertain.as_deref()
    }
}

/// Why a step of the transaction failed. No variant carries config bytes, key material or signature bytes.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ApprovalFailure {
    /// A write to the config directory failed.
    #[error(transparent)]
    ConfigDir(#[from] ConfigWriteError),
    /// The published config or signature could not be read back to verify it.
    #[error(transparent)]
    ReadBack(#[from] ConfigReadError),
    /// The approval state could not be reserved, committed or settled; [`ApprovalStateError::Exhausted`] means no
    /// version is left to reserve.
    #[error(transparent)]
    State(#[from] ApprovalStateError),
    /// The signer refused or failed to sign.
    #[error(transparent)]
    Sign(#[from] SignError),
    /// The signer's envelope does not verify against the pinned approver it names for this vault and config, or the
    /// published pair read back does not verify as the committed approval.
    #[error("the approval does not verify: {0}")]
    BadApproval(VerifyError),
    /// The signer's envelope verifies but carries a different version from the one reserved.
    #[error("the signer signed another approval version from the one reserved")]
    WrongVersion,
}

/// Step 1 done: `config.toml.pending` is durable, and this buffer is the one copy of its bytes.
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

    /// The proposed bytes, exactly as written: the bytes the service validates, activates and summarizes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The digest of [`bytes`](Self::bytes), the one the approval signs.
    pub fn digest(&self) -> ConfigDigest {
        self.digest
    }

    /// Ends the approval before anything is reserved and removes the pending config, best effort. The service calls it
    /// when the config is invalid, the owner declines or goes away, or the service leaves the state the approval
    /// started in. It needs no vault identity, so an approval can still clean up after the vault was locked.
    pub fn abandon<F: StoreFs>(self, config_dir: &ConfigDirLock, fs: &F) {
        discard_uncommitted(config_dir, fs);
    }

    /// Step 2: durably reserves the next version. The caller records the reservation in the audit log before it signs
    /// ([`ReservedApproval::version`]), so a signing failure, or a signer that waits for the owner, comes after it
    /// in the log ([spec §12](../../../../design/iron-vault-specification.md#12-configuration-approval-and-reload)).
    ///
    /// The `&mut` borrow of `state` lasts until the approval is committed or dropped, so approvals run one at a time.
    /// On failure it removes the pending config and any staged approval. A reservation whose directory fsync failed
    /// leaves its version consumed.
    pub fn reserve<'s, F: StoreFs>(
        self,
        storage: &ApprovalStorage<'_, F>,
        state: &'s mut ApprovalState,
    ) -> Result<ReservedApproval<'s>, ApprovalError> {
        let version = reserve(storage, state)?;
        let payload = ApprovalPayload::new(state.vault_id(), version, self.digest);
        Ok(ReservedApproval { state, payload })
    }

    /// Steps 2 to 4 in one call, for callers with nothing to record between the reservation and the signature.
    pub fn prepare<'s, F: StoreFs, S: ApprovalSigner>(
        self,
        storage: &ApprovalStorage<'_, F>,
        state: &'s mut ApprovalState,
        signer: S,
    ) -> Result<PreparedApproval<'s>, ApprovalError> {
        self.reserve(storage, state)?.sign(storage, signer)
    }
}

/// Step 2 done: the version is durably reserved, and nothing is signed or staged yet.
#[derive(Debug)]
pub struct ReservedApproval<'s> {
    state: &'s mut ApprovalState,
    payload: ApprovalPayload,
}

impl<'s> ReservedApproval<'s> {
    /// The reserved version. It stays consumed even if a later step fails.
    pub fn version(&self) -> ApprovalVersion {
        self.payload.version()
    }

    /// The digest of the config the version was reserved for.
    pub fn digest(&self) -> ConfigDigest {
        self.payload.digest()
    }

    /// The payload the signer must sign: this version and digest, for this vault. Step 3 checks the signed envelope
    /// against it, so an envelope over any other payload fails.
    pub fn payload(&self) -> ApprovalPayload {
        self.payload
    }

    /// Steps 3 and 4: signs with `signer` (dropped once it has signed), checks the envelope against the pinned
    /// approver it names, and durably writes it as `config.toml.sig.staged`. On failure it removes the pending config
    /// and any staged approval, and the version stays consumed.
    pub fn sign<F: StoreFs, S: ApprovalSigner>(
        self,
        storage: &ApprovalStorage<'_, F>,
        signer: S,
    ) -> Result<PreparedApproval<'s>, ApprovalError> {
        let Self { state, payload } = self;
        let version = payload.version();
        let envelope = sign(state, &payload, signer).map_err(|e| fail(storage, ApprovalStep::Sign, Some(version), e))?;
        write_staged(storage.config_dir, storage.fs, &envelope).map_err(|e| fail(storage, ApprovalStep::Stage, Some(version), e.into()))?;
        Ok(PreparedApproval { state, payload })
    }
}

/// Steps 1 to 4 done: the pending config and its staged approval are durable, and the version is reserved but not
/// committed. Requests see no change until [`commit`](Self::commit).
#[derive(Debug)]
pub struct PreparedApproval<'s> {
    state: &'s mut ApprovalState,
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

    /// Steps 5 and 6: durably commits the approval, publishes the pending config and the staged approval, then reads
    /// `config.toml` and `config.toml.sig` back and returns them verified as the committed approval.
    ///
    /// `_paused` is the proof that admission is paused, which must be in place before the commit. When the commit's
    /// directory fsync fails, a second durable write of the approval state settles it before anything is published.
    /// A failed directory fsync from publish is logged and passed over, because the commit, not the published files,
    /// is the durable record of the approval. The read-back proves the renames landed: a pair that is not in place, or
    /// does not verify, fails at [`ApprovalStep::Publish`] with the version committed.
    pub fn commit<F: StoreFs>(
        self,
        storage: &ApprovalStorage<'_, F>,
        _paused: &impl AdmissionPaused,
    ) -> Result<CommittedApproval, ApprovalError> {
        let (version, digest) = (self.version(), self.digest());
        let uncertain = commit(storage, &mut *self.state, version, digest)?;
        let committed = |cause| ApprovalError {
            step: ApprovalStep::Publish,
            progress: ApprovalProgress::Committed(version),
            cause,
            commit_uncertain: uncertain.clone(),
        };
        publish_both(storage, version).map_err(|e| committed(e.into()))?;
        let read = |name| read_config_file(storage.config_dir, storage.fs, name).map_err(|e| committed(e.into()));
        let (config, envelope) = (read(ConfigFileName::Active)?, read(ConfigFileName::ActiveSignature)?);
        let approval = verify_approval(self.state, &config, &envelope).map_err(|e| committed(ApprovalFailure::BadApproval(e)))?;
        Ok(CommittedApproval::new(approval, config.into_boxed_slice()).with_commit_uncertain(uncertain.map(|kind| *kind)))
    }
}

/// Steps 1 to 6 done: the approval is committed and published, and its config is the one to activate.
pub struct CommittedApproval {
    approval: VerifiedApproval,
    config: Box<[u8]>,
    commit_uncertain: Option<ErrorKindLabel>,
}

impl CommittedApproval {
    /// Wraps the published `config` as read back, which verified as `approval`.
    pub(super) fn new(approval: VerifiedApproval, config: Box<[u8]>) -> Self {
        Self {
            approval,
            config,
            commit_uncertain: None,
        }
    }

    fn with_commit_uncertain(self, commit_uncertain: Option<ErrorKindLabel>) -> Self {
        Self { commit_uncertain, ..self }
    }

    /// The kind of the directory fsync failure that made this commit uncertain until it was settled. `None` when the
    /// commit was certain at once, or approval recovery found the approval.
    pub fn commit_uncertain(&self) -> Option<&ErrorKindLabel> {
        self.commit_uncertain.as_ref()
    }

    /// The committed approval, verified over the published pair as read back.
    pub fn approval(&self) -> VerifiedApproval {
        self.approval
    }

    /// The published config bytes as read back and verified: the bytes to activate.
    pub fn config(&self) -> &[u8] {
        &self.config
    }
}

/// Shows the config's length and digest, never its bytes: the approval summary is where the config is described.
impl fmt::Debug for PendingConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingConfig")
            .field("len", &self.bytes.len())
            .field("digest", &self.digest)
            .finish()
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

/// Runs step 2. Exhaustion and a failure before the rename reserve nothing. A failed directory fsync after the rename
/// leaves the version consumed, because the next reservation reads it from disk. The caller records a durable
/// reservation as `config.version-reserved`. A reservation whose directory fsync failed is consumed but not returned:
/// it fails at this step, as `config.approval-failed`.
fn reserve<F: StoreFs>(storage: &ApprovalStorage<'_, F>, state: &mut ApprovalState) -> Result<ApprovalVersion, ApprovalError> {
    let next = state.highest_reserved().checked_add(1).and_then(ApprovalVersion::new);
    state.reserve(storage.state_dir, storage.fs, storage.identity).map_err(|e| {
        let consumed = matches!(e, ApprovalStateError::WriteUncertain(_)).then_some(next).flatten();
        fail(storage, ApprovalStep::Reserve, consumed, e.into())
    })
}

/// Runs step 3: signs `payload`, then checks the encoded envelope as the config check later will, so a misbehaving
/// signer fails here and not after the commit. The signer is dropped on return.
fn sign<S: ApprovalSigner>(state: &ApprovalState, payload: &ApprovalPayload, signer: S) -> Result<Vec<u8>, ApprovalFailure> {
    let envelope = signer.sign(payload)?.encode();
    let signed = verify_signed(state, payload.digest(), &envelope).map_err(ApprovalFailure::BadApproval)?;
    if signed == *payload {
        Ok(envelope)
    } else {
        Err(ApprovalFailure::WrongVersion)
    }
}

/// Runs step 5, and settles an uncertain commit with a second durable write. Returns the uncertain commit's error
/// kind, or `None` when the commit was certain. Only a failure before the rename of `approval.age` removes the pending
/// config and staged approval: after it, they may belong to the committed approval.
fn commit<F: StoreFs>(
    storage: &ApprovalStorage<'_, F>,
    state: &mut ApprovalState,
    version: ApprovalVersion,
    digest: ConfigDigest,
) -> Result<Option<Box<ErrorKindLabel>>, ApprovalError> {
    match state.commit(storage.state_dir, storage.fs, storage.identity, version, digest) {
        Ok(()) => Ok(None),
        Err(ApprovalStateError::WriteUncertain(uncertain)) => {
            let kind = Box::new(uncertain.error_kind_label());
            state
                .settle_commit(storage.state_dir, storage.fs, storage.identity, (version, digest))
                .map(|()| Some(kind.clone()))
                .map_err(|e| ApprovalError {
                    step: ApprovalStep::Commit,
                    progress: ApprovalProgress::CommitUncertain(version),
                    cause: e.into(),
                    commit_uncertain: Some(kind),
                })
        }
        Err(other) => Err(fail(storage, ApprovalStep::Commit, Some(version), other.into())),
    }
}

/// Runs step 6's renames. A directory fsync failure is logged and passed over, since it normally comes after both
/// renames. Publish also reports it, before any rename, when the platform cannot fsync a directory. The read-back in
/// [`PreparedApproval::commit`] then finds the previous published pair, which does not verify as the committed
/// approval, so that case fails too.
fn publish_both<F: StoreFs>(storage: &ApprovalStorage<'_, F>, version: ApprovalVersion) -> Result<(), ConfigWriteError> {
    match publish(storage.config_dir, storage.fs, PublishSet::Both) {
        Err(ConfigWriteError::Io {
            step: WriteStep::SyncDir,
            kind,
            ..
        }) => {
            tracing::warn!(
                %version,
                error_kind = %ErrorKindLabel::from(kind),
                "the approved config was published but the config directory fsync failed; recovery finishes it if power loss undoes it"
            );
            Ok(())
        }
        other => other,
    }
}

/// Handles a failure before the commit: removes the uncommitted files, then reports `step` with `reserved` consumed.
fn fail<F: StoreFs>(
    storage: &ApprovalStorage<'_, F>,
    step: ApprovalStep,
    reserved: Option<ApprovalVersion>,
    cause: ApprovalFailure,
) -> ApprovalError {
    discard_uncommitted(storage.config_dir, storage.fs);
    let progress = reserved.map_or(ApprovalProgress::NothingReserved, ApprovalProgress::Reserved);
    ApprovalError {
        step,
        progress,
        cause,
        commit_uncertain: None,
    }
}

/// Removes the pending config and the staged approval, best effort: a leftover is discarded and recorded as
/// `config.recovery-discarded` by the next config check.
fn discard_uncommitted<F: StoreFs>(config_dir: &ConfigDirLock, fs: &F) {
    if let Err(failed) = remove_pending_and_staged(config_dir, fs) {
        let error_kind = failed.cause.error_kind_label();
        tracing::warn!(
            %error_kind,
            "cannot remove the uncommitted pending config and staged approval; the next config check discards them"
        );
    }
}
