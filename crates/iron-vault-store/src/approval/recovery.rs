//! Approval recovery: the first part of every config check (design/config-approval.md, "Recovery"; spec §3.9).
//!
//! Multiple renames do not form a filesystem transaction, so after a crash the config directory may hold a committed
//! transaction that is only partly published. Recovery decides what to do from the committed approval alone, never
//! from which file landed: it finishes publishing only the committed transaction, and only when its files verify. It
//! never promotes a signed but uncommitted version, never accepts an older pair beside a newer commit, and never writes
//! the approval state, so loading never advances or repairs a counter.

#[cfg(test)]
mod tests;

use thiserror::Error;

use super::verify::verify_signed;
use super::{ApprovalEnvelope, ApprovalPayload, ApprovalState, ApprovalVersion, CommittedApproval, ConfigDigest, VerifyError};
use crate::ConfigFileName::{Active, ActiveSignature, Pending, StagedSignature};
use crate::{
    ConfigDirLock, ConfigFileName, ConfigWriteError, PublishSet, StoreFs, WriteStep, publish, read_config_file, remove_pending_and_staged,
    verify_approval,
};

/// The store's counterpart of the service's failure reason: what a refused recovery leaves the service as. The
/// service maps each variant to its `FailureReason` of the same name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryFailure {
    /// A committed transaction is on disk that cannot be completed; only a repair or a restart leaves it.
    RecoveryNeeded,
    /// Nothing is committed, or the published pair does not verify as the committed approval; a new approval leaves it.
    PolicyInvalid,
}

/// Why the published pair is not the committed approval: the first of these that applies, in the order of the detail
/// table in design/config-approval.md.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PublishedPairFault {
    /// `config.toml` or `config.toml.sig` is missing, over its limit or not a regular file.
    #[error("{0} is missing")]
    Missing(ConfigFileName),
    /// Both files are there, but the pair does not verify as the committed approval.
    #[error(transparent)]
    DoesNotVerify(VerifyError),
}

/// Why recovery left the service unavailable. Nothing on disk was changed, except as [`PublishFailed`] says; no variant
/// carries config or signature bytes.
///
/// [`PublishFailed`]: ApprovalRecoveryError::PublishFailed
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ApprovalRecoveryError {
    /// No approval was ever committed, so no config can be active.
    #[error("no approved config: no approval has been committed")]
    NothingCommitted,
    /// One file of the committed approval waits to be published, but the other is gone (recovery rows 5 and 6).
    #[error("committed version {version} cannot be published: its {missing} is missing; the published pair: {published}")]
    CommittedFileMissing {
        /// The committed version.
        version: ApprovalVersion,
        /// The committed approval's waiting file that is missing: [`ConfigFileName::StagedSignature`] for its approval,
        /// [`ConfigFileName::Pending`] for its config.
        missing: ConfigFileName,
        /// Why the published pair does not verify.
        published: PublishedPairFault,
    },
    /// The published pair does not verify as the committed approval, and nothing of it waits to be published
    /// (recovery rows 7 and 8).
    #[error("the published config is not committed version {version}: {published}")]
    PublishedPairInvalid {
        /// The committed version.
        version: ApprovalVersion,
        /// Why the published pair does not verify.
        published: PublishedPairFault,
    },
    /// Finishing the publish failed. Any rename that ran left a state the next recovery finishes.
    #[error("cannot finish publishing committed version {version}: {cause}")]
    PublishFailed {
        /// The committed version.
        version: ApprovalVersion,
        /// The failed publish step.
        cause: ConfigWriteError,
    },
    /// Publishing reported success, but the published pair as read back does not verify as the committed approval.
    #[error("committed version {version} was published but does not verify as read back: {published}")]
    PublishNotVerified {
        /// The committed version.
        version: ApprovalVersion,
        /// Why the published pair does not verify.
        published: PublishedPairFault,
    },
}

impl ApprovalRecoveryError {
    /// What the refusal leaves the service as (design/config-approval.md, open question 4).
    pub fn failure(&self) -> RecoveryFailure {
        match self {
            Self::NothingCommitted | Self::PublishedPairInvalid { .. } => RecoveryFailure::PolicyInvalid,
            Self::CommittedFileMissing { .. } | Self::PublishFailed { .. } | Self::PublishNotVerified { .. } => {
                RecoveryFailure::RecoveryNeeded
            }
        }
    }
}

/// An uncommitted leftover that recovery durably removed. Its version, if any, stays consumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscardedFile {
    /// The pending config or the staged approval.
    pub file: ConfigFileName,
    /// For a staged approval signed by the pinned approver for this vault, the version it was signed for.
    pub signed_for: Option<ApprovalVersion>,
}

/// Recovery passed: the published pair verifies as the committed approval, as read back.
#[derive(Debug)]
pub struct RecoveredApproval {
    published: CommittedApproval,
    finished: Option<PublishSet>,
    discarded: Vec<DiscardedFile>,
}

impl RecoveredApproval {
    /// The committed approval and its config bytes, verified as read back from `config.toml` and `config.toml.sig`.
    pub fn published(&self) -> &CommittedApproval {
        &self.published
    }

    /// The renames recovery ran to finish publishing the committed transaction, or `None` if it was already published.
    pub fn finished(&self) -> Option<PublishSet> {
        self.finished
    }

    /// The uncommitted leftovers recovery removed, pending first.
    pub fn discarded(&self) -> &[DiscardedFile] {
        &self.discarded
    }
}

/// Runs approval recovery on the config directory against the committed approval in `state`, which it never writes.
///
/// Serves the published pair when it verifies as the committed approval (row 1), finishes publishing when the committed
/// approval's files wait as the pending config or staged approval (rows 2 to 4), and otherwise refuses and touches
/// nothing (rows 5 to 8). Once the published pair verifies, any pending or staged file left is an uncommitted leftover
/// and is removed, best effort. A recovery that fails midway leaves a state the next one resolves, so it is safe to run
/// again, at startup or in any later config check (design/config-approval.md, open question 7).
pub fn recover_approval(
    config_dir: &ConfigDirLock,
    fs: &impl StoreFs,
    state: &ApprovalState,
) -> Result<RecoveredApproval, ApprovalRecoveryError> {
    let committed = state.committed().ok_or(ApprovalRecoveryError::NothingCommitted)?;
    let files = ConfigFiles::read(config_dir, fs);
    match files.published.verify(state) {
        Ok(published) => Ok(finish(config_dir, fs, state, published, None)),
        Err(published) => recover_unpublished(config_dir, fs, state, &files, committed, published),
    }
}

/// Rows 2 to 8: the published pair is not the committed approval.
fn recover_unpublished(
    config_dir: &ConfigDirLock,
    fs: &impl StoreFs,
    state: &ApprovalState,
    files: &ConfigFiles,
    (version, digest): (ApprovalVersion, ConfigDigest),
    published: PublishedPairFault,
) -> Result<RecoveredApproval, ApprovalRecoveryError> {
    let holds_config = |bytes: &Option<Vec<u8>>| bytes.as_deref().is_some_and(|b| ConfigDigest::of(b) == digest);
    let holds_approval = |bytes: &Option<Vec<u8>>| {
        bytes
            .as_deref()
            .is_some_and(|e| verify_signed(state, digest, e).is_ok_and(|p| p.version() == version))
    };
    let config = Place::of(holds_config(&files.published.config), holds_config(&files.pending));
    let approval = Place::of(holds_approval(&files.published.envelope), holds_approval(&files.staged));
    let missing = |missing| ApprovalRecoveryError::CommittedFileMissing {
        version,
        missing,
        published: published.clone(),
    };
    match (config, approval) {
        (Some(Place::InPlace), Some(Place::Waiting)) => publish_committed(config_dir, fs, state, version, PublishSet::SignatureOnly),
        (Some(Place::Waiting), Some(Place::InPlace)) => publish_committed(config_dir, fs, state, version, PublishSet::ConfigOnly),
        (Some(Place::Waiting), Some(Place::Waiting)) => publish_committed(config_dir, fs, state, version, PublishSet::Both),
        (Some(Place::Waiting), None) => Err(missing(StagedSignature)),
        (None, Some(Place::Waiting)) => Err(missing(Pending)),
        // Rows 7 and 8. Both files in place would verify, which is row 1, so refusing it here can only be the safe side.
        (Some(Place::InPlace) | None, None | Some(Place::InPlace)) => {
            Err(ApprovalRecoveryError::PublishedPairInvalid { version, published })
        }
    }
}

/// Where a file of the committed approval is: in place, or waiting as the pending config or staged approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Place {
    InPlace,
    Waiting,
}

impl Place {
    /// A file already in place is preferred over its waiting counterpart.
    fn of(in_place: bool, waiting: bool) -> Option<Self> {
        match (in_place, waiting) {
            (true, _) => Some(Self::InPlace),
            (false, true) => Some(Self::Waiting),
            (false, false) => None,
        }
    }
}

/// Rows 2 to 4: renames the committed approval's waiting files into place, then verifies the pair as read back. A
/// failed directory fsync after the renames is passed over, because the commit is the durable record and the
/// read-back decides; the leftovers are discarded only once the pair verifies, so a publish that did not happen never
/// costs the committed transaction its files.
fn publish_committed(
    config_dir: &ConfigDirLock,
    fs: &impl StoreFs,
    state: &ApprovalState,
    version: ApprovalVersion,
    set: PublishSet,
) -> Result<RecoveredApproval, ApprovalRecoveryError> {
    match publish(config_dir, fs, set) {
        Ok(()) => {}
        Err(ConfigWriteError::Io {
            step: WriteStep::SyncDir,
            kind,
            ..
        }) => tracing::warn!(%version, ?kind, "the config directory fsync failed while finishing a publish; the read-back decides"),
        Err(cause) => return Err(ApprovalRecoveryError::PublishFailed { version, cause }),
    }
    tracing::warn!(event = "config.recovery-published", %version, renames = ?set, "ran the publish renames of a committed approval");
    let published = PublishedPair::read(config_dir, fs)
        .verify(state)
        .map_err(|published| ApprovalRecoveryError::PublishNotVerified { version, published })?;
    Ok(finish(config_dir, fs, state, published, Some(set)))
}

/// The published pair verifies: discards the leftovers and reports the result.
fn finish(
    config_dir: &ConfigDirLock,
    fs: &impl StoreFs,
    state: &ApprovalState,
    published: CommittedApproval,
    finished: Option<PublishSet>,
) -> RecoveredApproval {
    RecoveredApproval {
        discarded: discard_leftovers(config_dir, fs, state),
        published,
        finished,
    }
}

/// Durably removes the pending config and staged approval beside a published pair that verifies, best effort: a
/// leftover is never promoted, so one left behind is discarded by the next config check. The counters are not touched.
fn discard_leftovers(config_dir: &ConfigDirLock, fs: &impl StoreFs, state: &ApprovalState) -> Vec<DiscardedFile> {
    let signed_for = read_config_file(config_dir, fs, StagedSignature)
        .ok()
        .and_then(|envelope| staged_payload(state, &envelope))
        .map(|payload| payload.version());
    let removed = remove_pending_and_staged(config_dir, fs).unwrap_or_else(|error| {
        tracing::warn!(%error, "cannot discard the uncommitted pending config and staged approval; the next config check retries");
        Vec::new()
    });
    let discarded: Vec<_> = removed
        .into_iter()
        .map(|file| DiscardedFile {
            file,
            signed_for: signed_for.filter(|_| file == StagedSignature),
        })
        .collect();
    discarded.iter().for_each(|d| {
        tracing::info!(event = "config.recovery-discarded", file = %d.file, signed_for = ?d.signed_for.map(ApprovalVersion::get));
    });
    discarded
}

/// The payload of a staged leftover the pinned approver signed for this vault. Logs at ERROR one that names the
/// committed version with another digest, which only a misbehaving signer produces.
fn staged_payload(state: &ApprovalState, envelope: &[u8]) -> Option<ApprovalPayload> {
    let claimed = ApprovalEnvelope::decode(envelope).ok()?.payload().digest();
    let payload = verify_signed(state, claimed, envelope).ok()?;
    if state
        .committed()
        .is_some_and(|(version, digest)| payload.version() == version && payload.digest() != digest)
    {
        let error = VerifyError::DigestNotCommitted {
            version: payload.version(),
        };
        tracing::error!(%error, "discarding a staged approval for the committed version with another config");
    }
    Some(payload)
}

/// The four config files as read once. A missing, oversized or non-regular file is absent for every purpose.
struct ConfigFiles {
    published: PublishedPair,
    pending: Option<Vec<u8>>,
    staged: Option<Vec<u8>>,
}

impl ConfigFiles {
    fn read(config_dir: &ConfigDirLock, fs: &impl StoreFs) -> Self {
        Self {
            published: PublishedPair::read(config_dir, fs),
            pending: read_config_file(config_dir, fs, Pending).ok(),
            staged: read_config_file(config_dir, fs, StagedSignature).ok(),
        }
    }
}

/// `config.toml` and `config.toml.sig` as read once.
struct PublishedPair {
    config: Option<Vec<u8>>,
    envelope: Option<Vec<u8>>,
}

impl PublishedPair {
    fn read(config_dir: &ConfigDirLock, fs: &impl StoreFs) -> Self {
        Self {
            config: read_config_file(config_dir, fs, Active).ok(),
            envelope: read_config_file(config_dir, fs, ActiveSignature).ok(),
        }
    }

    /// The pair, verified as the committed approval.
    fn verify(&self, state: &ApprovalState) -> Result<CommittedApproval, PublishedPairFault> {
        let config = self.config.as_deref().ok_or(PublishedPairFault::Missing(Active))?;
        let envelope = self.envelope.as_deref().ok_or(PublishedPairFault::Missing(ActiveSignature))?;
        let approval = verify_approval(state, config, envelope).map_err(PublishedPairFault::DoesNotVerify)?;
        Ok(CommittedApproval::new(approval, config.into()))
    }
}
