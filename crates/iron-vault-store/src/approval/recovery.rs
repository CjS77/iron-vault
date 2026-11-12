//! Approval recovery: the first part of every config check, at startup and on reload
//! ([config approval, "Recovery"](../../../../design/config-approval.md#recovery);
//! [spec §12](../../../../design/iron-vault-specification.md#12-configuration-approval-and-reload)).
//!
//! Two renames do not form a filesystem transaction, so after a crash the config directory may hold a committed
//! transaction that is only partly published. Recovery decides what to do from the committed approval `C` alone, never
//! from which file landed. It looks for `C`'s config and `C`'s approval, preferring a file in place over one waiting
//! to be published, and follows the [recovery table](../../../../design/config-approval.md#recovery-table):
//!
//! ```text
//! row  C's config in          C's approval in           outcome
//! 1    config.toml            config.toml.sig           serve the published pair
//! 2    config.toml            config.toml.sig.staged    finish publishing: rename the staged approval
//! 3    config.toml.pending    config.toml.sig           finish publishing: rename the pending config
//! 4    config.toml.pending    config.toml.sig.staged    finish publishing: both renames
//! 5    config.toml.pending    nowhere                   refuse, RecoveryNeeded (CommittedFileMissing)
//! 6    nowhere                config.toml.sig.staged    refuse, RecoveryNeeded (CommittedFileMissing)
//! 7    config.toml or nowhere nowhere                   refuse, PolicyInvalid (PublishedPairInvalid)
//! 8    nowhere                config.toml.sig           refuse, PolicyInvalid (PublishedPairInvalid)
//! ```
//!
//! After rows 1 to 4 the published pair verifies as `C`, and any pending or staged file left is an uncommitted
//! leftover that recovery removes. Recovery finishes publishing only the committed transaction, and only when its files
//! verify. It never promotes a signed but uncommitted version, never accepts an older pair beside a newer commit, and
//! never writes the approval state, so loading never advances or repairs a counter.

#[cfg(test)]
mod tests;

use std::io;

use thiserror::Error;

use super::verify::verify_signed;
use super::{ApprovalEnvelope, ApprovalPayload, ApprovalState, ApprovalVersion, CommittedApproval, ConfigDigest, VerifyError};
use crate::ConfigFileName::{Active, ActiveSignature, Pending, StagedSignature};
use crate::{
    ConfigDirLock, ConfigFileName, ConfigReadError, ConfigWriteError, ErrorKindLabel, PublishSet, StoreFs, WriteStep, publish,
    read_config_file, remove_pending_and_staged, verify_approval,
};

/// The store's counterpart of the service's failure reason: the state a refused recovery leaves the service in. The
/// service maps each variant to its `FailureReason` of the same name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryFailure {
    /// A config file cannot be read, or a committed transaction is on disk that cannot be completed. Only a repair, a
    /// fix to the file's permissions or disk, or a restart leaves it.
    RecoveryNeeded,
    /// Nothing is committed, or the published pair does not verify as the committed approval. A new approval leaves it.
    PolicyInvalid,
}

/// Why the published pair is not the committed approval: the first of these that applies, in the order of the
/// [detail table](../../../../design/config-approval.md#detail-when-the-service-stays-unavailable-rows-5-to-8).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PublishedPairFault {
    /// `config.toml` or `config.toml.sig` is absent: missing, over its limit or not a regular file. A file that is there
    /// but cannot be read is [`ApprovalRecoveryError::Unreadable`] before the recovery table, and
    /// [`PublishedPairFault::Unreadable`] in the read-back after a publish.
    #[error("{0} is missing, oversized or not a regular file")]
    Missing(ConfigFileName),
    /// Reading back `config.toml` or `config.toml.sig` after recovery's publish renames failed with an I/O error other
    /// than `NotFound`. Only [`ApprovalRecoveryError::PublishNotVerified`] carries it.
    #[error("cannot read {file}: {kind}")]
    Unreadable {
        /// The file that could not be read.
        file: ConfigFileName,
        /// The I/O error kind.
        kind: io::ErrorKind,
    },
    /// Both files are there, but the pair does not verify as the committed approval.
    #[error(transparent)]
    DoesNotVerify(VerifyError),
}

/// Why recovery left the service unavailable. Nothing on disk changed, except as [`PublishFailed`] and
/// [`PublishNotVerified`] say. No variant carries config or signature bytes.
///
/// [`PublishFailed`]: ApprovalRecoveryError::PublishFailed
/// [`PublishNotVerified`]: ApprovalRecoveryError::PublishNotVerified
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ApprovalRecoveryError {
    /// No approval was ever committed, so no config can be active.
    #[error("no approved config: no approval has been committed")]
    NothingCommitted,
    /// A config file is there but reading it failed, so recovery cannot tell what it holds. It may be the file that
    /// completes the commit, so recovery refuses before the recovery table and touches nothing. Recovery returns it only
    /// before any rename: an unreadable file in the read-back after a publish is
    /// [`PublishNotVerified`](ApprovalRecoveryError::PublishNotVerified), which says the renames ran.
    #[error("cannot read {file}: {kind}")]
    Unreadable {
        /// The first unreadable file, in the order `config.toml`, `config.toml.sig`, `config.toml.pending`,
        /// `config.toml.sig.staged`.
        file: ConfigFileName,
        /// The I/O error kind. Never [`io::ErrorKind::NotFound`], which recovery treats as absent.
        kind: io::ErrorKind,
    },
    /// One file of the committed approval waits to be published, but the other is gone (recovery table rows 5 and 6).
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
    /// The published pair does not verify as the committed approval, and no file of it waits to be published
    /// (recovery table rows 7 and 8).
    #[error("the published config is not committed version {version}: {published}")]
    PublishedPairInvalid {
        /// The committed version.
        version: ApprovalVersion,
        /// Why the published pair does not verify.
        published: PublishedPairFault,
    },
    /// Finishing the publish failed. Any rename that ran leaves a state the next recovery finishes.
    #[error("cannot finish publishing committed version {version}: {cause}")]
    PublishFailed {
        /// The committed version.
        version: ApprovalVersion,
        /// The failed publish step.
        cause: ConfigWriteError,
    },
    /// Publishing reported success, but the published pair as read back cannot be read or does not verify as the
    /// committed approval. The renames have run, so the committed version is on disk as the published pair.
    #[error("committed version {version} was published but does not verify as read back: {published}")]
    PublishNotVerified {
        /// The committed version.
        version: ApprovalVersion,
        /// The renames that ran.
        renames: PublishSet,
        /// Why the published pair does not verify.
        published: PublishedPairFault,
    },
}

impl ApprovalRecoveryError {
    /// Returns the state the refusal leaves the service in
    /// ([config approval, open question 4](../../../../design/config-approval.md#open-questions)).
    pub fn failure(&self) -> RecoveryFailure {
        match self {
            Self::NothingCommitted | Self::PublishedPairInvalid { .. } => RecoveryFailure::PolicyInvalid,
            Self::Unreadable { .. } | Self::CommittedFileMissing { .. } | Self::PublishFailed { .. } | Self::PublishNotVerified { .. } => {
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
    /// For a staged approval that a pinned approver signed for this vault, the version it was signed for.
    pub signed_for: Option<ApprovalVersion>,
    /// `true` if and only if this staged approval was signed for the committed version over a different config. Only a
    /// second signature over that version, or a file the service did not write, produces this.
    pub conflicting: bool,
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
/// Refuses and touches nothing if any config file is there but unreadable. Otherwise it serves the published pair when
/// it verifies as the committed approval (row 1), finishes publishing when the committed approval's files wait as the
/// pending config or staged approval (rows 2 to 4), and refuses and touches nothing in every other case (rows 5 to 8).
/// Once the published pair verifies, it removes any pending or staged file left, best effort. A recovery that fails
/// midway leaves a state the next one resolves, so it is safe to run again, at startup or in any later config check
/// ([config approval, open question 7](../../../../design/config-approval.md#open-questions)).
pub fn recover_approval(
    config_dir: &ConfigDirLock,
    fs: &impl StoreFs,
    state: &ApprovalState,
) -> Result<RecoveredApproval, ApprovalRecoveryError> {
    let committed = state.committed().ok_or(ApprovalRecoveryError::NothingCommitted)?;
    let files = ConfigFiles::read(config_dir, fs)?;
    match files.published.verify(state) {
        Ok(published) => Ok(serve_discarding_leftovers(config_dir, fs, state, &files, published, None)),
        Err(published) => recover_unpublished(config_dir, fs, state, &files, committed, published),
    }
}

/// Handles rows 2 to 8, where the published pair is not the committed approval.
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
        (Some(Place::InPlace), Some(Place::Waiting)) => publish_committed(config_dir, fs, state, files, version, PublishSet::SignatureOnly),
        (Some(Place::Waiting), Some(Place::InPlace)) => publish_committed(config_dir, fs, state, files, version, PublishSet::ConfigOnly),
        (Some(Place::Waiting), Some(Place::Waiting)) => publish_committed(config_dir, fs, state, files, version, PublishSet::Both),
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
    /// Places a file from where it was found. A file already in place is preferred over its waiting counterpart.
    fn of(in_place: bool, waiting: bool) -> Option<Self> {
        match (in_place, waiting) {
            (true, _) => Some(Self::InPlace),
            (false, true) => Some(Self::Waiting),
            (false, false) => None,
        }
    }
}

/// Handles rows 2 to 4: renames the committed approval's waiting files into place, then verifies the pair as read back.
/// A failed directory fsync after the renames is passed over, because the commit is the durable record and the
/// read-back decides. Leftovers are discarded only once the pair verifies, so a publish that did not happen never
/// costs the committed transaction its files.
fn publish_committed(
    config_dir: &ConfigDirLock,
    fs: &impl StoreFs,
    state: &ApprovalState,
    files: &ConfigFiles,
    version: ApprovalVersion,
    set: PublishSet,
) -> Result<RecoveredApproval, ApprovalRecoveryError> {
    match publish(config_dir, fs, set) {
        Ok(()) => {}
        Err(ConfigWriteError::Io {
            step: WriteStep::SyncDir,
            kind,
            ..
        }) => {
            tracing::warn!(
                %version,
                error_kind = %ErrorKindLabel::from(kind),
                "the config directory fsync failed while finishing a publish; the read-back decides"
            )
        }
        Err(cause) => return Err(ApprovalRecoveryError::PublishFailed { version, cause }),
    }
    let published = PublishedPair::read(config_dir, fs)
        .map_err(PublishedPairFault::from)
        .and_then(|pair| pair.verify(state))
        .map_err(|published| ApprovalRecoveryError::PublishNotVerified {
            version,
            renames: set,
            published,
        })?;
    Ok(serve_discarding_leftovers(config_dir, fs, state, files, published, Some(set)))
}

/// Discards the leftovers beside a published pair that verifies, and serves the pair. `files` is what recovery read
/// before any rename; a staged approval it held is still the one on disk if the publish left it there.
fn serve_discarding_leftovers(
    config_dir: &ConfigDirLock,
    fs: &impl StoreFs,
    state: &ApprovalState,
    files: &ConfigFiles,
    published: CommittedApproval,
    finished: Option<PublishSet>,
) -> RecoveredApproval {
    RecoveredApproval {
        discarded: discard_leftovers(config_dir, fs, state, files.staged.as_deref()),
        published,
        finished,
    }
}

/// Durably removes the pending config and staged approval beside a published pair that verifies, best effort. A
/// leftover is never promoted, so the next config check discards one left behind. Reports every file that was removed,
/// even when a later removal failed. The counters are not touched.
fn discard_leftovers(config_dir: &ConfigDirLock, fs: &impl StoreFs, state: &ApprovalState, staged: Option<&[u8]>) -> Vec<DiscardedFile> {
    let removed = remove_pending_and_staged(config_dir, fs).unwrap_or_else(|failed| {
        let removed = failed.removed.iter().map(|file| file.as_str()).collect::<Vec<_>>().join(",");
        let error_kind = failed.cause.error_kind_label();
        tracing::warn!(
            %error_kind,
            removed = removed.as_str(),
            "cannot discard all of the uncommitted pending config and staged approval; the next config check retries"
        );
        failed.removed
    });
    let staged = staged.and_then(|envelope| staged_payload(state, envelope));
    removed
        .into_iter()
        .map(|file| match (file, &staged) {
            (StagedSignature, Some(payload)) => DiscardedFile {
                file,
                signed_for: Some(payload.version()),
                conflicting: conflicts_with_committed(state, payload),
            },
            _ => DiscardedFile {
                file,
                signed_for: None,
                conflicting: false,
            },
        })
        .collect()
}

/// Returns the payload of a staged leftover that a pinned approver signed for this vault, or `None` for any other
/// file.
fn staged_payload(state: &ApprovalState, envelope: &[u8]) -> Option<ApprovalPayload> {
    let claimed = ApprovalEnvelope::decode(envelope).ok()?.payload().digest();
    verify_signed(state, claimed, envelope).ok()
}

/// Returns `true` if and only if `payload` names the committed version with a different digest, which only a
/// misbehaving signer produces.
fn conflicts_with_committed(state: &ApprovalState, payload: &ApprovalPayload) -> bool {
    state
        .committed()
        .is_some_and(|(version, digest)| payload.version() == version && payload.digest() != digest)
}

/// The four config files as read once. A missing, oversized or non-regular file is absent for every purpose.
struct ConfigFiles {
    published: PublishedPair,
    pending: Option<Vec<u8>>,
    staged: Option<Vec<u8>>,
}

impl ConfigFiles {
    /// Reads `config.toml`, `config.toml.sig`, `config.toml.pending` and `config.toml.sig.staged` in that order,
    /// stopping at the first that is unreadable.
    fn read(config_dir: &ConfigDirLock, fs: &impl StoreFs) -> Result<Self, ApprovalRecoveryError> {
        Ok(Self {
            published: PublishedPair::read(config_dir, fs)?,
            pending: read_if_present(config_dir, fs, Pending)?,
            staged: read_if_present(config_dir, fs, StagedSignature)?,
        })
    }
}

/// A config file that is there but could not be read. Which error it becomes depends on whether a rename has run.
struct UnreadableFile {
    file: ConfigFileName,
    kind: io::ErrorKind,
}

impl From<UnreadableFile> for ApprovalRecoveryError {
    fn from(UnreadableFile { file, kind }: UnreadableFile) -> Self {
        Self::Unreadable { file, kind }
    }
}

impl From<UnreadableFile> for PublishedPairFault {
    fn from(UnreadableFile { file, kind }: UnreadableFile) -> Self {
        Self::Unreadable { file, kind }
    }
}

/// Reads `file`: its bytes, `None` if it is absent, or [`UnreadableFile`] if it is there but reading it failed.
fn read_if_present(config_dir: &ConfigDirLock, fs: &impl StoreFs, file: ConfigFileName) -> Result<Option<Vec<u8>>, UnreadableFile> {
    match read_config_file(config_dir, fs, file) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(ConfigReadError::Io { kind, .. }) if kind != io::ErrorKind::NotFound => Err(UnreadableFile { file, kind }),
        Err(ConfigReadError::Io { .. } | ConfigReadError::TooLarge { .. } | ConfigReadError::NotARegularFile { .. }) => Ok(None),
    }
}

/// `config.toml` and `config.toml.sig` as read once.
struct PublishedPair {
    config: Option<Vec<u8>>,
    envelope: Option<Vec<u8>>,
}

impl PublishedPair {
    fn read(config_dir: &ConfigDirLock, fs: &impl StoreFs) -> Result<Self, UnreadableFile> {
        Ok(Self {
            config: read_if_present(config_dir, fs, Active)?,
            envelope: read_if_present(config_dir, fs, ActiveSignature)?,
        })
    }

    /// Verifies the pair as the committed approval.
    fn verify(&self, state: &ApprovalState) -> Result<CommittedApproval, PublishedPairFault> {
        let config = self.config.as_deref().ok_or(PublishedPairFault::Missing(Active))?;
        let envelope = self.envelope.as_deref().ok_or(PublishedPairFault::Missing(ActiveSignature))?;
        let approval = verify_approval(state, config, envelope).map_err(PublishedPairFault::DoesNotVerify)?;
        Ok(CommittedApproval::new(approval, config.into()))
    }
}
