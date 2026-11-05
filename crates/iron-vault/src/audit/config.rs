//! Audit events about an approval's reservation and commit, and about what a config check's recovery changed on disk
//! (`design/audit-logging.md`, "Config approvals and checks"). The store returns each fact and does not log it.

use iron_vault_store::{
    ApprovalError, ApprovalFailure, ApprovalProgress, ApprovalRecoveryError, ApprovalStateError, ApprovalStep, ApprovalVersion,
    ConfigDigest, ConfigFileName, DiscardedFile, ErrorKindLabel, PublishSet, RecoveredApproval,
};

use super::vault::emit_approval_state_uncertain;
use super::{AUDIT_TARGET, AuditEvent, EventName};

/// `config.version-reserved`: step 2's reservation is durable. Recorded before signing starts, so a signing failure, or
/// a crash while the signer waits for the owner, follows it in the log.
#[derive(Debug, Clone, Copy)]
pub struct VersionReserved {
    /// The reserved version, consumed whatever happens next.
    pub version: ApprovalVersion,
    /// The digest of the config the version was reserved for.
    pub digest: ConfigDigest,
}

impl AuditEvent for VersionReserved {
    const NAME: EventName = EventName("config.version-reserved");

    fn emit(&self) {
        tracing::info!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            version = self.version.get(),
            config_digest = self.digest.to_string().as_str(),
            "approval version reserved",
        );
    }
}

/// `config.commit-uncertain`: step 5's rename of `approval.age` landed, but its directory fsync failed.
#[derive(Debug, Clone, Copy)]
pub struct CommitUncertain<'a> {
    /// The version whose commit is uncertain.
    pub version: ApprovalVersion,
    /// The failed fsync's I/O kind.
    pub error_kind: &'a ErrorKindLabel,
}

impl AuditEvent for CommitUncertain<'_> {
    const NAME: EventName = EventName("config.commit-uncertain");

    fn emit(&self) {
        tracing::warn!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            version = self.version.get(),
            error_kind = self.error_kind.as_str(),
            "the commit landed but its directory fsync failed; settling it",
        );
    }
}

/// `config.recovery-published`: a config check finished publishing a committed transaction.
#[derive(Debug, Clone, Copy)]
pub struct RecoveryPublished {
    /// The committed version.
    pub version: ApprovalVersion,
    /// The renames that ran.
    pub renames: PublishSet,
}

impl AuditEvent for RecoveryPublished {
    const NAME: EventName = EventName("config.recovery-published");

    fn emit(&self) {
        let renames: Vec<&str> = self.renames.published().map(ConfigFileName::as_str).collect();
        tracing::warn!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            version = self.version.get(),
            renames = renames.join(",").as_str(),
            "ran the publish renames of a committed approval",
        );
    }
}

/// `config.recovery-discarded`: a config check removed an uncommitted file.
#[derive(Debug, Clone, Copy)]
pub struct RecoveryDiscarded {
    /// The removed file, with the version a staged approval was signed for when that is known.
    pub discarded: DiscardedFile,
}

impl AuditEvent for RecoveryDiscarded {
    const NAME: EventName = EventName("config.recovery-discarded");

    fn emit(&self) {
        tracing::info!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            file = self.discarded.file.as_str(),
            signed_for = self.discarded.signed_for.map(ApprovalVersion::get),
            "discarded an uncommitted file",
        );
    }
}

/// `config.conflicting-approval-discarded`: a staged approval signed for the committed version over another config was
/// discarded. A single approval transaction cannot produce one, so it is an ERROR.
#[derive(Debug, Clone, Copy)]
pub struct ConflictingApprovalDiscarded {
    /// The committed version the staged approval was signed for.
    pub version: ApprovalVersion,
}

impl AuditEvent for ConflictingApprovalDiscarded {
    const NAME: EventName = EventName("config.conflicting-approval-discarded");

    fn emit(&self) {
        tracing::error!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            version = self.version.get(),
            "discarding a staged approval for the committed version with another config",
        );
    }
}

/// Records what recovery changed: the publish it ran, then each file it discarded.
pub fn record_recovery(recovered: &RecoveredApproval) {
    let version = recovered.published().approval().version();
    recovered
        .finished()
        .into_iter()
        .for_each(|renames| RecoveryPublished { version, renames }.emit());
    recovered.discarded().iter().for_each(|&discarded| {
        if let (true, Some(version)) = (discarded.conflicting, discarded.signed_for) {
            ConflictingApprovalDiscarded { version }.emit();
        }
        RecoveryDiscarded { discarded }.emit();
    });
}

/// Records an uncertain commit and the approval state write behind it.
pub fn record_commit_uncertain(version: ApprovalVersion, error_kind: &ErrorKindLabel) {
    CommitUncertain { version, error_kind }.emit();
    emit_approval_state_uncertain(error_kind);
}

/// Records a publish whose renames ran but whose result did not verify; the renames happened either way.
pub fn record_unverified_publish(error: &ApprovalRecoveryError) {
    if let ApprovalRecoveryError::PublishNotVerified { version, renames, .. } = error {
        RecoveryPublished {
            version: *version,
            renames: *renames,
        }
        .emit();
    }
}

/// The version a failed approval reserved durably. A reservation whose own fsync failed is consumed but not durable,
/// so it is not one.
fn reserved_version(error: &ApprovalError) -> Option<ApprovalVersion> {
    match (error.step(), error.progress()) {
        (ApprovalStep::Reserve, _) | (_, ApprovalProgress::NothingReserved) => None,
        (_, ApprovalProgress::Reserved(version) | ApprovalProgress::CommitUncertain(version) | ApprovalProgress::Committed(version)) => {
            Some(version)
        }
    }
}

/// Records the uncertain approval state write a failed approval transaction met, if it met one.
pub fn record_uncertain_writes(error: &ApprovalError) {
    match (reserved_version(error), error.commit_uncertain(), error.cause()) {
        (Some(version), Some(kind), _) => record_commit_uncertain(version, kind),
        (_, _, ApprovalFailure::State(ApprovalStateError::WriteUncertain(write))) => {
            emit_approval_state_uncertain(&write.error_kind_label())
        }
        _ => {}
    }
}

/// Records a failed approval after the fact, for a caller that could not record its reservation as it happened: the
/// reservation, if it was durable, then what the transaction left uncertain.
pub fn record_failed_approval(error: &ApprovalError, digest: ConfigDigest) {
    reserved_version(error)
        .into_iter()
        .for_each(|version| VersionReserved { version, digest }.emit());
    record_uncertain_writes(error);
}
