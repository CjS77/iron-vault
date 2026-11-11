//! The approver events (`design/approval-signers.md`, "Audit events"): an approver change's `approver.enrolled`,
//! `approver.removed` and `approver.change-failed`, and step 3's `approver.orphan-removed`.
//!
//! They hold fixed labels, and approver IDs and labels, which are public (a label is escaped): never a passphrase, a key
//! or a file's bytes.

use iron_vault_store::{ApproverChangeError, ApproverId, ErrorKindLabel, KeyFileOutcome, PinnedApprover};

use super::{AUDIT_TARGET, AuditEvent, EventName, NamedApprover};

/// `approver.enrolled`: an approver change that enrolls committed.
#[derive(Debug, Clone, Copy)]
pub struct Enrolled<'a> {
    /// The approver the change pinned.
    pub approver: &'a PinnedApprover,
    /// How many approvers the vault pins now.
    pub approvers: usize,
    /// The approver whose owner presence authorized the change.
    pub authorizing: NamedApprover<'a>,
}

impl AuditEvent for Enrolled<'_> {
    const NAME: EventName = EventName("approver.enrolled");

    fn emit(&self) {
        let enrolled = NamedApprover::from(self.approver);
        tracing::info!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            approver_id = enrolled.id_text().as_str(),
            approver_label = enrolled.label_text().as_str(),
            signer_kind = self.approver.kind().name(),
            approvers = self.approvers,
            authorizing_approver_id = self.authorizing.id_text().as_str(),
            authorizing_approver_label = self.authorizing.label_text().as_str(),
            "approver enrolled",
        );
    }
}

/// `approver.removed`: an approver change that removes committed.
#[derive(Debug, Clone, Copy)]
pub struct Removed<'a> {
    /// The approver the change unpinned.
    pub approver: &'a PinnedApprover,
    /// How many approvers the vault pins now.
    pub approvers: usize,
    /// The approver whose owner presence authorized the change.
    pub authorizing: NamedApprover<'a>,
    /// What became of the removed approver's key file.
    pub key_file: &'a KeyFileOutcome,
}

impl AuditEvent for Removed<'_> {
    const NAME: EventName = EventName("approver.removed");

    fn emit(&self) {
        let removed = NamedApprover::from(self.approver);
        tracing::info!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            approver_id = removed.id_text().as_str(),
            approver_label = removed.label_text().as_str(),
            signer_kind = self.approver.kind().name(),
            approvers = self.approvers,
            authorizing_approver_id = self.authorizing.id_text().as_str(),
            authorizing_approver_label = self.authorizing.label_text().as_str(),
            key_file = match self.key_file {
                KeyFileOutcome::Removed => "removed",
                KeyFileOutcome::Left(_) => "left",
            },
            "approver removed",
        );
    }
}

/// Why an approver change was refused at its step 3 or 6, or failed while it was written.
#[derive(Debug, Clone, Copy)]
pub enum ChangeFailure<'a> {
    /// The set after the change would break the approver count limits.
    SetInvalid,
    /// `approver remove` named an ID that no pinned approver has.
    UnknownApprover,
    /// `approver remove` named the approver that signed the active approval.
    InUse,
    /// The new signer's secret broke a passphrase rule.
    PassphraseRejected,
    /// Step 3's read-back or orphan sweep failed, or the approver change failed.
    WriteFailed(&'a ApproverChangeError),
}

/// `approver.change-failed`: an approver command was refused at its step 3 or 6, or its approver change failed.
#[derive(Debug, Clone, Copy)]
pub struct ChangeFailed<'a> {
    /// `add` or `remove`.
    pub change: &'static str,
    /// The approver the change names, when it is known.
    pub approver: Option<ApproverId>,
    /// Why it failed.
    pub failure: ChangeFailure<'a>,
}

impl AuditEvent for ChangeFailed<'_> {
    const NAME: EventName = EventName("approver.change-failed");

    fn emit(&self) {
        let (failure, step, error_kind, committed) = match self.failure {
            ChangeFailure::SetInvalid => ("set_invalid", None, None, None),
            ChangeFailure::UnknownApprover => ("unknown_approver", None, None, None),
            ChangeFailure::InUse => ("in_use", None, None, None),
            ChangeFailure::PassphraseRejected => ("passphrase_rejected", None, None, None),
            ChangeFailure::WriteFailed(error) => (
                "write_failed",
                Some(error.step().label()),
                Some(error.error_kind_label()),
                Some(error.may_have_committed().label()),
            ),
        };
        tracing::warn!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            change = self.change,
            approver_id = self.approver.map(|id| id.to_string()).as_deref(),
            failure,
            step,
            error_kind = error_kind.as_ref().map(ErrorKindLabel::as_str),
            committed,
            "approver change failed",
        );
    }
}

/// `approver.orphan-removed`: step 3 of an approver command deleted a key file no pinned approver has.
#[derive(Debug, Clone, Copy)]
pub struct OrphanRemoved(pub ApproverId);

impl AuditEvent for OrphanRemoved {
    const NAME: EventName = EventName("approver.orphan-removed");

    fn emit(&self) {
        tracing::warn!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            approver_id = self.0.to_string().as_str(),
            "orphan approver key file removed",
        );
    }
}
