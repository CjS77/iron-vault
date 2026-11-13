// SPDX-License-Identifier: MPL-2.0
//! The recipient events: the inventory check's `recipient.inventory-damaged` and `recipient.change-recovered`, a change's
//! `recipient.added`, `recipient.removed` and `recipient.change-failed`, and `forget-machine`'s `recipient.forget-checked`
//! ([recipients: audit events](../../../../design/recipients.md#audit-events)).
//!
//! They hold fixed labels, and a recipient key or label, which are public (a label is escaped): never a secret or a
//! file's bytes.

use iron_vault_store::{
    ChangeCommitted, ChangeRecovery, ErrorKindLabel, InventoryDamage, RecipientChangeStep, RecipientEntry, RecipientKey,
};

use super::{AUDIT_TARGET, AuditEvent, EventName};

/// `recipient.inventory-damaged`: the inventory check found the recipient inventory missing or damaged, and wrote nothing.
#[derive(Debug, Clone, Copy)]
pub struct InventoryDamaged(pub InventoryDamage);

impl AuditEvent for InventoryDamaged {
    const NAME: EventName = EventName("recipient.inventory-damaged");

    fn emit(&self) {
        tracing::warn!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            inventory_damage = self.0.label(),
            "recipient inventory is damaged",
        );
    }
}

/// `recipient.change-recovered`: the inventory check finished a committed recipient change or removed a staged inventory.
#[derive(Debug, Clone, Copy)]
pub struct ChangeRecovered(pub ChangeRecovery);

impl AuditEvent for ChangeRecovered {
    const NAME: EventName = EventName("recipient.change-recovered");

    fn emit(&self) {
        tracing::warn!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            recovery = self.0.label(),
            "staged recipient change settled",
        );
    }
}

/// `recipient.added`: a recipient change that adds committed.
#[derive(Debug, Clone, Copy)]
pub struct Added<'a> {
    /// The enrolled entry.
    pub entry: &'a RecipientEntry,
    /// How many recipients the vault has now.
    pub recipients: usize,
}

impl AuditEvent for Added<'_> {
    const NAME: EventName = EventName("recipient.added");

    fn emit(&self) {
        tracing::info!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            recipient = self.entry.key().to_string().as_str(),
            recipient_role = self.entry.role().name(),
            recipient_label = iron_vault_policy::escaped(self.entry.label().as_str()).as_str(),
            recipients = self.recipients,
            "recipient added",
        );
    }
}

/// `recipient.removed`: a recipient change that removes a recipient committed.
#[derive(Debug, Clone, Copy)]
pub struct Removed<'a> {
    /// The recipient that was removed.
    pub entry: &'a RecipientEntry,
    /// The recipient count after the change.
    pub recipients: usize,
}

impl AuditEvent for Removed<'_> {
    const NAME: EventName = EventName("recipient.removed");

    fn emit(&self) {
        tracing::info!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            recipient = self.entry.key().to_string().as_str(),
            recipient_role = self.entry.role().name(),
            recipient_label = iron_vault_policy::escaped(self.entry.label().as_str()).as_str(),
            recipients = self.recipients,
            "recipient removed",
        );
    }
}

/// `recipient.forget-checked`: `forget-machine` ran the inventory check for a key. INFO when the key is gone and nothing
/// needs the owner's attention, else WARN.
#[derive(Debug, Clone, Copy)]
pub struct ForgetChecked<'a> {
    /// The key checked.
    pub recipient: &'a RecipientKey,
    /// What the check found.
    pub outcome: ForgetOutcome<'a>,
}

/// What `forget-machine`'s inventory check found for the key.
#[derive(Debug, Clone, Copy)]
pub enum ForgetOutcome<'a> {
    /// The key is still a recipient, with this entry.
    StillEnrolled(&'a RecipientEntry),
    /// The key is not a recipient.
    Forgotten {
        /// `true` if and only if the independence rule holds for the inventory.
        independence_holds: bool,
        /// `true` if and only if the recovery path is verified: a check ran and no reminder is due.
        recovery_verified: bool,
    },
}

impl AuditEvent for ForgetChecked<'_> {
    const NAME: EventName = EventName("recipient.forget-checked");

    fn emit(&self) {
        let recipient = self.recipient.to_string();
        match self.outcome {
            ForgetOutcome::StillEnrolled(entry) => tracing::warn!(
                target: AUDIT_TARGET,
                event = Self::NAME.as_str(),
                recipient = recipient.as_str(),
                forget_outcome = "still_enrolled",
                recipient_role = entry.role().name(),
                "retired machine's recipient is still enrolled",
            ),
            ForgetOutcome::Forgotten {
                independence_holds: true,
                recovery_verified: true,
            } => tracing::info!(
                target: AUDIT_TARGET,
                event = Self::NAME.as_str(),
                recipient = recipient.as_str(),
                forget_outcome = "forgotten",
                independence = "holds",
                recovery = "verified",
                "retired machine's recipient is not enrolled",
            ),
            ForgetOutcome::Forgotten {
                independence_holds,
                recovery_verified,
            } => tracing::warn!(
                target: AUDIT_TARGET,
                event = Self::NAME.as_str(),
                recipient = recipient.as_str(),
                forget_outcome = "forgotten",
                independence = if independence_holds { "holds" } else { "broken" },
                recovery = if recovery_verified { "verified" } else { "unverified" },
                "retired machine's recipient is not enrolled, with a warning",
            ),
        }
    }
}

/// Why a recipient change did not happen, or did not finish.
#[derive(Debug, Clone)]
pub enum ChangeFailure {
    /// The key to add is already enrolled.
    AlreadyEnrolled,
    /// No enrolled recipient has the key.
    UnknownRecipient,
    /// The set after the change would break the independence rule.
    SetInvalid,
    /// A step of the change failed. `step` is `None` when it failed before the first one.
    WriteFailed {
        /// The step that failed.
        step: Option<RecipientChangeStep>,
        /// The failure's kind, never its text.
        error_kind: ErrorKindLabel,
        /// If the change committed: no, yes, or unknown until the next inventory check.
        committed: ChangeCommitted,
    },
}

/// `recipient.change-failed`: a recipient change was refused at its own step 3, or failed while it was written.
#[derive(Debug, Clone)]
pub struct ChangeFailed<'a> {
    /// `add` or `remove`.
    pub change: &'static str,
    /// The recipient the change names.
    pub recipient: &'a RecipientKey,
    /// Why it failed.
    pub failure: ChangeFailure,
}

impl AuditEvent for ChangeFailed<'_> {
    const NAME: EventName = EventName("recipient.change-failed");

    fn emit(&self) {
        let (failure, step, error_kind, committed) = match &self.failure {
            ChangeFailure::AlreadyEnrolled => ("already_enrolled", None, None, None),
            ChangeFailure::UnknownRecipient => ("unknown_recipient", None, None, None),
            ChangeFailure::SetInvalid => ("set_invalid", None, None, None),
            ChangeFailure::WriteFailed {
                step,
                error_kind,
                committed,
            } => (
                "write_failed",
                step.map(RecipientChangeStep::label),
                Some(error_kind.as_str()),
                Some(committed.label()),
            ),
        };
        tracing::warn!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            change = self.change,
            recipient = self.recipient.to_string().as_str(),
            failure,
            step,
            error_kind,
            committed,
            "recipient change failed",
        );
    }
}
