//! The recipient events (`design/recipients.md`, "Audit events"): the inventory check's `recipient.inventory-damaged` and
//! `recipient.change-recovered`, and a removal's `recipient.removed` and `recipient.change-failed`.
//!
//! They hold fixed labels, and a recipient key or label, which are public: never a secret or a file's bytes.

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
            recipient_label = self.entry.label().as_str(),
            recipients = self.recipients,
            "recipient removed",
        );
    }
}

/// Why a recipient removal did not happen, or did not finish.
#[derive(Debug, Clone)]
pub enum ChangeFailure {
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
        /// Whether the change committed.
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
