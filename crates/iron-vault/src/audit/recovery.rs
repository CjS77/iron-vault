//! The recovery events: `recovery.checked` and `recovery.reminder` (`design/recovery.md`, "Logging").
//!
//! It carries the outcome and fixed labels only: never the key's text, the store's error text or the record's bytes.

use iron_vault_store::{ErrorKindLabel, RecoveryCheckError, VaultId};

use super::{AUDIT_TARGET, AuditEvent, EventName};
use crate::recovery_reminder::{Due, RecordState};

/// `recovery.checked`: how a recovery check ended, once the text was known to be a recovery key or not.
#[derive(Debug, Clone)]
pub enum RecoveryChecked<'a> {
    /// The key opens the vault. `record_error` is the write error's label when the check record was not written.
    Opened {
        /// The vault the key opened.
        vault_id: VaultId,
        /// Why the record was not written; `None` when it was.
        record_error: Option<ErrorKindLabel>,
    },
    /// The key was judged and does not open the vault: [`RecoveryCheckError::NotARecipient`] or
    /// [`RecoveryCheckError::IdentityNotGenuine`].
    Failed(&'a RecoveryCheckError),
    /// The text is not a recovery key.
    Invalid,
    /// The check could not be run, so the key was not judged.
    Unavailable(&'a RecoveryCheckError),
}

impl AuditEvent for RecoveryChecked<'_> {
    const NAME: EventName = EventName("recovery.checked");

    fn emit(&self) {
        match self {
            Self::Opened { vault_id, record_error } => tracing::info!(
                target: AUDIT_TARGET,
                event = Self::NAME.as_str(),
                recovery_outcome = "opened",
                vault_id = vault_id.to_string().as_str(),
                recorded = record_error.is_none(),
                error_kind = record_error.as_ref().map(ErrorKindLabel::as_str),
                "recovery key opens the vault",
            ),
            Self::Failed(error) => tracing::warn!(
                target: AUDIT_TARGET,
                event = Self::NAME.as_str(),
                recovery_outcome = "failed",
                recovery_failure = error.error_kind_label().as_str(),
                "recovery key does not open the vault",
            ),
            Self::Invalid => tracing::warn!(
                target: AUDIT_TARGET,
                event = Self::NAME.as_str(),
                recovery_outcome = "invalid",
                "recovery key text is not a recovery key",
            ),
            Self::Unavailable(error) => tracing::warn!(
                target: AUDIT_TARGET,
                event = Self::NAME.as_str(),
                recovery_outcome = "unavailable",
                file = error.file().map(|file| file.as_str()),
                error_kind = error.error_kind_label().as_str(),
                "recovery check could not be run",
            ),
        }
    }
}

/// What the owner is told to do, in every `recovery.reminder`. The second sentence is the rebuild list after complete
/// loss: with the vault gone, each credential is reissued from its provider.
pub const REMINDER_REMEDIATION: &str = "Run `sudo iron-vault recovery check` with your offline recovery key. Keep a copy of the approved \
config and of the output of `sudo iron-vault list` with the recovery key: the config names each routed credential and its upstream, \
and the list adds unrouted credentials and each one's kind and origins.";

/// `recovery.reminder`: the owner is due to run a recovery check. It carries the record's times as recorded, never as
/// proof that a key works.
#[derive(Debug, Clone)]
pub struct RecoveryReminder<'a>(pub &'a Due);

impl AuditEvent for RecoveryReminder<'_> {
    const NAME: EventName = EventName("recovery.reminder");

    fn emit(&self) {
        let days = u64::from(self.0.reminder_days);
        match &self.0.record {
            RecordState::Checked(last_checked) => tracing::info!(
                target: AUDIT_TARGET,
                event = Self::NAME.as_str(),
                recovery_record = "checked",
                last_checked = last_checked.to_string().as_str(),
                reminder_days = days,
                remediation = REMINDER_REMEDIATION,
                "a recovery check is due",
            ),
            RecordState::NeverChecked(since) => tracing::info!(
                target: AUDIT_TARGET,
                event = Self::NAME.as_str(),
                recovery_record = "never_checked",
                reminders_since = since.to_string().as_str(),
                reminder_days = days,
                remediation = REMINDER_REMEDIATION,
                "a recovery check is due",
            ),
            RecordState::Unusable(error_kind) => tracing::info!(
                target: AUDIT_TARGET,
                event = Self::NAME.as_str(),
                recovery_record = "unusable",
                error_kind = error_kind.as_str(),
                reminder_days = days,
                remediation = REMINDER_REMEDIATION,
                "a recovery check is due",
            ),
        }
    }
}
