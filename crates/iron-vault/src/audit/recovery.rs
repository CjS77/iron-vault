//! The recovery event: `recovery.checked` (`design/recovery.md`, "Logging").
//!
//! It carries the outcome and fixed labels only: never the key's text, the store's error text or the record's bytes.

use iron_vault_store::{ErrorKindLabel, RecoveryCheckError, VaultId};

use super::{AUDIT_TARGET, AuditEvent, EventName};

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
