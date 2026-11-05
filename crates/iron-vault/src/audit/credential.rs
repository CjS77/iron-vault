//! Audit events about credentials and caller tokens (`design/audit-logging.md`, "Credentials and vault writes").

use iron_vault_policy::{CredentialName, Host, Port};
use iron_vault_store::{ErrorKindLabel, RecordId};

use super::{AUDIT_TARGET, AuditEvent, EventName};

/// A credential's kind label and permitted origins, as the record states them.
#[derive(Debug, Clone, Copy)]
pub struct Stored<'a> {
    /// The kind label, such as `static`.
    pub kind: &'a str,
    /// The permitted origins.
    pub origins: &'a [(Host, Port)],
}

/// The origins as `https://host:port`, in a `,` list.
fn origins_text(origins: &[(Host, Port)]) -> String {
    origins
        .iter()
        .map(|(host, port)| format!("https://{host}:{}", port.get()))
        .collect::<Vec<_>>()
        .join(",")
}

/// `credential.added`: an `add` committed.
#[derive(Debug, Clone, Copy)]
pub struct CredentialAdded<'a> {
    /// The credential's configured name.
    pub credential: &'a CredentialName,
    /// The new record.
    pub record_id: RecordId,
    /// The new record's kind and origins.
    pub stored: Stored<'a>,
}

impl AuditEvent for CredentialAdded<'_> {
    const NAME: EventName = EventName("credential.added");

    fn emit(&self) {
        tracing::info!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            credential = self.credential.as_str(),
            record_id = self.record_id.to_string().as_str(),
            kind = self.stored.kind,
            origins = origins_text(self.stored.origins).as_str(),
            "credential added; routes can use it from the next approval",
        );
    }
}

/// `credential.replaced`: a `replace` committed.
#[derive(Debug, Clone, Copy)]
pub struct CredentialReplaced<'a> {
    /// The credential's configured name.
    pub credential: &'a CredentialName,
    /// The record replaced.
    pub old_record_id: RecordId,
    /// The new record.
    pub record_id: RecordId,
    /// The new record's kind and origins.
    pub stored: Stored<'a>,
    /// The old record's kind and origins; `None` when the old record was damaged.
    pub old: Option<Stored<'a>>,
}

impl AuditEvent for CredentialReplaced<'_> {
    const NAME: EventName = EventName("credential.replaced");

    fn emit(&self) {
        tracing::info!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            credential = self.credential.as_str(),
            old_record_id = self.old_record_id.to_string().as_str(),
            record_id = self.record_id.to_string().as_str(),
            kind = self.stored.kind,
            origins = origins_text(self.stored.origins).as_str(),
            old_kind = self.old.map(|old| old.kind),
            old_origins = self.old.map(|old| origins_text(old.origins)).as_deref(),
            "credential replaced",
        );
    }
}

/// `credential.removed`: an `rm` committed.
#[derive(Debug, Clone, Copy)]
pub struct CredentialRemoved<'a> {
    /// The credential's configured name.
    pub credential: &'a CredentialName,
    /// The record removed.
    pub record_id: RecordId,
}

impl AuditEvent for CredentialRemoved<'_> {
    const NAME: EventName = EventName("credential.removed");

    fn emit(&self) {
        tracing::info!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            credential = self.credential.as_str(),
            record_id = self.record_id.to_string().as_str(),
            "credential removed; no active route used it",
        );
    }
}

/// `caller.token-issued`. The token, and its hash, which would tie the record to a caller, are never logged.
#[derive(Debug, Clone, Copy)]
pub struct TokenIssued;

impl AuditEvent for TokenIssued {
    const NAME: EventName = EventName("caller.token-issued");

    fn emit(&self) {
        tracing::info!(target: AUDIT_TARGET, event = Self::NAME.as_str(), "a caller token was issued; the service keeps no copy");
    }
}

/// `caller.token-failed`: the random source failed, so no token was issued.
#[derive(Debug, Clone, Copy)]
pub struct TokenFailed<'a> {
    /// The failure's kind label.
    pub error_kind: &'a ErrorKindLabel,
}

impl AuditEvent for TokenFailed<'_> {
    const NAME: EventName = EventName("caller.token-failed");

    fn emit(&self) {
        tracing::error!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            error_kind = self.error_kind.as_str(),
            "no caller token was issued",
        );
    }
}
