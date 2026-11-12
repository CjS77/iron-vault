//! The three events of `reset` ([reset: logging](../../../../../design/reset.md#logging)). None carries a secret, a
//! typed confirmation or a file's contents; foreign file names, which the service did not choose, are escaped.

use iron_vault_store::{ErrorKindLabel, InitializationState, ResetStep, UnfinishedKind, VaultId};

use crate::audit::{AUDIT_TARGET, AuditEvent, EventName, state_label};
use crate::service_state::ServiceState;

/// `vault.reset-confirmed`: the owner confirmed, and `reset.unfinished` is about to be written. It comes first, so a log
/// write that fails and stops the service stops it with the vault intact.
#[derive(Debug, Clone, Copy)]
pub struct ResetConfirmed {
    /// The vault ID when the state was Initialized.
    pub vault_id: Option<VaultId>,
    /// `true` if and only if the vault ID was checked against an open vault; `false` when it was read from the manifest's
    /// clear header.
    pub verified: bool,
    /// The initialization state reset read.
    pub initialization: InitializationState,
    /// The service state reset started from.
    pub from_state: ServiceState,
    /// `true` if and only if this finishes an interrupted reset.
    pub resumes: bool,
}

impl AuditEvent for ResetConfirmed {
    const NAME: EventName = EventName("vault.reset-confirmed");

    fn emit(&self) {
        tracing::warn!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            vault_id = self.vault_id.map(|id| id.to_string()).as_deref(),
            verified = self.verified,
            initialization = initialization_label(self.initialization),
            from_state = state_label(self.from_state),
            resumes = self.resumes,
            "reset confirmed",
        );
    }
}

/// `vault.reset`: the vault and the config are discarded and `reset.unfinished` is removed.
#[derive(Debug, Clone, Copy)]
pub struct VaultReset<'a> {
    /// The vault ID when the state was Initialized.
    pub vault_id: Option<VaultId>,
    /// The store-owned file names removed.
    pub files: &'a [String],
    /// The foreign files left, by their raw names; the event escapes them.
    pub foreign: &'a [String],
    /// `true` if and only if the removal of `reset.unfinished` may not survive a power loss.
    pub finish_uncertain: bool,
}

impl AuditEvent for VaultReset<'_> {
    const NAME: EventName = EventName("vault.reset");

    fn emit(&self) {
        tracing::warn!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            vault_id = self.vault_id.map(|id| id.to_string()).as_deref(),
            files = self.files.join(",").as_str(),
            foreign = escaped_names(self.foreign).as_str(),
            finish_uncertain = self.finish_uncertain,
            "vault reset",
        );
    }
}

/// `vault.reset-failed`: a step from the write of `reset.unfinished` on failed.
#[derive(Debug, Clone, Copy)]
pub struct ResetFailed<'a> {
    /// The step that failed.
    pub step: ResetStep,
    /// The file it acted on; empty when no file was.
    pub file: &'a str,
    /// Why it failed.
    pub error_kind: &'a ErrorKindLabel,
    /// The files removed before it failed.
    pub removed: &'a [String],
}

impl AuditEvent for ResetFailed<'_> {
    const NAME: EventName = EventName("vault.reset-failed");

    fn emit(&self) {
        tracing::warn!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            step = self.step.to_string().as_str(),
            file = iron_vault_policy::escaped(self.file).as_str(),
            error_kind = self.error_kind.as_str(),
            removed = self.removed.join(",").as_str(),
            "reset failed",
        );
    }
}

/// Foreign names escaped as `vault.foreign-file` escapes its `file`, then joined with commas.
fn escaped_names(names: &[String]) -> String {
    names
        .iter()
        .map(|name| iron_vault_policy::escaped(name))
        .collect::<Vec<_>>()
        .join(",")
}

/// The log's spelling of an initialization state.
const fn initialization_label(state: InitializationState) -> &'static str {
    match state {
        InitializationState::Uninitialized => "uninitialized",
        InitializationState::Unfinished(UnfinishedKind::Initialization) => "unfinished",
        InitializationState::Unfinished(UnfinishedKind::Import) => "unfinished_import",
        InitializationState::Initialized => "initialized",
        InitializationState::Unrecognized => "unrecognized",
        InitializationState::UnfinishedReset => "unfinished_reset",
    }
}
