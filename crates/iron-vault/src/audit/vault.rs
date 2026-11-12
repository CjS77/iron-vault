//! Audit events about the vault: its initialization, unlock refusals, lock drains and the facts of a write report
//! ([audit logging: catalogue, "Credentials and vault writes" and "Initialization"](../../../../design/audit-logging.md#catalogue)).

// The events that name the service context's types build only where it does.
#[cfg(target_os = "linux")]
mod service_events;
#[cfg(target_os = "linux")]
pub use service_events::{HostUnlock, InitFailed, PresenceRefused, UnlockRefused};

mod reset;
pub use reset::{ResetConfirmed, ResetFailed, VaultReset};

use iron_vault_store::{ApprovalStateError, ErrorKindLabel, RecipientRole, StateFileName, VaultError, VaultId, WriteError};

use super::{AUDIT_TARGET, AuditEvent, EventName};

/// `vault.initialized`: init's last step is durable.
#[derive(Debug, Clone, Copy)]
pub struct VaultInitialized<'a> {
    /// The new vault's ID.
    pub vault_id: VaultId,
    /// The roles of the recipients enrolled: kinds, never keys.
    pub recipients: &'a [RecipientRole],
}

impl AuditEvent for VaultInitialized<'_> {
    const NAME: EventName = EventName("vault.initialized");

    fn emit(&self) {
        tracing::info!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            vault_id = self.vault_id.to_string().as_str(),
            recipients = self.recipients.iter().map(|role| role.name()).collect::<Vec<_>>().join(",").as_str(),
            "vault initialized",
        );
    }
}

/// `vault.init-discarded`: the files of an unfinished initialization were removed. They are names the service wrote.
#[derive(Debug, Clone, Copy)]
pub struct InitDiscarded<'a> {
    /// The removed file names.
    pub files: &'a [String],
}

impl AuditEvent for InitDiscarded<'_> {
    const NAME: EventName = EventName("vault.init-discarded");

    fn emit(&self) {
        tracing::warn!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            files = self.files.join(",").as_str(),
            "an unfinished initialization was discarded",
        );
    }
}

/// `vault.foreign-file`: `unlock` found a file in an Initialized state directory that init never writes.
#[derive(Debug, Clone, Copy)]
pub struct ForeignFile<'a> {
    /// The file's name, which the service did not choose.
    pub file: &'a str,
}

impl AuditEvent for ForeignFile<'_> {
    const NAME: EventName = EventName("vault.foreign-file");

    fn emit(&self) {
        tracing::warn!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            file = iron_vault_policy::escaped(self.file).as_str(),
            "unlock found a file that is not the vault's",
        );
    }
}

/// `vault.lock-incomplete`: a lock's drain ended with a serving snapshot or the vault identity still held.
#[derive(Debug, Clone, Copy)]
pub struct LockIncomplete {
    /// Serving snapshots still held.
    pub snapshots_held: u64,
    /// `true` if and only if the vault identity was still held.
    pub identity_held: bool,
}

impl AuditEvent for LockIncomplete {
    const NAME: EventName = EventName("vault.lock-incomplete");

    fn emit(&self) {
        tracing::warn!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            snapshots_held = self.snapshots_held,
            identity_held = self.identity_held,
            "lock incomplete: requests that ignore cancellation still hold the vault",
        );
    }
}

/// `vault.unindexed-removed`: a vault write removed an unindexed record file first.
#[derive(Debug, Clone, Copy)]
pub struct UnindexedRemoved<'a> {
    /// The removed file, a name the service chose.
    pub file: &'a StateFileName,
}

impl AuditEvent for UnindexedRemoved<'_> {
    const NAME: EventName = EventName("vault.unindexed-removed");

    fn emit(&self) {
        tracing::warn!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            file = self.file.as_str(),
            "a vault write removed a record file the vault manifest does not list",
        );
    }
}

/// `vault.superseded-left`: a committed write could not remove the record file it superseded.
#[derive(Debug, Clone, Copy)]
pub struct SupersededLeft<'a> {
    /// The file left behind.
    pub file: &'a StateFileName,
    /// Why the removal failed.
    pub error_kind: &'a ErrorKindLabel,
}

impl AuditEvent for SupersededLeft<'_> {
    const NAME: EventName = EventName("vault.superseded-left");

    fn emit(&self) {
        tracing::warn!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            file = self.file.as_str(),
            error_kind = self.error_kind.as_str(),
            "a superseded record file could not be removed; the next vault write removes it",
        );
    }
}

/// `vault.commit-uncertain`: the vault manifest or the approval state was replaced but its directory fsync failed, so the
/// write may not survive power loss.
#[derive(Debug, Clone, Copy)]
pub struct CommitUncertain<'a> {
    /// The file that was replaced.
    pub file: &'a StateFileName,
    /// The kind of the failed fsync.
    pub error_kind: &'a ErrorKindLabel,
}

impl AuditEvent for CommitUncertain<'_> {
    const NAME: EventName = EventName("vault.commit-uncertain");

    fn emit(&self) {
        tracing::error!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            file = self.file.as_str(),
            error_kind = self.error_kind.as_str(),
            "a state file was replaced but the state directory fsync failed; the change may not survive power loss",
        );
    }
}

/// Emits `vault.commit-uncertain` when a vault or approval state write failed at the commit's directory fsync, also when
/// it is the cause of an unrecorded approval state. Any other error is for the caller to report.
pub fn emit_commit_uncertain(error: &VaultError) {
    match error {
        VaultError::CommitUncertain(cause @ WriteError::Io { file, .. }) => CommitUncertain {
            file,
            error_kind: &cause.error_kind_label(),
        }
        .emit(),
        VaultError::ApprovalState(ApprovalStateError::WriteUncertain(cause)) => emit_approval_state_uncertain(&cause.error_kind_label()),
        VaultError::ApprovalStateUnrecorded(inner) => emit_commit_uncertain(inner),
        _ => {}
    }
}

/// `vault.commit-uncertain` for `approval.age`, the file the approval transaction and init's step 6 replace.
pub fn emit_approval_state_uncertain(error_kind: &ErrorKindLabel) {
    CommitUncertain {
        file: &StateFileName::approval_state(),
        error_kind,
    }
    .emit();
}
