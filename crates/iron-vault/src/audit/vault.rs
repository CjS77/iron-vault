//! Audit events about the vault: its initialization, unlock refusals, lock drains and the facts of a write report
//! (`design/audit-logging.md`, "Credentials and vault writes" and "Initialization").

use iron_vault_store::{ErrorKindLabel, InitFailure, InitStep, StateFileName, UnlockError, VaultError, VaultId, WriteError};

use super::{AUDIT_TARGET, AuditEvent, EventName};
use crate::service_context::{UnlockRefusal, step_names};

/// `vault.initialized`: init's last step is durable.
#[derive(Debug, Clone, Copy)]
pub struct VaultInitialized {
    /// The new vault's ID.
    pub vault_id: VaultId,
}

impl AuditEvent for VaultInitialized {
    const NAME: EventName = EventName("vault.initialized");

    fn emit(&self) {
        tracing::info!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            vault_id = self.vault_id.to_string().as_str(),
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

/// `vault.init-failed`: an init step failed, or its task ended without a result. `step` is the step number, or `discard`;
/// it is left out when no step is known.
#[derive(Debug, Clone, Copy)]
pub enum InitFailed<'a> {
    /// A step failed with `cause`, recorded by its variant only.
    Step {
        /// The failed step.
        step: InitStep,
        /// Why it failed.
        cause: &'a InitFailure,
    },
    /// The task ended without a result, so no step is known.
    TaskEnded,
}

impl AuditEvent for InitFailed<'_> {
    const NAME: EventName = EventName("vault.init-failed");

    fn emit(&self) {
        let (step, error_kind) = match self {
            Self::Step { step, cause } => (Some(step_names(*step).0), Some(init_failure_label(cause))),
            Self::TaskEnded => (None, None),
        };
        tracing::warn!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            step = step.as_deref(),
            error_kind,
            "vault initialization failed",
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

/// `vault.unlock-refused`: an unlock left the service where it was.
#[derive(Debug, Clone, Copy)]
pub struct UnlockRefused<'a> {
    /// Why, recorded as a fixed label.
    pub refusal: &'a UnlockRefusal,
}

impl AuditEvent for UnlockRefused<'_> {
    const NAME: EventName = EventName("vault.unlock-refused");

    fn emit(&self) {
        tracing::warn!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            refusal = unlock_refusal_label(self.refusal),
            "unlock refused, the service stays Locked",
        );
    }
}

/// `vault.lock-incomplete`: a lock's drain ended with a serving snapshot or the vault identity still held.
#[derive(Debug, Clone, Copy)]
pub struct LockIncomplete {
    /// Serving snapshots still held.
    pub snapshots_held: u64,
    /// Whether the vault identity was still held.
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

/// `vault.commit-uncertain`: the vault manifest was replaced but its directory fsync failed, so the write may not
/// survive power loss.
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
            "vault manifest was replaced but the state directory fsync failed; the write may not survive power loss",
        );
    }
}

/// Emits `vault.commit-uncertain` when a vault write failed at the commit's directory fsync, also when it is the cause
/// of an unrecorded approval state. Any other error is for the caller to report.
pub fn emit_commit_uncertain(error: &VaultError) {
    match error {
        VaultError::CommitUncertain(cause @ WriteError::Io { file, .. }) => CommitUncertain {
            file,
            error_kind: &cause.error_kind_label(),
        }
        .emit(),
        VaultError::ApprovalStateUnrecorded(inner) => emit_commit_uncertain(inner),
        _ => {}
    }
}

/// The failure's variant: none of the text it wraps reaches the record.
const fn init_failure_label(failure: &InitFailure) -> &'static str {
    match failure {
        InitFailure::State(_) => "init_state",
        InitFailure::Recipients(_) => "recipients",
        InitFailure::Envelope(_) => "envelope",
        InitFailure::Write(_) => "state_write",
        InitFailure::Read(_) => "state_read",
        InitFailure::IdentityMismatch => "identity_mismatch",
        InitFailure::Sign(_) => "sign",
        InitFailure::Vault(_) => "vault",
        InitFailure::Approval(_) => "approval",
        InitFailure::UnexpectedVersion(_) => "unexpected_version",
    }
}

const fn unlock_refusal_label(refusal: &UnlockRefusal) -> &'static str {
    match refusal {
        UnlockRefusal::WrongState(_) => "wrong_state",
        UnlockRefusal::WrongPassphrase | UnlockRefusal::Failed(UnlockError::WrongPassphrase) => "wrong_passphrase",
        UnlockRefusal::Failed(UnlockError::Read(_)) => "state_read",
        UnlockRefusal::Failed(UnlockError::PassphraseEnvelope(_)) => "passphrase_envelope",
        UnlockRefusal::Failed(UnlockError::IdentityEnvelope(_)) => "identity_envelope",
        UnlockRefusal::Failed(UnlockError::InitializationUnfinished) => "initialization_unfinished",
        UnlockRefusal::Failed(UnlockError::NotInitialized) => "not_initialized",
        UnlockRefusal::Failed(UnlockError::Unrecognized { .. }) => "unrecognized_files",
        UnlockRefusal::Failed(UnlockError::InitializationState(_) | UnlockError::ListStateDir { .. }) => "state_unreadable",
        UnlockRefusal::Interrupted => "interrupted",
    }
}
