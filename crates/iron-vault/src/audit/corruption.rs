// SPDX-License-Identifier: MPL-2.0
//! Audit events about a damaged vault, from the store's open report and errors
//! ([audit logging: catalogue, "Corruption"](../../../../design/audit-logging.md#catalogue)).
//!
//! The store returns these as facts and logs nothing; the service opens every vault through [`open_vault`], which emits
//! one event per fact. Each event carries `remediation`, a fixed phrase for the administrator.

use std::sync::Arc;

use iron_vault_store::{
    DamagedRecord, ErrorKindLabel, OpenReport, SharedStateDamage, StateDirLock, StateFileName, StoreFs, Vault, VaultError, VaultIdentity,
};

use super::{AUDIT_TARGET, AuditEvent, EventName};

/// The `remediation` for damaged shared state. Re-initializing would orphan the records, so it says not to.
const SHARED_STATE_REMEDIATION: &str = "restore the state directory from a backup taken by this vault, or recover the vault; \
     do not delete or re-initialize the state directory, which would orphan every credential record";

/// The `remediation` for a file the vault manifest does not list.
const UNINDEXED_REMEDIATION: &str = "the vault manifest does not list this file, so it is ignored and the next vault write removes it; \
     if no write was interrupted, investigate who can write to the state directory";

/// The `remediation` for a vault whose approval state is not recorded.
const UNRECORDED_REMEDIATION: &str = "record the approval state with `record_approval_state`";

/// The `remediation` for a state directory the service cannot list.
const STATE_DIR_REMEDIATION: &str = "check that the state directory exists and that the service account can read it";

/// `vault.record-damaged`: a listed record is damaged and was not loaded. `error_kind` is left out unless a read failed.
#[derive(Debug, Clone, Copy)]
pub struct RecordDamaged<'a> {
    /// The damaged record, as the open report names it.
    pub record: &'a DamagedRecord,
}

impl AuditEvent for RecordDamaged<'_> {
    const NAME: EventName = EventName("vault.record-damaged");

    fn emit(&self) {
        let record = self.record;
        tracing::error!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            credential = record.credential.as_str(),
            record_id = record.record_id.to_string().as_str(),
            file = record.file.as_str(),
            damage = record.damage.to_string().as_str(),
            error_kind = record.error_kind.as_ref().map(ErrorKindLabel::as_str),
            remediation = record.damage.remediation(),
            "credential record is damaged and was not loaded; routes that use this credential are unavailable",
        );
    }
}

/// `vault.unindexed-file`: opening the vault found a record file the manifest does not list.
#[derive(Debug, Clone, Copy)]
pub struct UnindexedFile<'a> {
    /// The file, a name the store accepted as a record file name.
    pub file: &'a StateFileName,
}

impl AuditEvent for UnindexedFile<'_> {
    const NAME: EventName = EventName("vault.unindexed-file");

    fn emit(&self) {
        tracing::warn!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            file = self.file.as_str(),
            remediation = UNINDEXED_REMEDIATION,
            "record file is not in the vault manifest and was not loaded",
        );
    }
}

/// `vault.approval-state-unrecorded`: the approval state exists but the vault manifest does not record it.
#[derive(Debug, Clone, Copy)]
pub struct ApprovalStateUnrecorded;

impl AuditEvent for ApprovalStateUnrecorded {
    const NAME: EventName = EventName("vault.approval-state-unrecorded");

    fn emit(&self) {
        tracing::warn!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            remediation = UNRECORDED_REMEDIATION,
            "the approval state exists but the vault manifest does not record it; its deletion cannot be detected until it is recorded",
        );
    }
}

/// `vault.shared-state-damaged`: the vault's shared state cannot be trusted, so the whole vault is unavailable.
#[derive(Debug, Clone, Copy)]
pub struct SharedStateDamaged<'a> {
    /// The damaged file.
    pub file: &'a StateFileName,
    /// What is wrong with it, recorded by its variant only.
    pub damage: &'a SharedStateDamage,
}

impl AuditEvent for SharedStateDamaged<'_> {
    const NAME: EventName = EventName("vault.shared-state-damaged");

    fn emit(&self) {
        tracing::error!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            file = self.file.as_str(),
            damage = shared_state_damage_label(self.damage),
            remediation = SHARED_STATE_REMEDIATION,
            "vault shared state is damaged; the whole vault is unavailable and recovery may be required",
        );
    }
}

/// `vault.state-dir-unreadable`: the state directory cannot be listed.
#[derive(Debug, Clone, Copy)]
pub struct StateDirUnreadable<'a> {
    /// The kind of the listing failure.
    pub error_kind: &'a ErrorKindLabel,
}

impl AuditEvent for StateDirUnreadable<'_> {
    const NAME: EventName = EventName("vault.state-dir-unreadable");

    fn emit(&self) {
        tracing::error!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            error_kind = self.error_kind.as_str(),
            remediation = STATE_DIR_REMEDIATION,
            "cannot list the state directory; the vault is unavailable",
        );
    }
}

/// Opens the vault and emits what the open found: an event per damaged record and unindexed file, one for an
/// unrecorded approval state, or the event of the error that refused the whole vault. A missing vault is not damage.
pub fn open_vault(
    lock: &StateDirLock,
    fs: &impl StoreFs,
    identity: impl Into<Arc<VaultIdentity>>,
) -> Result<(Vault, OpenReport), VaultError> {
    Vault::open(lock, fs, identity)
        .inspect(|(_, report)| emit_open_report(report))
        .inspect_err(emit_open_error)
}

/// One event per fact in an open report: each damaged record, each unindexed file, and an unrecorded approval state.
fn emit_open_report(report: &OpenReport) {
    report.damaged_records().iter().for_each(|record| RecordDamaged { record }.emit());
    report.unindexed().iter().for_each(|file| UnindexedFile { file }.emit());
    if report.approval_state_unrecorded() {
        ApprovalStateUnrecorded.emit();
    }
}

/// The event for an open error that is damage: damaged shared state, or a state directory that cannot be listed.
fn emit_open_error(error: &VaultError) {
    match error {
        VaultError::SharedStateDamaged { file, damage } => SharedStateDamaged { file, damage }.emit(),
        VaultError::ListStateDir { kind } => StateDirUnreadable {
            error_kind: &ErrorKindLabel::from(*kind),
        }
        .emit(),
        // A missing vault is not damage; the write variants go to the caller of the write, which audits them.
        _ => {}
    }
}

/// The shared state damage as its fixed `damage` label.
const fn shared_state_damage_label(damage: &SharedStateDamage) -> &'static str {
    match damage {
        SharedStateDamage::MissingWithRecords => "missing_with_records",
        SharedStateDamage::MissingWithApprovalState => "missing_with_approval_state",
        SharedStateDamage::Read(_) => "state_read",
        SharedStateDamage::Manifest(_) => "manifest",
        SharedStateDamage::ApprovalState(_) => "approval_state",
        SharedStateDamage::PartialRestore(_) => "partial_restore",
    }
}
