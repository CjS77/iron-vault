// SPDX-License-Identifier: MPL-2.0
//! The migration events:
//!
//! - the authorization events `migration.challenge-issued`, `migration.authorized` and `migration.authorization-refused`
//!   ([migration authorization: audit events](../../../../design/migration-authorization.md#audit-events));
//! - the bundle events `migration.exported`, `migration.export-failed`, `migration.import-refused`,
//!   `migration.import-discarded`, `migration.imported` and `migration.import-failed`
//!   ([migration bundle: audit events](../../../../design/migration-bundle.md#audit-events)).
//!
//! Each holds the operation, the method's label, fixed labels, counts, versions, a vault ID, file names and bundle entry
//! names: never the owner's input, a passphrase, a key, a byte of a record, a challenge's nonce or a binding digest. The
//! destination recipient is a public key.

use iron_vault_store::migration_bundle::EntryName;
use iron_vault_store::{ErrorKindLabel, ImportFailure, ImportStep, ImportedVault, SnapshotError, SnapshotStep, SnapshotSummary};

use super::{AUDIT_TARGET, AuditEvent, EventName, count_of};
use crate::migration_authorization::{MethodName, MigrationOperation, MigrationRefusal};

/// The destination recipient's `age1...` text for `add_recipient`; left out for `export`, which names none.
fn destination(operation: &MigrationOperation) -> Option<String> {
    operation.destination().map(ToString::to_string)
}

/// The `approver_id` field: the approver whose key proves the challenge, for a method that proves with one.
fn approver_id(method: MethodName) -> Option<String> {
    method.approver.map(|approver| approver.to_string())
}

/// `migration.challenge-issued`: a migration challenge went into the pending slot (step 5).
#[derive(Debug, Clone, Copy)]
pub struct ChallengeIssued<'a> {
    /// What the challenge is for.
    pub operation: &'a MigrationOperation,
    /// The label of the source-owner method the owner will be asked to prove it with.
    pub method: &'static str,
}

impl AuditEvent for ChallengeIssued<'_> {
    const NAME: EventName = EventName("migration.challenge-issued");

    fn emit(&self) {
        tracing::info!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            operation = self.operation.label(),
            method = self.method,
            destination_recipient = destination(self.operation).as_deref(),
            "migration challenge issued",
        );
    }
}

/// `migration.authorized`: a source-owner method proved the challenge (step 7). It records the proof, not the migration.
#[derive(Debug, Clone, Copy)]
pub struct Authorized<'a> {
    /// What was authorized.
    pub operation: &'a MigrationOperation,
    /// The method that proved the challenge.
    pub method: MethodName,
}

impl AuditEvent for Authorized<'_> {
    const NAME: EventName = EventName("migration.authorized");

    fn emit(&self) {
        tracing::info!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            operation = self.operation.label(),
            method = self.method.label,
            approver_id = approver_id(self.method).as_deref(),
            destination_recipient = destination(self.operation).as_deref(),
            "migration authorized",
        );
    }
}

/// `migration.import-discarded`: the files of an unfinished import were removed, by `import` or by `init`. They are names
/// the service wrote, and `config.toml` is the bundle's copy.
#[derive(Debug, Clone, Copy)]
pub struct ImportDiscarded<'a> {
    /// The removed file names.
    pub files: &'a [String],
}

impl AuditEvent for ImportDiscarded<'_> {
    const NAME: EventName = EventName("migration.import-discarded");

    fn emit(&self) {
        tracing::warn!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            files = self.files.join(",").as_str(),
            "an unfinished import was discarded",
        );
    }
}

/// `migration.import-refused`: an import was refused at step 2, 3 or 4, before the owner chose anything. It names the rule
/// or check by its fixed name, never a byte of the bundle.
#[derive(Debug, Clone, Copy)]
pub enum ImportRefused {
    /// The bytes break a rule of the bundle's encoding (step 2) or fail a check with the vault identity (step 4).
    BundleInvalid {
        /// The rule's or check's fixed name.
        detail: &'static str,
    },
    /// The export passphrase did not open the exported identity envelope (step 3).
    WrongPassphrase,
}

impl AuditEvent for ImportRefused {
    const NAME: EventName = EventName("migration.import-refused");

    fn emit(&self) {
        let (refusal, detail) = match self {
            Self::BundleInvalid { detail } => ("bundle_invalid", Some(*detail)),
            Self::WrongPassphrase => ("wrong_passphrase", None),
        };
        tracing::warn!(target: AUDIT_TARGET, event = Self::NAME.as_str(), refusal, detail, "an import was refused");
    }
}

/// `migration.imported`: the import's step 10 is durable, so the vault is Initialized and still Locked.
#[derive(Debug, Clone, Copy)]
pub struct Imported<'a> {
    /// What was written.
    pub vault: &'a ImportedVault,
}

impl AuditEvent for Imported<'_> {
    const NAME: EventName = EventName("migration.imported");

    fn emit(&self) {
        let vault = self.vault;
        tracing::info!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            vault_id = vault.vault_id.to_string().as_str(),
            records = count_of(vault.records),
            approvers = count_of(vault.approvers),
            committed_version = vault.committed_version.get(),
            highest_reserved = vault.highest_reserved,
            recipients = vault.recipients.iter().map(|role| role.name()).collect::<Vec<_>>().join(",").as_str(),
            "vault imported",
        );
    }
}

/// `migration.import-failed`: a step of the import's write order failed, or its task ended without a result.
#[derive(Debug, Clone, Copy)]
pub enum ImportFailed<'a> {
    /// A step failed with `cause`, recorded by its variant only.
    Step {
        /// The failed step.
        step: ImportStep,
        /// Why it failed.
        cause: &'a ImportFailure,
    },
    /// The task ended without a result, so no step is known.
    TaskEnded,
}

impl AuditEvent for ImportFailed<'_> {
    const NAME: EventName = EventName("migration.import-failed");

    fn emit(&self) {
        let (step, error_kind) = match self {
            Self::Step { step, cause } => (
                Some(step.number().map_or_else(|| "discard".to_owned(), |n| n.to_string())),
                Some(failure_label(cause)),
            ),
            Self::TaskEnded => (None, None),
        };
        tracing::warn!(target: AUDIT_TARGET, event = Self::NAME.as_str(), step = step.as_deref(), error_kind, "import failed");
    }
}

/// A failure's variant as a fixed label: the underlying errors name paths and bytes, so none is logged.
const fn failure_label(cause: &ImportFailure) -> &'static str {
    match cause {
        ImportFailure::State(_) => "init_state",
        ImportFailure::Write(_) => "state_write",
        ImportFailure::ConfigWrite(_) => "config_write",
        ImportFailure::Identity(_) => "identity",
        ImportFailure::Read(_) => "state_read",
        ImportFailure::ConfigRead(_) => "config_read",
        ImportFailure::Check(_) => "bundle_check",
    }
}

/// Why a challenge's exchange ended without an authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The service refused the challenge, at the attempt limit, the method or the consuming operation.
    Refused(MigrationRefusal),
    /// The prompt got no owner input: the CLI closed, the connection failed or the prompt deadline passed.
    Cancelled,
}

impl Refusal {
    /// The `refusal` field's label.
    fn label(self) -> &'static str {
        match self {
            Self::Refused(refusal) => refusal.label(),
            Self::Cancelled => "cancelled",
        }
    }

    /// The whole seconds left in the attempt limit's cooldown, when that is the refusal.
    fn retry_after(self) -> Option<u64> {
        match self {
            Self::Refused(MigrationRefusal::AttemptsCoolingDown(cooling)) => Some(cooling.retry_after),
            _ => None,
        }
    }
}

/// `migration.authorization-refused`: the challenge was refused or its prompt cancelled (steps 6 and 7), or the
/// authorization was refused when consumed (step 9).
#[derive(Debug, Clone, Copy)]
pub struct AuthorizationRefused<'a> {
    /// What was to be authorized.
    pub operation: &'a MigrationOperation,
    /// The source-owner method the owner answered, or the one first asked when none was answered.
    pub method: MethodName,
    /// Why it was refused.
    pub refusal: Refusal,
}

impl AuditEvent for AuthorizationRefused<'_> {
    const NAME: EventName = EventName("migration.authorization-refused");

    fn emit(&self) {
        tracing::warn!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            operation = self.operation.label(),
            method = self.method.label,
            approver_id = approver_id(self.method).as_deref(),
            refusal = self.refusal.label(),
            destination_recipient = destination(self.operation).as_deref(),
            retry_after = self.refusal.retry_after(),
            "migration authorization refused",
        );
    }
}

/// `migration.exported`: the last bundle data frame of an export was written. It closes the exchange's
/// `migration.authorized`.
#[derive(Debug, Clone, Copy)]
pub struct Exported<'a> {
    /// What the bundle holds.
    pub summary: &'a SnapshotSummary,
}

impl AuditEvent for Exported<'_> {
    const NAME: EventName = EventName("migration.exported");

    fn emit(&self) {
        let summary = self.summary;
        tracing::info!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            vault_id = summary.vault_id.to_string().as_str(),
            records = count_of(summary.record_count),
            approvers = count_of(summary.approver_count),
            committed_version = summary.committed_version.get(),
            highest_reserved = summary.highest_reserved,
            "vault exported",
        );
    }
}

/// `migration.export-failed`: an export failed at its snapshot checks, or after its authorization was consumed.
#[derive(Debug, Clone)]
pub struct ExportFailed {
    /// The step that failed: `check`, `snapshot`, `seal` or `transfer`.
    pub step: SnapshotStep,
    /// Why: a fixed label, `locked` for a `lock` and `deadline` for a missed deadline.
    pub error_kind: ErrorKindLabel,
    /// The bundle entry whose file failed, when a file did.
    pub file: Option<EntryName>,
}

impl ExportFailed {
    /// The record of a failed snapshot check or stream.
    pub fn of(error: &SnapshotError) -> Self {
        Self {
            step: error.step(),
            error_kind: error.error_kind_label(),
            file: error.file(),
        }
    }

    /// The record of a transfer that ended for `error_kind`, with no file at fault.
    pub fn transfer(error_kind: ErrorKindLabel) -> Self {
        Self {
            step: SnapshotStep::Transfer,
            error_kind,
            file: None,
        }
    }
}

impl AuditEvent for ExportFailed {
    const NAME: EventName = EventName("migration.export-failed");

    fn emit(&self) {
        tracing::warn!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            step = self.step.as_str(),
            error_kind = self.error_kind.as_str(),
            file = self.file.map(|file| file.to_string()).as_deref(),
            "export failed",
        );
    }
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use iron_vault_store::RecipientKey;

    use super::*;
    use crate::attempt_limit::AttemptsCoolingDown;
    use crate::audit::tests::{APPROVER_ID, approver, record_of};
    use crate::migration_authorization::OwnerRefusal;

    const RECIPIENT: &str = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";

    const PASSPHRASE: MethodName = MethodName {
        label: "vault_passphrase",
        approver: None,
    };

    fn add() -> MigrationOperation {
        MigrationOperation::AddRecipient(RECIPIENT.parse::<RecipientKey>().unwrap())
    }

    #[test]
    fn an_export_names_no_destination_and_an_add_names_its_recipient() {
        let export = record_of(
            ChallengeIssued {
                operation: &MigrationOperation::Export,
                method: "vault_passphrase",
            },
            "INFO",
            &["operation", "method"],
        );
        assert_eq!(export["operation"], "export");
        let operation = add();
        let added = record_of(
            Authorized {
                operation: &operation,
                method: PASSPHRASE,
            },
            "INFO",
            &["operation", "method", "destination_recipient"],
        );
        assert_eq!(
            (added["operation"].as_str(), added["destination_recipient"].as_str()),
            (Some("add_recipient"), Some(RECIPIENT))
        );
    }

    #[test]
    fn a_discarded_import_names_its_files() {
        let files = ["config.toml".to_owned(), "identity.age".to_owned()];
        let record = record_of(ImportDiscarded { files: &files }, "WARN", &["files"]);
        assert_eq!(record["files"], "config.toml,identity.age");
    }

    #[test]
    fn an_import_refusal_names_the_rule_only_for_a_bad_bundle() {
        let invalid = record_of(
            ImportRefused::BundleInvalid { detail: "gzip_header" },
            "WARN",
            &["refusal", "detail"],
        );
        assert_eq!(
            (invalid["refusal"].as_str(), invalid["detail"].as_str()),
            (Some("bundle_invalid"), Some("gzip_header"))
        );
        let denied = record_of(ImportRefused::WrongPassphrase, "WARN", &["refusal"]);
        assert_eq!(denied["refusal"], "wrong_passphrase");
    }

    #[test]
    fn a_failed_import_records_its_step_and_a_label_and_a_lost_task_neither() {
        let cause = ImportFailure::State(iron_vault_store::InitStateError::AlreadyInitialized);
        let failed = record_of(
            ImportFailed::Step {
                step: ImportStep::Config,
                cause: &cause,
            },
            "WARN",
            &["step", "error_kind"],
        );
        assert_eq!(
            (failed["step"].as_str(), failed["error_kind"].as_str()),
            (Some("5"), Some("init_state"))
        );
        let discard = record_of(
            ImportFailed::Step {
                step: ImportStep::Discard,
                cause: &cause,
            },
            "WARN",
            &["step", "error_kind"],
        );
        assert_eq!(discard["step"], "discard");
        record_of(ImportFailed::TaskEnded, "WARN", &[]);
    }

    #[test]
    fn a_refusal_is_a_label_and_only_the_cooldown_has_a_retry_after() {
        let operation = MigrationOperation::Export;
        let refused = |refusal| AuthorizationRefused {
            operation: &operation,
            method: PASSPHRASE,
            refusal,
        };
        let fields = ["operation", "method", "refusal"];
        [
            (
                Refusal::Refused(MigrationRefusal::Denied(OwnerRefusal::WrongSecret)),
                "wrong_passphrase",
            ),
            (
                Refusal::Refused(MigrationRefusal::Denied(OwnerRefusal::NotThisVault)),
                "not_this_vault",
            ),
            (Refusal::Refused(MigrationRefusal::Expired), "expired"),
            (Refusal::Refused(MigrationRefusal::Unavailable), "unavailable"),
            (
                Refusal::Refused(MigrationRefusal::TpmLockedOut { wait_seconds: 9 }),
                "tpm_locked_out",
            ),
            (Refusal::Cancelled, "cancelled"),
        ]
        .into_iter()
        .for_each(|(refusal, label)| assert_eq!(record_of(refused(refusal), "WARN", &fields)["refusal"], label));
        let cooling = Refusal::Refused(MigrationRefusal::AttemptsCoolingDown(AttemptsCoolingDown { retry_after: 30 }));
        let record = record_of(refused(cooling), "WARN", &["operation", "method", "refusal", "retry_after"]);
        assert_eq!(
            (record["refusal"].as_str(), record["retry_after"].as_u64()),
            (Some("rate_limited"), Some(30))
        );
    }

    #[test]
    fn a_tpm_pin_record_names_its_approver() {
        let tpm = MethodName {
            label: "tpm_pin",
            approver: Some(approver().id),
        };
        let authorized = Authorized {
            operation: &MigrationOperation::Export,
            method: tpm,
        };
        let record = record_of(authorized, "INFO", &["operation", "method", "approver_id"]);
        assert_eq!(
            (record["method"].as_str(), record["approver_id"].as_str()),
            (Some("tpm_pin"), Some(APPROVER_ID))
        );
        let refused = AuthorizationRefused {
            operation: &MigrationOperation::Export,
            method: tpm,
            refusal: Refusal::Refused(MigrationRefusal::Denied(OwnerRefusal::WrongPin)),
        };
        let record = record_of(refused, "WARN", &["operation", "method", "approver_id", "refusal"]);
        assert_eq!(
            (record["refusal"].as_str(), record["approver_id"].as_str()),
            (Some("wrong_pin"), Some(APPROVER_ID))
        );
    }
}
