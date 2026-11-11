//! Audit events: the typed records of administrative and security facts (specification §18;
//! `design/audit-logging.md`, "Audit events").
//!
//! Each event is a struct whose fields are domain types, and its [`AuditEvent::emit`] makes one `tracing` call under
//! [`AUDIT_TARGET`] with its event name, its level, a fixed message and exactly its own fields, each turned into a
//! `&str`, `u64` or `bool`. A header value, a URL or a library error's text therefore has no field to go into. Every
//! value from a fixed vocabulary is written as a snake_case label from this module, never as a type's `Debug` output.
//! The record's constant fields are the formatter's job ([`crate::logging::RecordFormat`]), so no event may use one of
//! [`CONSTANT_FIELDS`] as a field name.

#[cfg(test)]
mod config_events_tests;
#[cfg(test)]
mod corruption_tests;
// `service.started` names the log destination, which only Linux has.
#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests;
#[cfg(test)]
mod vault_events_tests;

pub mod admin;
pub mod approver;
pub mod config;
pub mod corruption;
pub mod credential;
pub mod migration;
pub mod recipient;
pub mod recovery;
pub mod route;
pub mod vault;

mod request;
pub use request::{Ending, REQUEST_TARGET, ReasonCode, RequestFacts, RequestId, RequestRecord};

use iron_vault_store::{ApprovalError, ApprovalFailure, ApprovalStep, ApprovalVersion, ApproverId, ConfigDigest, PinnedApprover};

use crate::config_check::{CheckFailure, InvalidConfig};
use crate::hardening::{CoreDumps, HardeningReport, MEMLOCK_REMEDIATION, MemoryProtection};
#[cfg(target_os = "linux")]
use crate::logging::LogDestination;
#[cfg(target_os = "linux")]
use crate::service_context::DenialKind;
use crate::service_state::{ServiceState, UnavailableReason};

/// The `tracing` target of every audit event. A hyphen cannot appear in a Rust path, so no module's target starts with
/// it, and a filter directive for code never catches an audit event.
pub const AUDIT_TARGET: &str = "iron-vault.audit";

/// The record schema's version, written as `schema_version` in every record. It rises when a field or event name is
/// removed or renamed, a field's type or unit changes, or a label changes meaning, so a dashboard can pin the version
/// it was written for.
pub const SCHEMA_VERSION: u32 = 1;

/// The fields the formatter adds to every record. An event that recorded one too would give its record a duplicate key.
pub const CONSTANT_FIELDS: [&str; 4] = ["service", "service_version", "schema_version", "deployment_profile"];

/// A length as a `u64` field; a length never exceeds `u64::MAX` on a supported target, so the fallback is unreachable.
// Every event with a count is emitted by the Linux-only service context, request server or proxy handler.
#[cfg(target_os = "linux")]
pub(crate) fn count_of(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

/// An event's stable name, `<subject>.<name>`, written in its `event` field. Renaming one changes the schema version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventName(&'static str);

impl EventName {
    /// The name as written in the record.
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

/// The approver a config approval or owner presence asked, or signed with, as its audit records name it: the approver ID
/// and the label, so the log says which signer approved each version.
#[derive(Debug, Clone, Copy)]
pub struct NamedApprover<'a> {
    /// The approver's ID, written as the hyphenated UUID.
    pub id: ApproverId,
    /// The approver's label, written escaped, since the owner chose it.
    pub label: &'a str,
}

impl NamedApprover<'_> {
    /// The `approver_id` field's value.
    pub(crate) fn id_text(&self) -> String {
        self.id.to_string()
    }

    /// The `approver_label` field's value: the label with control and non-ASCII characters escaped.
    pub(crate) fn label_text(&self) -> String {
        iron_vault_policy::escaped(self.label)
    }
}

impl<'a> From<&'a PinnedApprover> for NamedApprover<'a> {
    fn from(approver: &'a PinnedApprover) -> Self {
        Self {
            id: approver.id(),
            label: approver.label().as_str(),
        }
    }
}

/// One audit event: a fixed name, level, message and fields.
pub trait AuditEvent {
    /// The event's name.
    const NAME: EventName;

    /// Writes the event's one record.
    fn emit(&self);
}

/// `service.started`: the log destination is open, with where the log goes and what process hardening achieved. The
/// deployment profile is a constant field of every record, so a development run is visible here without a field of its
/// own. `serve` runs on Linux only, as does the log destination.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy)]
pub struct ServiceStarted<'a> {
    /// Where the log records go: approved configuration, never a request's path.
    pub destination: &'a LogDestination,
    /// What process hardening achieved.
    pub hardening: &'a HardeningReport,
}

#[cfg(target_os = "linux")]
impl AuditEvent for ServiceStarted<'_> {
    const NAME: EventName = EventName("service.started");

    fn emit(&self) {
        tracing::info!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            log_destination = self.destination.to_string().as_str(),
            core_dumps = core_dumps_label(&self.hardening.core_dumps),
            memory_protection = memory_label(&self.hardening.memory),
            "service started",
        );
    }
}

/// `service.hardening-incomplete`: core dumps are not disabled or memory is not locked, with the fix. The reason a
/// failed setting carries is an OS error's text, so it is not recorded.
#[derive(Debug, Clone, Copy)]
pub struct HardeningIncomplete<'a> {
    hardening: &'a HardeningReport,
}

impl<'a> HardeningIncomplete<'a> {
    /// The event for `hardening`, or `None` when every protection is in effect.
    pub fn of(hardening: &'a HardeningReport) -> Option<Self> {
        let complete = hardening.core_dumps == CoreDumps::Disabled && hardening.memory == MemoryProtection::Locked;
        (!complete).then_some(Self { hardening })
    }

    /// One fixed phrase per missing protection, in a fixed order.
    fn remediation(&self) -> String {
        let core = (self.hardening.core_dumps != CoreDumps::Disabled)
            .then_some("core dumps are not disabled, so a crash could write secrets to disk: run the service where it may set RLIMIT_CORE");
        let memory = match self.hardening.memory {
            MemoryProtection::Locked => None,
            MemoryProtection::Unavailable(_) => Some(format!(
                "swap protection is not in effect: {MEMLOCK_REMEDIATION}, or use encrypted swap as the install guide describes"
            )),
            MemoryProtection::Unsupported => {
                Some("swap protection is not in effect: use encrypted swap as the install guide describes".to_owned())
            }
        };
        [core.map(str::to_owned), memory]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join("; ")
    }
}

impl AuditEvent for HardeningIncomplete<'_> {
    const NAME: EventName = EventName("service.hardening-incomplete");

    fn emit(&self) {
        tracing::error!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            core_dumps = core_dumps_label(&self.hardening.core_dumps),
            memory_protection = memory_label(&self.hardening.memory),
            remediation = self.remediation().as_str(),
            "process hardening is incomplete",
        );
    }
}

/// `service.log-destination-changed`: an activated config moved the log. It is written to the old destination and again
/// as the new one's first record, so each says where the log went or came from.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
pub struct LogDestinationChanged {
    /// Where records go from now on.
    pub destination: LogDestination,
    /// Where they went before.
    pub previous: LogDestination,
    /// The approval version whose config moved the log.
    pub version: ApprovalVersion,
}

#[cfg(target_os = "linux")]
impl AuditEvent for LogDestinationChanged {
    const NAME: EventName = EventName("service.log-destination-changed");

    fn emit(&self) {
        tracing::info!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            log_destination = self.destination.to_string().as_str(),
            previous_log_destination = self.previous.to_string().as_str(),
            version = self.version.get(),
            "log destination changed",
        );
    }
}

/// `service.lock-transition` (glossary: *Lock transition*): it names the two states only, and nothing an unlock was
/// given.
#[derive(Debug, Clone, Copy)]
pub struct LockTransition {
    /// The state left.
    pub from: ServiceState,
    /// The state entered.
    pub to: ServiceState,
}

impl AuditEvent for LockTransition {
    const NAME: EventName = EventName("service.lock-transition");

    fn emit(&self) {
        tracing::info!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            from_state = state_label(self.from),
            to_state = state_label(self.to),
            unavailable_reason = state_unavailable(self.to).map(unavailable_label),
            "lock transition",
        );
    }
}

/// `config.approval-completed`: the commit is durable.
#[derive(Debug, Clone, Copy)]
pub struct ApprovalCompleted<'a> {
    /// The committed version.
    pub version: ApprovalVersion,
    /// The approved config's digest.
    pub digest: ConfigDigest,
    /// The approval summary the owner confirmed, rendered; its configured names are already escaped. Init's version 1
    /// has no summary but `initial config`.
    pub summary: &'a str,
    /// The approver that signed the version.
    pub approver: NamedApprover<'a>,
}

impl AuditEvent for ApprovalCompleted<'_> {
    const NAME: EventName = EventName("config.approval-completed");

    fn emit(&self) {
        tracing::info!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            version = self.version.get(),
            config_digest = self.digest.to_string().as_str(),
            summary = self.summary,
            approver_id = self.approver.id_text().as_str(),
            approver_label = self.approver.label_text().as_str(),
            "config approval completed",
        );
    }
}

/// `config.approval-refused`: the approval passphrase was wrong or the key is not the asked approver's; nothing was reserved.
// Its refusal is the service context's, and only the service context's approval emits it.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy)]
pub struct ApprovalRefused<'a> {
    /// Which check of the approver key refused.
    pub refusal: DenialKind,
    /// The digest of the config that was being approved.
    pub digest: ConfigDigest,
    /// The approver that was asked.
    pub approver: NamedApprover<'a>,
}

#[cfg(target_os = "linux")]
impl AuditEvent for ApprovalRefused<'_> {
    const NAME: EventName = EventName("config.approval-refused");

    fn emit(&self) {
        tracing::warn!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            refusal = self.refusal.label(),
            config_digest = self.digest.to_string().as_str(),
            approver_id = self.approver.id_text().as_str(),
            approver_label = self.approver.label_text().as_str(),
            "config approval refused; nothing was reserved",
        );
    }
}

/// `config.approval-failed`: the transaction failed after reserving `version`, which is consumed.
#[derive(Debug, Clone, Copy)]
pub struct ApprovalFailed<'a> {
    /// The consumed version.
    pub version: ApprovalVersion,
    /// The digest of the config that was being approved.
    pub digest: ConfigDigest,
    /// The failure, recorded by its step and its cause's kind only.
    pub error: &'a ApprovalError,
}

impl AuditEvent for ApprovalFailed<'_> {
    const NAME: EventName = EventName("config.approval-failed");

    fn emit(&self) {
        tracing::warn!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            version = self.version.get(),
            config_digest = self.digest.to_string().as_str(),
            step = step_label(self.error.step()),
            error_kind = approval_failure_label(self.error.cause()),
            "config approval failed after its reservation",
        );
    }
}

/// Why a committed approval is not active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationCause {
    /// The config check after the commit failed; its own `config.check-failed` record says why.
    CheckFailed,
    /// The commit's directory fsync failed and the write that settles it failed too.
    CommitUnsettled,
}

impl ActivationCause {
    const fn detail(self) -> &'static str {
        match self {
            Self::CheckFailed => "the config check after the commit failed; see config.check-failed",
            Self::CommitUnsettled => "the commit may not survive power loss and could not be settled",
        }
    }
}

/// `config.activation-failed`: `version` is committed but not active; the service settled in `state`.
#[derive(Debug, Clone, Copy)]
pub struct ActivationFailed {
    /// The committed version.
    pub version: ApprovalVersion,
    /// The state the service settled in; its unavailable reason is recorded when it has one.
    pub state: ServiceState,
    /// Why the version is not active.
    pub cause: ActivationCause,
}

impl AuditEvent for ActivationFailed {
    const NAME: EventName = EventName("config.activation-failed");

    fn emit(&self) {
        tracing::warn!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            version = self.version.get(),
            unavailable_reason = state_unavailable(self.state).map(unavailable_label),
            detail = self.cause.detail(),
            "the approved config is not active",
        );
    }
}

/// `config.check-failed`: a config check failed, whatever started it.
#[derive(Debug, Clone, Copy)]
pub struct CheckFailed<'a> {
    /// The failure; its detail names versions, routes and credentials only.
    pub failure: &'a CheckFailure,
}

impl AuditEvent for CheckFailed<'_> {
    const NAME: EventName = EventName("config.check-failed");

    fn emit(&self) {
        tracing::warn!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            unavailable_reason = unavailable_label(self.failure.unavailable()),
            failure = check_failure_label(self.failure),
            detail = self.failure.detail().as_str(),
            log_destination = self.failure.log_destination(),
            "the config check failed",
        );
    }
}

/// `config.reload-failed`: the config check of a SIGHUP reload failed, so the service stops proxying.
#[derive(Debug, Clone, Copy)]
pub struct ReloadFailed<'a> {
    /// The version committed before the reload, left out when none was.
    pub committed: Option<ApprovalVersion>,
    /// The check's failure.
    pub failure: &'a CheckFailure,
}

impl AuditEvent for ReloadFailed<'_> {
    const NAME: EventName = EventName("config.reload-failed");

    fn emit(&self) {
        tracing::warn!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            committed_version = self.committed.map(ApprovalVersion::get),
            unavailable_reason = unavailable_label(self.failure.unavailable()),
            detail = self.failure.detail().as_str(),
            "the reload failed, the service stops proxying",
        );
    }
}

const fn core_dumps_label(core_dumps: &CoreDumps) -> &'static str {
    match core_dumps {
        CoreDumps::Disabled => "disabled",
        CoreDumps::Failed(_) => "not_disabled",
    }
}

/// The memory protection status as the fixed `memory_protection` label.
pub(crate) const fn memory_label(memory: &MemoryProtection) -> &'static str {
    match memory {
        MemoryProtection::Locked => "locked",
        MemoryProtection::Unavailable(_) => "unavailable",
        MemoryProtection::Unsupported => "unsupported",
    }
}

const fn state_label(state: ServiceState) -> &'static str {
    match state {
        ServiceState::Starting => "starting",
        ServiceState::Locked => "locked",
        ServiceState::Checking => "checking",
        ServiceState::Ready => "ready",
        ServiceState::Unavailable(_) => "unavailable",
        ServiceState::Stopped => "stopped",
    }
}

const fn state_unavailable(state: ServiceState) -> Option<UnavailableReason> {
    match state {
        ServiceState::Unavailable(reason) => Some(UnavailableReason::from_failure(reason)),
        _ => None,
    }
}

/// The log's spelling of an unavailable reason; a `503` body spells it with a space.
const fn unavailable_label(reason: UnavailableReason) -> &'static str {
    match reason {
        UnavailableReason::Locked => "locked",
        UnavailableReason::PolicyInvalid => "policy_invalid",
        UnavailableReason::Checking => "checking",
        UnavailableReason::RecoveryNeeded => "recovery_needed",
    }
}

const fn check_failure_label(failure: &CheckFailure) -> &'static str {
    match failure {
        CheckFailure::Vault(_) => "vault_damaged",
        CheckFailure::ApprovalState(_) => "approval_state_damaged",
        CheckFailure::Recovery(_) => "recovery_refused",
        CheckFailure::Config(InvalidConfig::LogDestination(_)) => "log_destination_unusable",
        CheckFailure::Config(_) => "config_invalid",
        CheckFailure::Interrupted => "check_interrupted",
    }
}

const fn step_label(step: ApprovalStep) -> &'static str {
    match step {
        ApprovalStep::WritePending => "write_pending",
        ApprovalStep::Reserve => "reserve",
        ApprovalStep::Sign => "sign",
        ApprovalStep::Stage => "stage",
        ApprovalStep::Commit => "commit",
        ApprovalStep::Publish => "publish",
    }
}

/// The failure's variant: a domain error kind, so none of the text it wraps reaches the record.
const fn approval_failure_label(failure: &ApprovalFailure) -> &'static str {
    match failure {
        ApprovalFailure::ConfigDir(_) => "config_dir_write",
        ApprovalFailure::ReadBack(_) => "config_read_back",
        ApprovalFailure::State(_) => "approval_state",
        ApprovalFailure::Sign(_) => "sign",
        ApprovalFailure::BadApproval(_) => "bad_approval",
        ApprovalFailure::WrongVersion => "wrong_version",
    }
}
