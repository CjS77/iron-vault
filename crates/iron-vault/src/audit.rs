//! Audit events: the typed records of administrative and security facts (specification §3.15;
//! `design/audit-logging.md`, "Audit events").
//!
//! Each event is a struct whose fields are domain types, and its [`AuditEvent::emit`] makes one `tracing` call under
//! [`AUDIT_TARGET`] with its event name, its level, a fixed message and exactly its own fields, each turned into a
//! `&str`, `u64` or `bool`. A header value, a URL or a library error's text therefore has no field to go into. Every
//! value from a fixed vocabulary is written as a snake_case label from this module, never as a type's `Debug` output.
//! The record's constant fields are the formatter's job ([`crate::logging::RecordFormat`]), so no event may use one of
//! [`CONSTANT_FIELDS`] as a field name.

// `service.started` names the log destination, which only Linux has.
#[cfg(test)]
mod corruption_tests;
#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests;
#[cfg(test)]
mod vault_events_tests;

pub mod admin;
pub mod corruption;
pub mod credential;
pub mod route;
pub mod vault;

mod request;
pub use request::{Ending, REQUEST_TARGET, ReasonCode, RequestFacts, RequestId, RequestRecord};

use iron_vault_policy::ApprovalSummary;
use iron_vault_store::{ApprovalError, ApprovalFailure, ApprovalStep, ApprovalVersion, ConfigDigest};

use crate::config_check::CheckFailure;
use crate::hardening::{CoreDumps, HardeningReport, MemoryProtection};
#[cfg(target_os = "linux")]
use crate::logging::LogDestination;
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

/// An event's stable name, `<subject>.<name>`, written in its `event` field. Renaming one changes the schema version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventName(&'static str);

impl EventName {
    /// The name as written in the record.
    pub const fn as_str(self) -> &'static str {
        self.0
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
            MemoryProtection::Unavailable(_) => Some(
                "swap protection is not in effect: run the service with LimitMEMLOCK=infinity, or use encrypted swap as the \
                 install guide describes",
            ),
            MemoryProtection::Unsupported => Some("swap protection is not in effect: use encrypted swap as the install guide describes"),
        };
        [core, memory].into_iter().flatten().collect::<Vec<_>>().join("; ")
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
    /// The approval summary the owner confirmed; its configured names are already escaped.
    pub summary: &'a ApprovalSummary,
}

impl AuditEvent for ApprovalCompleted<'_> {
    const NAME: EventName = EventName("config.approval-completed");

    fn emit(&self) {
        tracing::info!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            version = self.version.get(),
            config_digest = self.digest.to_string().as_str(),
            summary = self.summary.render().as_str(),
            "config approval completed",
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

const fn memory_label(memory: &MemoryProtection) -> &'static str {
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
