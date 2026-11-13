// SPDX-License-Identifier: MPL-2.0
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use iron_vault_policy::{CallerName, CredentialName, ParsedConfig, RouteName, ValidatedConfig, summarize};
use tracing_subscriber::layer::{Context, SubscriberExt};

use super::*;
use crate::config_check::InvalidConfig;
use crate::deployment::DeploymentProfile;
use crate::hardening::LockUnavailable;
use crate::logging::LogDestination;
use crate::logging::tests::{capture, capture_as, parse};
use crate::service_state::FailureReason;
use crate::upstream::client::ClientBuildError;
use crate::upstream::trust::ClientConfigError;

/// Keys every record has besides an event's own fields.
pub(super) const RECORD_KEYS: [&str; 5] = ["timestamp", "level", "target", "message", "event"];

const CONFIG: &str = r#"schema_version = 1

[listeners.local]
unix_socket = "/run/iron-vault/proxy.sock"

[callers.agent]
listener = "local"
token_hash = "blake2b:0123456789abcdef00112233445566778899aabbccddeeff0f1e2d3c4b5a6978"
routes = ["fx"]

[routes.fx]
prefix = "/fx"
upstream = "https://api.example/v1"
credential = "fx-key"
slot = { header = "X-Api-Key" }
methods = ["GET"]
paths = ["/**"]
rate_limit = { requests = 60, per_seconds = 60, burst = 10 }
"#;

fn version(value: u64) -> ApprovalVersion {
    ApprovalVersion::new(value).unwrap()
}

fn hardened() -> HardeningReport {
    HardeningReport {
        core_dumps: CoreDumps::Disabled,
        memory: MemoryProtection::Locked,
    }
}

fn unhardened() -> HardeningReport {
    HardeningReport {
        core_dumps: CoreDumps::Failed("prctl: Operation not permitted /proc/self".to_owned()),
        memory: MemoryProtection::Unavailable(LockUnavailable::LimitTooLow { limit_bytes: 65_536 }),
    }
}

fn policy_invalid() -> CheckFailure {
    let error = ParsedConfig::from_toml(b"not = [toml").unwrap_err();
    CheckFailure::Config(InvalidConfig::Parse(error))
}

/// The one record `event` writes, checked for its name, its level, the audit target and exactly `fields`.
pub(super) fn record_of(event: impl AuditEvent, level: &str, fields: &[&str]) -> serde_json::Value {
    let out = capture(|| event.emit());
    assert_eq!(out.lines().count(), 1, "{out}");
    let record = parse(&out);
    assert_eq!(record["event"], impl_name(&event), "{out}");
    assert_eq!(record["level"], level, "{out}");
    assert_eq!(record["target"], AUDIT_TARGET, "{out}");
    let own: BTreeSet<&str> = record
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .filter(|key| !RECORD_KEYS.contains(key) && !CONSTANT_FIELDS.contains(key))
        .collect();
    assert_eq!(own, fields.iter().copied().collect(), "{out}");
    record
}

/// The approver ID the approver records name in these tests.
pub(super) const APPROVER_ID: &str = "0b7c4e8a-5d2f-4c1e-9a3b-6f8d2e1c7a90";

/// An approver whose label holds U+202E, which its records must escape.
pub(super) fn approver() -> NamedApprover<'static> {
    let bytes = [
        0x0b, 0x7c, 0x4e, 0x8a, 0x5d, 0x2f, 0x4c, 0x1e, 0x9a, 0x3b, 0x6f, 0x8d, 0x2e, 0x1c, 0x7a, 0x90,
    ];
    NamedApprover {
        id: ApproverId::from_bytes(bytes).unwrap(),
        label: "Dave\u{202e}key",
    }
}

/// Asserts `record` names [`approver`], with its label escaped.
pub(super) fn assert_names_the_approver(record: &serde_json::Value) {
    assert_eq!(record["approver_id"], APPROVER_ID);
    assert_eq!(record["approver_label"], "Dave\\u{202e}key");
}

fn impl_name<E: AuditEvent>(_: &E) -> &'static str {
    E::NAME.as_str()
}

#[test]
fn service_started_records_the_hardening_outcome_as_labels() {
    let report = unhardened();
    let destination = LogDestination::Directory(PathBuf::from("/var/log/iron-vault"));
    let event = ServiceStarted {
        destination: &destination,
        hardening: &report,
    };
    let record = record_of(event, "INFO", &["log_destination", "core_dumps", "memory_protection"]);
    assert_eq!(record["log_destination"], "/var/log/iron-vault");
    assert_eq!(record["core_dumps"], "not_disabled");
    assert_eq!(record["memory_protection"], "unavailable");
    assert!(!record.to_string().contains("Operation not permitted"), "{record}");
}

#[test]
fn service_started_names_the_build_profile() {
    let report = hardened();
    let event = ServiceStarted {
        destination: &LogDestination::Stdout,
        hardening: &report,
    };
    let record = parse(&capture_as(DeploymentProfile::current(), || event.emit()));
    let expected = match (cfg!(feature = "dev-mode"), cfg!(feature = "container")) {
        (true, _) => "development",
        (false, true) => "container",
        (false, false) => "protected",
    };
    assert_eq!(record["deployment_profile"], expected);
    assert_eq!(record["log_destination"], "stdout");
}

#[test]
fn hardening_incomplete_names_the_fix_and_never_the_os_error() {
    let report = unhardened();
    let event = HardeningIncomplete::of(&report).unwrap();
    let record = record_of(event, "ERROR", &["core_dumps", "memory_protection", "remediation"]);
    let remediation = record["remediation"].as_str().unwrap();
    assert!(
        remediation.contains("LimitMEMLOCK=infinity") && remediation.contains("RLIMIT_CORE"),
        "{remediation}"
    );
    assert!(!record.to_string().contains("Operation not permitted"), "{record}");
}

#[test]
fn full_hardening_has_no_incomplete_event() {
    assert!(HardeningIncomplete::of(&hardened()).is_none());
}

#[test]
fn unsupported_memory_locking_is_incomplete_with_its_own_fix() {
    let report = HardeningReport {
        memory: MemoryProtection::Unsupported,
        ..hardened()
    };
    let record = record_of(
        HardeningIncomplete::of(&report).unwrap(),
        "ERROR",
        &["core_dumps", "memory_protection", "remediation"],
    );
    assert_eq!(record["memory_protection"], "unsupported");
    assert!(!record["remediation"].as_str().unwrap().contains("RLIMIT_CORE"), "{record}");
}

#[test]
fn lock_transition_names_states_as_labels() {
    let event = LockTransition {
        from: ServiceState::Locked,
        to: ServiceState::Checking,
    };
    let record = record_of(event, "INFO", &["from_state", "to_state"]);
    assert_eq!(
        (record["from_state"].as_str(), record["to_state"].as_str()),
        (Some("locked"), Some("checking"))
    );
}

#[test]
fn lock_transition_into_unavailable_names_the_reason() {
    let event = LockTransition {
        from: ServiceState::Checking,
        to: ServiceState::Unavailable(FailureReason::PolicyInvalid),
    };
    let record = record_of(event, "INFO", &["from_state", "to_state", "unavailable_reason"]);
    assert_eq!(record["to_state"], "unavailable");
    assert_eq!(record["unavailable_reason"], "policy_invalid");
}

#[test]
fn approval_completed_records_version_digest_summary_and_approver() {
    let config = ValidatedConfig::try_from(ParsedConfig::from_toml(CONFIG.as_bytes()).unwrap()).unwrap();
    let summary = summarize(None, &config);
    let digest = ConfigDigest::of(CONFIG.as_bytes());
    let event = ApprovalCompleted {
        version: version(3),
        digest,
        summary: &summary.render(),
        approver: approver(),
    };
    let record = record_of(
        event,
        "INFO",
        &["version", "config_digest", "summary", "approver_id", "approver_label"],
    );
    assert_eq!(record["version"], 3);
    assert_eq!(record["config_digest"], digest.to_string());
    assert_eq!(record["summary"], summary.render());
    assert_names_the_approver(&record);
}

#[test]
fn approval_refused_records_its_kind_the_digest_and_the_approver() {
    let digest = ConfigDigest::of(CONFIG.as_bytes());
    let event = ApprovalRefused {
        refusal: DenialKind::KeyMismatch,
        tpm_status: None,
        digest,
        approver: approver(),
    };
    let record = record_of(event, "WARN", &["refusal", "config_digest", "approver_id", "approver_label"]);
    assert_eq!(record["refusal"], "key_mismatch");
    assert_eq!(record["config_digest"], digest.to_string());
    assert_names_the_approver(&record);
}

#[test]
fn approval_refused_names_the_tpm_status_of_a_tpm_approver() {
    let event = ApprovalRefused {
        refusal: DenialKind::TpmRefused,
        tpm_status: Some(TpmStatus::LockedOut),
        digest: ConfigDigest::of(CONFIG.as_bytes()),
        approver: approver(),
    };
    let record = record_of(
        event,
        "WARN",
        &["refusal", "tpm_status", "config_digest", "approver_id", "approver_label"],
    );
    assert_eq!(
        (record["refusal"].as_str(), record["tpm_status"].as_str()),
        (Some("tpm_refused"), Some("locked_out"))
    );
}

#[test]
fn activation_failed_records_a_fixed_detail() {
    let event = ActivationFailed {
        version: version(4),
        state: ServiceState::Unavailable(FailureReason::RecoveryNeeded),
        cause: ActivationCause::CommitUnsettled,
    };
    let record = record_of(event, "WARN", &["version", "unavailable_reason", "detail"]);
    assert_eq!(record["version"], 4);
    assert_eq!(record["unavailable_reason"], "recovery_needed");
}

#[test]
fn activation_failed_outside_unavailable_leaves_the_reason_out() {
    let event = ActivationFailed {
        version: version(4),
        state: ServiceState::Checking,
        cause: ActivationCause::CheckFailed,
    };
    record_of(event, "WARN", &["version", "detail"]);
}

#[test]
fn check_failed_records_its_failure_label_and_never_config_bytes() {
    let failure = policy_invalid();
    let record = record_of(
        CheckFailed { failure: &failure },
        "WARN",
        &["unavailable_reason", "failure", "detail"],
    );
    assert_eq!(record["unavailable_reason"], "policy_invalid");
    assert_eq!(record["failure"], "config_invalid");
    assert!(!record.to_string().contains("toml"), "{record}");
}

#[test]
fn log_destination_changed_names_both_destinations_and_the_version() {
    let event = LogDestinationChanged {
        destination: LogDestination::Directory(PathBuf::from("/srv/iron-vault/log")),
        previous: LogDestination::Stdout,
        version: version(3),
    };
    let record = record_of(event, "INFO", &["log_destination", "previous_log_destination", "version"]);
    assert_eq!(record["log_destination"], "/srv/iron-vault/log");
    assert_eq!(record["previous_log_destination"], "stdout");
    assert_eq!(record["version"], 3);
}

#[test]
fn check_failed_for_an_unusable_log_destination_names_it_beside_a_fixed_detail() {
    let failure = CheckFailure::Config(InvalidConfig::LogDestination(crate::config_check::UnusableLog {
        destination: "/srv/iron-vault/log".to_owned(),
        phrase: "the log directory does not exist".to_owned(),
    }));
    let record = record_of(
        CheckFailed { failure: &failure },
        "WARN",
        &["unavailable_reason", "failure", "detail", "log_destination"],
    );
    assert_eq!(record["unavailable_reason"], "policy_invalid");
    assert_eq!(record["failure"], "log_destination_unusable");
    assert_eq!(record["detail"], "the log directory does not exist");
    assert_eq!(record["log_destination"], "/srv/iron-vault/log");
}

/// `detail` is the one field built from a `ClientBuildError`'s text; no rustls diagnostic may reach it.
#[test]
fn check_failed_for_an_invalid_client_config_holds_no_library_text() {
    let library_text = "distinctive-rustls-text";
    let build = ClientBuildError::from(ClientConfigError::ProtocolVersions(rustls::Error::General(library_text.to_owned())));
    let failure = CheckFailure::Config(InvalidConfig::Clients(build));
    let record = record_of(
        CheckFailed { failure: &failure },
        "WARN",
        &["unavailable_reason", "failure", "detail"],
    );
    assert_eq!(record["failure"], "config_invalid");
    assert!(record["detail"].as_str().is_some_and(|detail| !detail.is_empty()), "{record}");
    assert!(!record.to_string().contains(library_text), "{record}");
}

#[test]
fn reload_failed_records_the_committed_version_as_a_number() {
    let failure = CheckFailure::Interrupted;
    let event = ReloadFailed {
        committed: Some(version(7)),
        failure: &failure,
    };
    let record = record_of(event, "WARN", &["committed_version", "unavailable_reason", "detail"]);
    assert_eq!(record["committed_version"], 7);
    assert_eq!(record["unavailable_reason"], "recovery_needed");
}

#[test]
fn reload_failed_with_nothing_committed_leaves_the_version_out() {
    let failure = CheckFailure::Interrupted;
    let event = ReloadFailed {
        committed: None,
        failure: &failure,
    };
    record_of(event, "WARN", &["unavailable_reason", "detail"]);
}

/// Configured names reject control and non-ASCII characters on construction, so no name an audit event records can
/// hold one; JSON escapes the rest.
#[test]
fn a_name_with_a_control_character_or_bidi_override_cannot_be_built() {
    ["fx\u{202e}", "fx\u{7}", "fx\n"].iter().for_each(|raw| {
        assert!(RouteName::try_from(*raw).is_err(), "{raw:?}");
        assert!(CallerName::try_from(*raw).is_err(), "{raw:?}");
        assert!(CredentialName::try_from(*raw).is_err(), "{raw:?}");
    });
}

/// The field names of every audit event seen, from its callsite metadata, so a name recorded twice is still seen once
/// per callsite (the JSON parse would keep only one of two duplicate keys).
#[derive(Clone, Default)]
struct FieldNames(Arc<Mutex<Vec<String>>>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for FieldNames {
    fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
        if [AUDIT_TARGET, REQUEST_TARGET].contains(&event.metadata().target()) {
            let names = event.metadata().fields().iter().map(|field| field.name().to_owned());
            self.0.lock().unwrap().extend(names);
        }
    }
}

/// Writes `request.completed` with every fact set, by dropping its record, with `response.scrubbed` beside it, and
/// `request.defect`. Their types are private to the request module, so they are reached through the record and its facts.
fn emit_request_events() {
    let mut record = RequestRecord::new("local".parse().unwrap(), "GET", crate::connection_tags::ServiceClose::default());
    let facts = record.facts();
    facts.caller(&"agent".parse().unwrap());
    facts.route(&"fx".parse().unwrap(), &"fx-key".parse().unwrap(), &"api.example".parse().unwrap());
    facts.scrub_matches(1);
    facts.report_defect("host");
    facts.refuse(ReasonCode::ServiceDefect);
    record.answered(500);
    record.sent(1);
}

// `ApprovalFailed` is absent because an `ApprovalError` can only be built inside the store crate. Its fields are version,
// config_digest, step and error_kind; `credentials::config_approve` pins its exact key set on a real failed approval.
#[test]
fn no_audit_event_records_a_constant_field() {
    let names = FieldNames::default();
    let (unhardened, failure) = (unhardened(), CheckFailure::Interrupted);
    let config = ValidatedConfig::try_from(ParsedConfig::from_toml(CONFIG.as_bytes()).unwrap()).unwrap();
    let summary = summarize(None, &config);
    tracing::subscriber::with_default(tracing_subscriber::registry().with(names.clone()), || {
        ServiceStarted {
            destination: &LogDestination::Stdout,
            hardening: &unhardened,
        }
        .emit();
        HardeningIncomplete::of(&unhardened).into_iter().for_each(|event| event.emit());
        LogDestinationChanged {
            destination: LogDestination::Stdout,
            previous: LogDestination::Directory(PathBuf::from("/var/log/iron-vault")),
            version: version(2),
        }
        .emit();
        LockTransition {
            from: ServiceState::Ready,
            to: ServiceState::Locked,
        }
        .emit();
        ApprovalCompleted {
            version: version(1),
            digest: ConfigDigest::of(b""),
            summary: &summary.render(),
            approver: approver(),
        }
        .emit();
        ApprovalRefused {
            refusal: DenialKind::WrongPassphrase,
            tpm_status: None,
            digest: ConfigDigest::of(b""),
            approver: approver(),
        }
        .emit();
        ActivationFailed {
            version: version(1),
            state: ServiceState::Ready,
            cause: ActivationCause::CheckFailed,
        }
        .emit();
        CheckFailed { failure: &failure }.emit();
        ReloadFailed {
            committed: None,
            failure: &failure,
        }
        .emit();
        super::vault_events_tests::emit_every_event();
        super::config_events_tests::emit_every_event();
        emit_request_events();
    });
    let seen = names.0.lock().unwrap().clone();
    assert!(seen.iter().any(|name| name == "event"), "{seen:?}");
    // A field only one of the three request-side events records was seen for each, so each of them was emitted:
    // `reason` and `scrubbed` are the request event's, `defect` the defect event's and `matches` the scrub event's.
    ["reason", "scrubbed", "defect", "matches"]
        .iter()
        .for_each(|own| assert!(seen.iter().any(|name| name == own), "{own} in {seen:?}"));
    CONSTANT_FIELDS
        .iter()
        .for_each(|constant| assert!(!seen.iter().any(|name| name == constant), "{constant} in {seen:?}"));
}

#[test]
fn event_names_have_the_subject_dot_kebab_form() {
    [
        ServiceStarted::NAME,
        HardeningIncomplete::NAME,
        LogDestinationChanged::NAME,
        LockTransition::NAME,
        ApprovalCompleted::NAME,
        ApprovalRefused::NAME,
        ApprovalFailed::NAME,
        ActivationFailed::NAME,
        CheckFailed::NAME,
        ReloadFailed::NAME,
    ]
    .iter()
    .chain(super::vault_events_tests::NAMES.iter())
    .chain(super::config_events_tests::NAMES.iter())
    .for_each(|name| {
        let (subject, rest) = name.as_str().split_once('.').unwrap();
        assert!(!subject.is_empty() && subject.chars().all(|c| c.is_ascii_lowercase()), "{name:?}");
        assert!(
            rest.split('-')
                .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_lowercase())),
            "{name:?}"
        );
    });
}
