//! The vault, credential, caller, route and response events: each writes its name, level and exactly its own fields.

use std::collections::BTreeSet;

use iron_vault_policy::{CredentialName, Host, Port, RouteName};
use iron_vault_store::{ErrorKindLabel, InitFailure, InitStep, RecordId, StateFileName, UnlockError, VaultId};

use super::credential::*;
use super::route::*;
use super::vault::*;
use super::{AUDIT_TARGET, AuditEvent, CONSTANT_FIELDS};
use crate::logging::tests::{capture, parse};
use crate::service_context::UnlockRefusal;

const RECORD_KEYS: [&str; 5] = ["timestamp", "level", "target", "message", "event"];

/// The one record `event` writes, checked for its name, level, audit target and exactly `fields`.
fn record_of<E: AuditEvent>(event: E, level: &str, fields: &[&str]) -> serde_json::Value {
    let out = capture(|| event.emit());
    assert_eq!(out.lines().count(), 1, "{out}");
    let record = parse(&out);
    assert_eq!(
        (record["event"].as_str(), record["level"].as_str()),
        (Some(E::NAME.as_str()), Some(level)),
        "{out}"
    );
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

fn credential() -> CredentialName {
    "fx-key".parse().unwrap()
}

fn origins() -> Vec<(Host, Port)> {
    vec![("api.example".parse().unwrap(), "443".parse().unwrap())]
}

#[test]
fn initialization_events_carry_ids_step_labels_and_kinds_only() {
    let id = VaultId::new_random();
    assert_eq!(
        record_of(VaultInitialized { vault_id: id }, "INFO", &["vault_id"])["vault_id"],
        id.to_string().as_str()
    );
    let files = ["init.unfinished".to_owned(), "identity.age".to_owned()];
    assert_eq!(
        record_of(InitDiscarded { files: &files }, "WARN", &["files"])["files"],
        "init.unfinished,identity.age"
    );
    let failed = InitFailed::Step {
        step: InitStep::PassphraseEnvelope,
        cause: &InitFailure::IdentityMismatch,
    };
    let record = record_of(failed, "WARN", &["step", "error_kind"]);
    assert_eq!(
        (record["step"].as_str(), record["error_kind"].as_str()),
        (Some("3"), Some("identity_mismatch"))
    );
    assert_eq!(record_of(InitFailed::TaskEnded, "WARN", &["step"])["step"], "unknown");
}

#[test]
fn a_foreign_file_name_is_escaped() {
    let record = record_of(ForeignFile { file: "a\u{202e}b\n.txt" }, "WARN", &["file"]);
    assert_eq!(record["file"], "a\\u{202e}b\\n.txt");
}

#[test]
fn an_unlock_refusal_is_a_snake_case_label() {
    let wrong = UnlockRefusal::Failed(UnlockError::WrongPassphrase);
    assert_eq!(
        record_of(UnlockRefused { refusal: &wrong }, "WARN", &["refusal"])["refusal"],
        "wrong_passphrase"
    );
    let unfinished = UnlockRefusal::Failed(UnlockError::InitializationUnfinished);
    assert_eq!(
        record_of(UnlockRefused { refusal: &unfinished }, "WARN", &["refusal"])["refusal"],
        "initialization_unfinished"
    );
}

#[test]
fn an_incomplete_lock_records_numbers_and_a_boolean() {
    let record = record_of(
        LockIncomplete {
            snapshots_held: 2,
            identity_held: true,
        },
        "WARN",
        &["snapshots_held", "identity_held"],
    );
    assert_eq!(
        (record["snapshots_held"].as_u64(), record["identity_held"].as_bool()),
        (Some(2), Some(true))
    );
}

#[test]
fn write_report_events_name_files_and_a_kind() {
    let file = StateFileName::record(&RecordId::new_random());
    let record = record_of(UnindexedRemoved { file: &file }, "WARN", &["file"]);
    assert_eq!(record["file"], file.as_str());
    let kind = ErrorKindLabel::fixed("permission_denied");
    let record = record_of(
        SupersededLeft {
            file: &file,
            error_kind: &kind,
        },
        "WARN",
        &["file", "error_kind"],
    );
    assert_eq!(record["error_kind"], "permission_denied");
}

#[test]
fn credential_events_record_names_ids_kinds_and_origins() {
    let (name, id, old_id) = (credential(), RecordId::new_random(), RecordId::new_random());
    let origins = origins();
    let stored = Stored {
        kind: "static",
        origins: &origins,
    };
    let record = record_of(
        CredentialAdded {
            credential: &name,
            record_id: id,
            stored,
        },
        "INFO",
        &["credential", "record_id", "kind", "origins"],
    );
    assert_eq!(
        (record["kind"].as_str(), record["origins"].as_str()),
        (Some("static"), Some("https://api.example:443"))
    );
    let replaced = |old| CredentialReplaced {
        credential: &name,
        old_record_id: old_id,
        record_id: id,
        stored,
        old,
    };
    let fields = ["credential", "old_record_id", "record_id", "kind", "origins"];
    record_of(replaced(None), "INFO", &fields);
    let healthy = record_of(
        replaced(Some(Stored { kind: "basic", ..stored })),
        "INFO",
        &[&fields[..], &["old_kind", "old_origins"]].concat(),
    );
    assert_eq!(healthy["old_kind"], "basic");
    record_of(
        CredentialRemoved {
            credential: &name,
            record_id: id,
        },
        "INFO",
        &["credential", "record_id"],
    );
}

#[test]
fn caller_token_events_hold_no_token() {
    record_of(TokenIssued, "INFO", &[]);
    let kind = ErrorKindLabel::fixed("random_source");
    assert_eq!(
        record_of(TokenFailed { error_kind: &kind }, "ERROR", &["error_kind"])["error_kind"],
        "random_source"
    );
}

#[test]
fn route_and_scrub_events_name_the_route_and_never_a_path_or_byte() {
    let route: RouteName = "fx".parse().unwrap();
    let record = record_of(PinnedCaUnavailable { route: &route }, "WARN", &["route", "config_field"]);
    assert_eq!(record["config_field"], "ca_file");
    let name = credential();
    let record = record_of(
        ResponseScrubbed {
            route: &route,
            credential: &name,
            matches: 4,
        },
        "WARN",
        &["route", "credential", "matches"],
    );
    assert_eq!(record["matches"].as_u64(), Some(4));
}
