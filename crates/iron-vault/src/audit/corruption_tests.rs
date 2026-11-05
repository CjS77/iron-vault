//! The corruption events, the short-secret and commit-uncertain events: exact field sets, and the open that emits them.

use std::collections::BTreeMap;

use iron_vault_kinds::{CredentialMaterial, SecretField};
use iron_vault_store::{
    DamagedRecord, ErrorKindLabel, OsFs, PermittedOrigins, RecordDamage, RecordId, SharedStateDamage, StateDirLock, StateFileName, Vault,
    VaultError, VaultIdentity, WriteError, WriteStep,
};

use super::corruption::*;
use super::credential::ShortSecretWritten;
use super::tests::record_of;
use super::vault::{CommitUncertain, emit_commit_uncertain};
use crate::logging::tests::{capture, parse};
use crate::serving_snapshot::tests::Scratch;

const SECRET: &str = "sk-live-never-in-a-log-9f3a";

fn damaged(error_kind: Option<ErrorKindLabel>) -> DamagedRecord {
    DamagedRecord {
        credential: "fx-key".parse().unwrap(),
        record_id: RecordId::new_random(),
        file: StateFileName::record(&RecordId::new_random()),
        damage: RecordDamage::Unreadable,
        error_kind,
    }
}

#[test]
fn a_damaged_record_carries_its_facts_and_a_kind_only_when_a_read_failed() {
    let kind = ErrorKindLabel::fixed("too_large");
    let fields = ["credential", "record_id", "file", "damage", "remediation"];
    let (with, without) = (damaged(Some(kind)), damaged(None));
    let record = record_of(RecordDamaged { record: &with }, "ERROR", &[&fields[..], &["error_kind"]].concat());
    assert_eq!(
        (record["damage"].as_str(), record["error_kind"].as_str()),
        (Some("unreadable"), Some("too_large"))
    );
    assert_eq!(record["record_id"], with.record_id.to_string().as_str());
    record_of(RecordDamaged { record: &without }, "ERROR", &fields);
}

#[test]
fn the_other_open_events_carry_their_own_fields_only() {
    let file = StateFileName::record(&RecordId::new_random());
    record_of(UnindexedFile { file: &file }, "WARN", &["file", "remediation"]);
    record_of(ApprovalStateUnrecorded, "WARN", &["remediation"]);
    let damage = SharedStateDamage::MissingWithApprovalState;
    let record = record_of(
        SharedStateDamaged {
            file: &StateFileName::manifest(),
            damage: &damage,
        },
        "ERROR",
        &["file", "damage", "remediation"],
    );
    assert_eq!(record["damage"], "missing_with_approval_state");
    let kind = ErrorKindLabel::fixed("permission_denied");
    record_of(StateDirUnreadable { error_kind: &kind }, "ERROR", &["error_kind", "remediation"]);
}

#[test]
fn write_events_carry_field_and_length_or_file_and_kind() {
    let name = "stripe".parse().unwrap();
    let short = ShortSecretWritten {
        credential: &name,
        field: SecretField::Password,
        len: 3,
    };
    let record = record_of(short, "WARN", &["credential", "secret_field", "len"]);
    assert_eq!(
        (record["secret_field"].as_str(), record["len"].as_u64()),
        (Some("password"), Some(3))
    );
    let kind = ErrorKindLabel::fixed("storage_full");
    let uncertain = CommitUncertain {
        file: &StateFileName::manifest(),
        error_kind: &kind,
    };
    let record = record_of(uncertain, "ERROR", &["file", "error_kind"]);
    assert_eq!(
        (record["file"].as_str(), record["error_kind"].as_str()),
        (Some("manifest.age"), Some("storage_full"))
    );
}

#[test]
fn an_uncertain_commit_is_emitted_also_inside_an_unrecorded_approval_state() {
    let io = WriteError::Io {
        step: WriteStep::SyncDir,
        file: StateFileName::manifest(),
        kind: std::io::ErrorKind::StorageFull,
    };
    let uncertain = VaultError::CommitUncertain(io);
    let wrapped = VaultError::ApprovalStateUnrecorded(Box::new(uncertain.clone()));
    let events = |error: &VaultError| capture(|| emit_commit_uncertain(error));
    assert_eq!(events(&uncertain).lines().count(), 1);
    assert_eq!(events(&wrapped).lines().count(), 1);
    assert_eq!(events(&VaultError::ReopenRequired), "");
}

fn identity() -> VaultIdentity {
    VaultIdentity::from_secret("AGE-SECRET-KEY-1QYPQXPQ9QCRSSZG2PVXQ6RS0ZQG3YYC5Z5TPWXQERGD3C8G7RUSQGPQYEE")
}

/// A vault with a healthy record, a deleted one, one whose file is replaced, and a planted record file.
fn damaged_vault(scratch: &Scratch) -> (StateDirLock, BTreeMap<&'static str, RecordId>) {
    let lock = StateDirLock::acquire(&scratch.0).unwrap();
    let mut vault = Vault::create(&lock, &OsFs, identity()).unwrap();
    let origins = || PermittedOrigins::new([("api.example".parse().unwrap(), "443".parse().unwrap())].into()).unwrap();
    let ids: BTreeMap<_, _> = ["good", "gone", "flipped"]
        .into_iter()
        .map(|name| {
            let material = CredentialMaterial::Static {
                key: SECRET.to_owned().into(),
            };
            (name, vault.add(&lock, &OsFs, name.parse().unwrap(), material, origins()).unwrap().0)
        })
        .collect();
    std::fs::remove_file(scratch.0.join(StateFileName::record(&ids["gone"]).as_str())).unwrap();
    std::fs::write(scratch.0.join(StateFileName::record(&ids["flipped"]).as_str()), b"not the file").unwrap();
    let planted = StateFileName::record(&RecordId::new_random());
    std::fs::write(scratch.0.join(planted.as_str()), SECRET).unwrap();
    (lock, ids)
}

#[test]
fn opening_a_damaged_vault_emits_one_event_per_fact_without_a_path_or_a_secret() {
    let scratch = Scratch::new();
    let (lock, ids) = damaged_vault(&scratch);
    let out = capture(|| assert!(open_vault(&lock, &OsFs, identity()).is_ok()));
    let records: Vec<_> = out.lines().map(parse).collect();
    let mut events: Vec<_> = records.iter().map(|r| r["event"].as_str().unwrap()).collect();
    events.sort_unstable();
    assert_eq!(
        events,
        ["vault.record-damaged", "vault.record-damaged", "vault.unindexed-file"],
        "{out}"
    );
    let damaged: BTreeMap<_, _> = records
        .iter()
        .filter(|r| r["event"] == "vault.record-damaged")
        .map(|r| (r["credential"].as_str().unwrap(), r))
        .collect();
    assert_eq!(damaged["gone"]["damage"], "missing");
    assert_eq!(damaged["flipped"]["damage"], "substituted");
    assert_eq!(damaged["gone"]["record_id"], ids["gone"].to_string().as_str());
    let keys = |r: &serde_json::Value| r.as_object().unwrap().keys().cloned().collect::<Vec<_>>();
    assert_eq!(keys(damaged["gone"]), keys(damaged["flipped"]));
    assert!(!out.contains(SECRET) && !out.contains(scratch.0.to_str().unwrap()), "{out}");
}

#[test]
fn a_vault_another_identity_cannot_open_is_refused_with_one_event() {
    let scratch = Scratch::new();
    let (lock, _) = damaged_vault(&scratch);
    let out = capture(|| assert!(open_vault(&lock, &OsFs, VaultIdentity::generate()).is_err()));
    let records: Vec<_> = out.lines().map(parse).collect();
    assert_eq!(records.len(), 1, "{out}");
    assert_eq!(
        (records[0]["event"].as_str(), records[0]["damage"].as_str()),
        (Some("vault.shared-state-damaged"), Some("manifest"))
    );
    assert!(!out.contains(scratch.0.to_str().unwrap()), "{out}");
}
