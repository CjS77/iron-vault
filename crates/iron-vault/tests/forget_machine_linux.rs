//! `forget-machine` end to end over a real admin socket against a running service context on an initialized vault
//! (`design/forget-machine.md`): a key that is still a recipient is not forgotten and nothing changes, a removed key with a
//! healthy recovery path is, an overdue recovery check or a broken independence rule is a fact in the result, and the
//! command spawns no process.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::fs;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use common::approval_harness::captured_logs;
use common::recipient_harness::{APPROVAL_PASSPHRASE, Fixture, exchange, init, list, listed, ready, refusal, unlock};
use iron_vault::admin::protocol::{AdminRequest, AdminResponse, ErrorCode, RecoveryStatus};
use iron_vault::service_context::ServiceContext;
use iron_vault_store::{
    RecipientEntry, RecipientIdentity, RecipientInventory, RecipientKey, RecipientLabel, RecipientRole, RecipientSet, RecoveryCheckRecord,
    RecoveryKey, UtcSecond, envelope_digest, open_recipient_inventory, seal_recipient_inventory, unwrap_identity, wrap_identity,
};
use secrecy::{ExposeSecret, SecretString};

fn at(seconds: u64) -> UtcSecond {
    UtcSecond::from_unix_seconds(seconds).unwrap()
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn write_record(fixture: &Fixture, last_checked: u64) {
    let record = RecoveryCheckRecord::new(at(last_checked), Some(at(last_checked))).unwrap();
    fs::write(fixture.path("state/recovery.toml"), record.encode()).unwrap();
}

/// A key no recipient inventory holds.
fn stranger() -> RecipientKey {
    RecoveryKey::generate().1
}

/// Rewrites `identity.age` and `recipients.age` for the entries `change` returns, with the service idle. Returns the identity of
/// the one `added` recipient that `change` appends, when it appends one.
fn rewrite(
    fixture: &Fixture,
    recovery_key: &str,
    change: impl FnOnce(Vec<RecipientEntry>, RecipientEntry) -> Vec<RecipientEntry>,
) -> RecipientIdentity {
    let recovery = RecipientIdentity::parse(&SecretString::from(recovery_key.to_owned())).unwrap();
    let vault = unwrap_identity(&fs::read(fixture.path("state/identity.age")).unwrap(), &recovery).unwrap();
    let current = open_recipient_inventory(&vault, &fs::read(fixture.path("state/recipients.age")).unwrap()).unwrap();
    let (secret, key) = RecoveryKey::generate();
    let added = RecipientEntry::new(
        key,
        RecipientRole::Added,
        RecipientLabel::new("old laptop").unwrap(),
        at(1_700_000_000),
    );
    let entries = change(current.entries().cloned().collect(), added);
    let keys = entries.iter().map(|entry| entry.key().clone());
    let envelope = wrap_identity(&vault, &RecipientSet::new(keys).unwrap()).unwrap();
    let inventory = RecipientInventory::new(current.vault_id(), envelope_digest(&envelope), entries).unwrap();
    fs::write(fixture.path("state/identity.age"), envelope).unwrap();
    fs::write(
        fixture.path("state/recipients.age"),
        seal_recipient_inventory(&vault, &inventory).unwrap(),
    )
    .unwrap();
    RecipientIdentity::parse(&SecretString::from(secret.expose_secret().to_owned())).unwrap()
}

/// Enrols a new `added` recipient and returns its key.
fn enrol_added(fixture: &Fixture, recovery_key: &str) -> RecipientKey {
    rewrite(fixture, recovery_key, |entries, added| entries.into_iter().chain([added]).collect()).recipient_key()
}

async fn forget(service: &Arc<ServiceContext>, key: &RecipientKey) -> AdminResponse {
    exchange(
        service,
        AdminRequest::ForgetMachine {
            recipient: key.to_string(),
        },
        &[],
    )
    .await
    .0
}

async fn remove(service: &Arc<ServiceContext>, key: &RecipientKey) {
    let request = AdminRequest::RecipientRemove {
        recipient: key.to_string(),
    };
    let (response, _) = exchange(service, request, &[APPROVAL_PASSPHRASE.as_bytes()]).await;
    assert!(matches!(response, AdminResponse::RecipientRemove { .. }), "{response:?}");
}

#[tokio::test]
async fn a_key_that_is_still_a_recipient_is_not_forgotten_and_nothing_changes() {
    let logs = captured_logs();
    let fixture = Fixture::new();
    let (service, recovery_key) = ready(&fixture).await;
    let laptop = enrol_added(&fixture, &recovery_key);
    let before = fixture.state_files();

    let (code, message) = refusal(forget(&service, &laptop).await);

    assert_eq!(code, ErrorCode::MachineNotForgotten);
    assert!(
        message.contains(&format!("run `iron-vault recipient remove {laptop}`")),
        "{message}"
    );
    assert!(message.contains("role added") && message.contains("label old laptop"), "{message}");
    assert_eq!(fixture.state_files(), before);
    assert!(logs.has_field("recipient.forget-checked", "forget_outcome", "still_enrolled"));
    assert!(logs.has_field("recipient.forget-checked", "recipient_role", "added"));
}

#[tokio::test]
async fn every_role_still_enrolled_is_not_forgotten() {
    let fixture = Fixture::new();
    let (service, _) = ready(&fixture).await;
    for entry in listed(list(&service).await) {
        let (code, message) = refusal(forget(&service, entry.key()).await);
        assert_eq!(code, ErrorCode::MachineNotForgotten);
        assert!(message.contains(entry.role().name()), "{message}");
    }
}

#[tokio::test]
async fn a_removed_key_with_a_healthy_recovery_path_is_forgotten() {
    let logs = captured_logs();
    let fixture = Fixture::new();
    let (service, recovery_key) = ready(&fixture).await;
    let laptop = enrol_added(&fixture, &recovery_key);
    remove(&service, &laptop).await;
    write_record(&fixture, now() - 3 * 86_400);
    let before = fixture.state_files();

    let response = forget(&service, &laptop).await;

    match response {
        AdminResponse::ForgetMachine { independence, recovery } => {
            assert_eq!(independence, None);
            assert!(
                matches!(recovery, RecoveryStatus::Checked { days: 3, due: false, .. }),
                "{recovery:?}"
            );
        }
        other => panic!("expected the result, got {other:?}"),
    }
    assert_eq!(fixture.state_files(), before, "a healthy check writes nothing");
    let recorded = logs.events("recipient.forget-checked");
    let ours = recorded
        .iter()
        .find(|record| record["recipient"] == laptop.to_string().as_str())
        .unwrap();
    assert_eq!(
        (
            ours["level"].as_str(),
            ours["forget_outcome"].as_str(),
            ours["independence"].as_str(),
            ours["recovery_due"].as_bool()
        ),
        (Some("INFO"), Some("forgotten"), Some("holds"), Some(false))
    );
}

#[tokio::test]
async fn an_overdue_recovery_check_is_reported_as_due() {
    let fixture = Fixture::new();
    let (service, _) = ready(&fixture).await;
    write_record(&fixture, now() - 100 * 86_400);

    match forget(&service, &stranger()).await {
        AdminResponse::ForgetMachine { independence, recovery } => {
            assert_eq!(independence, None);
            assert!(recovery.due(), "{recovery:?}");
        }
        other => panic!("expected the result, got {other:?}"),
    }
}

#[tokio::test]
async fn an_inventory_that_breaks_the_independence_rule_is_reported() {
    let fixture = Fixture::new();
    let (service, recovery_key) = ready(&fixture).await;
    rewrite(&fixture, &recovery_key, |entries, added| {
        entries
            .into_iter()
            .filter(|entry| entry.role() != RecipientRole::Recovery)
            .chain([added])
            .collect()
    });

    match forget(&service, &stranger()).await {
        AdminResponse::ForgetMachine { independence, .. } => {
            assert_eq!(independence.as_deref(), Some("the vault would be left with no recovery recipient"));
        }
        other => panic!("expected the result, got {other:?}"),
    }
}

#[tokio::test]
async fn it_is_refused_outside_ready_and_for_a_malformed_key() {
    let fixture = Fixture::new();
    let service = fixture.start();
    assert_eq!(refusal(forget(&service, &stranger()).await).0, ErrorCode::WrongState);

    init(&service).await;
    unlock(&service).await;
    let request = AdminRequest::ForgetMachine {
        recipient: "not a key".to_owned(),
    };
    assert_eq!(refusal(exchange(&service, request, &[]).await.0).0, ErrorCode::RecipientInvalid);
}

/// The command never runs a TPM tool because it runs nothing: none of the code it executes names a way to start a process.
#[test]
fn the_command_spawns_no_process() {
    let sources = [
        include_str!("../src/admin/forget_machine.rs"),
        include_str!("../src/service_context/forget_machine.rs"),
        include_str!("../src/cli/forget_machine.rs"),
    ];
    let spawners = [
        "std::process",
        "tokio::process",
        "Command::new",
        "posix_spawn",
        "libc::exec",
        "libc::fork",
        "libc::system",
    ];
    sources
        .iter()
        .flat_map(|source| spawners.iter().map(move |needle| (source, needle)))
        .for_each(|(source, needle)| assert!(!source.contains(needle), "forget-machine code mentions `{needle}`"));
}
