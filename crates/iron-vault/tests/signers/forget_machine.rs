// SPDX-License-Identifier: MPL-2.0
//! `forget-machine` end to end over a real admin socket against a running service context on an initialized vault
//! (`design/forget-machine.md`): a key that is still a recipient is not forgotten and nothing changes, a removed key with a
//! healthy recovery path is, an overdue recovery check or a broken independence rule is a fact in the result, and the
//! command spawns no process.

#![cfg(target_os = "linux")]

use crate::common;

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
    assert!(message.contains("run `iron-vault recipient remove` with the same key"), "{message}");
    assert!(message.contains("role added"), "{message}");
    assert!(
        !message.contains(&laptop.to_string()) && !message.contains("old laptop"),
        "the message echoes owner input: {message}"
    );
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
            ours["recovery"].as_str()
        ),
        (Some("INFO"), Some("forgotten"), Some("holds"), Some("verified"))
    );
}

#[tokio::test]
async fn an_overdue_recovery_check_is_not_verified() {
    let logs = captured_logs();
    let fixture = Fixture::new();
    let (service, _) = ready(&fixture).await;
    write_record(&fixture, now() - 100 * 86_400);
    let key = stranger();

    match forget(&service, &key).await {
        AdminResponse::ForgetMachine { independence, recovery } => {
            assert_eq!(independence, None);
            assert!(matches!(recovery, RecoveryStatus::Checked { due: true, .. }), "{recovery:?}");
        }
        other => panic!("expected the result, got {other:?}"),
    }
    assert_unverified_warning(&logs, &key);
}

/// The audit event for `key` is a WARN whose recovery path is unverified. The log is shared by the tests of this binary.
fn assert_unverified_warning(logs: &common::approval_harness::Captured, key: &RecipientKey) {
    let recorded = logs.events("recipient.forget-checked");
    let ours = recorded
        .iter()
        .find(|record| record["recipient"] == key.to_string().as_str())
        .unwrap();
    assert_eq!(
        (ours["level"].as_str(), ours["recovery"].as_str()),
        (Some("WARN"), Some("unverified")),
        "{ours}"
    );
}

/// A vault that has never had a recovery check is not a verified recovery path, however young it is.
#[tokio::test]
async fn a_fresh_vault_with_no_recovery_check_is_not_verified() {
    let logs = captured_logs();
    let fixture = Fixture::new();
    let (service, _) = ready(&fixture).await;
    let key = stranger();

    match forget(&service, &key).await {
        AdminResponse::ForgetMachine { independence, recovery } => {
            assert_eq!(independence, None);
            assert!(!recovery.verified(), "{recovery:?}");
            assert!(!matches!(recovery, RecoveryStatus::Checked { .. }), "{recovery:?}");
        }
        other => panic!("expected the result, got {other:?}"),
    }
    assert_unverified_warning(&logs, &key);
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

/// Every tool the guidance names, as a shim that records that it ran.
const TOOLS: [&str; 10] = [
    "tpm2_clear",
    "tpm2_getcap",
    "systemd-cryptenroll",
    "systemd-creds",
    "systemctl",
    "rm",
    "grep",
    "ls",
    "clevis",
    "tpm2_pkcs11_tool",
];

/// A directory of one marker-writing shim per tool, and the directory the markers go in.
fn shims(fixture: &Fixture) -> (std::path::PathBuf, std::path::PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let (bin, markers) = (fixture.path("shim-bin"), fixture.path("shim-markers"));
    fs::create_dir_all(&bin).unwrap();
    fs::create_dir_all(&markers).unwrap();
    TOOLS.iter().for_each(|tool| {
        let shim = bin.join(tool);
        fs::write(&shim, format!("#!/bin/sh\necho ran > '{}'\n", markers.join(tool).display())).unwrap();
        fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).unwrap();
    });
    (bin, markers)
}

/// The real CLI against the Ready service, with a `PATH` that holds only shims for the tools the guidance mentions: it prints the
/// guidance and the warning for the unchecked recovery path, exits 0, and starts none of the tools.
#[tokio::test]
async fn the_command_runs_no_tool_it_mentions() {
    let fixture = Fixture::new();
    let (service, _) = ready(&fixture).await;
    let (bin, markers) = shims(&fixture);
    let (socket, stop) = common::approval_harness::serve_admin(&service);
    let key = stranger().to_string();

    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(env!("CARGO_BIN_EXE_iron-vault"))
            .args(["forget-machine", &key, "--admin-socket"])
            .arg(&socket)
            .env("PATH", &bin)
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    let _ = stop.send(());

    let (stdout, stderr) = (String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    assert!(
        stdout.contains("is not a recipient of this vault") && stdout.contains("tpm2_clear"),
        "{stdout}"
    );
    assert!(stderr.contains("warning: the recovery check"), "{stderr}");
    let ran: Vec<_> = fs::read_dir(&markers).unwrap().map(|entry| entry.unwrap().file_name()).collect();
    assert!(ran.is_empty(), "the command started {ran:?}");
}

/// A second guard: none of the code the command runs names a way to start a process.
#[test]
fn the_command_spawns_no_process() {
    let sources = [
        include_str!("../../src/admin/forget_machine.rs"),
        include_str!("../../src/service_context/forget_machine.rs"),
        include_str!("../../src/cli/forget_machine.rs"),
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
