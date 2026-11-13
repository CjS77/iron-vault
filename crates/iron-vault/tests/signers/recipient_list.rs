// SPDX-License-Identifier: MPL-2.0
//! `recipient list` end to end over a real admin socket against a running service context on an initialized vault
//! (`design/recipients.md`, "`recipient list`"): the two entries `init` enrols, the refusal outside Ready, and a damaged
//! inventory, which is reported by its code and label and leaves every file as it was.

#![cfg(target_os = "linux")]

use crate::common;

use std::fs;

use common::approval_harness::captured_logs;
use common::recipient_harness::{Fixture, init, list, listed, ready, refusal, unlock};
use iron_vault::admin::protocol::ErrorCode;
use iron_vault_store::{RecipientRole, RecipientSet, RecoveryKeySecret, unwrap_identity, wrap_identity};
use secrecy::SecretString;

#[tokio::test]
async fn after_init_and_unlock_the_operational_and_recovery_entries_are_listed() {
    let fixture = Fixture::new();
    let (service, _) = ready(&fixture).await;
    let before = fixture.state_files();

    let entries = listed(list(&service).await);

    // Entries come in ascending key-text order; the keys are random, so the roles are compared sorted.
    let keys: Vec<_> = entries.iter().map(|entry| entry.key().to_string()).collect();
    assert!(keys.windows(2).all(|pair| pair[0] < pair[1]), "{keys:?}");
    let mut shown: Vec<_> = entries
        .iter()
        .map(|entry| (entry.role(), entry.label().as_str().to_owned()))
        .collect();
    shown.sort();
    assert_eq!(
        shown,
        [
            (RecipientRole::Operational, "vault passphrase".to_owned()),
            (RecipientRole::Recovery, "recovery key".to_owned())
        ]
    );
    assert!(entries.iter().all(|entry| entry.key().to_string().starts_with("age1")));
    assert_eq!(fixture.state_files(), before, "a healthy list writes nothing");
}

#[tokio::test]
async fn the_list_is_refused_in_locked_and_before_init() {
    let fixture = Fixture::new();
    let service = fixture.start();
    assert_eq!(refusal(list(&service).await).0, ErrorCode::WrongState);

    init(&service).await;
    assert_eq!(refusal(list(&service).await).0, ErrorCode::WrongState);

    unlock(&service).await;
    assert!(!listed(list(&service).await).is_empty());
}

#[tokio::test]
async fn a_flipped_byte_in_the_inventory_is_damage_and_changes_nothing() {
    let logs = captured_logs();
    let fixture = Fixture::new();
    let (service, _) = ready(&fixture).await;
    let path = fixture.path("state/recipients.age");
    let mut bytes = fs::read(&path).unwrap();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 1;
    fs::write(&path, bytes).unwrap();
    let before = fixture.state_files();

    let (code, message) = refusal(list(&service).await);

    assert_eq!(code, ErrorCode::RecipientInventoryDamaged);
    assert!(message.contains("nothing was changed"), "{message}");
    assert_eq!(fixture.state_files(), before);
    assert!(logs.has_field("recipient.inventory-damaged", "inventory_damage", &damage_label(&message)));
}

/// The label the message names, in its first parentheses.
fn damage_label(message: &str) -> String {
    message.split(['(', ')']).nth(1).unwrap().to_owned()
}

#[tokio::test]
async fn a_missing_inventory_says_an_older_vault_has_none() {
    let fixture = Fixture::new();
    let (service, _) = ready(&fixture).await;
    fs::remove_file(fixture.path("state/recipients.age")).unwrap();
    let before = fixture.state_files();

    let (code, message) = refusal(list(&service).await);

    assert_eq!(code, ErrorCode::RecipientInventoryDamaged);
    assert!(
        message.contains("(missing)") && message.contains("initialized before recipient commands"),
        "{message}"
    );
    assert_eq!(fixture.state_files(), before);
}

#[tokio::test]
async fn an_identity_envelope_the_inventory_does_not_describe_is_damage() {
    let fixture = Fixture::new();
    let (service, recovery_key) = ready(&fixture).await;
    let keys = listed(list(&service).await)
        .iter()
        .map(|entry| entry.key().clone())
        .collect::<Vec<_>>();
    // The same vault identity wrapped again for the same recipients: a different file, so a different digest.
    let recovery = RecoveryKeySecret::parse(SecretString::from(recovery_key)).unwrap();
    let identity = unwrap_identity(&fs::read(fixture.path("state/identity.age")).unwrap(), &recovery).unwrap();
    fs::write(
        fixture.path("state/identity.age"),
        wrap_identity(&identity, &RecipientSet::new(keys).unwrap()).unwrap(),
    )
    .unwrap();
    let before = fixture.state_files();

    let (code, message) = refusal(list(&service).await);

    assert_eq!(code, ErrorCode::RecipientInventoryDamaged);
    assert!(message.contains("(envelope_mismatch)"), "{message}");
    assert_eq!(fixture.state_files(), before);
}
