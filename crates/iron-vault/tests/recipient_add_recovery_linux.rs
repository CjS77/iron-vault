//! `recipient add --recovery` end to end over a real admin socket (`design/recipients.md`, "`recipient add --recovery`"): the
//! service generates the key and shows it once, enrols it only after the owner confirms and authorizes, and the old recovery
//! key can then be removed.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::approval_harness::captured_logs;
use common::recipient_harness::{APPROVAL_PASSPHRASE, Fixture, VAULT_PASSPHRASE, exchange, list, listed, ready, refusal};
use iron_vault::admin::protocol::{AdminRequest, AdminResponse, ErrorCode};
use iron_vault_store::{RecipientKey, RecipientRole};

const LABEL: &str = "recovery key 2026";

fn request() -> AdminRequest {
    AdminRequest::RecipientAddRecovery { label: LABEL.to_owned() }
}

fn recovery_keys(entries: &[iron_vault_store::RecipientEntry]) -> Vec<RecipientKey> {
    entries
        .iter()
        .filter(|entry| entry.role() == RecipientRole::Recovery)
        .map(|entry| entry.key().clone())
        .collect()
}

#[tokio::test]
async fn the_revealed_key_passes_recovery_check_and_the_old_recovery_key_can_then_be_removed() {
    let logs = captured_logs();
    let fixture = Fixture::new();
    let (service, old_recovery_key) = ready(&fixture).await;

    let (response, reveals) = exchange(&service, request(), &[b"yes", VAULT_PASSPHRASE.as_bytes()]).await;

    let AdminResponse::RecipientAdd {
        recipient: new_key,
        recipients,
    } = response
    else {
        panic!("{response:?}");
    };
    assert_eq!(recipients, 3);
    let [new_secret] = <[String; 1]>::try_from(reveals).expect("one reveal");
    assert!(new_secret.starts_with("AGE-SECRET-KEY-1"));
    let (check, _) = exchange(&service, AdminRequest::RecoveryCheck, &[new_secret.as_bytes()]).await;
    assert!(matches!(check, AdminResponse::RecoveryCheck { .. }), "{check:?}");
    let entries = listed(list(&service).await);
    let recovery = recovery_keys(&entries);
    assert_eq!(recovery.len(), 2);
    assert!(recovery.contains(&new_key));
    let old_key = recovery.into_iter().find(|key| *key != new_key).unwrap();

    let remove = AdminRequest::RecipientRemove {
        recipient: old_key.to_string(),
    };
    let (removed, _) = exchange(&service, remove, &[APPROVAL_PASSPHRASE.as_bytes()]).await;
    assert!(matches!(removed, AdminResponse::RecipientRemove { recipients: 2 }), "{removed:?}");
    assert_eq!(recovery_keys(&listed(list(&service).await)), [new_key]);

    let added = logs.events("recipient.added");
    assert_eq!(added.len(), 1);
    assert_eq!(
        (added[0]["recipient_role"].as_str(), added[0]["recipient_label"].as_str()),
        (Some("recovery"), Some(LABEL))
    );
    assert!(!logs.text().contains("AGE-SECRET-KEY-1"), "a log record holds secret-key text");
    assert!(!logs.text().contains(&new_secret) && !logs.text().contains(&old_recovery_key));
}

#[tokio::test]
async fn a_cancel_at_the_reveal_enrols_nothing_and_leaves_both_files_untouched() {
    let fixture = Fixture::new();
    let (service, _) = ready(&fixture).await;
    let before = fixture.state_files();

    let (response, reveals) = exchange(&service, request(), &[b"no"]).await;

    let (code, message) = refusal(response);
    assert_eq!(code, ErrorCode::Declined);
    assert!(message.ends_with("the recovery key shown opens nothing: discard it"), "{message}");
    assert_eq!(reveals.len(), 1);
    assert!(!message.contains(&reveals[0]));
    assert_eq!(fixture.state_files(), before);
}

#[tokio::test]
async fn a_wrong_vault_passphrase_after_the_reveal_enrols_nothing_and_calls_the_key_dead() {
    let fixture = Fixture::new();
    let (service, _) = ready(&fixture).await;
    let before = fixture.state_files();

    let (response, reveals) = exchange(&service, request(), &[b"yes", b"not the vault passphrase"]).await;

    let (code, message) = refusal(response);
    assert_eq!(code, ErrorCode::MigrationDenied);
    assert!(message.ends_with("the recovery key shown opens nothing: discard it"), "{message}");
    assert!(!message.contains(&reveals[0]));
    assert_eq!(fixture.state_files(), before);
}

#[tokio::test]
async fn a_bad_label_is_refused_before_anything_is_shown() {
    let fixture = Fixture::new();
    let (service, _) = ready(&fixture).await;

    let (response, reveals) = exchange(&service, AdminRequest::RecipientAddRecovery { label: String::new() }, &[]).await;

    assert_eq!(refusal(response).0, ErrorCode::RecipientInvalid);
    assert!(reveals.is_empty());
}
