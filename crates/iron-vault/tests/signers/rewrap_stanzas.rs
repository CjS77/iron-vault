//! Release check 8 (specification §19): "Recovery opens the vault through an independent recipient; passphrase envelopes
//! never create an invalid mixed-recipient `age` file."
//!
//! One vault goes through every command that rewraps `identity.age` or writes a passphrase envelope. After each step the
//! files on disk are parsed here, by a header reader of this file's own rather than the store's, and the current
//! recovery key is run through `recovery check` against the Locked service. The store enforces the rule where it
//! writes (`check_x25519_only`); this test notices a later rewrap path that skipped that check.
//!
//! Covered: `recipient add`, `recipient add --host-unlock` (the service only wraps for the key it is given, so it needs
//! no root or TPM), `recipient add --recovery`, `recipient remove`, `approver add` and `approver remove` (software
//! approvers), after `init` and an `unlock` and `lock` round trip.
//!
//! Not covered here: a vault passphrase change, which v0 has no command for; `import`, whose wrapping is checked by the
//! import tests; `approver add --kind tpm`, which writes a TPM key blob and no `age` file, so it is outside this check;
//! and the Compose host unlock enrolment, which needs a TPM and is on the `root + VM` checks.

#![cfg(target_os = "linux")]

use crate::common;

use std::fs;
use std::sync::Arc;

use common::recipient_harness::{APPROVAL_PASSPHRASE, Fixture, VAULT_PASSPHRASE, exchange, list, listed, ready, refusal, unlock};
use iron_vault::admin::protocol::{AdminRequest, AdminResponse, ErrorCode, RequestedSignerKind};
use iron_vault::service_context::ServiceContext;
use iron_vault_store::{RecipientKey, RecipientRole, RecoveryKey};

const SECOND_APPROVER_PASSPHRASE: &str = "REWRAP-second-approver-passphrase-3c8e";

/// The stanza types of an `age` file's header: the `age-encryption.org/v1` line, then each `-> <type> ...` line up to the
/// `---` MAC line. Body lines are base64 and cannot start with `-`, so only a stanza starts with `-> `.
fn stanza_types(file: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(file);
    let mut lines = text.lines();
    assert_eq!(lines.next(), Some("age-encryption.org/v1"), "not an age v1 file");
    let mut saw_mac = false;
    let header: Vec<&str> = lines
        .by_ref()
        .take_while(|line| {
            saw_mac = line.starts_with("---");
            !saw_mac
        })
        .collect();
    assert!(saw_mac, "the header has no MAC line");
    header
        .iter()
        .filter_map(|line| line.strip_prefix("-> "))
        .filter_map(|stanza| stanza.split(' ').next())
        .map(str::to_owned)
        .collect()
}

/// `identity.age` holds one `X25519` stanza per listed recipient and nothing but `age`'s own random grease besides.
fn assert_identity_is_x25519_only(fixture: &Fixture, recipients: usize, step: &str) {
    let types = stanza_types(&fs::read(fixture.path("state/identity.age")).unwrap());
    let x25519 = types.iter().filter(|kind| *kind == "X25519").count();
    let others: Vec<&String> = types
        .iter()
        .filter(|kind| *kind != "X25519" && !kind.ends_with("-grease"))
        .collect();
    assert!(others.is_empty(), "{step}: identity.age has stanzas {others:?}");
    let grease = types
        .iter()
        .filter(|kind| kind.len() > "-grease".len() && kind.ends_with("-grease"))
        .count();
    assert!(grease <= 1, "{step}: identity.age has {grease} grease stanzas: {types:?}");
    assert_eq!(
        x25519, recipients,
        "{step}: identity.age has {x25519} X25519 stanzas for {recipients} recipients: {types:?}"
    );
}

/// Every passphrase envelope, `operational.age` and each `approver-<id>.age`, holds exactly one `scrypt` stanza.
fn assert_passphrase_envelopes_are_single_scrypt(fixture: &Fixture, approvers: usize, step: &str) {
    let files = fixture.state_files();
    let envelopes: Vec<(&String, Vec<String>)> = files
        .iter()
        .filter(|(name, _)| name.as_str() == "operational.age" || (name.starts_with("approver-") && name.ends_with(".age")))
        .map(|(name, bytes)| (name, stanza_types(bytes)))
        .collect();
    envelopes
        .iter()
        .for_each(|(name, types)| assert_eq!(types, &["scrypt"], "{step}: {name} has stanzas {types:?}"));
    assert_eq!(envelopes.len(), approvers + 1, "{step}: passphrase envelopes found: {envelopes:?}");
}

/// Locks the service, runs `recovery check` with `key`, and unlocks again; `Ok` when the key opened the Locked vault.
async fn recovery_check_locked(service: &Arc<ServiceContext>, key: &str) -> Result<(), ErrorCode> {
    let (locked, _) = exchange(service, AdminRequest::Lock, &[]).await;
    assert!(matches!(locked, AdminResponse::Lock { .. }), "{locked:?}");
    let (checked, _) = exchange(service, AdminRequest::RecoveryCheck, &[key.as_bytes()]).await;
    unlock(service).await;
    match checked {
        AdminResponse::RecoveryCheck { .. } => Ok(()),
        other => Err(refusal(other).0),
    }
}

/// The checks after one step: both file shapes, and that `recovery_key` still opens the Locked vault.
async fn assert_rewrapped_vault_is_sound(
    fixture: &Fixture,
    service: &Arc<ServiceContext>,
    recovery_key: &str,
    approvers: usize,
    step: &str,
) {
    let recipients = listed(list(service).await).len();
    assert_identity_is_x25519_only(fixture, recipients, step);
    assert_passphrase_envelopes_are_single_scrypt(fixture, approvers, step);
    assert_eq!(
        recovery_check_locked(service, recovery_key).await,
        Ok(()),
        "{step}: the recovery key no longer opens the vault"
    );
}

fn fresh_key() -> RecipientKey {
    RecoveryKey::generate().1
}

async fn run(service: &Arc<ServiceContext>, request: AdminRequest, answers: &[&str], step: &str) -> Vec<String> {
    let answers: Vec<&[u8]> = answers.iter().map(|answer| answer.as_bytes()).collect();
    let (response, reveals) = exchange(service, request, &answers).await;
    assert!(
        matches!(
            response,
            AdminResponse::RecipientAdd { .. }
                | AdminResponse::RecipientRemove { .. }
                | AdminResponse::ApproverAdd { .. }
                | AdminResponse::ApproverRemove { .. }
        ),
        "{step}: {response:?}"
    );
    reveals
}

async fn key_with_role(service: &Arc<ServiceContext>, role: RecipientRole) -> RecipientKey {
    listed(list(service).await)
        .iter()
        .find(|entry| entry.role() == role)
        .unwrap()
        .key()
        .clone()
}

#[tokio::test]
async fn identity_age_stays_x25519_only_and_the_recovery_key_opens_the_vault_after_every_rewrap() {
    let fixture = Fixture::new();
    let (service, recovery_key) = ready(&fixture).await;
    assert_rewrapped_vault_is_sound(&fixture, &service, &recovery_key, 1, "init").await;

    let vault = [VAULT_PASSPHRASE];
    let added = fresh_key();
    let request = AdminRequest::RecipientAdd {
        recipient: added.to_string(),
        label: "rewrap key".to_owned(),
    };
    run(&service, request, &vault, "recipient add").await;
    assert_rewrapped_vault_is_sound(&fixture, &service, &recovery_key, 1, "recipient add").await;

    let request = AdminRequest::RecipientAddHostUnlock {
        recipient: fresh_key().to_string(),
        label: "rewrap host".to_owned(),
    };
    run(&service, request, &vault, "recipient add --host-unlock").await;
    assert_rewrapped_vault_is_sound(&fixture, &service, &recovery_key, 1, "recipient add --host-unlock").await;

    let old_recovery_key = key_with_role(&service, RecipientRole::Recovery).await;
    let request = AdminRequest::RecipientAddRecovery {
        label: "rotated".to_owned(),
    };
    let new_recovery = run(&service, request, &["yes", VAULT_PASSPHRASE], "recipient add --recovery")
        .await
        .remove(0);
    assert_rewrapped_vault_is_sound(&fixture, &service, &new_recovery, 1, "recipient add --recovery").await;
    assert_eq!(
        recovery_check_locked(&service, &recovery_key).await,
        Ok(()),
        "the old key opens the vault until removed"
    );

    let remove = |key: &RecipientKey| AdminRequest::RecipientRemove {
        recipient: key.to_string(),
    };
    run(&service, remove(&added), &[APPROVAL_PASSPHRASE], "recipient remove an added key").await;
    assert_rewrapped_vault_is_sound(&fixture, &service, &new_recovery, 1, "recipient remove an added key").await;

    run(
        &service,
        remove(&old_recovery_key),
        &[APPROVAL_PASSPHRASE],
        "recipient remove the old recovery key",
    )
    .await;
    assert_rewrapped_vault_is_sound(&fixture, &service, &new_recovery, 1, "recipient remove the old recovery key").await;
    assert_eq!(
        recovery_check_locked(&service, &recovery_key).await,
        Err(ErrorCode::RecoveryCheckFailed),
        "the removed recovery key still opens the vault"
    );
    let recovery_key = new_recovery;

    let request = AdminRequest::ApproverAdd {
        kind: RequestedSignerKind::Software,
        label: "second".to_owned(),
    };
    run(
        &service,
        request,
        &[APPROVAL_PASSPHRASE, SECOND_APPROVER_PASSPHRASE, SECOND_APPROVER_PASSPHRASE],
        "approver add",
    )
    .await;
    assert_rewrapped_vault_is_sound(&fixture, &service, &recovery_key, 2, "approver add").await;

    let (response, _) = exchange(&service, AdminRequest::ApproverList, &[]).await;
    let AdminResponse::ApproverList { entries } = response else {
        panic!("expected the approver list")
    };
    let second = entries.iter().find(|entry| entry.label.to_string() == "second").unwrap().id;
    let request = AdminRequest::ApproverRemove {
        approver: *second.as_bytes(),
    };
    run(&service, request, &[APPROVAL_PASSPHRASE], "approver remove").await;
    assert_rewrapped_vault_is_sound(&fixture, &service, &recovery_key, 1, "approver remove").await;
}
