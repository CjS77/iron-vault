//! The approver release checks (`design/approval-signers.md`, "Release checks"): what holds across `approver add`,
//! `approver remove` and `config approve` together. Each command's own tests cover its exchange and refusals.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use common::approval_harness::{
    APPROVAL_PASSPHRASE, Answer, Exchanged, Fixture, WRONG_PASSPHRASE, captured_logs, converse_switching, error_code, get, send,
    serve_admin,
};
use common::recipient_harness::{self, VAULT_PASSPHRASE};
use iron_vault::admin::protocol::{AdminRequest, AdminResponse, ErrorCode, Frame, ProposedConfig, RequestedSignerKind};
use iron_vault_store::{ApprovalEnvelope, ApproverId, UtcSecond};
use tokio::net::UnixStream;

const NEW_PASSPHRASE: &str = "ROTATED-approver-passphrase-5b19";
const SECOND_PASSPHRASE: &str = "SECOND-approver-passphrase-c04e";

async fn request(path: &Path, request: AdminRequest, answers: &[Answer<'_>]) -> Exchanged {
    let mut stream = UnixStream::connect(path).await.unwrap();
    send(&mut stream, &Frame::Request(request)).await;
    converse_switching(&mut stream, answers).await
}

/// A software `approver add` labelled `backup`, authorized by `presence` and choosing `new` twice.
async fn add(path: &Path, presence: &str, new: &str) -> Exchanged {
    let answers = [Answer::Input(presence), Answer::Input(new), Answer::Input(new)];
    let add = AdminRequest::ApproverAdd {
        kind: RequestedSignerKind::Software,
        label: "backup".to_owned(),
    };
    request(path, add, &answers).await
}

async fn remove(path: &Path, id: ApproverId, answers: &[Answer<'_>]) -> Exchanged {
    request(path, AdminRequest::ApproverRemove { approver: *id.as_bytes() }, answers).await
}

/// `config approve` for `route`, confirmed with `yes` and then answered with `answers`.
async fn approve(path: &Path, fixture: &Fixture, route: &str, answers: &[Answer<'_>]) -> Exchanged {
    let config = ProposedConfig::new(fixture.config(route).into_bytes()).unwrap();
    let answers = [&[Answer::Input("yes")], answers].concat();
    request(path, AdminRequest::ConfigApprove(config), &answers).await
}

fn enrolled(exchanged: &Exchanged) -> ApproverId {
    match exchanged.response {
        AdminResponse::ApproverAdd { approver, .. } => approver,
        ref other => panic!("expected an enrolled approver, got {other:?}"),
    }
}

fn is_approved(exchanged: &Exchanged) -> bool {
    matches!(exchanged.response, AdminResponse::ConfigApprove(_))
}

fn signer_of_published(fixture: &Fixture) -> ApproverId {
    ApprovalEnvelope::decode(&fixture.published_pair()[1]).unwrap().approver_id()
}

fn state_files(fixture: &Fixture) -> BTreeMap<String, Vec<u8>> {
    fs::read_dir(fixture.path("state"))
        .unwrap()
        .map(|entry| entry.unwrap())
        .filter(|entry| entry.file_type().unwrap().is_file())
        .map(|entry| (entry.file_name().to_string_lossy().into_owned(), fs::read(entry.path()).unwrap()))
        .collect()
}

fn key_file_exists(fixture: &Fixture, id: ApproverId) -> bool {
    fixture.path(&format!("state/approver-{id}.age")).exists()
}

#[tokio::test]
async fn an_enrolled_approver_approves_and_the_envelope_names_it() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    let (path, _stop) = serve_admin(&service);

    let id = enrolled(&add(&path, APPROVAL_PASSPHRASE, NEW_PASSPHRASE).await);
    let approved = approve(&path, &fixture, "rates", &[Answer::Switch, Answer::Input(NEW_PASSPHRASE)]).await;

    assert!(is_approved(&approved), "{approved:?}");
    assert_eq!(signer_of_published(&fixture), id);
    assert_eq!(get(&fixture, "rates").await.status, 200);
}

#[tokio::test]
async fn rotating_the_approver_keeps_routes_serving() {
    let fixture = Fixture::new().await;
    let first = fixture.approver_id();
    let service = fixture.ready().await;
    let (path, _stop) = serve_admin(&service);
    let new = enrolled(&add(&path, APPROVAL_PASSPHRASE, NEW_PASSPHRASE).await);
    assert!(is_approved(
        &approve(&path, &fixture, "rates", &[Answer::Switch, Answer::Input(NEW_PASSPHRASE)]).await
    ));

    // The new approver signs the active approval, so it is asked first.
    let removed = remove(&path, first, &[Answer::Input(NEW_PASSPHRASE)]).await;

    assert!(
        matches!(removed.response, AdminResponse::ApproverRemove { approvers: 1 }),
        "{removed:?}"
    );
    assert!(!key_file_exists(&fixture, first) && key_file_exists(&fixture, new));
    assert_eq!(get(&fixture, "rates").await.status, 200);
    let again = approve(&path, &fixture, "fx", &[Answer::Input(NEW_PASSPHRASE)]).await;
    assert!(is_approved(&again), "{again:?}");
    assert_eq!(get(&fixture, "fx").await.status, 200);
}

#[tokio::test]
async fn the_last_and_the_active_approver_cannot_be_removed() {
    let fixture = Fixture::new().await;
    let first = fixture.approver_id();
    let service = fixture.ready().await;
    let (path, _stop) = serve_admin(&service);

    let last = remove(&path, first, &[]).await;
    let second = enrolled(&add(&path, APPROVAL_PASSPHRASE, NEW_PASSPHRASE).await);
    let before = state_files(&fixture);
    let active = remove(&path, first, &[]).await;

    assert_eq!((error_code(&last.response), last.prompts.len()), (ErrorCode::ApproverSetInvalid, 0));
    assert_eq!((error_code(&active.response), active.prompts.len()), (ErrorCode::ApproverInUse, 0));
    assert_eq!(state_files(&fixture), before);
    assert!(key_file_exists(&fixture, first) && key_file_exists(&fixture, second));
}

#[tokio::test]
async fn a_wrong_answer_never_falls_through_to_another_approver() {
    let fixture = Fixture::new().await;
    let second = fixture.enroll_second_approver("second", SECOND_PASSPHRASE, UtcSecond::from_unix_seconds(100).unwrap());
    let service = fixture.ready().await;
    let (path, _stop) = serve_admin(&service);
    let before = state_files(&fixture);

    // The second approver's correct passphrase is never reached: the wrong answer to the first ends the exchange.
    let approval = approve(
        &path,
        &fixture,
        "rates",
        &[Answer::Input(WRONG_PASSPHRASE), Answer::Input(SECOND_PASSPHRASE)],
    )
    .await;
    let removal = remove(&path, second, &[Answer::Input(WRONG_PASSPHRASE), Answer::Input(SECOND_PASSPHRASE)]).await;

    assert_eq!(
        (error_code(&approval.response), approval.prompts.len()),
        (ErrorCode::ApprovalDenied, 2)
    );
    assert_eq!(
        (error_code(&removal.response), removal.prompts.len()),
        (ErrorCode::ApprovalDenied, 1)
    );
    assert_eq!(state_files(&fixture), before);
}

#[tokio::test]
async fn only_a_pinned_approver_authorizes_an_approver_change() {
    let fixture = recipient_harness::Fixture::new();
    let (service, _) = recipient_harness::ready(&fixture).await;
    let request_recovery = AdminRequest::RecipientAddRecovery {
        label: "second recovery".to_owned(),
    };
    let (added, reveals) = recipient_harness::exchange(&service, request_recovery, &[b"yes", VAULT_PASSPHRASE.as_bytes()]).await;
    assert!(matches!(added, AdminResponse::RecipientAdd { .. }), "{added:?}");
    let new_recovery_key = reveals.into_iter().next().unwrap();
    let (path, _stop) = serve_admin(&service);
    let before = fixture.state_files();

    for presence in [VAULT_PASSPHRASE, new_recovery_key.as_str()] {
        let denied = add(&path, presence, NEW_PASSPHRASE).await;
        assert_eq!(error_code(&denied.response), ErrorCode::ApprovalDenied);
        assert_eq!(denied.prompts.len(), 1);
    }

    assert_eq!(fixture.state_files(), before);
    assert!(fixture.state_files().keys().filter(|name| name.starts_with("approver-")).count() == 1);
}

#[tokio::test]
async fn a_removed_approver_gives_no_presence_and_leaves_no_key_file() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    let (path, _stop) = serve_admin(&service);
    let second = enrolled(&add(&path, APPROVAL_PASSPHRASE, SECOND_PASSPHRASE).await);
    let removed = remove(&path, second, &[Answer::Switch, Answer::Input(SECOND_PASSPHRASE)]).await;
    assert!(
        matches!(removed.response, AdminResponse::ApproverRemove { approvers: 1 }),
        "{removed:?}"
    );
    assert!(!key_file_exists(&fixture, second));
    let before = state_files(&fixture);

    let by_add = add(&path, SECOND_PASSPHRASE, NEW_PASSPHRASE).await;
    let by_approval = approve(&path, &fixture, "rates", &[Answer::Input(SECOND_PASSPHRASE)]).await;

    assert_eq!((error_code(&by_add.response), by_add.prompts.len()), (ErrorCode::ApprovalDenied, 1));
    assert_eq!(error_code(&by_approval.response), ErrorCode::ApprovalDenied);
    assert_eq!(state_files(&fixture), before);
}

#[tokio::test]
async fn no_typed_secret_reaches_the_log_through_approver_commands() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let first = fixture.approver_id();
    let service = fixture.ready().await;
    let (path, _stop) = serve_admin(&service);

    let second = enrolled(&add(&path, APPROVAL_PASSPHRASE, SECOND_PASSPHRASE).await);
    let key_file = fs::read(fixture.path(&format!("state/approver-{second}.age"))).unwrap();
    add(&path, WRONG_PASSPHRASE, NEW_PASSPHRASE).await;
    approve(&path, &fixture, "rates", &[Answer::Switch, Answer::Input(SECOND_PASSPHRASE)]).await;
    remove(&path, first, &[Answer::Input(WRONG_PASSPHRASE)]).await;
    remove(&path, first, &[Answer::Input(SECOND_PASSPHRASE)]).await;

    assert!(!logs.events("approver.enrolled").is_empty() && !logs.events("approver.removed").is_empty());
    let text = logs.text();
    [
        APPROVAL_PASSPHRASE,
        WRONG_PASSPHRASE,
        NEW_PASSPHRASE,
        SECOND_PASSPHRASE,
        "AGE-SECRET-KEY-1",
    ]
    .iter()
    .for_each(|secret| assert!(!text.contains(secret), "a typed secret reached the log"));
    assert!(
        !text.contains(String::from_utf8_lossy(&key_file).as_ref()),
        "key file bytes reached the log"
    );
}
