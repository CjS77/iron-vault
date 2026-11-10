//! The approver prompt over a real admin socket with two software approvers pinned (design/approval-signers.md, "The
//! approver prompt"): the order they are asked in, switching, and a wrong answer that never falls through.
//!
//! The vault pins `init`'s approver, labelled `approval passphrase`, and a `second` approver enrolled after it with a
//! passphrase of its own.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use common::approval_harness::{
    APPROVAL_PASSPHRASE, Answer, Exchanged, Fixture, WRONG_PASSPHRASE, converse_switching, error_code, send, serve_admin,
};
use iron_vault::admin::protocol::{AdminRequest, AdminResponse, ErrorCode, Frame, ProposedConfig};
use iron_vault::service_context::ServiceContext;
use iron_vault_store::{ApprovalEnvelope, ApproverId, UtcSecond};
use tokio::sync::oneshot;

const SECOND_PASSPHRASE: &str = "SECOND-correct-52d1";

/// A vault pinning both approvers, a service running on it, its admin socket and the sender that stops it when dropped,
/// and the second approver's ID.
async fn two_approvers() -> (Fixture, Arc<ServiceContext>, (PathBuf, oneshot::Sender<()>), ApproverId) {
    let fixture = Fixture::new().await;
    let second = fixture.enroll_second_approver("second", SECOND_PASSPHRASE, UtcSecond::from_unix_seconds(100).unwrap());
    let service = fixture.ready().await;
    let admin = serve_admin(&service);
    (fixture, service, admin, second)
}

/// `config approve` for `route`, with `answers` to the prompts.
async fn approve(path: &Path, fixture: &Fixture, route: &str, answers: &[Answer<'_>]) -> Exchanged {
    let mut stream = tokio::net::UnixStream::connect(path).await.unwrap();
    let request = AdminRequest::ConfigApprove(ProposedConfig::new(fixture.config(route).into_bytes()).unwrap());
    send(&mut stream, &Frame::Request(request)).await;
    converse_switching(&mut stream, answers).await
}

fn asked(label: &str, switchable: bool) -> (String, bool) {
    (format!("Approval passphrase for \"{label}\""), switchable)
}

fn shown(exchanged: &Exchanged) -> Vec<(String, bool)> {
    exchanged
        .prompts
        .iter()
        .map(|prompt| (prompt.label.clone(), prompt.switchable))
        .collect()
}

fn signer_of_published(fixture: &Fixture) -> ApproverId {
    ApprovalEnvelope::decode(&fixture.published_pair()[1]).unwrap().approver_id()
}

#[tokio::test]
async fn a_switch_asks_the_second_approver_which_signs_and_is_named_in_the_envelope() {
    let (fixture, _service, (path, _stop), second) = two_approvers().await;
    let answers = [Answer::Input("yes"), Answer::Switch, Answer::Input(SECOND_PASSPHRASE)];

    let approved = approve(&path, &fixture, "rates", &answers).await;

    assert!(matches!(approved.response, AdminResponse::ConfigApprove(_)), "{approved:?}");
    let prompts = shown(&approved);
    assert_eq!(&prompts[1..], [asked("approval passphrase", true), asked("second", true)]);
    assert_eq!(signer_of_published(&fixture), second);
}

#[tokio::test]
async fn the_signer_of_the_active_approval_is_asked_first_next_time() {
    let (fixture, _service, (path, _stop), _second) = two_approvers().await;
    let answers = [Answer::Input("yes"), Answer::Switch, Answer::Input(SECOND_PASSPHRASE)];
    approve(&path, &fixture, "rates", &answers).await;

    let again = approve(&path, &fixture, "fx", &[Answer::Input("yes"), Answer::Input(SECOND_PASSPHRASE)]).await;

    assert!(matches!(again.response, AdminResponse::ConfigApprove(_)), "{again:?}");
    assert_eq!(&shown(&again)[1..], [asked("second", true)]);
}

#[tokio::test]
async fn a_wrong_passphrase_for_the_first_approver_is_denied_and_never_asks_the_second() {
    let (fixture, _service, (path, _stop), _second) = two_approvers().await;
    let before = fs::read(fixture.path("state/approval.age")).unwrap();

    let denied = approve(&path, &fixture, "rates", &[Answer::Input("yes"), Answer::Input(WRONG_PASSPHRASE)]).await;

    assert_eq!(error_code(&denied.response), ErrorCode::ApprovalDenied);
    assert_eq!(&shown(&denied)[1..], [asked("approval passphrase", true)]);
    assert_eq!(fs::read(fixture.path("state/approval.age")).unwrap(), before);
}

#[tokio::test]
async fn the_first_approvers_passphrase_does_not_open_the_second() {
    let (fixture, _service, (path, _stop), _second) = two_approvers().await;
    let answers = [Answer::Input("yes"), Answer::Switch, Answer::Input(APPROVAL_PASSPHRASE)];

    let denied = approve(&path, &fixture, "rates", &answers).await;

    assert_eq!(error_code(&denied.response), ErrorCode::ApprovalDenied);
    assert_eq!(&shown(&denied)[1..], [asked("approval passphrase", true), asked("second", true)]);
}
