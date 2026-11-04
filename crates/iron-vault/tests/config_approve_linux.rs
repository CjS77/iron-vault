//! `config approve` end to end over a real admin socket against a running service context (specification §3.9, §3.2,
//! §3.13): the summary as notices, the confirmation, the approval passphrase, then the transaction, the admission pause
//! and the config check. Every test's log goes to one captured buffer, which must never hold an approval passphrase.
//!
//! Each test builds a vault holding `fx_key`, pins a software approver whose key is sealed in `approver.age` under
//! [`APPROVAL_PASSPHRASE`], and approves the base config through the store, then releases both locks so the service
//! takes them. The service account is the test's own uid.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::fs;
use std::path::Path;

use common::WAIT;
use common::approval_harness::{
    APPROVAL_PASSPHRASE, Fixture, WRONG_PASSPHRASE, approve, approve_request, captured_logs, converse, error_code, get, identity,
    read_frame, send, serve_admin, the_two_prompts, versions,
};
use iron_vault::admin::protocol::{AdminResponse, ApprovalResult, ErrorCode, Frame, OwnerInput};
use iron_vault::service_state::{FailureReason, ServiceEvent, ServiceState};
use iron_vault_store::ConfigDigest;
use tokio::net::UnixStream;
use zeroize::Zeroizing;

#[tokio::test]
async fn a_valid_change_is_active_when_the_response_arrives_and_the_old_pair_no_longer_verifies() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    let old_pair = ["config.toml", "config.toml.sig"].map(|file| fs::read(fixture.path(&format!("etc/{file}"))).unwrap());
    let proposed = fixture.config("rates");

    let exchanged = approve(&service, &proposed, &["yes", APPROVAL_PASSPHRASE]).await;

    let digest = *ConfigDigest::of(proposed.as_bytes()).as_bytes();
    match &exchanged.response {
        AdminResponse::ConfigApprove(ApprovalResult {
            version: 2,
            digest: got,
            headline,
        }) => {
            assert_eq!(*got, digest);
            assert!(headline.contains("routes: 1 added, 1 removed"), "{headline}");
        }
        other => panic!("expected an approval, got {other:?}"),
    }
    assert_eq!(exchanged.prompts, the_two_prompts(2));
    assert!(exchanged.notices.contains("version to commit: 2\n"), "{}", exchanged.notices);
    assert!(exchanged.notices.contains("committed version: 1\n"), "{}", exchanged.notices);
    assert!(exchanged.notices.contains("+ rates"), "{}", exchanged.notices);
    assert_eq!(service.state().await, ServiceState::Ready);
    assert_eq!(get(&fixture, "rates").await.status, 200);
    assert_eq!(get(&fixture, "fx").await.status, 404);
    assert_eq!(fs::read(fixture.path("etc/config.toml")).unwrap(), proposed.as_bytes());
    assert_eq!(versions(&service).await, (Some(2), 2));

    // Putting the version 1 pair back is a rollback, which the config check refuses.
    ["config.toml", "config.toml.sig"]
        .iter()
        .zip(&old_pair)
        .for_each(|(file, bytes)| fs::write(fixture.path(&format!("etc/{file}")), bytes).unwrap());
    let reloaded = service.recheck(ServiceEvent::Reload).await;
    assert_eq!(reloaded, Ok(ServiceState::Unavailable(FailureReason::PolicyInvalid)));
    logs.assert_no_passphrase();
}

#[tokio::test]
async fn declining_the_summary_consumes_no_version_and_keeps_the_active_pair() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    let active = fs::read(fixture.path("etc/config.toml")).unwrap();

    let exchanged = approve(&service, &fixture.config("rates"), &["no"]).await;

    assert_eq!(error_code(&exchanged.response), ErrorCode::Declined);
    assert_eq!(exchanged.prompts.len(), 1, "no passphrase is asked for after a decline");
    assert_eq!(versions(&service).await, (Some(1), 1));
    assert_eq!(fs::read(fixture.path("etc/config.toml")).unwrap(), active);
    assert!(!fixture.path("etc/config.toml.pending").exists());
    assert_eq!(get(&fixture, "fx").await.status, 200);
}

#[tokio::test]
async fn a_wrong_approval_passphrase_consumes_no_version() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;

    let exchanged = approve(&service, &fixture.config("rates"), &["yes", WRONG_PASSPHRASE]).await;

    assert_eq!(error_code(&exchanged.response), ErrorCode::ApprovalDenied);
    assert_eq!(exchanged.prompts, the_two_prompts(2));
    assert_eq!(versions(&service).await, (Some(1), 1));
    assert!(!fixture.path("etc/config.toml.pending").exists());
    assert_eq!(get(&fixture, "fx").await.status, 200);
    logs.assert_no_passphrase();
}

#[tokio::test]
async fn a_failure_after_the_reservation_consumes_the_version_and_the_next_approval_gets_a_higher_one() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    // A leftover temp file makes the durable write of the staged approval (step 4) refuse.
    let blocker = fixture.path("etc/.config.toml.sig.staged.tmp");
    fs::write(&blocker, b"").unwrap();
    let proposed = fixture.config("rates");

    let failed = approve(&service, &proposed, &["yes", APPROVAL_PASSPHRASE]).await;

    assert_eq!(error_code(&failed.response), ErrorCode::ApprovalFailed);
    let digest = ConfigDigest::of(proposed.as_bytes());
    assert!(logs.has_event("config.version-reserved", 2, &digest), "{}", logs.text());
    assert!(logs.has_event("config.approval-failed", 2, &digest), "{}", logs.text());
    assert_eq!(versions(&service).await, (Some(1), 2));
    assert_eq!(service.state().await, ServiceState::Ready);
    assert_eq!(get(&fixture, "fx").await.status, 200);

    fs::remove_file(blocker).unwrap();
    let approved = approve(&service, &fixture.config("rates"), &["yes", APPROVAL_PASSPHRASE]).await;

    assert_eq!(approved.prompts, the_two_prompts(3));
    assert!(matches!(
        approved.response,
        AdminResponse::ConfigApprove(ApprovalResult { version: 3, .. })
    ));
    assert_eq!(versions(&service).await, (Some(3), 3));
}

#[tokio::test]
async fn a_second_approval_while_one_waits_at_its_prompt_is_busy() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    let (path, stop) = serve_admin(&service);
    let mut first = UnixStream::connect(&path).await.unwrap();
    send(&mut first, &approve_request(&fixture.config("rates"))).await;
    while !matches!(read_frame(&mut first).await, Frame::Prompt(_)) {}

    let second = approve(&service, &fixture.config("other"), &[]).await;

    assert_eq!(error_code(&second.response), ErrorCode::Busy);
    assert!(second.prompts.is_empty() && second.notices.is_empty());
    send(&mut first, &Frame::OwnerInput(OwnerInput::new(Zeroizing::new(b"no".to_vec())))).await;
    assert_eq!(error_code(&converse(&mut first, &[]).await.response), ErrorCode::Declined);
    let _ = stop.send(());
}

#[tokio::test]
async fn an_unknown_credential_is_refused_before_any_prompt() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;

    let exchanged = approve(&service, &fixture.config_with("rates", "nope_key"), &[]).await;

    match &exchanged.response {
        AdminResponse::Error {
            code: ErrorCode::ConfigInvalid,
            message,
        } => assert!(message.contains("nope_key"), "{message}"),
        other => panic!("expected config-invalid, got {other:?}"),
    }
    assert!(exchanged.prompts.is_empty() && exchanged.notices.is_empty());
    assert_eq!(versions(&service).await, (Some(1), 1));
    assert!(!fixture.path("etc/config.toml.pending").exists());
}

#[tokio::test]
async fn an_approval_out_of_an_invalid_policy_makes_the_service_ready() {
    let fixture = Fixture::new().await;
    fs::write(fixture.path("etc/config.toml"), fixture.config("edited")).unwrap();
    let service = fixture.start().await;
    assert_eq!(service.state().await, ServiceState::Unavailable(FailureReason::PolicyInvalid));

    let exchanged = approve(&service, &fixture.config("rates"), &["yes", APPROVAL_PASSPHRASE]).await;

    assert!(matches!(
        exchanged.response,
        AdminResponse::ConfigApprove(ApprovalResult { version: 2, .. })
    ));
    assert!(exchanged.notices.contains("no active config"), "{}", exchanged.notices);
    assert_eq!(service.state().await, ServiceState::Ready);
    assert_eq!(get(&fixture, "rates").await.status, 200);
}

#[tokio::test]
async fn a_locked_service_cannot_approve() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    service.lock(WAIT).await.unwrap();

    let exchanged = approve(&service, &fixture.config("rates"), &[]).await;

    assert_eq!(error_code(&exchanged.response), ErrorCode::ApprovalUnavailable);
    assert!(exchanged.prompts.is_empty());
    assert!(!fixture.path("etc/config.toml.pending").exists());
}

/// Sends `config approve` for `config` on a connection of its own and reads up to the confirmation prompt.
async fn at_confirmation(path: &Path, config: &str) -> UnixStream {
    let mut stream = UnixStream::connect(path).await.unwrap();
    send(&mut stream, &approve_request(config)).await;
    while !matches!(read_frame(&mut stream).await, Frame::Prompt(_)) {}
    stream
}

#[tokio::test]
async fn a_lock_and_an_unlock_at_the_prompt_end_the_approval_with_nothing_reserved() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    let (path, stop) = serve_admin(&service);
    let mut stream = at_confirmation(&path, &fixture.config("rates")).await;

    service.lock(WAIT).await.unwrap();
    assert_eq!(service.enter_checking(identity()).await, Ok(ServiceState::Ready));
    send(&mut stream, &Frame::OwnerInput(OwnerInput::new(Zeroizing::new(b"yes".to_vec())))).await;
    let exchanged = converse(&mut stream, &[APPROVAL_PASSPHRASE]).await;

    assert_eq!(error_code(&exchanged.response), ErrorCode::ApprovalUnavailable);
    assert_eq!(versions(&service).await, (Some(1), 1));
    assert_eq!(service.state().await, ServiceState::Ready);
    assert_eq!(get(&fixture, "fx").await.status, 200);
    ["etc/config.toml.pending", "etc/config.toml.sig.staged"]
        .iter()
        .for_each(|file| assert!(!fixture.path(file).exists(), "{file} is left behind"));
    let _ = stop.send(());
}

#[tokio::test]
async fn a_client_that_goes_away_at_the_prompt_releases_the_service_wide_lock() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    let (path, stop) = serve_admin(&service);
    drop(at_confirmation(&path, &fixture.config("rates")).await);

    // The handler sees the close when it next reads, so the lock is released shortly after, not at once.
    let mut second = None;
    for _ in 0..100 {
        let mut stream = UnixStream::connect(&path).await.unwrap();
        send(&mut stream, &approve_request(&fixture.config("other"))).await;
        match read_frame(&mut stream).await {
            Frame::Response(response) => assert_eq!(error_code(&response), ErrorCode::Busy),
            _ => {
                second = Some(stream);
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let mut second = second.expect("the second approval stayed busy");
    assert_eq!(error_code(&converse(&mut second, &["no"]).await.response), ErrorCode::Declined);
    assert_eq!(versions(&service).await, (Some(1), 1));
    // Both approvals wrote the pending config and both ended before a reservation, so none may be left; this cannot
    // tell which of the two cleanups removed it.
    assert!(!fixture.path("etc/config.toml.pending").exists());
    let _ = stop.send(());
}

#[tokio::test]
async fn a_lock_and_an_unlock_at_the_prompt_of_an_approval_out_of_an_invalid_policy_reserve_nothing() {
    let fixture = Fixture::new().await;
    fs::write(fixture.path("etc/config.toml"), fixture.config("edited")).unwrap();
    let service = fixture.start().await;
    let invalid = ServiceState::Unavailable(FailureReason::PolicyInvalid);
    assert_eq!(service.state().await, invalid);
    let (path, stop) = serve_admin(&service);
    let mut stream = at_confirmation(&path, &fixture.config("rates")).await;

    service.lock(WAIT).await.unwrap();
    assert_eq!(service.enter_checking(identity()).await, Ok(invalid));
    send(&mut stream, &Frame::OwnerInput(OwnerInput::new(Zeroizing::new(b"yes".to_vec())))).await;
    let exchanged = converse(&mut stream, &[APPROVAL_PASSPHRASE]).await;

    assert_eq!(error_code(&exchanged.response), ErrorCode::ApprovalUnavailable);
    assert_eq!(service.state().await, invalid);
    assert!(!fixture.path("etc/config.toml.pending").exists());
    let _ = stop.send(());
}
