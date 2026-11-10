//! `replace` end to end over a real admin socket against a running service context (design/credential-commands.md):
//! the vault change check before any prompt, the summary, owner presence before the secret, a `lock` that cancels the
//! secret prompt, and the write whose config check serves the new secret. Every test's log goes to one captured buffer
//! at TRACE, which must never hold a passphrase or a secret typed at a prompt.
//!
//! Each test uses the `config approve` harness: a vault holding `fx_key`, used by the route `fx` that the caller `agent`
//! is granted, with a software approver sealed under [`APPROVAL_PASSPHRASE`].

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::fs;
use std::sync::Arc;

use common::WAIT;
use common::approval_harness::{
    APPROVAL_PASSPHRASE, Captured, Exchanged, Fixture, WRONG_PASSPHRASE, captured_logs, converse, error_code, get, identity, read_frame,
    send, spawn_admin,
};
use iron_vault::admin::protocol::{AdminRequest, AdminResponse, ErrorCode, Frame, OwnerInput, Prompt, RequestedOrigin};
use iron_vault::service_context::ServiceContext;
use iron_vault::service_state::ServiceState;
use iron_vault::serving_snapshot::{Admission, ServingSnapshot};
use iron_vault_policy::{CredentialKind, Port};
use iron_vault_store::{RecordId, StateFileName, open_manifest};
use tokio::net::UnixStream;
use zeroize::Zeroizing;

/// The new key typed at the secret prompt; distinctive, so a search of the logs and notices cannot match anything else.
const NEW_SECRET: &str = "REPLACE-SECRET-91c7e4";

fn manifest_bytes(fixture: &Fixture) -> Vec<u8> {
    fs::read(fixture.path("state/manifest.age")).unwrap()
}

/// The record ID the manifest on disk lists for `fx_key`, read without the state-directory lock the service holds.
fn record_id(fixture: &Fixture) -> RecordId {
    let manifest = open_manifest(&identity(), &manifest_bytes(fixture)).unwrap();
    let entries = manifest.entries().iter();
    entries
        .filter(|(_, entry)| entry.name().as_str() == "fx_key")
        .map(|(id, _)| *id)
        .next()
        .unwrap()
}

fn record_path(fixture: &Fixture, id: &RecordId) -> std::path::PathBuf {
    fixture.path(&format!("state/{}", StateFileName::record(id)))
}

fn served(service: &ServiceContext) -> Arc<ServingSnapshot> {
    match service.holder().load() {
        Admission::Serve(snapshot) => snapshot,
        Admission::Refuse(reason) => panic!("expected a served snapshot, got {reason:?}"),
    }
}

/// `replace fx_key` as a static key permitted at `origins`.
fn replace_request(origins: &[(&str, u16)]) -> Frame {
    let origins = origins.iter().map(|(host, port)| RequestedOrigin {
        host: (*host).to_owned(),
        port: Port::try_from(*port).unwrap(),
    });
    Frame::Request(AdminRequest::Replace {
        name: "fx_key".to_owned(),
        kind: CredentialKind::Static,
        origins: origins.collect(),
    })
}

/// The fixture's own origin, which the route `fx` forwards to.
fn upstream_origin(fixture: &Fixture) -> (&'static str, u16) {
    ("localhost", fixture.upstream().port())
}

/// Sends `request` and answers the prompts in turn with `answers`.
async fn replace(service: &Arc<ServiceContext>, request: Frame, answers: &[&str]) -> Exchanged {
    let (path, stop, task) = spawn_admin(service);
    let mut stream = UnixStream::connect(path).await.unwrap();
    send(&mut stream, &request).await;
    let exchanged = converse(&mut stream, answers).await;
    let _ = stop.send(());
    let _ = task.await;
    exchanged
}

fn prompt(label: &str) -> Prompt {
    Prompt {
        label: label.to_owned(),
        secret: true,
    }
}

/// Neither passphrase nor the new secret reached the log or what the owner was shown.
fn assert_nothing_typed_leaked(logs: &Captured, exchanged: &Exchanged) {
    logs.assert_no_passphrase();
    let text = logs.text();
    assert!(!text.contains(NEW_SECRET), "the new secret reached the log:\n{text}");
    let shown = format!("{}{:?}", exchanged.notices, exchanged.response);
    [APPROVAL_PASSPHRASE, WRONG_PASSPHRASE, NEW_SECRET]
        .iter()
        .for_each(|typed| assert!(!shown.contains(typed), "{typed} was shown: {shown}"));
}

#[tokio::test]
async fn a_healthy_replace_serves_the_new_secret_and_the_old_snapshot_drops_when_its_requests_end() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    let old_id = record_id(&fixture);
    // Held as a request admitted before the change would hold it.
    let old = served(&service);
    let origin = upstream_origin(&fixture);

    let exchanged = replace(&service, replace_request(&[origin]), &[APPROVAL_PASSPHRASE, NEW_SECRET]).await;

    let AdminResponse::Replace { record_id: new_id } = exchanged.response else {
        panic!("expected success, got {:?}", exchanged.response);
    };
    assert_ne!(new_id, old_id);
    assert_eq!(record_id(&fixture), new_id);
    assert!(!record_path(&fixture, &old_id).exists(), "the old record file was removed");
    assert_eq!(
        exchanged.prompts,
        [
            prompt("Approval passphrase for \"approval passphrase\""),
            prompt("Secret for fx_key")
        ]
    );
    let origin_text = format!("localhost:{}", origin.1);
    assert_eq!(
        exchanged.notices,
        format!(
            "replace credential fx_key\n  record: {old_id} -> a new record ID, assigned when the change is written\n  \
             kind: static -> static\n  origins: {origin_text} -> {origin_text}\n  routes using fx_key: fx (callers: agent)\n"
        )
    );
    assert_eq!(service.state().await, ServiceState::Ready);
    assert_eq!(get(&fixture, "fx").await.status, 200);
    let last = fixture.upstream().requests().pop().unwrap();
    assert!(
        last.headers().contains(&("x-api-key".to_owned(), NEW_SECRET.to_owned())),
        "{}",
        last.head
    );
    let probe = Arc::downgrade(&old);
    drop(old);
    assert!(probe.upgrade().is_none(), "the old snapshot outlived its last request");
    let (old_field, new_field) = (format!("\"old_record_id\":\"{old_id}\""), format!("\"record_id\":\"{new_id}\""));
    let logged = logs.text();
    let line = logged
        .lines()
        .find(|line| line.contains("credential.replaced") && line.contains(&new_field));
    assert!(
        line.is_some_and(|line| line.contains(&old_field) && line.contains("\"old_kind\":\"static\"")),
        "{logged}"
    );
    assert_nothing_typed_leaked(&logs, &exchanged);
}

#[tokio::test]
async fn origins_that_drop_a_routes_upstream_are_refused_before_any_prompt_naming_the_route() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    let before = manifest_bytes(&fixture);

    let exchanged = replace(&service, replace_request(&[("other.example", 443)]), &[]).await;

    assert_eq!(error_code(&exchanged.response), ErrorCode::CredentialInUse);
    let AdminResponse::Error { message, .. } = &exchanged.response else {
        unreachable!()
    };
    assert!(message.contains("fx"), "{message}");
    assert!(exchanged.prompts.is_empty() && exchanged.notices.is_empty());
    assert_eq!(manifest_bytes(&fixture), before);
}

#[tokio::test]
async fn replacing_a_damaged_record_makes_its_routes_available_again() {
    let fixture = Fixture::new().await;
    fs::remove_file(record_path(&fixture, &record_id(&fixture))).unwrap();
    let service = fixture.start().await;
    assert_ne!(
        get(&fixture, "fx").await.status,
        200,
        "the route is unavailable while its record is damaged"
    );

    let exchanged = replace(
        &service,
        replace_request(&[upstream_origin(&fixture)]),
        &[APPROVAL_PASSPHRASE, NEW_SECRET],
    )
    .await;

    assert!(
        matches!(exchanged.response, AdminResponse::Replace { .. }),
        "{:?}",
        exchanged.response
    );
    assert!(
        exchanged.notices.contains("  kind: unknown (record damaged: "),
        "{}",
        exchanged.notices
    );
    assert!(
        exchanged.notices.ends_with("  routes available again: fx\n"),
        "{}",
        exchanged.notices
    );
    assert_eq!(service.state().await, ServiceState::Ready);
    assert_eq!(get(&fixture, "fx").await.status, 200);
}

#[tokio::test]
async fn a_wrong_approval_passphrase_writes_nothing_and_asks_for_no_secret() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    let before = manifest_bytes(&fixture);

    let exchanged = replace(&service, replace_request(&[upstream_origin(&fixture)]), &[WRONG_PASSPHRASE]).await;

    assert_eq!(error_code(&exchanged.response), ErrorCode::ApprovalDenied);
    assert_eq!(exchanged.prompts, [prompt("Approval passphrase for \"approval passphrase\"")]);
    assert_eq!(manifest_bytes(&fixture), before);
    assert_eq!(service.state().await, ServiceState::Ready);
    assert_nothing_typed_leaked(&logs, &exchanged);
}

#[tokio::test]
async fn a_lock_at_the_secret_prompt_cancels_the_change_with_nothing_written() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    let before = manifest_bytes(&fixture);
    let (path, stop, task) = spawn_admin(&service);
    let mut stream = UnixStream::connect(path).await.unwrap();
    send(&mut stream, &replace_request(&[upstream_origin(&fixture)])).await;
    let passphrase_prompt = loop {
        if let Frame::Prompt(prompt) = read_frame(&mut stream).await {
            break prompt;
        }
    };
    assert_eq!(passphrase_prompt, prompt("Approval passphrase for \"approval passphrase\""));
    let passphrase = OwnerInput::new(Zeroizing::new(APPROVAL_PASSPHRASE.as_bytes().to_vec()));
    send(&mut stream, &Frame::OwnerInput(passphrase)).await;
    assert!(matches!(read_frame(&mut stream).await, Frame::Prompt(prompt) if prompt.label == "Secret for fx_key"));

    let locking = tokio::spawn({
        let service = Arc::clone(&service);
        async move { service.lock(WAIT).await }
    });
    let response = read_frame(&mut stream).await;

    let Frame::Response(response) = response else {
        panic!("expected the response, got {response:?}");
    };
    assert_eq!(error_code(&response), ErrorCode::WrongState);
    tokio::time::timeout(WAIT, locking).await.unwrap().unwrap().unwrap();
    assert_eq!(service.state().await, ServiceState::Locked);
    assert_eq!(manifest_bytes(&fixture), before);
    let _ = stop.send(());
    let _ = task.await;
}

#[tokio::test]
async fn a_cli_gone_at_the_secret_prompt_writes_nothing_and_releases_the_service_wide_lock() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    let before = manifest_bytes(&fixture);
    let (path, stop, task) = spawn_admin(&service);
    let mut stream = UnixStream::connect(&path).await.unwrap();
    send(&mut stream, &replace_request(&[upstream_origin(&fixture)])).await;
    let passphrase = loop {
        if let Frame::Prompt(_) = read_frame(&mut stream).await {
            break OwnerInput::new(Zeroizing::new(APPROVAL_PASSPHRASE.as_bytes().to_vec()));
        }
    };
    send(&mut stream, &Frame::OwnerInput(passphrase)).await;
    assert!(matches!(read_frame(&mut stream).await, Frame::Prompt(prompt) if prompt.label == "Secret for fx_key"));

    drop(stream);
    let next = tokio::time::timeout(WAIT, next_replace_not_busy(&path, &fixture)).await.unwrap();

    assert_eq!(error_code(&next.response), ErrorCode::ApprovalDenied);
    assert_eq!(manifest_bytes(&fixture), before);
    assert_eq!(service.state().await, ServiceState::Ready);
    assert_nothing_typed_leaked(&logs, &next);
    let _ = stop.send(());
    let _ = task.await;
}

/// A `replace` with the wrong passphrase over a new connection to `path`, retried while the abandoned one still holds
/// the service-wide lock: the handler sees its CLI gone only when it next reads.
async fn next_replace_not_busy(path: &std::path::Path, fixture: &Fixture) -> Exchanged {
    loop {
        let mut stream = UnixStream::connect(path).await.unwrap();
        send(&mut stream, &replace_request(&[upstream_origin(fixture)])).await;
        let exchanged = converse(&mut stream, &[WRONG_PASSPHRASE]).await;
        if error_code(&exchanged.response) != ErrorCode::Busy {
            return exchanged;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}
