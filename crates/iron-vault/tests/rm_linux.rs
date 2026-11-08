//! `rm` end to end over a real admin socket against a running service context (specification §3.3, §3.13, §3.11;
//! design/credential-commands.md): refused while a route uses the name and before any prompt, the summary and the
//! approval passphrase after it, the removal of the record, and the config check that replaces the serving snapshot.
//!
//! Each test starts from the `config approve` harness: a vault holding `fx_key`, used by the route `fx`, plus an
//! `old_key` that no route uses.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::fs;
use std::sync::Arc;
use std::time::Duration;

use common::approval_harness::{
    APPROVAL_PASSPHRASE, Exchanged, Fixture, WRONG_PASSPHRASE, captured_logs, converse, error_code, get, identity, send, serve_admin,
};
use iron_vault::admin::protocol::{AdminRequest, AdminResponse, Frame, Prompt, ProposedConfig};
use iron_vault::service_context::ServiceContext;
use iron_vault::service_state::ServiceState;
use iron_vault::serving_snapshot::{Admission, ServingSnapshot};
use iron_vault::standing::Standing;
use iron_vault_kinds::CredentialMaterial;
use iron_vault_policy::Port;
use iron_vault_store::{OsFs, PermittedOrigins, RecordId, StateDirLock, StateFileName, Vault, VaultManifest, open_manifest};

const OLD_NAME: &str = "old_key";

/// Adds `old_key` to the vault on disk, before the service starts, and returns its record ID.
fn seed_old_key(fixture: &Fixture) -> RecordId {
    let lock = StateDirLock::acquire(&fixture.path("state")).unwrap();
    let (mut vault, _) = Vault::open(&lock, &OsFs, Arc::new(identity())).unwrap();
    let origins = PermittedOrigins::new([("legacy.example".parse().unwrap(), Port::HTTPS)].into()).unwrap();
    let material = CredentialMaterial::Static { key: "old-secret".into() };
    vault.add(&lock, &OsFs, OLD_NAME.parse().unwrap(), material, origins).unwrap().0
}

fn manifest_bytes(fixture: &Fixture) -> Vec<u8> {
    fs::read(fixture.path("state/manifest.age")).unwrap()
}

fn manifest(fixture: &Fixture) -> VaultManifest {
    open_manifest(&identity(), &manifest_bytes(fixture)).unwrap()
}

fn lists(fixture: &Fixture, name: &str) -> bool {
    manifest(fixture).entries().values().any(|entry| entry.name().as_str() == name)
}

fn record_file(fixture: &Fixture, id: &RecordId) -> std::path::PathBuf {
    fixture.path(&format!("state/{}", StateFileName::record(id)))
}

fn served<F: iron_vault_store::StoreFs + Send + Sync + 'static>(service: &ServiceContext<F>) -> Arc<ServingSnapshot> {
    match service.holder().load() {
        Admission::Serve(snapshot) => snapshot,
        Admission::Refuse(reason) => panic!("expected a served snapshot, got {reason:?}"),
    }
}

fn rm_request(name: &str) -> Frame {
    Frame::Request(AdminRequest::Rm { name: name.to_owned() })
}

/// Sends `rm` for `name` on a new connection and answers the prompts with `answers`.
async fn rm(path: &std::path::Path, name: &str, answers: &[&str]) -> Exchanged {
    let mut stream = tokio::net::UnixStream::connect(path).await.unwrap();
    send(&mut stream, &rm_request(name)).await;
    converse(&mut stream, answers).await
}

fn presence_prompt() -> Prompt {
    Prompt {
        label: "Approval passphrase".to_owned(),
        secret: true,
    }
}

#[tokio::test]
async fn an_unused_healthy_record_is_removed_and_the_serving_snapshot_is_replaced() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let record_id = seed_old_key(&fixture);
    let service = fixture.ready().await;
    let (path, stop) = serve_admin(&service);
    let before = served(&service);
    assert!(before.record(&OLD_NAME.parse().unwrap()).is_some());

    let removed = rm(&path, OLD_NAME, &[APPROVAL_PASSPHRASE]).await;

    assert!(matches!(removed.response, AdminResponse::Success), "{removed:?}");
    assert_eq!(removed.prompts, [presence_prompt()]);
    assert!(removed.notices.contains("remove credential old_key"), "{}", removed.notices);
    assert!(removed.notices.contains(&format!("record: {record_id}")), "{}", removed.notices);
    assert!(removed.notices.contains("kind: static"), "{}", removed.notices);
    assert!(removed.notices.contains("origins: legacy.example:443"), "{}", removed.notices);
    assert!(removed.notices.contains("routes using old_key: none"), "{}", removed.notices);
    assert!(!lists(&fixture, OLD_NAME));
    assert!(!record_file(&fixture, &record_id).exists());
    let names = service
        .list()
        .await
        .unwrap()
        .into_iter()
        .map(|c| c.name.to_string())
        .collect::<Vec<_>>();
    assert_eq!(names, ["fx_key"]);
    assert_eq!(service.state().await, ServiceState::Ready);
    assert!(!Arc::ptr_eq(&before, &served(&service)), "the serving snapshot was not replaced");
    assert!(served(&service).record(&OLD_NAME.parse().unwrap()).is_none());
    assert_eq!(get(&fixture, "fx").await.status, 200);
    let removed_line = logs
        .text()
        .lines()
        .any(|line| line.contains("credential.removed") && line.contains(&record_id.to_string()) && line.contains(OLD_NAME));
    assert!(removed_line, "no credential.removed event for {record_id}");
    let _ = stop.send(());
}

#[tokio::test]
async fn a_damaged_record_can_be_removed() {
    let fixture = Fixture::new().await;
    let record_id = seed_old_key(&fixture);
    fs::write(record_file(&fixture, &record_id), b"not a record").unwrap();
    let service = fixture.ready().await;
    let standing = service
        .list()
        .await
        .unwrap()
        .into_iter()
        .find(|c| c.name.as_str() == OLD_NAME)
        .unwrap();
    assert!(matches!(standing.standing, Standing::Damaged(_)));
    let (path, stop) = serve_admin(&service);

    let removed = rm(&path, OLD_NAME, &[APPROVAL_PASSPHRASE]).await;

    assert!(matches!(removed.response, AdminResponse::Success), "{removed:?}");
    assert!(removed.notices.contains("record damaged"), "{}", removed.notices);
    assert!(removed.notices.contains(&format!("record: {record_id}")), "{}", removed.notices);
    assert!(!lists(&fixture, OLD_NAME));
    assert!(!record_file(&fixture, &record_id).exists());
    assert_eq!(service.state().await, ServiceState::Ready);
    let _ = stop.send(());
}

#[tokio::test]
async fn a_name_a_route_uses_is_refused_before_any_prompt_and_naming_the_route() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    let before = manifest_bytes(&fixture);
    let snapshot = served(&service);
    let (path, stop) = serve_admin(&service);

    let refused = rm(&path, "fx_key", &[]).await;

    assert_eq!(
        error_code(&refused.response),
        iron_vault::admin::protocol::ErrorCode::CredentialInUse
    );
    let AdminResponse::Error { message, .. } = &refused.response else {
        panic!("{refused:?}")
    };
    assert!(message.contains("is used by route fx;"), "{message}");
    assert!(!message.contains("does not hold"), "{message}");
    assert!(refused.prompts.is_empty() && refused.notices.is_empty(), "{refused:?}");
    assert_eq!(manifest_bytes(&fixture), before);
    assert!(Arc::ptr_eq(&snapshot, &served(&service)));
    let _ = stop.send(());
}

#[tokio::test]
async fn a_wrong_approval_passphrase_is_denied_and_writes_nothing() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let record_id = seed_old_key(&fixture);
    let service = fixture.ready().await;
    let before = manifest_bytes(&fixture);
    let (path, stop) = serve_admin(&service);

    let denied = rm(&path, OLD_NAME, &[WRONG_PASSPHRASE]).await;

    assert_eq!(error_code(&denied.response), iron_vault::admin::protocol::ErrorCode::ApprovalDenied);
    assert_eq!(manifest_bytes(&fixture), before);
    assert!(record_file(&fixture, &record_id).exists());
    logs.assert_no_passphrase();
    assert_eq!(service.state().await, ServiceState::Ready);
    let _ = stop.send(());
}

#[tokio::test]
async fn an_unknown_name_an_invalid_name_and_a_locked_service_are_refused_before_any_prompt() {
    use iron_vault::admin::protocol::ErrorCode;
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    let (path, stop) = serve_admin(&service);

    let unknown = rm(&path, "nothing_here", &[]).await;
    let invalid = rm(&path, "Bad Name", &[]).await;
    assert_eq!(error_code(&unknown.response), ErrorCode::UnknownCredential);
    assert_eq!(error_code(&invalid.response), ErrorCode::CredentialInvalid);

    service.lock(Duration::from_secs(5)).await.unwrap();
    let locked = rm(&path, "fx_key", &[]).await;
    assert_eq!(error_code(&locked.response), ErrorCode::WrongState);
    [unknown, invalid, locked]
        .iter()
        .for_each(|refused| assert!(refused.prompts.is_empty() && refused.notices.is_empty(), "{refused:?}"));
    let _ = stop.send(());
}

#[tokio::test]
async fn a_removed_name_added_again_is_a_new_record_that_no_active_route_uses() {
    let fixture = Fixture::new().await;
    let old_id = seed_old_key(&fixture);
    let service = fixture.ready().await;
    let (path, stop) = serve_admin(&service);
    let removed = rm(&path, OLD_NAME, &[APPROVAL_PASSPHRASE]).await;
    assert!(matches!(removed.response, AdminResponse::Success), "{removed:?}");

    let origins = PermittedOrigins::new([("attacker.example".parse().unwrap(), Port::HTTPS)].into()).unwrap();
    let material = CredentialMaterial::Static {
        key: "another-secret".into(),
    };
    let new_id = service.add_credential(OLD_NAME.parse().unwrap(), material, origins).await.unwrap();

    assert_ne!(new_id, old_id);
    let snapshot = served(&service);
    let used = snapshot
        .policy()
        .config()
        .routes()
        .values()
        .map(|route| route.credential().to_string())
        .collect::<Vec<_>>();
    assert_eq!(used, ["fx_key"], "no active route may name the re-added credential");
    assert!(lists(&fixture, OLD_NAME));
    assert_eq!(get(&fixture, "fx").await.status, 200);
    let _ = stop.send(());
}

#[tokio::test]
async fn an_rm_during_an_approval_is_busy_and_prompts_nothing() {
    let fixture = Fixture::new().await;
    seed_old_key(&fixture);
    let service = fixture.ready().await;
    let before = manifest_bytes(&fixture);
    let (path, stop) = serve_admin(&service);
    let mut approval = tokio::net::UnixStream::connect(&path).await.unwrap();
    let config = ProposedConfig::new(fixture.config("fx").into_bytes()).unwrap();
    send(&mut approval, &Frame::Request(AdminRequest::ConfigApprove(config))).await;
    while !matches!(common::approval_harness::read_frame(&mut approval).await, Frame::Prompt(_)) {}

    let busy = rm(&path, OLD_NAME, &[]).await;

    assert_eq!(error_code(&busy.response), iron_vault::admin::protocol::ErrorCode::Busy);
    assert!(busy.prompts.is_empty() && busy.notices.is_empty(), "{busy:?}");
    assert_eq!(manifest_bytes(&fixture), before);
    let _ = stop.send(());
}

#[tokio::test]
async fn a_lock_at_the_presence_prompt_cancels_the_removal() {
    let fixture = Fixture::new().await;
    let record_id = seed_old_key(&fixture);
    let service = fixture.ready().await;
    let before = manifest_bytes(&fixture);
    let (path, stop) = serve_admin(&service);
    let mut stream = tokio::net::UnixStream::connect(&path).await.unwrap();
    send(&mut stream, &rm_request(OLD_NAME)).await;
    while !matches!(common::approval_harness::read_frame(&mut stream).await, Frame::Prompt(_)) {}

    let locking = tokio::spawn({
        let service = Arc::clone(&service);
        async move { service.lock(Duration::from_secs(5)).await }
    });
    let cancelled = converse(&mut stream, &[]).await;

    locking.await.unwrap().unwrap();
    assert_eq!(
        error_code(&cancelled.response),
        iron_vault::admin::protocol::ErrorCode::ApprovalUnavailable
    );
    assert_eq!(manifest_bytes(&fixture), before);
    assert!(record_file(&fixture, &record_id).exists());
    assert_eq!(service.state().await, ServiceState::Locked);
    let _ = stop.send(());
}
