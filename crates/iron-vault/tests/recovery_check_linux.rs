//! `recovery check` end to end over a real admin socket against a running service context (specification §16, §18, §19;
//! design/recovery.md): the right key in Locked and Ready, a key of another vault, text that is no key, the states and
//! checks that end before the prompt, and the service-wide lock.
//!
//! Each test enrols a fresh recovery key in the harness vault's `identity.age`. The log buffer is shared by every test of
//! this binary, so each test finds its own records by its vault ID, and every key is unique.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use common::approval_harness::{CONFIRM, Exchanged, Fixture, captured_logs, converse, error_code, identity, read_frame, send, serve_admin};
use iron_vault::admin::protocol::{AdminRequest, AdminResponse, ErrorCode, Frame, OwnerInput};
use iron_vault::service_context::ServiceContext;
use iron_vault::service_state::{FailureReason, ServiceState};
use iron_vault_store::{
    OsFs, RecipientSet, RecoveryCheckRecord, RecoveryKey, StateDirLock, StoreFs, VaultId, open_manifest, wrap_identity,
    write_identity_envelope,
};
use secrecy::ExposeSecret;
use zeroize::Zeroizing;

const KEY_PROMPT: &str = "Recovery key";
const FILES: [&str; 3] = ["state/identity.age", "state/approval.age", "state/manifest.age"];

/// A fixture whose `identity.age` lists a fresh recovery key, and that key's text.
fn with_recovery_key(fixture: &Fixture) -> String {
    let (secret, recovery) = RecoveryKey::generate();
    let (_, other) = RecoveryKey::generate();
    let lock = StateDirLock::acquire(&fixture.path("state")).unwrap();
    let envelope = wrap_identity(&identity(), &RecipientSet::new([recovery, other]).unwrap()).unwrap();
    write_identity_envelope(&lock, &OsFs, &envelope).unwrap();
    secret.expose_secret().to_owned()
}

fn vault_id(fixture: &Fixture) -> VaultId {
    open_manifest(&identity(), &fs::read(fixture.path("state/manifest.age")).unwrap())
        .unwrap()
        .vault_id()
}

fn files(fixture: &Fixture) -> Vec<Vec<u8>> {
    FILES.iter().map(|file| fs::read(fixture.path(file)).unwrap()).collect()
}

/// The check record on disk, read around the running service, which holds the state directory lock.
fn record(fixture: &Fixture) -> Option<RecoveryCheckRecord> {
    fs::read(fixture.path("state/recovery.toml"))
        .ok()
        .map(|bytes| RecoveryCheckRecord::decode(&bytes).unwrap())
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn key_prompt() -> iron_vault::admin::protocol::Prompt {
    iron_vault::admin::protocol::Prompt {
        label: KEY_PROMPT.to_owned(),
        secret: true,
    }
}

/// Sends `recovery check` on a new connection and answers the prompts with `answers`.
async fn check(path: &std::path::Path, answers: &[&str]) -> Exchanged {
    let mut stream = tokio::net::UnixStream::connect(path).await.unwrap();
    send(&mut stream, &Frame::Request(AdminRequest::RecoveryCheck)).await;
    converse(&mut stream, answers).await
}

fn message(response: &AdminResponse) -> &str {
    match response {
        AdminResponse::Error { message, .. } => message,
        other => panic!("expected an error, got {other:?}"),
    }
}

fn opened(exchanged: &Exchanged) -> (VaultId, u64, bool) {
    match &exchanged.response {
        AdminResponse::RecoveryCheck {
            vault_id,
            checked_at,
            recorded,
        } => (*vault_id, *checked_at, *recorded),
        other => panic!("expected a recovery check result, got {other:?}"),
    }
}

async fn lock<F: iron_vault_store::StoreFs + Send + Sync + 'static>(service: &ServiceContext<F>) {
    service.lock(Duration::from_secs(5)).await.unwrap();
}

#[tokio::test]
async fn the_right_key_opens_the_vault_in_ready_and_in_locked_and_changes_nothing_else() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let key = with_recovery_key(&fixture);
    let id = vault_id(&fixture);
    let service = fixture.ready().await;
    let (path, stop) = serve_admin(&service);
    let before = files(&fixture);
    assert_eq!(record(&fixture), None);

    for state in [ServiceState::Ready, ServiceState::Locked] {
        if state == ServiceState::Locked {
            lock(&service).await;
        }
        let started = now();
        let exchanged = check(&path, &[&key]).await;

        let (checked, at, recorded) = opened(&exchanged);
        assert_eq!((checked, recorded, exchanged.prompts), (id, true, vec![key_prompt()]));
        assert!((started..=now()).contains(&at), "{at}");
        let saved = record(&fixture).unwrap();
        assert_eq!(saved.last_checked().unwrap().unix_seconds(), at);
        assert!(saved.since().unix_seconds() <= at);
        assert_eq!(service.state().await, state);
        assert_eq!(files(&fixture), before);
    }
    let events = logs.events("recovery.checked");
    let ours: Vec<_> = events.iter().filter(|e| e["vault_id"] == id.to_string().as_str()).collect();
    assert_eq!(ours.len(), 2);
    assert!(
        ours.iter()
            .all(|e| e["level"] == "INFO" && e["recovery_outcome"] == "opened" && e["recorded"] == true)
    );
    assert!(!logs.text().contains(&key[16..]), "the recovery key reached the log");
    let _ = stop.send(());
}

#[tokio::test]
async fn a_second_check_keeps_the_record_start_and_moves_the_check_time() {
    let fixture = Fixture::new().await;
    let key = with_recovery_key(&fixture);
    let service = fixture.ready().await;
    let (path, stop) = serve_admin(&service);
    check(&path, &[&key]).await;
    let first = record(&fixture).unwrap();

    tokio::time::sleep(Duration::from_millis(1100)).await;
    let second = opened(&check(&path, &[&key]).await);

    let saved = record(&fixture).unwrap();
    assert_eq!(saved.since(), first.since());
    assert!(saved.last_checked() > first.last_checked());
    assert_eq!(saved.last_checked().unwrap().unix_seconds(), second.1);
    let _ = stop.send(());
}

#[tokio::test]
async fn another_vaults_key_fails_with_the_fixed_message_and_leaves_the_record() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let key = with_recovery_key(&fixture);
    let (foreign, _) = RecoveryKey::generate();
    let foreign = foreign.expose_secret().to_owned();
    let service = fixture.ready().await;
    let (path, stop) = serve_admin(&service);
    // A record exists from an earlier good check, so the failed one has bytes to leave unchanged.
    opened(&check(&path, &[&key]).await);
    let saved = fs::read(fixture.path("state/recovery.toml")).unwrap();
    let before = files(&fixture);

    let failed = check(&path, &[&foreign]).await;

    assert_eq!(error_code(&failed.response), ErrorCode::RecoveryCheckFailed);
    assert_eq!(message(&failed.response), "the recovery key does not open this vault");
    assert_eq!(fs::read(fixture.path("state/recovery.toml")).unwrap(), saved);
    assert_eq!(files(&fixture), before);
    let warned = logs
        .events("recovery.checked")
        .into_iter()
        .any(|e| e["level"] == "WARN" && e["recovery_outcome"] == "failed" && e["recovery_failure"] == "not_a_recipient");
    assert!(warned);
    assert!(!logs.text().contains(&foreign[16..]), "the key reached the log");
    assert!(!message(&failed.response).contains(&foreign[16..]));
    let _ = stop.send(());
}

#[tokio::test]
async fn text_that_is_no_recovery_key_is_invalid_and_touches_no_file() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    with_recovery_key(&fixture);
    let service = fixture.ready().await;
    let (path, stop) = serve_admin(&service);
    // An unreadable identity.age would make the store check fail with another code if it were read.
    fs::write(fixture.path("state/identity.age"), b"not an envelope").unwrap();
    let garbage = "GARBAGE-not-a-key-77e1";

    let invalid = check(&path, &[garbage]).await;

    assert_eq!(error_code(&invalid.response), ErrorCode::RecoveryKeyInvalid);
    assert!(!message(&invalid.response).contains(garbage));
    assert_eq!(record(&fixture), None);
    assert!(
        logs.events("recovery.checked")
            .iter()
            .any(|e| e["recovery_outcome"] == "invalid" && e["level"] == "WARN")
    );
    assert!(!logs.text().contains(garbage));
    let empty = check(&path, &[""]).await;
    assert_eq!(error_code(&empty.response), ErrorCode::RecoveryKeyInvalid);
    let _ = stop.send(());
}

#[tokio::test]
async fn an_unreadable_envelope_is_unavailable_not_a_bad_key() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let key = with_recovery_key(&fixture);
    let service = fixture.ready().await;
    let (path, stop) = serve_admin(&service);
    fs::remove_file(fixture.path("state/identity.age")).unwrap();

    let unavailable = check(&path, &[&key]).await;

    assert_eq!(error_code(&unavailable.response), ErrorCode::RecoveryCheckUnavailable);
    assert!(message(&unavailable.response).contains("identity.age"), "{unavailable:?}");
    assert_eq!(record(&fixture), None);
    let event = logs
        .events("recovery.checked")
        .into_iter()
        .find(|e| e["recovery_outcome"] == "unavailable" && e["file"] == "identity.age")
        .unwrap();
    assert_eq!(
        (event["level"].as_str(), event["error_kind"].as_str()),
        (Some("WARN"), Some("not_found"))
    );
    let _ = stop.send(());
}

#[tokio::test]
async fn an_unavailable_service_and_a_vault_that_is_not_initialized_end_before_the_prompt() {
    let fixture = Fixture::new().await;
    with_recovery_key(&fixture);
    let service = fixture.ready().await;
    let (path, stop) = serve_admin(&service);

    fs::write(fixture.path("etc/config.toml"), b"tampered").unwrap();
    assert_eq!(service.reload().await, Ok(ServiceState::Unavailable(FailureReason::PolicyInvalid)));
    let wrong_state = check(&path, &[]).await;
    assert_eq!(error_code(&wrong_state.response), ErrorCode::WrongState);
    assert!(wrong_state.prompts.is_empty() && wrong_state.notices.is_empty(), "{wrong_state:?}");

    lock(&service).await;
    fs::remove_file(fixture.path("state/manifest.age")).unwrap();
    let uninitialized = check(&path, &[]).await;
    assert_eq!(error_code(&uninitialized.response), ErrorCode::RecoveryCheckUnavailable);
    assert!(uninitialized.prompts.is_empty(), "{uninitialized:?}");
    let _ = stop.send(());
}

#[tokio::test]
async fn a_held_service_wide_lock_is_busy_and_the_check_does_not_wait() {
    let fixture = Fixture::new().await;
    let key = with_recovery_key(&fixture);
    let service = fixture.ready().await;
    let (path, stop) = serve_admin(&service);
    let mut approval = tokio::net::UnixStream::connect(&path).await.unwrap();
    send(&mut approval, &common::approval_harness::approve_request(&fixture.config("fx"))).await;
    // The approval holds the service-wide lock from its summary through its prompts.
    loop {
        match read_frame(&mut approval).await {
            Frame::Prompt(prompt) if prompt.label.contains(CONFIRM) => break,
            Frame::Notice(_) => {}
            other => panic!("unexpected frame {other:?}"),
        }
    }

    let busy = tokio::time::timeout(Duration::from_secs(5), check(&path, &[&key])).await.unwrap();

    assert_eq!(error_code(&busy.response), ErrorCode::Busy);
    assert_eq!(record(&fixture), None);
    send(&mut approval, &Frame::OwnerInput(OwnerInput::new(Zeroizing::new(b"no".to_vec())))).await;
    let _ = stop.send(());
}

/// The real filesystem, except that once armed the rename onto `recovery.toml`, or the directory fsync after it, fails.
#[derive(Clone, Default)]
struct RecordFailingFs {
    armed: Arc<AtomicBool>,
    fail_rename: bool,
    fail_sync_dir: bool,
}

impl RecordFailingFs {
    fn failing(fail_rename: bool, fail_sync_dir: bool) -> Self {
        Self {
            fail_rename,
            fail_sync_dir,
            ..Self::default()
        }
    }

    fn armed(&self) -> bool {
        self.armed.load(Ordering::SeqCst)
    }
}

impl StoreFs for RecordFailingFs {
    type File = fs::File;

    fn create_private(&self, path: &Path) -> io::Result<fs::File> {
        OsFs.create_private(path)
    }

    fn write_all(&self, file: &mut fs::File, bytes: &[u8]) -> io::Result<()> {
        OsFs.write_all(file, bytes)
    }

    fn sync_file(&self, file: &fs::File) -> io::Result<()> {
        OsFs.sync_file(file)
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        if self.armed() && self.fail_rename && to.file_name().is_some_and(|name| name == "recovery.toml") {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        OsFs.rename(from, to)
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        OsFs.remove_file(path)
    }

    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        if self.armed() && self.fail_sync_dir {
            return Err(io::ErrorKind::Other.into());
        }
        OsFs.sync_dir(dir)
    }

    fn list_dir(&self, dir: &Path) -> io::Result<Vec<OsString>> {
        OsFs.list_dir(dir)
    }

    fn read_bounded(&self, path: &Path, max_len: u64) -> io::Result<Vec<u8>> {
        OsFs.read_bounded(path, max_len)
    }
}

#[tokio::test]
async fn a_failed_record_rename_still_answers_success_unrecorded_and_leaves_the_record() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let key = with_recovery_key(&fixture);
    let id = vault_id(&fixture);
    let fs = RecordFailingFs::failing(true, false);
    let service = fixture.ready_on(fs.clone()).await;
    let (path, stop) = serve_admin(&service);
    opened(&check(&path, &[&key]).await);
    let saved = fs::read(fixture.path("state/recovery.toml")).unwrap();
    fs.armed.store(true, Ordering::SeqCst);

    let exchanged = check(&path, &[&key]).await;

    let (checked, _, recorded) = opened(&exchanged);
    assert_eq!((checked, recorded), (id, false));
    assert_eq!(fs::read(fixture.path("state/recovery.toml")).unwrap(), saved);
    let unsaved = logs
        .events("recovery.checked")
        .into_iter()
        .find(|e| e["vault_id"] == id.to_string().as_str() && e["recorded"] == false)
        .unwrap();
    assert_eq!(
        (
            unsaved["level"].as_str(),
            unsaved["recovery_outcome"].as_str(),
            unsaved["error_kind"].as_str()
        ),
        (Some("INFO"), Some("opened"), Some("permission_denied"))
    );
    let _ = stop.send(());
}

#[tokio::test]
async fn a_failed_directory_fsync_after_the_rename_counts_as_recorded() {
    let fixture = Fixture::new().await;
    let key = with_recovery_key(&fixture);
    let fs = RecordFailingFs::failing(false, true);
    let service = fixture.ready_on(fs.clone()).await;
    let (path, stop) = serve_admin(&service);
    fs.armed.store(true, Ordering::SeqCst);

    let (_, at, recorded) = opened(&check(&path, &[&key]).await);

    assert!(recorded);
    assert_eq!(record(&fixture).unwrap().last_checked().unwrap().unix_seconds(), at);
    let _ = stop.send(());
}
