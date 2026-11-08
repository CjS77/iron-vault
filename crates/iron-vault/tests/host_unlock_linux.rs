//! The Container profile's host unlock at startup (specification §3.12; design/docker-compose.md, "In the container"):
//! a good unlock handoff takes the service from Starting through Checking to Ready with no `unlock`, and every other
//! outcome leaves it Locked with passphrase `unlock` still offered.
//!
//! The handoff lives in a private directory under `$XDG_RUNTIME_DIR` or `$HOME`, because the `UnlockHandoff` rule
//! refuses a sticky `/tmp` ancestor. The log buffer is shared by every test of this binary, so the tests take turns and
//! each counts only the records written while it held the turn.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use common::approval_harness::{Captured, Fixture, assert_audit_record, captured_logs, converse_revealing, get, identity, send};
use iron_vault::admin::ADMIN_SOCKET_NAME;
use iron_vault::admin::dispatch::Handlers;
use iron_vault::admin::principal::AdminPrincipals;
use iron_vault::admin::protocol::{AdminRequest, AdminResponse, ErrorCode, Frame};
use iron_vault::admin::server::{AdminServer, Limits};
use iron_vault::admin::socket::AdminSocket;
use iron_vault::deployment::DeploymentProfile;
use iron_vault::hardening::{LockUnavailable, MemoryProtection};
use iron_vault::logging::LogSwitch;
use iron_vault::path_metadata::invoking_user;
use iron_vault::service_context::ServiceContext;
use iron_vault::service_state::ServiceState;
use iron_vault_store::{
    OperationalIdentity, OsFs, Passphrase, RecipientRole, RecipientSet, RecoveryKey, StateDirLock, seal_passphrase_envelope_for_tests,
    wrap_identity, write_identity_envelope, write_passphrase_envelope,
};
use secrecy::{ExposeSecret, SecretString};
use tokio::net::UnixStream;
use tokio::sync::{Mutex, MutexGuard};

const PASSPHRASE: &str = "PASSPHRASE-host-unlock-5d1a";
const EVENT: &str = "vault.host-unlock";

/// One test at a time, so the records a test counts are its own.
static TURN: Mutex<()> = Mutex::const_new(());

/// A private `0700` directory holding the handoff, removed on drop.
struct HandoffDir(PathBuf);

impl HandoffDir {
    fn new() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let base = std::env::var_os("XDG_RUNTIME_DIR").or_else(|| std::env::var_os("HOME")).unwrap();
        let dir = PathBuf::from(base).join(format!("iv-hu-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        Self(dir)
    }

    fn path(&self) -> PathBuf {
        self.0.join("host-unlock")
    }

    /// Writes `secret` as the handoff, `0400` as the host would leave it.
    fn write(&self, secret: &str) -> PathBuf {
        let path = self.path();
        fs::write(&path, format!("{secret}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        path
    }
}

impl Drop for HandoffDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The harness vault with `identity.age` wrapped for an operational identity sealed to [`PASSPHRASE`] and for a fresh
/// host unlock identity, whose secret text this returns.
fn with_host_key(fixture: &Fixture) -> String {
    let (operational, operational_key) = OperationalIdentity::generate();
    let (host, host_key) = RecoveryKey::generate();
    let lock = StateDirLock::acquire(&fixture.path("state")).unwrap();
    let envelope = wrap_identity(&identity(), &RecipientSet::new([operational_key, host_key]).unwrap()).unwrap();
    write_identity_envelope(&lock, &OsFs, &envelope).unwrap();
    let sealed = seal_passphrase_envelope_for_tests(&operational, &passphrase()).unwrap();
    write_passphrase_envelope(&lock, &OsFs, &sealed).unwrap();
    host.expose_secret().to_owned()
}

fn passphrase() -> Passphrase {
    Passphrase::new(SecretString::from(PASSPHRASE)).unwrap()
}

fn start(fixture: &Fixture, profile: DeploymentProfile, memory: MemoryProtection) -> ServiceContext {
    fixture.start_as(
        OsFs,
        LogSwitch::stdout_for_tests(invoking_user().unwrap()).unwrap(),
        profile,
        memory,
    )
}

fn container(fixture: &Fixture) -> ServiceContext {
    start(fixture, DeploymentProfile::Container, MemoryProtection::Locked)
}

/// The turn and the log, with the number of host unlock records already in it.
async fn turn() -> (MutexGuard<'static, ()>, Captured, usize) {
    let turn = TURN.lock().await;
    let logs = captured_logs();
    let before = logs.events(EVENT).len();
    (turn, logs, before)
}

/// The one host unlock record written since `before`, checked to hold `level` and the outcome and refusal labels.
fn assert_one_record(logs: &Captured, before: usize, level: &str, outcome: &str, refusal: Option<&str>) {
    let records = logs.events(EVENT);
    assert_eq!(records.len(), before + 1, "{records:?}");
    let record = &records[before];
    let own: &[&str] = refusal.map_or(&["host_unlock_outcome"], |_| &["host_unlock_outcome", "refusal"]);
    assert_audit_record(record, level, own);
    assert_eq!(
        (record["host_unlock_outcome"].as_str(), record["refusal"].as_str()),
        (Some(outcome), refusal)
    );
}

fn assert_not_logged(logs: &Captured, secret: &str) {
    assert!(!logs.text().contains(secret), "the handoff's secret text reached the log");
}

/// The fallback every refusal must leave: the passphrase still opens the vault.
async fn assert_passphrase_unlock_works(service: &ServiceContext) {
    assert_eq!(service.unlock(passphrase()).await.unwrap(), ServiceState::Ready);
}

#[tokio::test]
async fn a_good_handoff_reaches_ready_and_serves_with_no_unlock() {
    let (_turn, logs, before) = turn().await;
    let fixture = Fixture::new().await;
    let secret = with_host_key(&fixture);
    let dir = HandoffDir::new();
    let handoff = dir.write(&secret);
    let service = container(&fixture);
    assert_eq!(service.state().await, ServiceState::Starting);

    assert_eq!(service.unlock_at_start(&handoff).await, ServiceState::Ready);

    assert_eq!(get(&fixture, "fx").await.status, 200);
    assert_one_record(&logs, before, "INFO", "unlocked", None);
    assert!(
        logs.events("service.lock-transition")
            .iter()
            .any(|record| record["from_state"] == "starting" && record["to_state"] == "checking"),
        "no lock transition from Starting"
    );
    assert_not_logged(&logs, &secret);
}

#[tokio::test]
async fn without_locked_memory_the_handoff_is_never_opened() {
    let (_turn, logs, before) = turn().await;
    let fixture = Fixture::new().await;
    let secret = with_host_key(&fixture);
    let dir = HandoffDir::new();
    // World-readable, so opening it would be refused as untrusted: the memory refusal shows it was never opened.
    let handoff = dir.write(&secret);
    fs::set_permissions(&handoff, fs::Permissions::from_mode(0o644)).unwrap();
    let memory = MemoryProtection::Unavailable(LockUnavailable::LimitTooLow { limit_bytes: 65_536 });
    let service = start(&fixture, DeploymentProfile::Container, memory);

    assert_eq!(service.unlock_at_start(&handoff).await, ServiceState::Locked);

    assert_one_record(&logs, before, "WARN", "refused", Some("memory_unprotected"));
    assert_not_logged(&logs, &secret);
}

#[tokio::test]
async fn a_missing_handoff_leaves_it_locked_for_the_passphrase() {
    let (_turn, logs, before) = turn().await;
    let fixture = Fixture::new().await;
    with_host_key(&fixture);
    let dir = HandoffDir::new();
    let service = container(&fixture);

    assert_eq!(service.unlock_at_start(&dir.path()).await, ServiceState::Locked);

    assert_one_record(&logs, before, "INFO", "absent", None);
    assert_passphrase_unlock_works(&service).await;
}

#[tokio::test]
async fn an_identity_that_is_not_a_recipient_leaves_it_locked_for_the_passphrase() {
    let (_turn, logs, before) = turn().await;
    let fixture = Fixture::new().await;
    with_host_key(&fixture);
    let (stranger, _) = RecoveryKey::generate();
    let dir = HandoffDir::new();
    let handoff = dir.write(stranger.expose_secret());
    let service = container(&fixture);

    assert_eq!(service.unlock_at_start(&handoff).await, ServiceState::Locked);

    assert_one_record(&logs, before, "WARN", "refused", Some("not_a_recipient"));
    assert_not_logged(&logs, stranger.expose_secret());
    assert_passphrase_unlock_works(&service).await;
}

#[tokio::test]
async fn an_uninitialized_vault_stays_locked() {
    let (_turn, logs, before) = turn().await;
    let fixture = Fixture::new().await;
    let secret = with_host_key(&fixture);
    ["state", "etc"].into_iter().for_each(|name| empty(&fixture.path(name)));
    let dir = HandoffDir::new();
    let handoff = dir.write(&secret);
    let service = container(&fixture);

    assert_eq!(service.unlock_at_start(&handoff).await, ServiceState::Locked);

    assert_one_record(&logs, before, "WARN", "refused", Some("not_initialized"));
}

#[tokio::test]
async fn other_profiles_never_try_the_handoff() {
    let (_turn, logs, before) = turn().await;
    let fixture = Fixture::new().await;
    let secret = with_host_key(&fixture);
    let dir = HandoffDir::new();
    let handoff = dir.write(&secret);

    for profile in [DeploymentProfile::Development, DeploymentProfile::Protected] {
        let service = start(&fixture, profile, MemoryProtection::Locked);
        assert_eq!(service.state().await, ServiceState::Locked, "{profile:?}");
        assert_eq!(service.unlock_at_start(&handoff).await, ServiceState::Locked, "{profile:?}");
        drop(service);
    }

    assert_eq!(logs.events(EVENT).len(), before);
}

fn empty(dir: &Path) {
    fs::read_dir(dir)
        .unwrap()
        .for_each(|entry| fs::remove_file(entry.unwrap().path()).unwrap());
}

/// The passphrases and confirmation of an owner who chooses both passphrases and confirms the recovery key.
const APPROVAL_PASSPHRASE: &str = "APPROVAL-host-unlock-7e3c";
const INIT_ANSWERS: [&str; 5] = [PASSPHRASE, PASSPHRASE, APPROVAL_PASSPHRASE, APPROVAL_PASSPHRASE, "yes"];

/// A fresh vault directory and a service of `profile` that reads `init --host-unlock`'s handoff at `handoff`, Locked.
async fn uninitialized(fixture: &Fixture, profile: DeploymentProfile, handoff: &Path) -> Arc<ServiceContext> {
    ["state", "etc"].into_iter().for_each(|name| empty(&fixture.path(name)));
    let service = start(fixture, profile, MemoryProtection::Locked).with_handoff_path(handoff.to_path_buf());
    service.unlock_at_start(handoff).await;
    assert_eq!(service.state().await, ServiceState::Locked);
    Arc::new(service)
}

/// Sends `init` with the host unlock flag as `host_unlock` says and answers its prompts in turn. The admin principal is the
/// test's own account whatever the service's profile, since the Container profile admits root only.
async fn init(service: &Arc<ServiceContext>, host_unlock: bool) -> (AdminResponse, Vec<String>, usize) {
    let paths = service.paths().clone();
    let runtime_dir = paths.runtime_dir.clone().unwrap();
    let socket = AdminSocket::bind(&runtime_dir, paths.owner).unwrap();
    let principals = AdminPrincipals::new(DeploymentProfile::Development, paths.owner.uid);
    let server = AdminServer::new(principals, Handlers::for_service(service), Limits::default());
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(async move { server.serve(socket, async { drop(stopped.await) }).await });
    let mut stream = UnixStream::connect(runtime_dir.join(ADMIN_SOCKET_NAME)).await.unwrap();
    send(&mut stream, &Frame::Request(AdminRequest::Init { host_unlock })).await;
    let (exchanged, revealed) = converse_revealing(&mut stream, &INIT_ANSWERS).await;
    let _ = stop.send(());
    let _ = task.await;
    let prompts = exchanged.prompts.into_iter().map(|prompt| prompt.label).collect();
    (exchanged.response, prompts, revealed.len())
}

fn file_names(fixture: &Fixture, dir: &str) -> Vec<String> {
    fs::read_dir(fixture.path(dir))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect()
}

#[tokio::test]
async fn init_host_unlock_with_no_handoff_is_refused_before_any_prompt_and_writes_nothing() {
    let (_turn, _logs, _before) = turn().await;
    let fixture = Fixture::new().await;
    let dir = HandoffDir::new();
    let service = uninitialized(&fixture, DeploymentProfile::Container, &dir.path()).await;

    let (response, prompts, revealed) = init(&service, true).await;

    let AdminResponse::Error { code, message } = response else {
        panic!("expected a refusal, got {response:?}");
    };
    assert_eq!(code, ErrorCode::InitFailed);
    assert!(
        message.contains("no unlock handoff") && message.contains("nothing was written"),
        "{message}"
    );
    assert_eq!((prompts.len(), revealed), (0, 0));
    assert_eq!(file_names(&fixture, "state"), ["lock"]);
    assert_eq!(file_names(&fixture, "etc"), ["config.toml.lock"]);
}

#[tokio::test]
async fn init_host_unlock_with_an_untrusted_handoff_names_the_reason_and_not_the_key() {
    let (_turn, logs, _before) = turn().await;
    let fixture = Fixture::new().await;
    let (secret, _) = RecoveryKey::generate();
    let dir = HandoffDir::new();
    let handoff = dir.write(secret.expose_secret());
    fs::set_permissions(&handoff, fs::Permissions::from_mode(0o644)).unwrap();
    let service = uninitialized(&fixture, DeploymentProfile::Container, &dir.path()).await;

    let (response, prompts, _) = init(&service, true).await;

    let AdminResponse::Error { code, message } = response else {
        panic!("expected a refusal, got {response:?}");
    };
    assert_eq!((code, prompts.len()), (ErrorCode::InitFailed, 0));
    assert!(message.contains("not trusted"), "{message}");
    assert!(!message.contains(secret.expose_secret()), "{message}");
    assert_not_logged(&logs, secret.expose_secret());
}

#[tokio::test]
async fn init_host_unlock_is_refused_by_a_service_that_has_no_host_unlock() {
    let (_turn, _logs, _before) = turn().await;
    let fixture = Fixture::new().await;
    let (secret, _) = RecoveryKey::generate();
    let dir = HandoffDir::new();
    dir.write(secret.expose_secret());
    let service = uninitialized(&fixture, DeploymentProfile::Development, &dir.path()).await;

    let (response, prompts, _) = init(&service, true).await;

    let AdminResponse::Error { code, message } = response else {
        panic!("expected a refusal, got {response:?}");
    };
    assert_eq!((code, prompts.len()), (ErrorCode::InitFailed, 0));
    assert!(message.contains("no host unlock"), "{message}");
}

#[tokio::test]
async fn init_host_unlock_then_a_restart_reaches_ready_with_no_unlock() {
    let (_turn, logs, _before) = turn().await;
    let fixture = Fixture::new().await;
    let (secret, _) = RecoveryKey::generate();
    let dir = HandoffDir::new();
    let handoff = dir.write(secret.expose_secret());
    let service = uninitialized(&fixture, DeploymentProfile::Container, &handoff).await;

    let (response, prompts, revealed) = init(&service, true).await;

    let AdminResponse::Init { vault_id, recipients, .. } = response else {
        panic!("expected init to succeed, got {response:?}");
    };
    assert_eq!((prompts.len(), revealed), (5, 1));
    assert_eq!(
        recipients,
        [RecipientRole::Operational, RecipientRole::Recovery, RecipientRole::HostUnlock]
    );
    assert!(logs.has_field("vault.initialized", "vault_id", &vault_id.to_string()));
    assert!(logs.has_field("vault.initialized", "recipients", "operational,recovery,host-unlock"));
    service.stop().await;
    drop(service);

    let restarted = container(&fixture);
    assert_eq!(restarted.unlock_at_start(&handoff).await, ServiceState::Ready);
    assert_not_logged(&logs, secret.expose_secret());
}
