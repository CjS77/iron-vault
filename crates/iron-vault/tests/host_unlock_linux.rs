//! The Protected and Container profiles' host unlock at startup (specification §15; design/tpm-unlock.md, "In the service"):
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

use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use common::approval_harness::{
    Captured, Exchanged, Fixture, assert_audit_record, captured_logs, converse, converse_revealing, get, identity, send,
};
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
use iron_vault::service_context::{LockOutcome, LockResult, ServiceContext, Unlocked};
use iron_vault::service_state::ServiceState;
use iron_vault_store::{
    OperationalIdentity, OsFs, Passphrase, RecipientKey, RecipientRole, RecipientSet, RecoveryKey, StateDirLock, StoreFs, open_manifest,
    seal_passphrase_envelope_for_tests, wrap_identity, write_identity_envelope, write_passphrase_envelope,
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

    /// Writes `secret` as the handoff, `0400` as the host would leave it, in place of any handoff already there.
    fn write(&self, secret: &str) -> PathBuf {
        let path = self.path();
        let _ = fs::remove_file(&path);
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
/// host unlock identity, whose secret text and `age1…` recipient key this returns.
fn with_host_key(fixture: &Fixture) -> (String, String) {
    let (operational, operational_key) = OperationalIdentity::generate();
    let (host, host_key) = RecoveryKey::generate();
    let host_recipient = host_key.to_string();
    let lock = StateDirLock::acquire(&fixture.path("state")).unwrap();
    let envelope = wrap_identity(&identity(), &RecipientSet::new([operational_key, host_key]).unwrap()).unwrap();
    write_identity_envelope(&lock, &OsFs, &envelope).unwrap();
    let sealed = seal_passphrase_envelope_for_tests(&operational, &passphrase()).unwrap();
    write_passphrase_envelope(&lock, &OsFs, &sealed).unwrap();
    (host.expose_secret().to_owned(), host_recipient)
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

fn service_on(fixture: &Fixture, profile: DeploymentProfile) -> ServiceContext {
    start(fixture, profile, MemoryProtection::Locked)
}

/// Runs each case once as a Protected service and once as a Container service: both try the unlock handoff.
macro_rules! on_both_profiles {
    ($($case:ident),* $(,)?) => {$(
        mod $case {
            use super::*;

            #[tokio::test]
            async fn protected() {
                super::$case(DeploymentProfile::Protected).await;
            }

            #[tokio::test]
            async fn container() {
                super::$case(DeploymentProfile::Container).await;
            }
        }
    )*};
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
    assert_eq!(service.unlock(passphrase()).await.unwrap().state, ServiceState::Ready);
}

async fn a_good_handoff_reaches_ready_and_serves_with_no_unlock(profile: DeploymentProfile) {
    let (_turn, logs, before) = turn().await;
    let fixture = Fixture::new().await;
    let (secret, host_key) = with_host_key(&fixture);
    let dir = HandoffDir::new();
    let handoff = dir.write(&secret);
    let service = service_on(&fixture, profile);
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
    assert_not_logged(&logs, &host_key);
}

async fn without_locked_memory_the_handoff_is_never_opened(profile: DeploymentProfile) {
    let (_turn, logs, before) = turn().await;
    let fixture = Fixture::new().await;
    let (secret, _) = with_host_key(&fixture);
    let dir = HandoffDir::new();
    // World-readable, so opening it would be refused as untrusted: the memory refusal shows it was never opened.
    let handoff = dir.write(&secret);
    fs::set_permissions(&handoff, fs::Permissions::from_mode(0o644)).unwrap();
    let memory = MemoryProtection::Unavailable(LockUnavailable::LimitTooLow { limit_bytes: 65_536 });
    let service = start(&fixture, profile, memory);

    assert_eq!(service.unlock_at_start(&handoff).await, ServiceState::Locked);

    assert_one_record(&logs, before, "WARN", "refused", Some("memory_unprotected"));
    assert_not_logged(&logs, &secret);
}

async fn a_missing_handoff_leaves_it_locked_for_the_passphrase(profile: DeploymentProfile) {
    let (_turn, logs, before) = turn().await;
    let fixture = Fixture::new().await;
    with_host_key(&fixture);
    let dir = HandoffDir::new();
    let service = service_on(&fixture, profile);

    assert_eq!(service.unlock_at_start(&dir.path()).await, ServiceState::Locked);

    assert_one_record(&logs, before, "INFO", "absent", None);
    assert_passphrase_unlock_works(&service).await;
}

async fn an_identity_that_is_not_a_recipient_leaves_it_locked_for_the_passphrase(profile: DeploymentProfile) {
    let (_turn, logs, before) = turn().await;
    let fixture = Fixture::new().await;
    let (_, host_key) = with_host_key(&fixture);
    let (stranger, _) = RecoveryKey::generate();
    let dir = HandoffDir::new();
    let handoff = dir.write(stranger.expose_secret());
    let service = service_on(&fixture, profile);

    assert_eq!(service.unlock_at_start(&handoff).await, ServiceState::Locked);

    assert_one_record(&logs, before, "WARN", "refused", Some("not_a_recipient"));
    assert_not_logged(&logs, stranger.expose_secret());
    assert_not_logged(&logs, &host_key);
    assert_passphrase_unlock_works(&service).await;
}

async fn an_uninitialized_vault_stays_locked(profile: DeploymentProfile) {
    let (_turn, logs, before) = turn().await;
    let fixture = Fixture::new().await;
    let (secret, _) = with_host_key(&fixture);
    ["state", "etc"].into_iter().for_each(|name| empty(&fixture.path(name)));
    let dir = HandoffDir::new();
    let handoff = dir.write(&secret);
    let service = service_on(&fixture, profile);

    assert_eq!(service.unlock_at_start(&handoff).await, ServiceState::Locked);

    assert_one_record(&logs, before, "WARN", "refused", Some("not_initialized"));
}

#[tokio::test]
async fn the_development_profile_never_tries_the_handoff() {
    let (_turn, logs, before) = turn().await;
    let fixture = Fixture::new().await;
    let (secret, _) = with_host_key(&fixture);
    let dir = HandoffDir::new();
    let handoff = dir.write(&secret);

    let service = service_on(&fixture, DeploymentProfile::Development);
    assert_eq!(service.state().await, ServiceState::Locked);
    assert_eq!(service.unlock_at_start(&handoff).await, ServiceState::Locked);

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

/// Sends `init` with the host unlock flag as `host_unlock` says and answers its prompts in turn.
async fn init(service: &Arc<ServiceContext>, host_unlock: bool) -> (AdminResponse, Vec<String>, usize) {
    let (exchanged, revealed) = exchange(service, AdminRequest::Init { host_unlock }, &INIT_ANSWERS).await;
    let prompts = exchanged.prompts.into_iter().map(|prompt| prompt.label).collect();
    (exchanged.response, prompts, revealed)
}

/// Sends `request` and answers its prompts in turn with `answers`, returning the exchange and the number of secrets
/// revealed. The admin principal is the test's own account whatever the service's profile, since the Container profile
/// admits root only.
async fn exchange(service: &Arc<ServiceContext>, request: AdminRequest, answers: &[&str]) -> (Exchanged, usize) {
    let paths = service.paths().clone();
    let runtime_dir = paths.runtime_dir.clone().unwrap();
    let socket = AdminSocket::bind(&runtime_dir, paths.owner).unwrap();
    let principals = AdminPrincipals::new(DeploymentProfile::Development, paths.owner.uid);
    let server = AdminServer::new(principals, Handlers::for_service(service), Limits::default());
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(async move { server.serve(socket, async { drop(stopped.await) }).await });
    let mut stream = UnixStream::connect(runtime_dir.join(ADMIN_SOCKET_NAME)).await.unwrap();
    send(&mut stream, &Frame::Request(request)).await;
    let (exchanged, revealed) = converse_revealing(&mut stream, answers).await;
    let _ = stop.send(());
    let _ = task.await;
    (exchanged, revealed.len())
}

fn file_names(fixture: &Fixture, dir: &str) -> Vec<String> {
    fs::read_dir(fixture.path(dir))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect()
}

async fn init_host_unlock_with_no_handoff_is_refused_before_any_prompt_and_writes_nothing(profile: DeploymentProfile) {
    let (_turn, _logs, _before) = turn().await;
    let fixture = Fixture::new().await;
    let dir = HandoffDir::new();
    let service = uninitialized(&fixture, profile, &dir.path()).await;

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

async fn init_host_unlock_with_an_untrusted_handoff_names_the_reason_and_not_the_key(profile: DeploymentProfile) {
    let (_turn, logs, _before) = turn().await;
    let fixture = Fixture::new().await;
    let (secret, _) = RecoveryKey::generate();
    let dir = HandoffDir::new();
    let handoff = dir.write(secret.expose_secret());
    fs::set_permissions(&handoff, fs::Permissions::from_mode(0o644)).unwrap();
    let service = uninitialized(&fixture, profile, &dir.path()).await;

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
    assert_eq!(file_names(&fixture, "state"), ["lock"]);
    assert_eq!(file_names(&fixture, "etc"), ["config.toml.lock"]);
}

async fn init_host_unlock_then_a_restart_reaches_ready_with_no_unlock(profile: DeploymentProfile) {
    let (_turn, logs, _before) = turn().await;
    let fixture = Fixture::new().await;
    let (secret, _) = RecoveryKey::generate();
    let dir = HandoffDir::new();
    let handoff = dir.write(secret.expose_secret());
    let service = uninitialized(&fixture, profile, &handoff).await;

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

    let restarted = service_on(&fixture, profile);
    assert_eq!(restarted.unlock_at_start(&handoff).await, ServiceState::Ready);
    assert_not_logged(&logs, secret.expose_secret());
}

/// A `profile` service on the vault in `fixture`, reading the handoff at `handoff`, after its host unlock at startup.
async fn restarted(fixture: &Fixture, profile: DeploymentProfile, handoff: &Path) -> (Arc<ServiceContext>, ServiceState) {
    let service = service_on(fixture, profile).with_handoff_path(handoff.to_path_buf());
    let state = service.unlock_at_start(handoff).await;
    (Arc::new(service), state)
}

async fn remove(service: &Arc<ServiceContext>, key: &RecipientKey, answers: &[&str]) -> AdminResponse {
    let request = AdminRequest::RecipientRemove {
        recipient: key.to_string(),
    };
    exchange(service, request, answers).await.0.response
}

/// The guide's steps after a lost TPM: the host provisions a new identity into the handoff, the owner unlocks and enrols
/// it with `recipient add --host-unlock`, a restart reaches Ready with no `unlock`, and then the old `host-unlock`
/// recipient can be removed while the one the handoff holds cannot.
async fn a_new_host_unlock_key_reaches_ready_after_a_restart_and_the_old_one_can_then_be_removed(profile: DeploymentProfile) {
    let (_turn, logs, _before) = turn().await;
    let fixture = Fixture::new().await;
    let (old_secret, old_key) = RecoveryKey::generate();
    let dir = HandoffDir::new();
    let handoff = dir.write(old_secret.expose_secret());
    let service = uninitialized(&fixture, profile, &handoff).await;
    assert!(matches!(init(&service, true).await.0, AdminResponse::Init { .. }));
    service.stop().await;
    drop(service);

    let (new_secret, new_key) = RecoveryKey::generate();
    dir.write(new_secret.expose_secret());
    let (service, state) = restarted(&fixture, profile, &handoff).await;
    assert_eq!(state, ServiceState::Locked);
    assert_passphrase_unlock_works(&service).await;
    let request = AdminRequest::RecipientAddHostUnlock {
        recipient: new_key.to_string(),
        label: "host unlock, new TPM".to_owned(),
    };
    let (added, _) = exchange(&service, request, &[PASSPHRASE]).await;
    assert!(
        matches!(added.response, AdminResponse::RecipientAdd { recipients: 4, .. }),
        "{added:?}"
    );
    service.stop().await;
    drop(service);

    let (service, state) = restarted(&fixture, profile, &handoff).await;
    assert_eq!(state, ServiceState::Ready);
    let (code, message) = match remove(&service, &new_key, &[]).await {
        AdminResponse::Error { code, message } => (code, message),
        other => panic!("expected a refusal, got {other:?}"),
    };
    assert_eq!(code, ErrorCode::RecipientSetInvalid);
    assert!(message.contains("unlock handoff holds"), "{message}");
    assert!(matches!(
        remove(&service, &old_key, &[APPROVAL_PASSPHRASE]).await,
        AdminResponse::RecipientRemove { recipients: 3 }
    ));
    let host_unlocks: Vec<RecipientKey> = service
        .list_recipients()
        .await
        .unwrap()
        .into_iter()
        .filter(|entry| entry.role() == RecipientRole::HostUnlock)
        .map(|entry| entry.key().clone())
        .collect();
    assert_eq!(host_unlocks, std::slice::from_ref(&new_key));
    assert!(matches!(
        remove(&service, &new_key, &[]).await,
        AdminResponse::Error {
            code: ErrorCode::RecipientSetInvalid,
            ..
        }
    ));
    fs::remove_file(&handoff).unwrap();
    assert!(matches!(
        remove(&service, &new_key, &[APPROVAL_PASSPHRASE]).await,
        AdminResponse::RecipientRemove { recipients: 2 }
    ));
    [&old_secret, &new_secret]
        .into_iter()
        .for_each(|secret| assert_not_logged(&logs, secret.expose_secret()));
}

async fn an_untrusted_handoff_leaves_it_locked_for_the_passphrase(profile: DeploymentProfile) {
    let (_turn, logs, before) = turn().await;
    let fixture = Fixture::new().await;
    let (secret, _) = with_host_key(&fixture);
    let dir = HandoffDir::new();
    let handoff = dir.write(&secret);
    fs::set_permissions(&handoff, fs::Permissions::from_mode(0o644)).unwrap();
    let service = service_on(&fixture, profile);

    assert_eq!(service.unlock_at_start(&handoff).await, ServiceState::Locked);

    assert_one_record(&logs, before, "WARN", "refused", Some("untrusted"));
    assert_not_logged(&logs, &secret);
    assert_passphrase_unlock_works(&service).await;
}

async fn a_handoff_that_is_not_an_identity_leaves_it_locked_for_the_passphrase(profile: DeploymentProfile) {
    let (_turn, logs, before) = turn().await;
    let fixture = Fixture::new().await;
    with_host_key(&fixture);
    let dir = HandoffDir::new();
    let handoff = dir.write("not an age secret key");
    let service = service_on(&fixture, profile);

    assert_eq!(service.unlock_at_start(&handoff).await, ServiceState::Locked);

    assert_one_record(&logs, before, "WARN", "refused", Some("not_an_identity"));
    assert_passphrase_unlock_works(&service).await;
}

on_both_profiles!(
    a_good_handoff_reaches_ready_and_serves_with_no_unlock,
    without_locked_memory_the_handoff_is_never_opened,
    a_missing_handoff_leaves_it_locked_for_the_passphrase,
    an_identity_that_is_not_a_recipient_leaves_it_locked_for_the_passphrase,
    an_uninitialized_vault_stays_locked,
    an_untrusted_handoff_leaves_it_locked_for_the_passphrase,
    a_handoff_that_is_not_an_identity_leaves_it_locked_for_the_passphrase,
    init_host_unlock_with_no_handoff_is_refused_before_any_prompt_and_writes_nothing,
    init_host_unlock_with_an_untrusted_handoff_names_the_reason_and_not_the_key,
    init_host_unlock_then_a_restart_reaches_ready_with_no_unlock,
    a_new_host_unlock_key_reaches_ready_after_a_restart_and_the_old_one_can_then_be_removed,
    an_explicit_lock_survives_a_restart_until_a_passphrase_unlock,
    a_failed_owner_lock_write_still_locks_and_says_so,
    a_failed_owner_lock_removal_still_unlocks_and_says_so,
    a_lock_in_locked_writes_nothing,
    init_removes_a_stale_owner_lock_so_the_new_vault_host_unlocks,
    reset_writes_the_owner_lock_before_the_discard,
    a_reset_whose_owner_lock_write_fails_still_completes,
);

// The owner-lock file (design/tpm-unlock.md, "`lock` across restarts").

const OWNER_LOCK: &str = "locked-by-owner";
const DRAIN: Duration = Duration::from_secs(5);

/// The real filesystem, except that while armed the rename onto the owner-lock file (its write) or the unlink of it (its
/// removal) fails. It also notes whether the owner-lock file existed when the manifest was unlinked, the first removal of
/// a reset's discard. `FaultFs` keeps its state in a `RefCell`, so a service, which shares its filesystem across blocking
/// tasks, cannot hold one.
#[derive(Clone, Default)]
struct OwnerLockFs {
    fail_write: Arc<AtomicBool>,
    fail_removal: Arc<AtomicBool>,
    lock_at_manifest_removal: Arc<StdMutex<Option<bool>>>,
}

impl OwnerLockFs {
    fn failing_write() -> Self {
        let fs = Self::default();
        fs.fail_write.store(true, Ordering::SeqCst);
        fs
    }

    fn failing_removal() -> Self {
        let fs = Self::default();
        fs.fail_removal.store(true, Ordering::SeqCst);
        fs
    }
}

fn names_owner_lock(path: &Path) -> bool {
    path.file_name().is_some_and(|name| name == OWNER_LOCK)
}

impl StoreFs for OwnerLockFs {
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
        match names_owner_lock(to) && self.fail_write.load(Ordering::SeqCst) {
            true => Err(io::ErrorKind::PermissionDenied.into()),
            false => OsFs.rename(from, to),
        }
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        if names_owner_lock(path) && self.fail_removal.load(Ordering::SeqCst) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        if path.file_name().is_some_and(|name| name == "manifest.age") {
            let present = path.with_file_name(OWNER_LOCK).exists();
            *self.lock_at_manifest_removal.lock().unwrap() = Some(present);
        }
        OsFs.remove_file(path)
    }

    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        OsFs.sync_dir(dir)
    }

    fn list_dir(&self, dir: &Path) -> io::Result<Vec<OsString>> {
        OsFs.list_dir(dir)
    }

    fn read_bounded(&self, path: &Path, max_len: u64) -> io::Result<Vec<u8>> {
        OsFs.read_bounded(path, max_len)
    }
}

fn owner_lock_exists(fixture: &Fixture) -> bool {
    fixture.path("state").join(OWNER_LOCK).exists()
}

/// A `profile` service on the vault in `fixture` over `fs`, as `start` leaves it.
fn start_on<F: StoreFs + Send + Sync + 'static>(fixture: &Fixture, profile: DeploymentProfile, fs: F) -> ServiceContext<F> {
    fixture.start_as(
        fs,
        LogSwitch::stdout_for_tests(invoking_user().unwrap()).unwrap(),
        profile,
        MemoryProtection::Locked,
    )
}

/// The outcome and refusal labels of every `vault.host-unlock` record written since `before`.
fn outcomes_since(logs: &Captured, before: usize) -> Vec<(String, Option<String>)> {
    logs.events(EVENT)
        .into_iter()
        .skip(before)
        .map(|record| {
            (
                record["host_unlock_outcome"].as_str().unwrap().to_owned(),
                record["refusal"].as_str().map(str::to_owned),
            )
        })
        .collect()
}

fn locked(outcome: LockOutcome, persisted: bool) -> LockResult {
    LockResult { outcome, persisted }
}

async fn an_explicit_lock_survives_a_restart_until_a_passphrase_unlock(profile: DeploymentProfile) {
    let (_turn, logs, before) = turn().await;
    let fixture = Fixture::new().await;
    let (secret, _) = with_host_key(&fixture);
    let dir = HandoffDir::new();
    let handoff = dir.write(&secret);
    let (service, state) = restarted(&fixture, profile, &handoff).await;
    assert_eq!(state, ServiceState::Ready);

    assert_eq!(service.lock(DRAIN).await, Ok(locked(LockOutcome::Cleared, true)));
    assert!(owner_lock_exists(&fixture));
    assert_eq!(fs::read(fixture.path("state").join(OWNER_LOCK)).unwrap(), b"");
    service.stop().await;
    drop(service);

    // An untrusted handoff would be a refusal had it been opened: the owner-lock file is read first.
    fs::set_permissions(&handoff, fs::Permissions::from_mode(0o644)).unwrap();
    let (service, state) = restarted(&fixture, profile, &handoff).await;
    assert_eq!(state, ServiceState::Locked);
    assert_eq!(
        outcomes_since(&logs, before),
        [("unlocked".to_owned(), None), ("owner_locked".to_owned(), None)]
    );
    let record = &logs.events(EVENT)[before + 1];
    assert_audit_record(record, "INFO", &["host_unlock_outcome"]);
    assert!(owner_lock_exists(&fixture), "host unlock never removes the file");

    let unlocked = service.unlock(passphrase()).await.unwrap();
    assert_eq!(
        unlocked,
        Unlocked {
            state: ServiceState::Ready,
            owner_lock_removed: true
        }
    );
    assert!(!owner_lock_exists(&fixture));
    service.stop().await;
    drop(service);

    dir.write(&secret);
    let (_, state) = restarted(&fixture, profile, &handoff).await;
    assert_eq!(state, ServiceState::Ready);
    assert_eq!(outcomes_since(&logs, before).last(), Some(&("unlocked".to_owned(), None)));
}

async fn a_failed_owner_lock_write_still_locks_and_says_so(profile: DeploymentProfile) {
    let (_turn, logs, _before) = turn().await;
    let fixture = Fixture::new().await;
    let (secret, _) = with_host_key(&fixture);
    let dir = HandoffDir::new();
    let handoff = dir.write(&secret);
    let service = start_on(&fixture, profile, OwnerLockFs::failing_write());
    assert_eq!(service.unlock_at_start(&handoff).await, ServiceState::Ready);

    let result = service.lock(DRAIN).await;

    assert_eq!(result, Ok(locked(LockOutcome::Cleared, false)));
    assert_eq!(service.state().await, ServiceState::Locked);
    assert!(!owner_lock_exists(&fixture));
    let text = logs.text();
    assert!(
        text.contains("owner-lock file write failed") && text.contains("permission_denied"),
        "{text}"
    );
    assert_not_logged(&logs, &secret);
}

async fn a_failed_owner_lock_removal_still_unlocks_and_says_so(profile: DeploymentProfile) {
    let (_turn, logs, before) = turn().await;
    let fixture = Fixture::new().await;
    let (secret, _) = with_host_key(&fixture);
    let dir = HandoffDir::new();
    let handoff = dir.write(&secret);
    fs::write(fixture.path("state").join(OWNER_LOCK), b"").unwrap();
    let service = start_on(&fixture, profile, OwnerLockFs::failing_removal());
    assert_eq!(service.unlock_at_start(&handoff).await, ServiceState::Locked);
    assert_eq!(outcomes_since(&logs, before), [("owner_locked".to_owned(), None)]);

    let unlocked = service.unlock(passphrase()).await.unwrap();

    assert_eq!(
        unlocked,
        Unlocked {
            state: ServiceState::Ready,
            owner_lock_removed: false
        }
    );
    assert!(owner_lock_exists(&fixture));
    assert!(logs.text().contains("owner-lock file removal failed"));
}

async fn a_lock_in_locked_writes_nothing(profile: DeploymentProfile) {
    let (_turn, _logs, _before) = turn().await;
    let fixture = Fixture::new().await;
    with_host_key(&fixture);
    let dir = HandoffDir::new();
    let service = start_on(&fixture, profile, OsFs);
    assert_eq!(service.unlock_at_start(&dir.path()).await, ServiceState::Locked);

    assert!(service.lock(DRAIN).await.is_err());

    assert!(!owner_lock_exists(&fixture));
}

async fn init_removes_a_stale_owner_lock_so_the_new_vault_host_unlocks(profile: DeploymentProfile) {
    let (_turn, _logs, _before) = turn().await;
    let fixture = Fixture::new().await;
    let (secret, _) = RecoveryKey::generate();
    let dir = HandoffDir::new();
    let handoff = dir.write(secret.expose_secret());
    let service = uninitialized(&fixture, profile, &handoff).await;
    fs::write(fixture.path("state").join(OWNER_LOCK), b"").unwrap();

    let (response, _, _) = init(&service, true).await;

    assert!(matches!(response, AdminResponse::Init { .. }), "{response:?}");
    assert!(!owner_lock_exists(&fixture));
    service.stop().await;
    drop(service);
    let (_, state) = restarted(&fixture, profile, &handoff).await;
    assert_eq!(state, ServiceState::Ready);
}

/// Resets the vault in `fixture` through a Ready service over `fs` and returns the service's answer.
async fn reset_over(fixture: &Fixture, fs: OwnerLockFs, profile: DeploymentProfile) -> AdminResponse {
    let (secret, _) = with_host_key(fixture);
    let dir = HandoffDir::new();
    let handoff = dir.write(&secret);
    let service = Arc::new(start_on(fixture, profile, fs));
    assert_eq!(service.unlock_at_start(&handoff).await, ServiceState::Ready);
    let id = open_manifest(&identity(), &fs::read(fixture.path("state/manifest.age")).unwrap())
        .unwrap()
        .vault_id();
    let (path, stop) = serve_admin_as_owner(&service);
    let mut stream = UnixStream::connect(&path).await.unwrap();
    send(&mut stream, &Frame::Request(AdminRequest::Reset)).await;
    let exchanged = converse(&mut stream, &[&id.to_string()]).await;
    let _ = stop.send(());
    exchanged.response
}

/// The admin server of `service` on its runtime directory, with the test's own account as the admin principal whatever
/// the service's profile, since the Container profile admits root only.
fn serve_admin_as_owner<F: StoreFs + Send + Sync + 'static>(
    service: &Arc<ServiceContext<F>>,
) -> (PathBuf, tokio::sync::oneshot::Sender<()>) {
    let paths = service.paths().clone();
    let runtime_dir = paths.runtime_dir.clone().unwrap();
    let socket = AdminSocket::bind(&runtime_dir, paths.owner).unwrap();
    let principals = AdminPrincipals::new(DeploymentProfile::Development, paths.owner.uid);
    let server = AdminServer::new(principals, Handlers::for_service(service), Limits::default());
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move { server.serve(socket, async { drop(stopped.await) }).await });
    (runtime_dir.join(ADMIN_SOCKET_NAME), stop)
}

async fn reset_writes_the_owner_lock_before_the_discard(profile: DeploymentProfile) {
    let (_turn, _logs, _before) = turn().await;
    let fixture = Fixture::new().await;
    let fs = OwnerLockFs::default();

    let response = reset_over(&fixture, fs.clone(), profile).await;

    assert!(matches!(response, AdminResponse::Reset { .. }), "{response:?}");
    assert_eq!(
        *fs.lock_at_manifest_removal.lock().unwrap(),
        Some(true),
        "written before the discard's first removal"
    );
    assert!(
        !owner_lock_exists(&fixture),
        "a finished reset removes it with the other state files"
    );
}

async fn a_reset_whose_owner_lock_write_fails_still_completes(profile: DeploymentProfile) {
    let (_turn, logs, _before) = turn().await;
    let fixture = Fixture::new().await;
    let fs = OwnerLockFs::failing_write();

    let response = reset_over(&fixture, fs.clone(), profile).await;

    assert!(matches!(response, AdminResponse::Reset { .. }), "{response:?}");
    assert_eq!(*fs.lock_at_manifest_removal.lock().unwrap(), Some(false));
    assert!(!fixture.path("state/manifest.age").exists());
    assert!(logs.text().contains("owner-lock file write failed"));
}

#[tokio::test]
async fn a_development_service_writes_and_removes_the_owner_lock_but_never_reads_it_at_startup() {
    let (_turn, logs, before) = turn().await;
    let fixture = Fixture::new().await;
    with_host_key(&fixture);
    let service = start_on(&fixture, DeploymentProfile::Development, OsFs);
    assert_eq!(service.state().await, ServiceState::Locked);
    let unlocked = service.unlock(passphrase()).await.unwrap();
    assert_eq!(
        unlocked,
        Unlocked {
            state: ServiceState::Ready,
            owner_lock_removed: true
        }
    );

    assert_eq!(service.lock(DRAIN).await, Ok(locked(LockOutcome::Cleared, true)));
    assert!(owner_lock_exists(&fixture));
    service.stop().await;
    drop(service);

    let service = start_on(&fixture, DeploymentProfile::Development, OsFs);
    assert_eq!(service.unlock_at_start(Path::new("/nonexistent")).await, ServiceState::Locked);
    assert!(service.unlock(passphrase()).await.unwrap().owner_lock_removed);
    assert!(!owner_lock_exists(&fixture));
    assert_eq!(logs.events(EVENT).len(), before, "a Development service never tries host unlock");
}
