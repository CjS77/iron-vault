//! `import` end to end over a real admin socket: one service exports a vault and another, with a state directory of its
//! own, imports the bundle (`design/migration-bundle.md`, "Import" and "Admin exchanges"). The destination stays Locked,
//! `unlock` then leaves it Unavailable with `PolicyInvalid` because the committed config has no signature, and every
//! refusal before the owner's `yes` writes nothing.
//!
//! The destination runs the development profile with the test's own account as its service account, except where a test
//! asks for another profile. Each import runs scrypt at 256 MiB twice, so one test runs at a time.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use common::approval_harness::{APPROVAL_PASSPHRASE, Captured, assert_audit_record, captured_logs, get, mkdir, send};
use common::migration_source::{EXPORT_PASSPHRASE, Source, bundle_frames, read_frame, send_bundle, source, write_ignoring_errors};
use common::proxy_harness::TempDir;
use iron_vault::admin::dispatch::Handlers;
use iron_vault::admin::principal::AdminPrincipals;
use iron_vault::admin::protocol::{
    self, AdminRequest, AdminResponse, ErrorCode, Frame, ImportResult, OwnerInput, Prompt, ProposedConfig, VaultStatus,
};
use iron_vault::admin::server::{AdminServer, Limits};
use iron_vault::admin::socket::AdminSocket;
use iron_vault::deployment::{Accounts, DeploymentProfile, PasswdDirectory};
use iron_vault::hardening::{CoreDumps, HardeningReport, LockUnavailable, MemoryProtection};
use iron_vault::path_metadata::invoking_user;
use iron_vault::service_context::{ServiceContext, ServiceLocks, ServiceSetup};
use iron_vault::service_state::{FailureReason, ServiceState};
use iron_vault::socket_activation::PassedSockets;
use iron_vault::trusted_path_report::ServicePaths;
use iron_vault::upstream::client::TransportLimits;
use iron_vault_policy::Capabilities;
use iron_vault_store::{OsFs, RecipientRole};
use tokio::net::UnixStream;
use tokio::sync::{Mutex, MutexGuard};
use zeroize::Zeroizing;

const DEST_PASSPHRASE: &str = "DEST-vault-passphrase-41c7";
/// The bundle's one credential's secret, which no log, message or destination file besides its record may hold.
const FX_SECRET: &str = "fx-secret";

/// The answers of an owner who knows the export passphrase, chooses a vault passphrase and confirms the recovery key.
const COMPLETE: [&[u8]; 4] = [
    EXPORT_PASSPHRASE.as_bytes(),
    DEST_PASSPHRASE.as_bytes(),
    DEST_PASSPHRASE.as_bytes(),
    b"yes",
];

static ONE_AT_A_TIME: Mutex<()> = Mutex::const_new(());

/// Empty state and config directories in a temporary directory that is also the runtime directory.
struct Dest {
    dir: TempDir,
}

impl Dest {
    fn new() -> Self {
        let dir = TempDir::new();
        mkdir(&dir.path().join("state"));
        mkdir(&dir.path().join("etc"));
        Self { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn start(&self) -> Arc<ServiceContext> {
        Arc::new(self.context_as(DeploymentProfile::Development, MemoryProtection::Unsupported))
    }

    fn context_as(&self, profile: DeploymentProfile, memory: MemoryProtection) -> ServiceContext {
        let paths = ServicePaths {
            profile,
            owner: invoking_user().unwrap(),
            config: self.path("etc/config.toml"),
            state_dir: self.path("state"),
            runtime_dir: Some(self.dir.path().to_path_buf()),
        };
        let locks = ServiceLocks::acquire(&paths).unwrap();
        let provisional = locks.unverified_listeners(&OsFs);
        let setup = ServiceSetup {
            accounts: PasswdDirectory::new(Accounts::parse(""), &paths, Path::new("/nonexistent")).unwrap(),
            paths,
            fs: OsFs,
            capabilities: Capabilities::default(),
            upstream: iron_vault::config_check::UpstreamSettings::new(
                DeploymentProfile::Development,
                invoking_user().unwrap(),
                TransportLimits::default(),
            ),
            hardening: HardeningReport {
                core_dumps: CoreDumps::Disabled,
                memory,
            },
            log: iron_vault::logging::LogSwitch::stdout_for_tests(invoking_user().unwrap()).unwrap(),
        };
        ServiceContext::start(locks, setup, &provisional, PassedSockets::default()).unwrap()
    }

    /// The file names in the state and config directories, each sorted.
    fn files(&self) -> (Vec<String>, Vec<String>) {
        let names = |dir: &str| {
            let mut names: Vec<_> = fs::read_dir(self.path(dir))
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        };
        (names("state"), names("etc"))
    }

    fn assert_only_lock_files(&self) {
        assert_eq!(self.files(), (vec!["lock".to_owned()], vec!["config.toml.lock".to_owned()]));
    }
}

/// What one exchange showed the owner and how it ended; `response` is `None` when the service closed without one.
#[derive(Debug)]
struct Exchanged {
    notices: String,
    prompts: Vec<Prompt>,
    reveals: Vec<String>,
    response: Option<AdminResponse>,
}

impl Exchanged {
    fn error(&self) -> (ErrorCode, &str) {
        match &self.response {
            Some(AdminResponse::Error { code, message }) => (*code, message),
            other => panic!("expected an error, got {other:?}"),
        }
    }

    fn result(&self) -> &ImportResult {
        match &self.response {
            Some(AdminResponse::Import(result)) => result,
            other => panic!("expected an import result, got {other:?}"),
        }
    }

    fn labels(&self) -> Vec<&str> {
        self.prompts.iter().map(|prompt| prompt.label.as_str()).collect()
    }
}

/// The admin server with the test's own account as the admin principal whatever the service's profile, so a Protected or
/// Container service can be asked to `import` without root.
fn spawn_admin(service: &Arc<ServiceContext>, limits: Limits) -> (PathBuf, tokio::sync::oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
    let owner = service.paths().owner;
    let runtime_dir = service.paths().runtime_dir.clone().unwrap();
    let socket = AdminSocket::bind(&runtime_dir, owner).unwrap();
    let server = AdminServer::new(
        AdminPrincipals::new(DeploymentProfile::Development, owner.uid),
        Handlers::for_service(service),
        limits,
    );
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        let _ = server
            .serve(socket, async {
                let _ = stopped.await;
            })
            .await;
    });
    (runtime_dir.join(iron_vault::admin::ADMIN_SOCKET_NAME), stop, task)
}

/// Sends the `import` request and the bundle on a new connection. A service that refuses at its first check closes while
/// the bundle is still going out, so a failed write is not the test's failure.
async fn start_import(path: &Path, bundle: &[u8]) -> UnixStream {
    let mut stream = UnixStream::connect(path).await.unwrap();
    send(&mut stream, &Frame::Request(AdminRequest::Import { host_unlock: false })).await;
    send_bundle(&mut stream, bundle).await;
    stream
}

/// Reads frames until the response or the close, answering each prompt with the next of `answers`.
async fn converse(stream: &mut UnixStream, answers: &[&[u8]]) -> Exchanged {
    let mut answers = answers.iter();
    let mut exchanged = Exchanged {
        notices: String::new(),
        prompts: Vec::new(),
        reveals: Vec::new(),
        response: None,
    };
    while let Some(frame) = read_frame(stream).await {
        match frame {
            Frame::Response(response) => {
                exchanged.response = Some(response);
                break;
            }
            Frame::Notice(notice) => exchanged.notices.push_str(&notice.text),
            Frame::Reveal(secret) => exchanged.reveals.push(String::from_utf8(secret.expose_secret().to_vec()).unwrap()),
            Frame::Prompt(prompt) => {
                exchanged.prompts.push(prompt);
                let answer = answers.next().expect("a prompt beyond the answers given");
                send(stream, &Frame::OwnerInput(OwnerInput::new(Zeroizing::new(answer.to_vec())))).await;
            }
            other => panic!("unexpected frame {other:?}"),
        }
    }
    exchanged
}

/// Sends `request` over a fresh admin socket and answers the prompts in turn with `answers`.
async fn exchange(service: &Arc<ServiceContext>, request: AdminRequest, answers: &[&[u8]]) -> Exchanged {
    let (path, stop, task) = spawn_admin(service, Limits::default());
    let mut stream = UnixStream::connect(path).await.unwrap();
    send(&mut stream, &Frame::Request(request)).await;
    let exchanged = converse(&mut stream, answers).await;
    let _ = stop.send(());
    // The next exchange binds the admin socket again, and the handlers hold the service until the server ends.
    task.await.unwrap();
    exchanged
}

async fn import(service: &Arc<ServiceContext>, bundle: &[u8], answers: &[&[u8]]) -> Exchanged {
    let (path, stop, task) = spawn_admin(service, Limits::default());
    let mut stream = start_import(&path, bundle).await;
    let exchanged = converse(&mut stream, answers).await;
    let _ = stop.send(());
    task.await.unwrap();
    exchanged
}

/// The log records of `event` that were added since `before` of them were there.
fn since(logs: &Captured, event: &str, before: usize) -> Vec<serde_json::Value> {
    logs.events(event).into_iter().skip(before).collect()
}

/// No passphrase, no credential secret and no recovery key reached the log, in any case.
fn assert_no_secret_logged(logs: &Captured, recovery_keys: &[&str]) {
    let text = logs.text();
    [EXPORT_PASSPHRASE, DEST_PASSPHRASE, FX_SECRET]
        .iter()
        .chain(recovery_keys)
        .flat_map(|secret| [secret.to_string(), secret.to_lowercase()])
        .for_each(|secret| assert!(!text.contains(&secret), "a secret reached the log:\n{text}"));
}

/// Serializes the test and returns the source its bundle comes from.
async fn begin() -> (MutexGuard<'static, ()>, &'static Source, Captured) {
    let one = ONE_AT_A_TIME.lock().await;
    let logs = captured_logs();
    (one, source().await, logs)
}

#[tokio::test(flavor = "multi_thread")]
async fn an_import_makes_a_locked_vault_with_the_sources_fields_and_unlock_leaves_it_unavailable() {
    let (_one, source, logs) = begin().await;
    let dest = Dest::new();
    let service = dest.start();
    let imported_before = logs.events("migration.imported").len();

    let shown = import(&service, &source.bytes, &COMPLETE).await;

    assert_eq!(
        shown.labels(),
        [
            "Export passphrase",
            "Vault passphrase",
            "Repeat the vault passphrase",
            "Type yes once you have saved the recovery key"
        ]
    );
    assert_eq!(
        shown.result(),
        &ImportResult {
            vault_id: source.vault_id,
            records: source.records,
            version: source.committed,
            highest_reserved: source.highest_reserved,
            digest: source.digest,
            recipients: vec![RecipientRole::Operational, RecipientRole::Recovery],
        }
    );
    assert_eq!(shown.reveals.len(), 1);
    let summary = [
        format!("vault: {}", source.vault_id),
        format!("credentials: {}", source.records),
        "approvers: approval passphrase".to_owned(),
        format!(
            "committed approval: version {}; highest reserved version: {}",
            source.committed, source.highest_reserved
        ),
        format!("at version {} or later", source.highest_reserved + 1),
    ];
    summary
        .iter()
        .for_each(|line| assert!(shown.notices.contains(line), "{line} not in {}", shown.notices));
    assert_steps_announced_in_order(&shown.notices);
    assert_eq!(service.state().await, ServiceState::Locked);
    assert_eq!(service.status().await.vault, VaultStatus::Locked);

    // The provisional listeners are bound from `config.toml` when the process starts, so a restart brings them up.
    drop(service);
    let _ = fs::remove_file(source.fixture.socket());
    let service = dest.start();
    let unlocked = exchange(&service, AdminRequest::Unlock, &[DEST_PASSPHRASE.as_bytes()]).await;
    assert_eq!(unlocked.prompts.len(), 1, "{unlocked:?}");
    assert_eq!(service.state().await, ServiceState::Unavailable(FailureReason::PolicyInvalid));
    assert_eq!(get(&source.fixture, "fx").await.status, 503);

    let imported = since(&logs, "migration.imported", imported_before);
    assert_eq!(imported.len(), 1, "{imported:?}");
    assert_audit_record(
        &imported[0],
        "INFO",
        &[
            "vault_id",
            "records",
            "approvers",
            "committed_version",
            "highest_reserved",
            "recipients",
        ],
    );
    assert_eq!(imported[0]["vault_id"], source.vault_id.to_string().as_str());
    assert_eq!(imported[0]["recipients"], "operational,recovery");
    assert_eq!(imported[0]["highest_reserved"].as_u64(), Some(source.highest_reserved));
    assert_no_secret_logged(&logs, &[&shown.reveals[0]]);
}

/// Each of the write order's ten steps is announced before it starts, in order.
fn assert_steps_announced_in_order(notices: &str) {
    let positions: Vec<_> = (1..=10).map(|step| notices.find(&format!("step {step}, "))).collect();
    assert!(positions.iter().all(Option::is_some), "{notices}");
    assert!(positions.windows(2).all(|pair| pair[0] < pair[1]), "{notices}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_export_passphrase_ends_with_import_denied_and_writes_nothing() {
    let (_one, source, logs) = begin().await;
    let dest = Dest::new();
    let service = dest.start();
    let refused_before = logs.events("migration.import-refused").len();

    let shown = import(&service, &source.bytes, &[b"EXPORT-wrong-guess-0000"]).await;

    assert_eq!(shown.labels(), ["Export passphrase"]);
    assert_eq!(shown.error().0, ErrorCode::ImportDenied);
    dest.assert_only_lock_files();
    let refused = since(&logs, "migration.import-refused", refused_before);
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert_audit_record(&refused[0], "WARN", &["refusal"]);
    assert_eq!(refused[0]["refusal"], "wrong_passphrase");
    // A second wrong guess is answered the same way: there is no attempt limit.
    assert_eq!(
        import(&service, &source.bytes, &[b"EXPORT-wrong-guess-0001"]).await.error().0,
        ErrorCode::ImportDenied
    );
    assert!(!logs.text().contains("EXPORT-wrong-guess"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bundle_that_breaks_a_rule_ends_with_bundle_invalid_before_any_prompt() {
    let (_one, source, logs) = begin().await;
    let dest = Dest::new();
    let service = dest.start();
    let refused_before = logs.events("migration.import-refused").len();
    let mut wrong_magic = source.bytes.clone();
    wrong_magic[0] ^= 0xff;
    let truncated = source.bytes[..source.bytes.len() / 2].to_vec();
    let mut trailing = source.bytes.clone();
    trailing.extend_from_slice(b"trailing");
    let cases = [(wrong_magic, "gzip_header"), (truncated, "truncated"), (trailing, "gzip_trailing")];

    for (bundle, rule) in &cases {
        let shown = import(&service, bundle, &[]).await;

        let (code, message) = shown.error();
        assert_eq!(code, ErrorCode::BundleInvalid, "{rule}");
        assert!(message.contains(rule) && message.contains("nothing was written"), "{message}");
        assert!(shown.prompts.is_empty(), "{rule}: {shown:?}");
        dest.assert_only_lock_files();
    }
    let refused = since(&logs, "migration.import-refused", refused_before);
    assert_eq!(refused.len(), cases.len(), "{refused:?}");
    refused.iter().zip(&cases).for_each(|(record, (_, rule))| {
        assert_audit_record(record, "WARN", &["refusal", "detail"]);
        assert_eq!(
            (record["refusal"].as_str(), record["detail"].as_str()),
            (Some("bundle_invalid"), Some(*rule))
        );
    });
}

/// Polls until an import holds the slot.
async fn wait_for_taken_slot(service: &ServiceContext) {
    let deadline = tokio::time::Instant::now() + common::WAIT;
    while service.take_import_slot().is_ok() {
        assert!(tokio::time::Instant::now() < deadline, "no import ever took the slot");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Polls until the import slot is free, since a dropped exchange releases it when its task unwinds.
async fn wait_for_free_slot(service: &ServiceContext) {
    let deadline = tokio::time::Instant::now() + common::WAIT;
    while service.take_import_slot().is_err() {
        assert!(tokio::time::Instant::now() < deadline, "the import slot was never released");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_import_while_one_holds_the_slot_is_busy() {
    let (_one, source, _logs) = begin().await;
    let dest = Dest::new();
    let service = dest.start();
    let (path, stop, task) = spawn_admin(&service, Limits::default());
    let mut first = start_import(&path, &source.bytes).await;
    // The first import is past step 1 once it asks for the export passphrase.
    assert!(matches!(next_prompt(&mut first).await, Some(prompt) if prompt.label == "Export passphrase"));

    let second = converse(&mut start_import(&path, &source.bytes).await, &[]).await;

    assert_eq!(second.error().0, ErrorCode::Busy);
    assert!(second.prompts.is_empty());
    drop(first);
    wait_for_free_slot(&service).await;
    let _ = stop.send(());
    task.await.unwrap();
    dest.assert_only_lock_files();
}

async fn next_prompt(stream: &mut UnixStream) -> Option<Prompt> {
    while let Some(frame) = read_frame(stream).await {
        if let Frame::Prompt(prompt) = frame {
            return Some(prompt);
        }
    }
    None
}

/// Serves `service` with limits short enough for a test to see a deadline pass.
fn short_limits() -> Limits {
    Limits {
        request_deadline: Duration::from_millis(400),
        transfer_deadline: Duration::from_millis(900),
        ..Limits::default()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sender_that_stalls_is_closed_after_the_frame_deadline_and_the_slot_is_free_again() {
    let (_one, source, logs) = begin().await;
    let dest = Dest::new();
    let service = dest.start();
    let (path, stop, task) = spawn_admin(&service, short_limits());
    let mut stream = UnixStream::connect(&path).await.unwrap();
    send(&mut stream, &Frame::Request(AdminRequest::Import { host_unlock: false })).await;
    write_ignoring_errors(&mut stream, &bundle_frames(&source.bytes)[0][..1000]).await;

    let shown = converse(&mut stream, &[]).await;

    assert!(shown.response.is_none() && shown.prompts.is_empty(), "{shown:?}");
    wait_for_free_slot(&service).await;
    assert!(logs.text().contains("admin command `import` cancelled"), "{}", logs.text());
    let _ = stop.send(());
    task.await.unwrap();
    dest.assert_only_lock_files();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sender_that_trickles_is_closed_after_the_transfer_deadline() {
    let (_one, source, _logs) = begin().await;
    let dest = Dest::new();
    let service = dest.start();
    let (path, stop, task) = spawn_admin(&service, short_limits());
    let mut stream = UnixStream::connect(&path).await.unwrap();
    send(&mut stream, &Frame::Request(AdminRequest::Import { host_unlock: false })).await;
    // Each frame arrives within the frame deadline, but the bundle is never whole within the transfer deadline.
    for piece in source.bytes.chunks(64).take(40) {
        let mut frame = Vec::new();
        protocol::encode_bundle_data(piece, &mut frame).unwrap();
        write_ignoring_errors(&mut stream, &frame).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let shown = converse(&mut stream, &[]).await;

    assert!(shown.response.is_none() && shown.prompts.is_empty(), "{shown:?}");
    wait_for_free_slot(&service).await;
    let _ = stop.send(());
    task.await.unwrap();
    dest.assert_only_lock_files();
}

/// A destination that is not Uninitialized or Unfinished is refused with `already-initialized` before any prompt, naming
/// what is there, and nothing in it changes.
#[tokio::test(flavor = "multi_thread")]
async fn initialized_unrecognized_and_unfinished_reset_destinations_are_refused_before_any_prompt() {
    let (_one, source, _logs) = begin().await;
    let initialized = common::approval_harness::Fixture::new().await;
    let service = initialized.ready().await;
    assert_eq!(import(&service, &source.bytes, &COMPLETE).await.error().0, ErrorCode::WrongState);
    service.lock(Duration::from_secs(5)).await.unwrap();
    let before = state_files(&initialized.path("state"));

    let shown = import(&service, &source.bytes, &COMPLETE).await;

    let (code, message) = shown.error();
    assert_eq!(code, ErrorCode::AlreadyInitialized);
    assert!(message.contains("the vault is Initialized"), "{message}");
    assert!(shown.prompts.is_empty());
    assert_eq!(state_files(&initialized.path("state")), before);

    let cases = [
        ("state/foreign-notes.txt", "foreign-notes.txt"),
        ("state/reset.unfinished", "run `iron-vault reset` again"),
    ];
    for (file, expected) in cases {
        let dest = Dest::new();
        fs::write(dest.path(file), b"x").unwrap();
        let service = dest.start();
        let before = dest.files();

        let shown = import(&service, &source.bytes, &COMPLETE).await;

        let (code, message) = shown.error();
        assert_eq!(code, ErrorCode::AlreadyInitialized, "{file}");
        assert!(message.contains(expected), "{message}");
        assert!(shown.prompts.is_empty() && shown.reveals.is_empty(), "{file}");
        assert_eq!(dest.files(), before, "{file}");
    }
}

fn state_files(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut files: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap())
        .map(|entry| {
            (
                entry.file_name().to_string_lossy().into_owned(),
                fs::read(entry.path()).unwrap_or_default(),
            )
        })
        .collect();
    files.sort();
    files
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unfinished_initialization_is_discarded_after_a_notice_and_logged_as_an_init_discard() {
    let (_one, source, logs) = begin().await;
    let dest = Dest::new();
    ["init.unfinished", "identity.age", "operational.age"]
        .iter()
        .for_each(|name| fs::write(dest.path(&format!("state/{name}")), b"").unwrap());
    fs::write(dest.path("etc/config.toml"), b"schema_version = 1\n").unwrap();
    let service = dest.start();
    let (init_before, import_before) = (
        logs.events("vault.init-discarded").len(),
        logs.events("migration.import-discarded").len(),
    );

    let shown = import(&service, &source.bytes, &COMPLETE).await;

    assert_eq!(shown.result().vault_id, source.vault_id);
    assert!(shown.notices.starts_with("An unfinished initialization"), "{}", shown.notices);
    let discarded = since(&logs, "vault.init-discarded", init_before);
    assert_eq!(discarded.len(), 1, "{discarded:?}");
    assert_audit_record(&discarded[0], "WARN", &["files"]);
    let files = discarded[0]["files"].as_str().unwrap();
    ["init.unfinished", "identity.age", "operational.age", "config.toml"]
        .iter()
        .for_each(|name| assert!(files.contains(name), "{name} not in {files}"));
    assert!(since(&logs, "migration.import-discarded", import_before).is_empty());
    assert_no_secret_logged(&logs, &[&shown.reveals[0]]);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unfinished_import_is_announced_by_kind_and_names_config_toml() {
    let (_one, source, _logs) = begin().await;
    let dest = Dest::new();
    fs::write(dest.path("state/import.unfinished"), b"").unwrap();
    fs::write(dest.path("etc/config.toml"), b"schema_version = 1\n").unwrap();

    let shown = import(&dest.start(), &source.bytes, &[b"EXPORT-wrong-guess-0000"]).await;

    assert!(
        shown.notices.starts_with("An unfinished import is here") && shown.notices.contains("config.toml"),
        "{}",
        shown.notices
    );
    assert_eq!(shown.error().0, ErrorCode::ImportDenied);
    assert!(dest.path("state/import.unfinished").exists() && dest.path("etc/config.toml").exists());
}

/// A write that fails leaves the destination Unfinished, with the failed step named, the recovery key declared dead and
/// the failure logged. The next import discards it and completes.
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_write_step_leaves_an_unfinished_import_that_the_next_import_discards() {
    let (_one, source, logs) = begin().await;
    let dest = Dest::new();
    let service = dest.start();
    let (failed_before, discarded_before) = (
        logs.events("migration.import-failed").len(),
        logs.events("migration.import-discarded").len(),
    );
    // Step 5 writes `config.toml`; a config directory the service cannot write to fails exactly there.
    fs::set_permissions(dest.path("etc"), fs::Permissions::from_mode(0o500)).unwrap();

    let failed = import(&service, &source.bytes, &COMPLETE).await;

    fs::set_permissions(dest.path("etc"), fs::Permissions::from_mode(0o700)).unwrap();
    let (code, message) = failed.error();
    assert_eq!(code, ErrorCode::ImportFailed);
    assert!(
        message.contains("step 5, writing config.toml") && message.ends_with("the recovery key shown opens nothing: discard it"),
        "{message}"
    );
    assert!(message.contains("run `iron-vault import` again"), "{message}");
    let events = since(&logs, "migration.import-failed", failed_before);
    assert_eq!(events.len(), 1, "{events:?}");
    assert_audit_record(&events[0], "WARN", &["step", "error_kind"]);
    assert_eq!(
        (events[0]["step"].as_str(), events[0]["error_kind"].as_str()),
        (Some("5"), Some("config_write"))
    );
    assert_eq!(service.status().await.vault, VaultStatus::ImportUnfinished);
    let refused = exchange(&service, AdminRequest::Unlock, &[DEST_PASSPHRASE.as_bytes()]).await;
    assert!(refused.error().1.contains("iron-vault import"), "{refused:?}");

    let finished = import(&service, &source.bytes, &COMPLETE).await;

    assert_eq!(finished.result().vault_id, source.vault_id);
    assert!(finished.notices.starts_with("An unfinished import is here"), "{}", finished.notices);
    let discarded = since(&logs, "migration.import-discarded", discarded_before);
    assert_eq!(discarded.len(), 1, "{discarded:?}");
    assert_audit_record(&discarded[0], "WARN", &["files"]);
    assert!(discarded[0]["files"].as_str().unwrap().contains("approval.age"), "{discarded:?}");
    assert_no_secret_logged(&logs, &[&failed.reveals[0], &finished.reveals[0]]);
}

/// A protected install whose memory is not locked refuses before any prompt or write, as `init` does.
#[tokio::test(flavor = "multi_thread")]
async fn a_protected_install_without_locked_memory_refuses_import_before_any_prompt_or_write() {
    let (_one, source, _logs) = begin().await;
    let unavailable = MemoryProtection::Unavailable(LockUnavailable::LimitTooLow { limit_bytes: 65_536 });
    for profile in [DeploymentProfile::Protected, DeploymentProfile::Container] {
        for memory in [unavailable.clone(), MemoryProtection::Unsupported] {
            let dest = Dest::new();
            let service = dest.context_as(profile, memory);
            assert_eq!(service.unlock_at_start(&dest.path("no-handoff")).await, ServiceState::Locked);

            let shown = import(&Arc::new(service), &source.bytes, &COMPLETE).await;

            let (code, message) = shown.error();
            assert_eq!(code, ErrorCode::MemoryUnprotected, "{message}");
            assert!(message.contains("memory is not locked against swap"), "{message}");
            assert!(shown.prompts.is_empty() && shown.reveals.is_empty());
            dest.assert_only_lock_files();
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_host_unlock_request_is_refused_before_any_prompt_until_it_is_implemented() {
    let (_one, source, _logs) = begin().await;
    let dest = Dest::new();
    let service = dest.start();
    let (path, stop, task) = spawn_admin(&service, Limits::default());
    let mut stream = UnixStream::connect(&path).await.unwrap();
    send(&mut stream, &Frame::Request(AdminRequest::Import { host_unlock: true })).await;
    send_bundle(&mut stream, &source.bytes).await;

    let shown = converse(&mut stream, &[]).await;

    assert_eq!(shown.error().0, ErrorCode::ImportFailed);
    assert!(shown.prompts.is_empty());
    let _ = stop.send(());
    task.await.unwrap();
    dest.assert_only_lock_files();
}

/// Without a terminal the CLI shows no recovery key, so it exits before it connects or reads the bundle.
#[tokio::test(flavor = "multi_thread")]
async fn the_cli_refuses_without_a_terminal_before_connecting() {
    let (_one, source, _logs) = begin().await;
    let dest = Dest::new();
    let probe = dest.path("probe.sock");
    let listener = std::os::unix::net::UnixListener::bind(&probe).unwrap();
    listener.set_nonblocking(true).unwrap();
    let bundle = dest.path("vault.bundle");
    fs::write(&bundle, &source.bytes).unwrap();

    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(env!("CARGO_BIN_EXE_iron-vault"))
            .arg("import")
            .arg(&bundle)
            .arg("--admin-socket")
            .arg(&probe)
            .stdin(std::process::Stdio::piped())
            .output()
            .unwrap()
    })
    .await
    .unwrap();

    assert_eq!(output.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("controlling terminal only") && stderr.contains("nothing was sent"),
        "{stderr}"
    );
    assert!(listener.accept().is_err(), "the CLI connected");
}

/// What `iron-vault import` did when the CLI ran as a child process.
#[derive(Debug)]
struct CliRan {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// A pseudo-terminal the CLI gets as its controlling terminal, which is where it shows the recovery key. The test keeps
/// the slave open until the CLI is done, and drains the master so a long reveal cannot block the CLI.
struct Terminal {
    slave: fs::File,
    path: String,
}

impl Terminal {
    fn open() -> Self {
        use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
        let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC).unwrap();
        grantpt(&master).unwrap();
        unlockpt(&master).unwrap();
        let path = ptsname(&master, Vec::new()).unwrap().into_string().unwrap();
        let slave = fs::File::options()
            .read(true)
            .write(true)
            .custom_flags(rustix::fs::OFlags::NOCTTY.bits() as i32)
            .open(&path)
            .unwrap();
        let mut master = fs::File::from(master);
        std::thread::spawn(move || while matches!(master.read(&mut [0; 1024]), Ok(1..)) {});
        Self { slave, path }
    }
}

/// A running `iron-vault import <bundle>` whose stdin is a pipe the test types the owner's answers into, in `cwd`.
struct CliImport {
    child: std::process::Child,
    _terminal: Terminal,
}

impl CliImport {
    /// `setsid` and a shell make the pseudo-terminal the CLI's controlling terminal, and `exec` puts the CLI in the shell's place.
    fn start(socket: &Path, bundle: &Path, cwd: &Path) -> Self {
        let terminal = Terminal::open();
        let child = Command::new("setsid")
            .args(["sh", "-c", r#"exec 9<"$IV_PTS" && exec 9<&- && exec "$@""#, "sh"])
            .arg(env!("CARGO_BIN_EXE_iron-vault"))
            .arg("import")
            .arg(bundle)
            .arg("--admin-socket")
            .arg(socket)
            .env("IV_PTS", &terminal.path)
            .current_dir(cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let _ = &terminal.slave;
        Self {
            child,
            _terminal: terminal,
        }
    }

    /// Types `answers`, one line each, then closes stdin and waits for the CLI to end.
    fn finish(mut self, answers: &[&[u8]]) -> CliRan {
        let mut stdin = self.child.stdin.take().unwrap();
        answers.iter().for_each(|answer| {
            let _ = stdin.write_all(answer).and_then(|()| stdin.write_all(b"\n"));
        });
        drop(stdin);
        let output = self.child.wait_with_output().unwrap();
        CliRan {
            code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }
}

/// Runs the CLI's `import` of `bundle` (as typed, relative to `cwd`) against `service` with all of `answers` at once.
async fn cli_import(service: &Arc<ServiceContext>, cwd: &Path, bundle: &Path, answers: &[&[u8]]) -> CliRan {
    let (socket, stop, task) = spawn_admin(service, Limits::default());
    let (cwd, bundle) = (cwd.to_path_buf(), bundle.to_path_buf());
    let answers: Vec<Vec<u8>> = answers.iter().map(|answer| answer.to_vec()).collect();
    let ran = tokio::task::spawn_blocking(move || {
        let answers: Vec<&[u8]> = answers.iter().map(Vec::as_slice).collect();
        CliImport::start(&socket, &bundle, &cwd).finish(&answers)
    })
    .await
    .unwrap();
    let _ = stop.send(());
    task.await.unwrap();
    ran
}

/// The config copy beside `bundle` and its mode, or `None` when there is none.
fn config_copy(bundle: &Path) -> Option<(Vec<u8>, u32)> {
    let copy = PathBuf::from(format!("{}.config.toml", bundle.display()));
    let mode = fs::metadata(&copy).ok()?.permissions().mode() & 0o777;
    Some((fs::read(&copy).unwrap(), mode))
}

fn source_config(source: &Source) -> Vec<u8> {
    fs::read(source.fixture.path("etc/config.toml")).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_config_copy_is_the_sources_config_and_its_printed_command_approves_it_as_all_added() {
    let (_one, source, _logs) = begin().await;
    let dest = Dest::new();
    let service = dest.start();
    let bundle = dest.path("vault.bundle");
    fs::write(&bundle, &source.bytes).unwrap();

    let ran = cli_import(&service, dest.dir.path(), &bundle, &COMPLETE).await;

    assert_eq!(ran.code, Some(0), "{ran:?}");
    assert_eq!(config_copy(&bundle), Some((source_config(source), 0o600)));
    let command = format!("iron-vault config approve {}.config.toml\n", bundle.display());
    assert!(ran.stdout.contains(&command), "{}", ran.stdout);
    assert!(
        ran.stdout.contains("one of the approvers") && ran.stdout.contains("an edited copy"),
        "{}",
        ran.stdout
    );

    // A restart brings the provisional listeners up, and `unlock` ends Unavailable until the copy is approved.
    drop(service);
    let _ = fs::remove_file(source.fixture.socket());
    let service = dest.start();
    exchange(&service, AdminRequest::Unlock, &[DEST_PASSPHRASE.as_bytes()]).await;
    let copy = fs::read(format!("{}.config.toml", bundle.display())).unwrap();
    let request = AdminRequest::ConfigApprove(ProposedConfig::new(copy).unwrap());
    let approved = exchange(&service, request, &[b"yes", APPROVAL_PASSPHRASE.as_bytes()]).await;
    assert!(matches!(approved.response, Some(AdminResponse::ConfigApprove(_))), "{approved:?}");
    assert!(approved.notices.contains("no active config"), "{}", approved.notices);
    assert!(!approved.notices.contains("same config"), "{}", approved.notices);
    ["listeners:", "callers:", "routes:"]
        .iter()
        .for_each(|section| assert!(approved.notices.contains(section), "{section} not in {}", approved.notices));
    assert_eq!(service.state().await, ServiceState::Ready);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_taken_copy_name_is_refused_before_the_request_and_nothing_is_written() {
    let (_one, source, _logs) = begin().await;
    let dest = Dest::new();
    let service = dest.start();
    let bundle = dest.path("vault.bundle");
    fs::write(&bundle, &source.bytes).unwrap();
    let taken = dest.path("vault.bundle.config.toml");
    fs::write(&taken, b"mine").unwrap();

    let ran = cli_import(&service, dest.dir.path(), &bundle, &COMPLETE).await;

    assert_eq!(ran.code, Some(2), "{ran:?}");
    assert!(
        ran.stderr.contains(&taken.display().to_string()) && ran.stderr.contains("nothing was sent"),
        "{}",
        ran.stderr
    );
    assert_eq!(fs::read(&taken).unwrap(), b"mine");
    dest.assert_only_lock_files();
}

#[tokio::test(flavor = "multi_thread")]
async fn every_ending_but_success_leaves_no_copy() {
    let (_one, source, _logs) = begin().await;
    let dest = Dest::new();
    let service = dest.start();
    let mut broken = source.bytes.clone();
    broken[0] ^= 0xff;
    let answers = |given: &[&'static [u8]]| given.to_vec();
    let cases = [
        ("import-denied", source.bytes.clone(), answers(&[b"EXPORT-wrong-guess-0000"])),
        ("bundle-invalid", broken, answers(&[])),
        (
            "declined",
            source.bytes.clone(),
            answers(&[
                EXPORT_PASSPHRASE.as_bytes(),
                DEST_PASSPHRASE.as_bytes(),
                DEST_PASSPHRASE.as_bytes(),
                b"no",
            ]),
        ),
        ("cancelled", source.bytes.clone(), answers(&[EXPORT_PASSPHRASE.as_bytes()])),
    ];

    for (ending, bytes, answers) in cases {
        let bundle = dest.path(&format!("{ending}.bundle"));
        fs::write(&bundle, &bytes).unwrap();

        let ran = cli_import(&service, dest.dir.path(), &bundle, &answers).await;

        assert_ne!(ran.code, Some(0), "{ending}: {ran:?}");
        assert_eq!(config_copy(&bundle), None, "{ending}: a copy was left");
        dest.assert_only_lock_files();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bundle_replaced_during_the_import_leaves_no_copy_and_prints_the_digest_with_exit_zero() {
    let (_one, source, _logs) = begin().await;
    let dest = Dest::new();
    let service = dest.start();
    let bundle = dest.path("vault.bundle");
    fs::write(&bundle, &source.bytes).unwrap();
    let (socket, stop, task) = spawn_admin(&service, Limits::default());
    let import = CliImport::start(&socket, &bundle, dest.dir.path());
    // The service holds the import slot from its first check, after the CLI has opened the bundle it streams and before the
    // CLI decodes the path again. A new file under the bundle's name, put there meanwhile, is what that second read finds.
    wait_for_taken_slot(&service).await;
    fs::write(dest.path("other"), b"not a bundle").unwrap();
    fs::rename(dest.path("other"), &bundle).unwrap();
    let ran = tokio::task::spawn_blocking(move || import.finish(&COMPLETE)).await.unwrap();
    let _ = stop.send(());
    task.await.unwrap();

    assert_eq!(ran.code, Some(0), "{ran:?}");
    assert_eq!(config_copy(&bundle), None);
    let digest: String = source.digest.iter().map(|byte| format!("{byte:02x}")).collect();
    assert!(ran.stdout.contains(&format!("blake2b:{digest}")), "{}", ran.stdout);
    assert!(ran.stderr.contains("no config copy was kept"), "{}", ran.stderr);
    assert!(!ran.stdout.contains(".config.toml"), "{}", ran.stdout);
    assert_eq!(service.status().await.vault, VaultStatus::Locked);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_relative_bundle_path_with_a_space_prints_a_quoted_command_for_the_copy_as_created() {
    let (_one, source, _logs) = begin().await;
    let dest = Dest::new();
    let service = dest.start();
    fs::write(dest.path("my vault.bundle"), &source.bytes).unwrap();

    let ran = cli_import(&service, dest.dir.path(), Path::new("my vault.bundle"), &COMPLETE).await;

    assert_eq!(ran.code, Some(0), "{ran:?}");
    assert!(
        ran.stdout.contains("iron-vault config approve 'my vault.bundle.config.toml'\n"),
        "{}",
        ran.stdout
    );
    assert_eq!(config_copy(&dest.path("my vault.bundle")), Some((source_config(source), 0o600)));
}
