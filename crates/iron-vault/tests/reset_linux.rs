//! `reset` end to end over a real admin socket against a running service context (specification §5, §16;
//! design/reset.md): the confirmation, the lock-first withdrawal, the discard and the state it leaves, the refusals that
//! remove nothing, and the audit log.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use common::approval_harness::{
    Exchanged, Fixture, approve, captured_logs, converse, converse_revealing, error_code, identity, read_frame, send, serve_admin,
};
use iron_vault::admin::protocol::{AdminRequest, AdminResponse, ErrorCode, Frame, Prompt, VaultStatus};
use iron_vault::service_context::{ServiceContext, UnlockRefusal};
use iron_vault::service_state::{FailureReason, ServiceState};
use iron_vault::serving_snapshot::Admission;
use iron_vault_store::{VaultId, open_manifest};
use tokio::net::UnixStream;

const DRAIN: Duration = Duration::from_secs(5);
const INIT_ANSWERS: [&str; 5] = [
    "RESET-vault-passphrase-41c7",
    "RESET-vault-passphrase-41c7",
    "RESET-approval-9d2e",
    "RESET-approval-9d2e",
    "yes",
];

fn vault_id(fixture: &Fixture) -> VaultId {
    open_manifest(&identity(), &fs::read(fixture.path("state/manifest.age")).unwrap())
        .unwrap()
        .vault_id()
}

/// Every file of the state and config directories with its bytes, so a test sees that nothing changed.
fn files(fixture: &Fixture) -> BTreeMap<String, Vec<u8>> {
    ["state", "etc"]
        .into_iter()
        .flat_map(|dir| {
            fs::read_dir(fixture.path(dir)).unwrap().map(move |entry| {
                let entry = entry.unwrap();
                (
                    format!("{dir}/{}", entry.file_name().to_string_lossy()),
                    fs::read(entry.path()).unwrap_or_default(),
                )
            })
        })
        .collect()
}

fn confirmation_prompt(text: &str, what: &str) -> Prompt {
    Prompt {
        label: format!("Type {text} to discard {what}"),
        secret: false,
        switchable: false,
    }
}

/// Sends `reset` on a new connection and answers its prompt with `answers`.
async fn reset(path: &std::path::Path, answers: &[&str]) -> Exchanged {
    let mut stream = UnixStream::connect(path).await.unwrap();
    send(&mut stream, &Frame::Request(AdminRequest::Reset)).await;
    converse(&mut stream, answers).await
}

/// Sends `reset` and reads up to its confirmation prompt, leaving the exchange open there.
async fn reset_to_prompt(path: &std::path::Path) -> UnixStream {
    let mut stream = UnixStream::connect(path).await.unwrap();
    send(&mut stream, &Frame::Request(AdminRequest::Reset)).await;
    while !matches!(read_frame(&mut stream).await, Frame::Prompt(_)) {}
    stream
}

async fn answer(stream: &mut UnixStream, text: &str) -> AdminResponse {
    send(
        stream,
        &Frame::OwnerInput(iron_vault::admin::protocol::OwnerInput::new(text.as_bytes().to_vec().into())),
    )
    .await;
    loop {
        if let Frame::Response(response) = read_frame(stream).await {
            return response;
        }
    }
}

fn result(exchanged: &Exchanged) -> (Option<VaultId>, u64, Vec<String>, bool, bool) {
    match &exchanged.response {
        AdminResponse::Reset {
            vault_id,
            removed,
            foreign,
            cleared,
            finish_uncertain,
        } => (*vault_id, *removed, foreign.clone(), *cleared, *finish_uncertain),
        other => panic!("expected a reset result, got {other:?}"),
    }
}

/// Resets the fixture's vault with its vault ID (typed in capitals), then checks the directories and runs `init`.
async fn reset_then_init(fixture: &Fixture, service: &Arc<ServiceContext>) {
    let id = vault_id(fixture);
    let (path, stop) = serve_admin(service);

    let exchanged = reset(&path, &[&id.to_string().to_uppercase()]).await;

    assert_eq!(exchanged.prompts, [confirmation_prompt(&id.to_string(), "this vault")]);
    let (confirmed, removed, foreign, cleared, uncertain) = result(&exchanged);
    assert_eq!((confirmed, foreign, cleared, uncertain), (Some(id), Vec::new(), true, false));
    assert!(removed > 3, "{removed}");
    assert_eq!(service.state().await, ServiceState::Locked);
    assert_eq!(service.status().await.vault, VaultStatus::NotInitialized);
    let left: Vec<_> = files(fixture).into_keys().collect();
    assert!(
        left.iter()
            .all(|name| !name.ends_with(".age") && !name.contains("config.toml") || name.ends_with(".lock")),
        "{left:?}"
    );

    assert_eq!(error_code(&reset(&path, &[]).await.response), ErrorCode::NothingToReset);
    let mut stream = UnixStream::connect(&path).await.unwrap();
    send(&mut stream, &Frame::Request(AdminRequest::Init { host_unlock: false })).await;
    let (initialized, _) = converse_revealing(&mut stream, &INIT_ANSWERS).await;
    assert!(
        matches!(initialized.response, AdminResponse::Init { .. }),
        "{:?}",
        initialized.response
    );
    let _ = stop.send(());
}

#[tokio::test]
async fn release_check_1_reset_from_ready_ends_uninitialized_and_init_then_works() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    reset_then_init(&fixture, &service).await;
}

#[tokio::test]
async fn release_check_1_reset_from_locked_ends_uninitialized_and_init_then_works() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    service.lock(DRAIN).await.unwrap();
    reset_then_init(&fixture, &service).await;
}

#[tokio::test]
async fn release_check_1_reset_from_policy_invalid_ends_uninitialized_and_init_then_works() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    fs::write(fixture.path("etc/config.toml"), "not a config").unwrap();
    service.reload().await.unwrap();
    assert_eq!(service.state().await, ServiceState::Unavailable(FailureReason::PolicyInvalid));
    reset_then_init(&fixture, &service).await;
}

#[tokio::test]
async fn release_check_2_a_wrong_confirmation_a_cancel_and_a_closed_cli_change_nothing() {
    let fixture = Fixture::new().await;
    let id = vault_id(&fixture);
    let service = fixture.ready().await;
    let (path, stop) = serve_admin(&service);
    let before = files(&fixture);

    for typed in ["yes", "", "/not/the/vault", &format!(" {id}")] {
        assert_eq!(error_code(&reset(&path, &[typed]).await.response), ErrorCode::Declined, "{typed:?}");
    }
    drop(reset_to_prompt(&path).await);
    drop(UnixStream::connect(&path).await.unwrap());
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert_eq!(files(&fixture), before);
    assert_eq!(service.state().await, ServiceState::Ready);
    assert!(matches!(service.holder().load(), Admission::Serve(_)));
    let _ = stop.send(());
}

#[tokio::test]
async fn release_check_10_a_vault_change_between_the_summary_and_step_4_declines_and_removes_nothing() {
    let fixture = Fixture::new().await;
    let id = vault_id(&fixture);
    let service = fixture.ready().await;
    service.lock(DRAIN).await.unwrap();
    let (path, stop) = serve_admin(&service);

    let mut stream = reset_to_prompt(&path).await;
    let manifest = fs::read(fixture.path("state/manifest.age")).unwrap();
    let mut other = manifest.clone();
    other[5..21].copy_from_slice(&[
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x41, 0x11, 0x91, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    ]);
    fs::write(fixture.path("state/manifest.age"), &other).unwrap();
    let before = files(&fixture);
    assert_eq!(error_code(&answer(&mut stream, &id.to_string()).await), ErrorCode::Declined);
    assert_eq!(files(&fixture), before, "a different vault ID");

    let mut stream = reset_to_prompt(&path).await;
    fs::remove_file(fixture.path("state/manifest.age")).unwrap();
    let before = files(&fixture);
    let other_id = "11111111-1111-4111-9111-111111111111";
    assert_eq!(error_code(&answer(&mut stream, other_id).await), ErrorCode::Declined);
    assert_eq!(files(&fixture), before, "no longer Initialized");
    let _ = stop.send(());
}

#[tokio::test]
async fn release_check_6_and_9_no_request_after_the_withdrawal_and_challenge_and_attempt_limit_cleared() {
    let fixture = Fixture::new().await;
    let id = vault_id(&fixture);
    let service = fixture.ready().await;
    let snapshot = match service.holder().load() {
        Admission::Serve(snapshot) => Arc::downgrade(&snapshot),
        Admission::Refuse(reason) => panic!("a Ready service serves a snapshot, got {reason:?}"),
    };
    let identity_probe = service.identity_probe().await.unwrap();
    let mut limiter = service.attempt_limiter().await;
    (0..10).for_each(|_| limiter.record_failure(tokio::time::Instant::now()));
    drop(limiter);
    service
        .pending_migration()
        .await
        .issue(
            id,
            iron_vault::migration_authorization::MigrationOperation::Export,
            tokio::time::Instant::now(),
            [7; 32],
        )
        .unwrap();
    let (path, stop) = serve_admin(&service);

    let exchanged = reset(&path, &[&id.to_string()]).await;

    assert!(result(&exchanged).3);
    assert!(matches!(service.holder().load(), Admission::Refuse(_)));
    assert!(snapshot.upgrade().is_none() && identity_probe.upgrade().is_none());
    assert!(!service.pending_migration().await.is_pending());
    assert!(service.attempt_limiter().await.check(tokio::time::Instant::now()).is_ok());
    let _ = stop.send(());
}

#[tokio::test]
async fn release_check_7_a_foreign_file_stays_and_is_named_escaped_in_the_summary_the_result_and_the_log() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let id = vault_id(&fixture);
    let service = fixture.ready().await;
    fs::write(fixture.path("state/odd\nname.txt"), b"mine").unwrap();
    let (path, stop) = serve_admin(&service);

    let exchanged = reset(&path, &[&id.to_string()]).await;

    assert!(exchanged.notices.contains("odd\\nname.txt"), "{}", exchanged.notices);
    assert!(!exchanged.notices.contains("odd\nname.txt"));
    assert_eq!(result(&exchanged).2, ["odd\\nname.txt"]);
    assert_eq!(fs::read(fixture.path("state/odd\nname.txt")).unwrap(), b"mine");
    let event = logs
        .events("vault.reset")
        .into_iter()
        .find(|e| e["vault_id"] == id.to_string().as_str())
        .unwrap();
    assert_eq!(
        (event["level"].as_str(), event["foreign"].as_str()),
        (Some("WARN"), Some("odd\\nname.txt"))
    );
    assert!(
        logs.events("vault.reset-confirmed")
            .iter()
            .any(|e| e["vault_id"] == id.to_string().as_str())
    );
    assert!(!logs.text().contains("fx-secret"), "a secret reached the log");
    let _ = stop.send(());
}

#[tokio::test]
async fn release_check_5_an_interrupted_reset_is_reported_refused_by_unlock_and_finished_by_the_next_reset() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    service.lock(DRAIN).await.unwrap();
    fs::write(fixture.path("state/reset.unfinished"), b"").unwrap();
    assert_eq!(service.status().await.vault, VaultStatus::ResetUnfinished);
    let passphrase = iron_vault_store::Passphrase::new("anything-long-enough".into()).unwrap();
    assert!(matches!(service.unlock(passphrase).await, Err(UnlockRefusal::Failed(_))));
    let (path, stop) = serve_admin(&service);
    let state_dir = fixture.path("state").to_string_lossy().into_owned();

    assert_eq!(
        error_code(&reset(&path, &[&vault_id(&fixture).to_string()]).await.response),
        ErrorCode::Declined
    );
    let exchanged = reset(&path, &[&state_dir]).await;

    assert_eq!(exchanged.prompts, [confirmation_prompt(&state_dir, "these files")]);
    assert_eq!(result(&exchanged).0, None);
    assert_eq!(service.status().await.vault, VaultStatus::NotInitialized);
    assert!(
        logs.events("vault.reset-confirmed")
            .iter()
            .any(|e| e["resumes"] == true && e["initialization"] == "unfinished_reset")
    );
    let _ = stop.send(());
}

/// Removes every file of the state and config directories, leaving the lock files, and writes `marker` into the state directory.
fn leave_only(fixture: &Fixture, marker: &str) {
    ["state", "etc"]
        .into_iter()
        .flat_map(|dir| fs::read_dir(fixture.path(dir)).unwrap().map(|entry| entry.unwrap().path()))
        .filter(|path| path.extension().is_none_or(|ext| ext != "lock") && path.file_name() != Some("lock".as_ref()))
        .for_each(|path| fs::remove_file(path).unwrap());
    fs::write(fixture.path("state").join(marker), b"").unwrap();
}

/// Unlocks the vault `reset_then_init` created.
async fn unlock_new_vault(service: &Arc<ServiceContext>) {
    let passphrase = iron_vault_store::Passphrase::new(INIT_ANSWERS[0].into()).unwrap();
    assert!(service.unlock(passphrase).await.is_ok());
}

/// Release check 1, last clause: the old config and signature, saved aside before the reset, are refused by the new vault.
#[tokio::test]
async fn release_check_1_the_old_config_and_signature_are_refused_by_the_new_vault() {
    let fixture = Fixture::new().await;
    let old = fixture.published_pair();
    let service = fixture.ready().await;
    reset_then_init(&fixture, &service).await;

    unlock_new_vault(&service).await;
    fixture.put_back(&old);
    service.reload().await.unwrap();

    assert!(
        matches!(service.state().await, ServiceState::Unavailable(_)),
        "{:?}",
        service.state().await
    );
}

/// Release check 3: the CLI exits with code 3 before connecting, for a pipe, a file, `/dev/null` and no controlling terminal.
#[tokio::test]
async fn release_check_3_the_cli_refuses_without_a_terminal_before_connecting() {
    let fixture = Fixture::new().await;
    let before = files(&fixture);
    // A socket nothing connects to: the CLI must exit before it tries.
    let path = fixture.path("probe.sock");
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    listener.set_nonblocking(true).unwrap();
    let stdins = [
        Stdio::piped(),
        Stdio::from(fs::File::create(fixture.path("answers")).unwrap()),
        Stdio::null(),
    ];

    let socket = path.clone();
    let codes = tokio::task::spawn_blocking(move || {
        let run = |mut command: Command| command.stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap().code();
        let cli = |stdin| {
            let mut command = Command::new(env!("CARGO_BIN_EXE_iron-vault"));
            command.args(["reset", "--admin-socket"]).arg(&socket).stdin(stdin);
            command
        };
        let mut codes: Vec<_> = stdins.into_iter().map(|stdin| run(cli(stdin))).collect();
        let mut detached = Command::new("setsid");
        detached
            .arg("--wait")
            .arg(env!("CARGO_BIN_EXE_iron-vault"))
            .args(["reset", "--admin-socket"])
            .arg(&socket);
        codes.push(run(detached));
        codes
    })
    .await
    .unwrap();

    assert_eq!(codes, [Some(3); 4]);
    assert!(listener.accept().is_err(), "the CLI connected");
    fs::remove_file(&path).unwrap();
    fs::remove_file(fixture.path("answers")).unwrap();
    assert_eq!(files(&fixture), before);
}

/// Release check 4: every approver unusable, so no config can be approved; reset and `init` make the vault usable again, and
/// the owner's copy of the config is approved against it.
#[tokio::test]
async fn release_check_4_a_vault_with_no_usable_approver_is_rebuilt_by_reset_and_init() {
    let fixture = Fixture::new().await;
    let config = fixture.config("fx");
    fs::read_dir(fixture.path("state"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.file_name().is_some_and(|name| name.to_string_lossy().starts_with("approver-")))
        .for_each(|path| fs::remove_file(path).unwrap());
    let service = fixture.ready().await;
    let broken = approve(&service, &config, &["yes", "APPROVAL-correct-3e8b"]).await;
    assert!(matches!(broken.response, AdminResponse::Error { .. }), "{:?}", broken.response);

    reset_then_init(&fixture, &service).await;
    unlock_new_vault(&service).await;

    let rebuilt = fs::read_to_string(fixture.path("etc/config.toml")).unwrap();
    let approved = approve(&service, &format!("{rebuilt}# the owner's copy\n"), &["yes", INIT_ANSWERS[2]]).await;
    assert!(
        matches!(approved.response, AdminResponse::ConfigApprove { .. }),
        "{:?}",
        approved.response
    );
}

/// Release check 5, last clause: a `reset.unfinished` put back over empty directories reads Unfinished reset, and the next reset
/// removes it. (The crash before each removal is injected in the store's own tests.)
#[tokio::test]
async fn release_check_5_a_reset_unfinished_over_empty_directories_reads_unfinished_and_the_next_reset_removes_it() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    service.lock(DRAIN).await.unwrap();
    leave_only(&fixture, "reset.unfinished");
    let (path, stop) = serve_admin(&service);
    assert_eq!(service.status().await.vault, VaultStatus::ResetUnfinished);

    let state_dir = fixture.path("state").to_string_lossy().into_owned();
    let exchanged = reset(&path, &[&state_dir]).await;

    assert_eq!(result(&exchanged).0, None);
    assert!(!fixture.path("state/reset.unfinished").exists());
    assert_eq!(service.status().await.vault, VaultStatus::NotInitialized);
    let _ = stop.send(());
}

/// Release check 8: Uninitialized, and a config file alone, end with `nothing-to-reset`.
#[tokio::test]
async fn release_check_8_uninitialized_and_a_config_file_alone_are_nothing_to_reset() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    service.lock(DRAIN).await.unwrap();
    leave_only(&fixture, "scratch");
    fs::remove_file(fixture.path("state/scratch")).unwrap();
    let (path, stop) = serve_admin(&service);
    assert_eq!(error_code(&reset(&path, &[]).await.response), ErrorCode::NothingToReset);

    fs::write(fixture.path("etc/config.toml"), b"schema_version = 1\n").unwrap();
    assert_eq!(error_code(&reset(&path, &[]).await.response), ErrorCode::NothingToReset);
    assert!(fixture.path("etc/config.toml").exists());
    let _ = stop.send(());
}

/// Release check 11: an Unfinished initialization, confirmed with the state directory's path, ends Uninitialized.
#[tokio::test]
async fn release_check_11_an_unfinished_initialization_is_reset_with_the_state_directory_path() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    service.lock(DRAIN).await.unwrap();
    leave_only(&fixture, "init.unfinished");
    let (path, stop) = serve_admin(&service);
    assert_eq!(service.status().await.vault, VaultStatus::InitializationUnfinished);
    let state_dir = fixture.path("state").to_string_lossy().into_owned();

    let exchanged = reset(&path, &[&state_dir]).await;

    assert_eq!(exchanged.prompts, [confirmation_prompt(&state_dir, "these files")]);
    assert_eq!(service.status().await.vault, VaultStatus::NotInitialized);
    assert!(!fixture.path("state/init.unfinished").exists());
    let _ = stop.send(());
}

/// Release check 11, import clause: an unfinished import is reset the same way. Unfinished imports are not built yet.
#[tokio::test]
#[ignore = "an unfinished import cannot be created until import lands (K-312, K-313)"]
async fn release_check_11_an_unfinished_import_is_reset_with_the_state_directory_path() {}

/// Release check 10, import clause: an import writing at the summary that finishes before step 4 declines the reset.
#[tokio::test]
#[ignore = "import does not exist yet (K-312, K-313)"]
async fn release_check_10_an_import_finishing_before_step_4_declines_the_reset() {}

/// Release check 12: the three audit events reach the log, and none holds a secret or the typed confirmation.
#[tokio::test]
async fn release_check_12_the_audit_events_reach_the_log_without_a_secret_or_the_confirmation() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let id = vault_id(&fixture);
    let service = fixture.ready().await;
    let (path, stop) = serve_admin(&service);
    let typed = id.to_string().to_uppercase();

    reset(&path, &[&typed]).await;

    ["vault.reset-confirmed", "vault.reset"]
        .iter()
        .for_each(|event| assert!(!logs.events(event).is_empty(), "{event}"));
    let text = logs.text();
    assert!(
        !text.contains(&typed) && !text.contains("fx-secret") && !text.contains(INIT_ANSWERS[0]),
        "{text}"
    );
    let _ = stop.send(());
}
