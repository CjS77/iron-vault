//! `reset` end to end over a real admin socket against a running service context (specification §5, §16;
//! design/reset.md): the confirmation, the lock-first withdrawal, the discard and the state it leaves, the refusals that
//! remove nothing, and the audit log.

#![cfg(target_os = "linux")]

use crate::common;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use common::WAIT;
use common::approval_harness::{
    Exchanged, Fixture, approve, captured_logs, converse, converse_revealing, error_code, identity, read_frame, send, serve_admin,
};
use common::migration_source::{EXPORT_PASSPHRASE, send_bundle, source};
use common::mock_upstream::Reply;
use common::proxy_harness::{CallerRequest, Via};
use iron_vault::admin::protocol::{AdminRequest, AdminResponse, ErrorCode, Frame, Prompt, RequestedOrigin, VaultStatus};
use iron_vault::service_context::{ServiceContext, UnlockRefusal};
use iron_vault::service_state::{FailureReason, ServiceState};
use iron_vault::serving_snapshot::Admission;
use iron_vault_policy::CredentialKind;
use iron_vault_store::{OsFs, StoreFs, VaultId, open_manifest};
use tokio::net::UnixStream;

/// The files a reset removes from the fixture's vault: store-owned state files plus the owner lock, the config and its signature.
/// The owner lock is always counted: the reset writes `locked-by-owner` before its withdrawal, from every state, and the
/// discard removes it.
const FULL_VAULT_FILES: u64 = 7;
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

fn message(response: &AdminResponse) -> &str {
    match response {
        AdminResponse::Error { message, .. } => message,
        other => panic!("expected an error, got {other:?}"),
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

/// Resets the fixture's vault with its vault ID (typed in capitals), checks that it removed `expected_removed` files and left
/// no `.age` or config file, then runs `init`.
async fn reset_then_init(fixture: &Fixture, service: &Arc<ServiceContext>, expected_removed: u64) {
    let id = vault_id(fixture);
    let (path, stop) = serve_admin(service);

    let exchanged = reset(&path, &[&id.to_string().to_uppercase()]).await;

    assert_eq!(exchanged.prompts, [confirmation_prompt(&id.to_string(), "this vault")]);
    let (confirmed, removed, foreign, cleared, uncertain) = result(&exchanged);
    assert_eq!((confirmed, foreign, cleared, uncertain), (Some(id), Vec::new(), true, false));
    assert_eq!(removed, expected_removed);
    assert_eq!(service.state().await, ServiceState::Locked);
    assert_eq!(service.status().await.vault, VaultStatus::NotInitialized);
    assert_discarded(fixture);

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
    reset_then_init(&fixture, &service, FULL_VAULT_FILES).await;
}

#[tokio::test]
async fn release_check_1_reset_from_locked_ends_uninitialized_and_init_then_works() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    service.lock(DRAIN).await.unwrap();
    reset_then_init(&fixture, &service, FULL_VAULT_FILES).await;
}

#[tokio::test]
async fn release_check_1_reset_from_policy_invalid_ends_uninitialized_and_init_then_works() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    fs::write(fixture.path("etc/config.toml"), "not a config").unwrap();
    service.reload().await.unwrap();
    assert_eq!(service.state().await, ServiceState::Unavailable(FailureReason::PolicyInvalid));
    reset_then_init(&fixture, &service, FULL_VAULT_FILES).await;
}

#[tokio::test]
async fn release_check_1_reset_from_recovery_needed_ends_uninitialized_and_init_then_works() {
    let fixture = Fixture::new().await;
    fs::write(fixture.path("state/approval.age"), b"damaged").unwrap();
    let service = fixture.start().await;
    assert_eq!(service.state().await, ServiceState::Unavailable(FailureReason::RecoveryNeeded));
    reset_then_init(&fixture, &service, FULL_VAULT_FILES).await;
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

/// Release check 10, first clause: a different vault, or no vault, at step 4 declines there, not at the confirmation.
#[tokio::test]
async fn release_check_10_a_vault_change_between_the_summary_and_step_4_declines_and_removes_nothing() {
    let fixture = Fixture::new().await;
    let id = vault_id(&fixture).to_string();
    let service = fixture.ready().await;
    service.lock(DRAIN).await.unwrap();
    let (path, stop) = serve_admin(&service);
    let manifest = fs::read(fixture.path("state/manifest.age")).unwrap();

    let mut stream = reset_to_prompt(&path).await;
    let mut other = manifest.clone();
    other[5..21].copy_from_slice(&[
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x41, 0x11, 0x91, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    ]);
    fs::write(fixture.path("state/manifest.age"), &other).unwrap();
    let before = files(&fixture);
    let response = answer(&mut stream, &id).await;
    assert_eq!(error_code(&response), ErrorCode::Declined);
    assert!(
        message(&response).contains("not the one the summary named"),
        "{}",
        message(&response)
    );
    assert_eq!(files(&fixture), before, "a different vault ID");
    fs::write(fixture.path("state/manifest.age"), &manifest).unwrap();

    let mut stream = reset_to_prompt(&path).await;
    fs::remove_file(fixture.path("state/manifest.age")).unwrap();
    let before = files(&fixture);
    let response = answer(&mut stream, &id).await;
    assert_eq!(error_code(&response), ErrorCode::Declined);
    assert!(message(&response).contains("at the summary"), "{}", message(&response));
    assert_eq!(files(&fixture), before, "no longer Initialized");
    let _ = stop.send(());
}

/// Release check 10, `init` clauses: an `init` that finishes after the summary, or the removal of `init.unfinished`, turns an
/// Unfinished initialization into an Initialized vault, so step 4 declines and removes nothing.
#[tokio::test]
async fn release_check_10_an_init_between_the_summary_and_step_4_declines_and_removes_nothing() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    unfinished_init(&fixture, &service).await;
    let state_dir = fixture.path("state").to_string_lossy().into_owned();
    let (path, stop) = serve_admin(&service);

    let mut stream = reset_to_prompt(&path).await;
    let mut init = UnixStream::connect(&path).await.unwrap();
    send(&mut init, &Frame::Request(AdminRequest::Init { host_unlock: false })).await;
    let (initialized, _) = converse_revealing(&mut init, &INIT_ANSWERS).await;
    assert!(
        matches!(initialized.response, AdminResponse::Init { .. }),
        "{:?}",
        initialized.response
    );
    let before = files(&fixture);
    let response = answer(&mut stream, &state_dir).await;
    assert_eq!(error_code(&response), ErrorCode::Declined);
    assert!(message(&response).contains("at the summary"), "{}", message(&response));
    assert_eq!(files(&fixture), before, "an init finished before step 4");

    fs::write(fixture.path("state/init.unfinished"), b"").unwrap();
    let mut stream = reset_to_prompt(&path).await;
    fs::remove_file(fixture.path("state/init.unfinished")).unwrap();
    let before = files(&fixture);
    let response = answer(&mut stream, &state_dir).await;
    assert_eq!(error_code(&response), ErrorCode::Declined);
    assert!(message(&response).contains("at the summary"), "{}", message(&response));
    assert_eq!(files(&fixture), before, "init.unfinished removed");
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

/// Removes every file of the state and config directories, leaving the lock files.
fn empty_directories(fixture: &Fixture) {
    ["state", "etc"]
        .into_iter()
        .flat_map(|dir| fs::read_dir(fixture.path(dir)).unwrap().map(|entry| entry.unwrap().path()))
        .filter(|path| path.extension().is_none_or(|ext| ext != "lock") && path.file_name() != Some("lock".as_ref()))
        .for_each(|path| fs::remove_file(path).unwrap());
}

/// Asserts the directories hold no `.age` file and no config file: the vault is discarded.
fn assert_discarded(fixture: &Fixture) {
    let left: Vec<_> = files(fixture).into_keys().collect();
    assert!(
        left.iter()
            .all(|name| !name.ends_with(".age") && !name.contains("config.toml") || name.ends_with(".lock")),
        "{left:?}"
    );
    // `locked-by-owner` has no `.age` suffix, so the check above cannot see it.
    assert!(!fixture.path("state/locked-by-owner").exists(), "{left:?}");
}

/// Resets, runs `init`, then writes `init.unfinished` over the new vault: an Unfinished initialization built from a real one.
async fn unfinished_init(fixture: &Fixture, service: &Arc<ServiceContext>) {
    reset_then_init(fixture, service, FULL_VAULT_FILES).await;
    fs::write(fixture.path("state/init.unfinished"), b"").unwrap();
    assert_eq!(service.status().await.vault, VaultStatus::InitializationUnfinished);
}

/// Adds the credential `fx_key` the fixture's config routes to, with the upstream's origin, to the vault `init` just made.
async fn add_fx_key(fixture: &Fixture, service: &Arc<ServiceContext>) {
    let (path, stop) = serve_admin(service);
    let mut stream = UnixStream::connect(&path).await.unwrap();
    let origins = vec![RequestedOrigin {
        host: "localhost".to_owned(),
        port: fixture.upstream().port().to_string().parse().unwrap(),
    }];
    let request = AdminRequest::Add {
        name: "fx_key".to_owned(),
        kind: CredentialKind::Static,
        origins,
    };
    send(&mut stream, &Frame::Request(request)).await;
    let added = converse(&mut stream, &["fx-secret"]).await;
    assert!(matches!(added.response, AdminResponse::Add { .. }), "{:?}", added.response);
    let _ = stop.send(());
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
    reset_then_init(&fixture, &service, FULL_VAULT_FILES).await;
    unlock_new_vault(&service).await;
    add_fx_key(&fixture, &service).await;
    assert_eq!(service.state().await, ServiceState::Ready);

    fixture.put_back(&old);
    service.reload().await.unwrap();

    assert_eq!(service.state().await, ServiceState::Unavailable(FailureReason::PolicyInvalid));
}

/// Release check 3: the CLI exits with code 3 before connecting, for a pipe, a file, `/dev/null` and no controlling terminal,
/// and its message names the check that refused it.
#[tokio::test]
async fn release_check_3_the_cli_refuses_without_a_terminal_before_connecting() {
    let fixture = Fixture::new().await;
    let before = files(&fixture);
    // A socket nothing connects to: the CLI must exit before it tries.
    let path = fixture.path("probe.sock");
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    listener.set_nonblocking(true).unwrap();
    let answers = Stdio::from(fs::File::create(fixture.path("answers")).unwrap());
    let socket = path.clone();

    let refusals = tokio::task::spawn_blocking(move || {
        let cli = |stdin: Stdio| {
            let output = Command::new(env!("CARGO_BIN_EXE_iron-vault"))
                .args(["reset", "--admin-socket"])
                .arg(&socket)
                .stdin(stdin)
                .output()
                .unwrap();
            (output.status.code(), String::from_utf8_lossy(&output.stderr).into_owned())
        };
        // `script` gives the command a pseudo-terminal for stdin, and `setsid` then drops it as the controlling terminal, so
        // only the `/dev/tty` check can refuse. The pseudo-terminal carries stderr too.
        let detached = Command::new("script")
            .args([
                "-qec",
                &format!(
                    "setsid --wait '{}' reset --admin-socket '{}'",
                    env!("CARGO_BIN_EXE_iron-vault"),
                    socket.display()
                ),
            ])
            .arg("/dev/null")
            .stdin(Stdio::null())
            .output()
            .expect("`script` (util-linux) is needed to give the CLI a terminal without a controlling one");
        let detached = (detached.status.code(), String::from_utf8_lossy(&detached.stdout).into_owned());
        [cli(Stdio::piped()), cli(answers), cli(Stdio::null()), detached]
    })
    .await
    .unwrap();

    let stdin_not_a_terminal = "stdin is not a terminal";
    let (codes, messages): (Vec<_>, Vec<_>) = refusals.into_iter().unzip();
    assert_eq!(codes, [Some(3); 4], "{messages:?}");
    assert!(messages[..3].iter().all(|m| m.contains(stdin_not_a_terminal)), "{messages:?}");
    assert!(
        messages[3].contains("/dev/tty cannot be opened") && !messages[3].contains(stdin_not_a_terminal),
        "{messages:?}"
    );
    assert!(listener.accept().is_err(), "the CLI connected");
    fs::remove_file(&path).unwrap();
    fs::remove_file(fixture.path("answers")).unwrap();
    assert_eq!(files(&fixture), before);
}

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
    assert_eq!(
        error_code(&broken.response),
        ErrorCode::ApprovalUnavailable,
        "{:?}",
        broken.response
    );

    reset_then_init(&fixture, &service, FULL_VAULT_FILES - 1).await;
    unlock_new_vault(&service).await;
    add_fx_key(&fixture, &service).await;

    let approved = approve(&service, &config, &["yes", INIT_ANSWERS[2]]).await;
    assert!(
        matches!(approved.response, AdminResponse::ConfigApprove { .. }),
        "{:?}",
        approved.response
    );
    assert_eq!(service.state().await, ServiceState::Ready);
}

/// Release check 5, last clause: a `reset.unfinished` put back over empty directories reads Unfinished reset, and the next reset
/// removes it. (The crash before each removal is injected in the store's own tests.)
#[tokio::test]
async fn release_check_5_a_reset_unfinished_over_empty_directories_reads_unfinished_and_the_next_reset_removes_it() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    service.lock(DRAIN).await.unwrap();
    empty_directories(&fixture);
    fs::write(fixture.path("state/reset.unfinished"), b"").unwrap();
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
    empty_directories(&fixture);
    let (path, stop) = serve_admin(&service);
    assert_eq!(error_code(&reset(&path, &[]).await.response), ErrorCode::NothingToReset);

    fs::write(fixture.path("etc/config.toml"), b"schema_version = 1\n").unwrap();
    assert_eq!(error_code(&reset(&path, &[]).await.response), ErrorCode::NothingToReset);
    assert!(fixture.path("etc/config.toml").exists());
    let _ = stop.send(());
}

/// Release check 11, and check 2's clause: the old vault ID typed for an Unfinished vault is declined; the state directory's
/// path resets it, leaving no record, `.age` or config file.
#[tokio::test]
async fn release_check_11_an_unfinished_initialization_is_reset_with_the_state_directory_path() {
    let fixture = Fixture::new().await;
    let old_id = vault_id(&fixture).to_string();
    let service = fixture.ready().await;
    unfinished_init(&fixture, &service).await;
    let (path, stop) = serve_admin(&service);
    let state_dir = fixture.path("state").to_string_lossy().into_owned();
    let before = files(&fixture);

    assert_eq!(error_code(&reset(&path, &[&old_id]).await.response), ErrorCode::Declined);
    assert_eq!(files(&fixture), before);
    let exchanged = reset(&path, &[&state_dir]).await;

    assert_eq!(exchanged.prompts, [confirmation_prompt(&state_dir, "these files")]);
    assert!(
        exchanged.notices.contains("discard the unfinished initialization"),
        "{}",
        exchanged.notices
    );
    assert!(!exchanged.notices.contains("unfinished import"), "{}", exchanged.notices);
    assert_eq!(service.status().await.vault, VaultStatus::NotInitialized);
    assert_discarded(&fixture);
    let _ = stop.send(());
}

/// The fixture's vault as an import left it: the import marker, and no config file but `config.toml` (its signature is
/// removed, so the directories read Unfinished and not Unrecognized). The credential's record file stays.
async fn unfinished_import(fixture: &Fixture, service: &Arc<ServiceContext>) {
    service.lock(DRAIN).await.unwrap();
    fs::write(fixture.path("state/import.unfinished"), b"").unwrap();
    fs::remove_file(fixture.path("etc/config.toml.sig")).unwrap();
    assert_eq!(service.status().await.vault, VaultStatus::ImportUnfinished);
}

/// Release check 11, import clause: the old vault ID typed for an unfinished import is declined; the state directory's path
/// resets it, and the summary names the import and its record file.
#[tokio::test]
async fn release_check_11_an_unfinished_import_is_reset_with_the_state_directory_path() {
    let fixture = Fixture::new().await;
    let old_id = vault_id(&fixture).to_string();
    let service = fixture.ready().await;
    unfinished_import(&fixture, &service).await;
    let (path, stop) = serve_admin(&service);
    let state_dir = fixture.path("state").to_string_lossy().into_owned();
    let before = files(&fixture);

    assert_eq!(error_code(&reset(&path, &[&old_id]).await.response), ErrorCode::Declined);
    assert_eq!(files(&fixture), before);
    let exchanged = reset(&path, &[&state_dir]).await;

    assert_eq!(exchanged.prompts, [confirmation_prompt(&state_dir, "these files")]);
    assert!(
        exchanged.notices.contains("discard the unfinished import and its 1 record file"),
        "{}",
        exchanged.notices
    );
    assert!(exchanged.notices.contains("config.toml"), "{}", exchanged.notices);
    assert_eq!(service.status().await.vault, VaultStatus::NotInitialized);
    assert_discarded(&fixture);
    let _ = stop.send(());
}

/// An init and an import swapped under the confirmation decline the reset and remove nothing.
#[tokio::test]
async fn an_init_and_an_import_swapped_under_the_confirmation_decline_and_remove_nothing() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    unfinished_init(&fixture, &service).await;
    let (path, stop) = serve_admin(&service);
    let state_dir = fixture.path("state").to_string_lossy().into_owned();

    let mut stream = reset_to_prompt(&path).await;
    fs::remove_file(fixture.path("state/init.unfinished")).unwrap();
    fs::write(fixture.path("state/import.unfinished"), b"").unwrap();
    // `init` signed its config; an import's directories hold no signature.
    let _ = fs::remove_file(fixture.path("etc/config.toml.sig"));
    assert_eq!(service.status().await.vault, VaultStatus::ImportUnfinished);
    let before = files(&fixture);
    assert_eq!(error_code(&answer(&mut stream, &state_dir).await), ErrorCode::Declined);
    assert_eq!(files(&fixture), before);
    let _ = stop.send(());
}

/// Release check 10, import clause: an import writing at the summary that finishes before step 4 declines the reset.
#[tokio::test(flavor = "multi_thread")]
async fn release_check_10_an_import_finishing_before_step_4_declines_the_reset() {
    let _one = super::export::one_at_a_time().await;
    let source = source().await;
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    unfinished_import(&fixture, &service).await;
    let state_dir = fixture.path("state").to_string_lossy().into_owned();
    let (path, stop) = serve_admin(&service);

    let mut stream = reset_to_prompt(&path).await;
    let mut import = UnixStream::connect(&path).await.unwrap();
    send(&mut import, &Frame::Request(AdminRequest::Import { host_unlock: false })).await;
    send_bundle(&mut import, &source.bytes).await;
    let answers = [EXPORT_PASSPHRASE, INIT_ANSWERS[0], INIT_ANSWERS[1], "yes"];
    let (imported, _) = converse_revealing(&mut import, &answers).await;
    assert!(matches!(imported.response, AdminResponse::Import(_)), "{:?}", imported.response);
    let before = files(&fixture);
    let response = answer(&mut stream, &state_dir).await;
    assert_eq!(error_code(&response), ErrorCode::Declined);
    assert!(message(&response).contains("at the summary"), "{}", message(&response));
    assert_eq!(files(&fixture), before, "an import finished before step 4");
    let _ = stop.send(());
}

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

/// Release check 6, in flight: a request waiting on the upstream when the reset withdraws the vault is cancelled at once, so the
/// reset returns well inside the lock drain and the caller sees a closed connection or a 503, not a hang.
#[tokio::test]
async fn release_check_6_a_request_in_flight_is_cancelled_by_the_withdrawal() {
    let fixture = Fixture::with_reply(Reply::Stall).await;
    let id = vault_id(&fixture);
    let service = fixture.ready().await;
    let socket = fixture.socket();
    let waiting = tokio::spawn(async move {
        let mut stream = UnixStream::connect(socket).await.unwrap();
        stream
            .write_all(&CallerRequest::get("/fx/latest").signed(Via::Unix).to_bytes())
            .await
            .unwrap();
        let mut raw = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut raw))
            .await
            .map(|_| raw)
    });
    tokio::time::timeout(WAIT, async {
        while fixture.upstream().requests().is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the request reaches the upstream");
    let (path, stop) = serve_admin(&service);

    let started = Instant::now();
    let exchanged = reset(&path, &[&id.to_string()]).await;

    assert!(result(&exchanged).3, "a request still held the vault");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the reset waited {:?}",
        started.elapsed()
    );
    let raw = waiting.await.unwrap().expect("the request ends instead of waiting on the upstream");
    assert!(
        raw.is_empty() || raw.starts_with(b"HTTP/1.1 503"),
        "{}",
        String::from_utf8_lossy(&raw)
    );
    let _ = stop.send(());
}

/// The real filesystem, except that removing `file` fails while armed.
#[derive(Clone)]
struct FailingRemoval {
    file: &'static str,
    armed: Arc<AtomicBool>,
}

impl StoreFs for FailingRemoval {
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
        OsFs.rename(from, to)
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        if self.armed.load(Ordering::SeqCst) && path.file_name() == Some(self.file.as_ref()) {
            return Err(io::Error::other("injected removal failure"));
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

/// Release check 12, `vault.reset-failed`, and check 5 at the service: a removal failing after `manifest.age` and the approver key
/// ends in the partly-discarded error and the event, the directories read Unfinished reset, `init` is refused, and the next reset
/// finishes.
#[tokio::test]
async fn release_check_12_a_failed_removal_logs_reset_failed_and_the_next_reset_finishes() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let id = vault_id(&fixture);
    let fs = FailingRemoval {
        file: "approval.age",
        armed: Arc::new(AtomicBool::new(true)),
    };
    let service = fixture.ready_on(fs.clone()).await;
    let (path, stop) = serve_admin(&service);

    let failed = reset(&path, &[&id.to_string()]).await;

    assert_eq!(error_code(&failed.response), ErrorCode::ResetFailed);
    assert!(
        message(&failed.response).contains("partly discarded"),
        "{}",
        message(&failed.response)
    );
    let event = logs
        .events("vault.reset-failed")
        .into_iter()
        .find(|e| e["file"] == "approval.age")
        .expect("vault.reset-failed names the file");
    assert_eq!(event["step"].as_str(), Some("remove"));
    assert!(
        event["removed"]
            .as_str()
            .is_some_and(|removed| removed.starts_with("manifest.age,approver-")),
        "{event}"
    );
    assert!(event["error_kind"].as_str().is_some_and(|kind| !kind.is_empty()), "{event}");
    assert_eq!(service.status().await.vault, VaultStatus::ResetUnfinished);
    let mut stream = UnixStream::connect(&path).await.unwrap();
    send(&mut stream, &Frame::Request(AdminRequest::Init { host_unlock: false })).await;
    assert_eq!(
        error_code(&converse(&mut stream, &[]).await.response),
        ErrorCode::AlreadyInitialized
    );

    fs.armed.store(false, Ordering::SeqCst);
    let state_dir = fixture.path("state").to_string_lossy().into_owned();
    let finished = reset(&path, &[&state_dir]).await;

    assert_eq!(result(&finished).0, None);
    assert_eq!(service.status().await.vault, VaultStatus::NotInitialized);
    assert_discarded(&fixture);
    let _ = stop.send(());
}
