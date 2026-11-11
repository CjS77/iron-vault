//! `approver add --kind tpm` end to end over a real admin socket (`design/tpm-approval-signer.md`, "Enrollment"): a stand-in
//! for the TPM signing helper runs in the default suite; the same enrollment against the real helper and `swtpm` is
//! `#[ignore]`d (see the module documentation of `crates/iron-vault-tpm-signer/tests/swtpm.rs` for starting the emulator).
//!
//! ```sh
//! cargo build -p iron-vault-tpm-signer --features tpm
//! IRON_VAULT_SWTPM=swtpm:host=127.0.0.1,port=2321 cargo test -p iron-vault --test approver_add_tpm_linux -- --ignored
//! ```
//! `IRON_VAULT_TPM_SIGNER` names the helper binary when it is not `target/debug/iron-vault-tpm-signer`.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use common::approval_harness::{
    APPROVAL_PASSPHRASE, Answer, Exchanged, Fixture, WRONG_PASSPHRASE, captured_logs, converse, converse_switching, error_code, identity,
    read_frame, send, serve_admin, spawn_admin,
};
use common::recipient_harness;
use common::tpm_helper::{Script, Stub, serve_real, serve_stub};
use iron_vault::admin::protocol::{AdminRequest, AdminResponse, ErrorCode, Frame, RequestedSignerKind};
use iron_vault::deployment::DeploymentProfile;
use iron_vault::hardening::MemoryProtection;
use iron_vault::logging::LogSwitch;
use iron_vault::path_metadata::invoking_user;
use iron_vault::service_context::ServiceContext;
use iron_vault_store::{ApproverId, OsFs, SignerKind, open_approval_state};
use iron_vault_tpm_protocol::Response;
use tokio::net::UnixStream;

const PIN: &str = "correct horse";

/// A service in Ready whose `tpm` kind is offered with the helper socket at `socket`, with its admin socket served.
async fn ready(fixture: &Fixture, socket: &Path) -> (Arc<ServiceContext>, PathBuf, tokio::sync::oneshot::Sender<()>) {
    let log = LogSwitch::stdout_for_tests(invoking_user().unwrap()).unwrap();
    let service = fixture.start_as(OsFs, log, DeploymentProfile::Development, MemoryProtection::Unsupported);
    let service = Arc::new(service.with_tpm_socket(socket.to_owned()));
    service.enter_checking(identity()).await.unwrap();
    let (path, stop) = serve_admin(&service);
    (service, path, stop)
}

async fn add_tpm(path: &Path, answers: &[Answer<'_>]) -> Exchanged {
    let mut stream = UnixStream::connect(path).await.unwrap();
    let request = AdminRequest::ApproverAdd {
        kind: RequestedSignerKind::Tpm,
        label: "laptop TPM".to_owned(),
    };
    send(&mut stream, &Frame::Request(request)).await;
    converse_switching(&mut stream, answers).await
}

/// `approver add --kind tpm` authorized by the first approver's passphrase, choosing `new` and `repeat` as the PIN.
async fn enroll(path: &Path, [new, repeat]: [&str; 2]) -> Exchanged {
    add_tpm(
        path,
        &[Answer::Input(APPROVAL_PASSPHRASE), Answer::Input(new), Answer::Input(repeat)],
    )
    .await
}

fn state_files(fixture: &Fixture) -> BTreeMap<String, Vec<u8>> {
    fs::read_dir(fixture.path("state"))
        .unwrap()
        .map(|entry| entry.unwrap())
        .filter(|entry| entry.file_type().unwrap().is_file())
        .map(|entry| (entry.file_name().to_string_lossy().into_owned(), fs::read(entry.path()).unwrap()))
        .collect()
}

fn blob_files(fixture: &Fixture) -> Vec<String> {
    state_files(fixture).into_keys().filter(|name| name.ends_with(".tpm")).collect()
}

/// The approver kinds the vault pins, read from the approval state on disk.
fn pinned_kinds(fixture: &Fixture) -> Vec<SignerKind> {
    let state = open_approval_state(&identity(), &fs::read(fixture.path("state/approval.age")).unwrap()).unwrap();
    state.approvers().iter().map(|approver| approver.kind()).collect()
}

/// The kinds `approver list` shows.
async fn listed_kinds(path: &Path) -> Vec<SignerKind> {
    let mut stream = UnixStream::connect(path).await.unwrap();
    send(&mut stream, &Frame::Request(AdminRequest::ApproverList)).await;
    match read_frame(&mut stream).await {
        Frame::Response(AdminResponse::ApproverList { entries }) => entries.iter().map(|entry| entry.kind).collect(),
        other => panic!("expected the approver list, got {other:?}"),
    }
}

/// The reserved and committed approval versions on disk.
fn counters(fixture: &Fixture) -> (u64, Option<u64>) {
    let state = open_approval_state(&identity(), &fs::read(fixture.path("state/approval.age")).unwrap()).unwrap();
    (state.highest_reserved(), state.committed().map(|(version, _)| version.get()))
}

fn enrolled(exchanged: &Exchanged) -> ApproverId {
    match exchanged.response {
        AdminResponse::ApproverAdd { approver, approvers: 2 } => approver,
        ref other => panic!("expected an enrolled approver, got {other:?}"),
    }
}

async fn assert_enrolls(fixture: &Fixture, path: &Path) {
    let logs = captured_logs();
    let before = counters(fixture);

    let added = enroll(path, [PIN, PIN]).await;

    let id = enrolled(&added);
    let labels: Vec<_> = added.prompts.iter().map(|prompt| (prompt.label.as_str(), prompt.secret)).collect();
    assert_eq!(
        labels,
        [
            ("Approval passphrase for \"approval passphrase\"", true),
            ("New TPM approval PIN for \"laptop TPM\"", true),
            ("Repeat the new TPM approval PIN", true)
        ]
    );
    assert!(
        added.notices.contains("  kind: tpm\n") && added.notices.contains("will not move with a migration bundle"),
        "{}",
        added.notices
    );
    assert!(
        added.notices.contains("recovered only through another approver"),
        "{}",
        added.notices
    );
    assert!(
        added
            .notices
            .ends_with(&format!("enrolled approver {id} (tpm); the vault has 2 approvers.\n"))
    );
    assert!(pinned_kinds(fixture).contains(&SignerKind::Tpm) && pinned_kinds(fixture).len() == 2);
    assert_eq!(counters(fixture), before);
    assert_eq!(listed_kinds(path).await.iter().filter(|kind| **kind == SignerKind::Tpm).count(), 1);
    let blob = fixture.path(&format!("state/approver-{id}.tpm"));
    assert_eq!(fs::metadata(&blob).unwrap().permissions().mode() & 0o777, 0o600);
    assert!(logs.has_field("approver.enrolled", "signer_kind", "tpm"));
    assert!(!logs.text().contains(PIN));
}

#[tokio::test]
async fn an_enrolled_tpm_approver_is_pinned_with_a_blob_and_the_counters_stay() {
    let fixture = Fixture::new().await;
    let stub = serve_stub(&fixture.path("helper.sock"), Script::default());
    let (_service, path, _stop) = ready(&fixture, &fixture.path("helper.sock")).await;

    assert_enrolls(&fixture, &path).await;

    assert_eq!(stub.calls(), ["create", "sign"]);
}

#[tokio::test]
async fn removing_a_tpm_approver_removes_its_blob() {
    let fixture = Fixture::new().await;
    serve_stub(&fixture.path("helper.sock"), Script::default());
    let (_service, path, _stop) = ready(&fixture, &fixture.path("helper.sock")).await;
    let id = enrolled(&enroll(&path, [PIN, PIN]).await);

    let mut stream = UnixStream::connect(&path).await.unwrap();
    send(
        &mut stream,
        &Frame::Request(AdminRequest::ApproverRemove { approver: *id.as_bytes() }),
    )
    .await;
    let removed = converse(&mut stream, &[APPROVAL_PASSPHRASE]).await;

    assert!(
        matches!(removed.response, AdminResponse::ApproverRemove { approvers: 1 }),
        "{removed:?}"
    );
    assert!(blob_files(&fixture).is_empty());
}

/// `approver add --kind tpm` against `service` is refused as unavailable before any prompt, and changes nothing.
async fn assert_kind_not_offered(fixture: &Fixture, service: &Arc<ServiceContext>) {
    let (path, _stop) = serve_admin(service);
    let before = state_files(fixture);

    let refused = add_tpm(&path, &[]).await;

    assert_eq!(
        (error_code(&refused.response), refused.prompts.len()),
        (ErrorCode::ApproverKindUnavailable, 0),
        "{refused:?}"
    );
    assert_eq!(state_files(fixture), before);
}

#[tokio::test]
async fn a_development_install_does_not_offer_the_kind() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    assert_kind_not_offered(&fixture, &service).await;
}

#[tokio::test]
async fn the_kind_is_not_offered_while_the_helper_socket_is_missing() {
    let fixture = Fixture::new().await;
    let log = LogSwitch::stdout_for_tests(invoking_user().unwrap()).unwrap();
    let service = fixture.start_as(OsFs, log, DeploymentProfile::Development, MemoryProtection::Unsupported);
    let service = Arc::new(service.with_tpm_socket(fixture.path("missing.sock")));
    service.enter_checking(identity()).await.unwrap();
    assert_kind_not_offered(&fixture, &service).await;
}

#[tokio::test]
async fn a_pin_that_breaks_a_rule_is_rejected_before_the_helper_is_asked() {
    let fixture = Fixture::new().await;
    let stub = serve_stub(&fixture.path("helper.sock"), Script::default());
    let (_service, path, _stop) = ready(&fixture, &fixture.path("helper.sock")).await;
    let before = state_files(&fixture);

    let mismatched = enroll(&path, [PIN, "correct horsf"]).await;
    let short = enroll(&path, ["12345", "12345"]).await;

    assert_eq!(error_code(&mismatched.response), ErrorCode::PassphraseRejected);
    assert_eq!(error_code(&short.response), ErrorCode::PassphraseRejected);
    assert!(
        matches!(&short.response, AdminResponse::Error { message, .. } if message.contains("at least 6")),
        "{short:?}"
    );
    assert_eq!((stub.calls(), state_files(&fixture)), (vec![], before));
}

#[tokio::test]
async fn a_lock_at_either_pin_prompt_cancels_the_enrollment() {
    for secret_prompts_answered in 0..2 {
        let fixture = Fixture::new().await;
        let stub = serve_stub(&fixture.path("helper.sock"), Script::default());
        let (service, path, _stop) = ready(&fixture, &fixture.path("helper.sock")).await;
        let mut before = state_files(&fixture);
        let mut stream = UnixStream::connect(&path).await.unwrap();
        let request = AdminRequest::ApproverAdd {
            kind: RequestedSignerKind::Tpm,
            label: "laptop TPM".to_owned(),
        };
        send(&mut stream, &Frame::Request(request)).await;
        let answers = [APPROVAL_PASSPHRASE, PIN];
        reach_prompt(&mut stream, &answers[..=secret_prompts_answered]).await;

        let locking = tokio::spawn({
            let service = Arc::clone(&service);
            async move { service.lock(std::time::Duration::from_secs(5)).await }
        });
        let cancelled = converse(&mut stream, &[]).await;

        locking.await.unwrap().unwrap();
        assert_eq!(error_code(&cancelled.response), ErrorCode::WrongState);
        let mut after = state_files(&fixture);
        after.remove("locked-by-owner");
        before.remove("locked-by-owner");
        assert_eq!((stub.calls(), after), (vec![], before));
    }
}

/// Answers each prompt with `answers` and returns once the next prompt is showing.
async fn reach_prompt(stream: &mut UnixStream, answers: &[&str]) {
    for answer in answers {
        while !matches!(read_frame(stream).await, Frame::Prompt(_)) {}
        send(
            stream,
            &Frame::OwnerInput(iron_vault::admin::protocol::OwnerInput::new(zeroize::Zeroizing::new(
                answer.as_bytes().to_vec(),
            ))),
        )
        .await;
    }
    while !matches!(read_frame(stream).await, Frame::Prompt(_)) {}
}

#[tokio::test]
async fn a_helper_refusal_at_create_enrolls_nothing_and_writes_no_blob() {
    let fixture = Fixture::new().await;
    let script = Script {
        create: Some(Response::WeakDaSettings),
        ..Script::default()
    };
    let stub = serve_stub(&fixture.path("helper.sock"), script);
    let (_service, path, _stop) = ready(&fixture, &fixture.path("helper.sock")).await;
    let before = state_files(&fixture);

    let refused = enroll(&path, [PIN, PIN]).await;

    assert!(
        matches!(&refused.response, AdminResponse::Error { code: ErrorCode::ApproverKindUnavailable, message } if message.contains("dictionary-attack settings too weak")),
        "{refused:?}"
    );
    assert_eq!((stub.calls(), state_files(&fixture)), (vec!["create"], before));
}

#[tokio::test]
async fn a_lockout_is_reported_with_the_seconds_to_wait() {
    let fixture = Fixture::new().await;
    let script = Script {
        sign: Some(Response::LockedOut { wait_seconds: 1200 }),
        ..Script::default()
    };
    serve_stub(&fixture.path("helper.sock"), script);
    let (_service, path, _stop) = ready(&fixture, &fixture.path("helper.sock")).await;

    let refused = enroll(&path, [PIN, PIN]).await;

    assert!(
        matches!(&refused.response, AdminResponse::Error { code: ErrorCode::ApproverKindUnavailable, message } if message.contains("1200 seconds")),
        "{refused:?}"
    );
}

/// A crash, or a refusal, between the blob write and the approver change leaves an orphan blob that the next approver command
/// removes before it asks for anything.
#[tokio::test]
async fn an_orphan_blob_is_removed_by_the_next_approver_command() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let script = Script {
        sign: Some(Response::KeyMismatch),
        ..Script::default()
    };
    serve_stub(&fixture.path("helper.sock"), script);
    let (_service, path, _stop) = ready(&fixture, &fixture.path("helper.sock")).await;

    let failed = enroll(&path, [PIN, PIN]).await;
    assert_eq!(error_code(&failed.response), ErrorCode::ApproverKindUnavailable);
    let orphans = blob_files(&fixture);
    assert_eq!(orphans.len(), 1);
    assert_eq!(pinned_kinds(&fixture), [SignerKind::Software]);

    let denied = add_tpm(&path, &[Answer::Input(WRONG_PASSPHRASE)]).await;

    assert_eq!(error_code(&denied.response), ErrorCode::ApprovalDenied);
    assert!(blob_files(&fixture).is_empty());
    assert!(
        logs.events("approver.orphan-removed")
            .iter()
            .any(|record| orphans[0].contains(record["approver_id"].as_str().unwrap()))
    );
}

#[tokio::test]
async fn a_wrong_approval_passphrase_is_denied_before_the_helper_is_asked() {
    let fixture = Fixture::new().await;
    let stub: Stub = serve_stub(&fixture.path("helper.sock"), Script::default());
    let (_service, path, _stop) = ready(&fixture, &fixture.path("helper.sock")).await;
    let before = state_files(&fixture);

    let denied = add_tpm(&path, &[Answer::Input(WRONG_PASSPHRASE)]).await;

    assert_eq!(error_code(&denied.response), ErrorCode::ApprovalDenied);
    assert_eq!((denied.prompts.len(), stub.calls(), state_files(&fixture)), (1, vec![], before));
}

#[tokio::test]
async fn the_vault_passphrase_cannot_authorize_a_tpm_enrollment() {
    let vault = recipient_harness::Fixture::new();
    let socket = vault.path("helper.sock");
    let stub: Stub = serve_stub(&socket, Script::default());
    let service = vault.start_offering_tpm(&socket);
    recipient_harness::init(&service).await;
    recipient_harness::unlock(&service).await;
    let before = vault.state_files();
    let (path, _stop, _task) = spawn_admin(&service);

    let denied = add_tpm(&path, &[Answer::Input(recipient_harness::VAULT_PASSPHRASE)]).await;

    assert_eq!(error_code(&denied.response), ErrorCode::ApprovalDenied, "{denied:?}");
    assert_eq!((denied.prompts.len(), stub.calls(), vault.state_files()), (1, vec![], before));
}

fn real_helper() -> (PathBuf, String) {
    let tcti = std::env::var("IRON_VAULT_SWTPM").expect("IRON_VAULT_SWTPM names the swtpm TCTI");
    let binary = std::env::var_os("IRON_VAULT_TPM_SIGNER").map(PathBuf::from).unwrap_or_else(|| {
        let exe = std::env::current_exe().unwrap();
        exe.parent().unwrap().parent().unwrap().join("iron-vault-tpm-signer")
    });
    (binary, tcti)
}

/// Gives the emulator 32 tries and a recovery interval of `interval` seconds, with the lockout counter cleared. The emulator
/// is shared, so run the ignored tests one at a time.
fn set_dictionary_attack(tcti: &str, interval: u32) {
    let run = |args: &[&str]| {
        let status = std::process::Command::new("tpm2_dictionarylockout")
            .args(args)
            .env("TPM2TOOLS_TCTI", tcti)
            .status()
            .unwrap();
        assert!(status.success());
    };
    run(&["--clear-lockout"]);
    run(&[
        "--setup-parameters",
        "--max-tries=32",
        &format!("--recovery-time={interval}"),
        "--lockout-recovery-time=1",
    ]);
}

#[tokio::test]
#[ignore = "needs swtpm named by IRON_VAULT_SWTPM and the helper built with --features tpm"]
async fn the_real_helper_enrolls_a_tpm_approver_against_swtpm() {
    let fixture = Fixture::new().await;
    let (binary, tcti) = real_helper();
    set_dictionary_attack(&tcti, 600);
    serve_real(&fixture.path("helper.sock"), binary, tcti);
    let (_service, path, _stop) = ready(&fixture, &fixture.path("helper.sock")).await;

    assert_enrolls(&fixture, &path).await;
}

/// An emulator whose dictionary-attack interval is under the floor makes the helper refuse, and `approver add` says why.
#[tokio::test]
#[ignore = "needs swtpm named by IRON_VAULT_SWTPM and the helper built with --features tpm"]
async fn the_real_helper_refuses_weak_dictionary_attack_settings() {
    let fixture = Fixture::new().await;
    let (binary, tcti) = real_helper();
    let set = |interval: u32| set_dictionary_attack(&tcti, interval);
    serve_real(&fixture.path("helper.sock"), binary, tcti.clone());
    let (_service, path, _stop) = ready(&fixture, &fixture.path("helper.sock")).await;
    let before = state_files(&fixture);
    set(599);

    let refused = enroll(&path, [PIN, PIN]).await;
    set(600);

    assert!(
        matches!(&refused.response, AdminResponse::Error { code: ErrorCode::ApproverKindUnavailable, message } if message.contains("too weak")),
        "{refused:?}"
    );
    assert_eq!(state_files(&fixture), before);
}
