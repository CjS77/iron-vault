//! A TPM approver end to end over a real admin socket (`design/tpm-approval-signer.md`, "Enrollment" and "Prompt and proof"):
//! `approver add --kind tpm`, then `config approve` and `replace` asking the enrolled approver for its PIN. A stand-in for the
//! TPM signing helper runs in the default suite; the same flows against the real helper and `swtpm` are `#[ignore]`d (see the
//! module documentation of `crates/iron-vault-tpm-signer/tests/swtpm.rs` for starting the emulator).
//!
//! ```sh
//! cargo build -p iron-vault-tpm-signer --features tpm
//! IRON_VAULT_SWTPM=swtpm:host=127.0.0.1,port=2321 cargo test -p iron-vault --test signers -- approver_add_tpm --ignored
//! ```
//! `IRON_VAULT_TPM_SIGNER` names the helper binary when it is not `target/debug/iron-vault-tpm-signer`.

#![cfg(target_os = "linux")]

use crate::common;

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use common::approval_harness::{
    APPROVAL_PASSPHRASE, Answer, Captured, Exchanged, Fixture, WRONG_PASSPHRASE, approve_request, captured_logs, converse,
    converse_switching, error_code, identity, read_frame, send, serve_admin, spawn_admin,
};
use common::recipient_harness;
use common::tpm_helper::{Script, Stub, serve_real, serve_stub};
use iron_vault::admin::protocol::{AdminRequest, AdminResponse, ErrorCode, Frame, RequestedOrigin, RequestedSignerKind};
use iron_vault::deployment::DeploymentProfile;
use iron_vault::hardening::MemoryProtection;
use iron_vault::logging::LogSwitch;
use iron_vault::path_metadata::invoking_user;
use iron_vault::service_context::ServiceContext;
use iron_vault::service_state::ServiceState;
use iron_vault_policy::{CredentialKind, Port};
use iron_vault_store::{ApprovalEnvelope, ApproverId, OsFs, SignerKind, open_approval_state, verify_approval};
use iron_vault_tpm_protocol::Response;
use std::time::Duration;
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
        matches!(&refused.response, AdminResponse::Error { code: ErrorCode::TpmLockedOut, message } if message.contains("1200 seconds")),
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

/// Gives the emulator `max_tries` tries and a recovery interval of `interval` seconds, with the lockout counter cleared. The
/// emulator is shared, so run the ignored tests one at a time.
fn set_dictionary_attack(tcti: &str, max_tries: u32, interval: u32) {
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
        &format!("--max-tries={max_tries}"),
        &format!("--recovery-time={interval}"),
        "--lockout-recovery-time=1",
    ]);
}

#[tokio::test]
#[ignore = "needs swtpm named by IRON_VAULT_SWTPM and the helper built with --features tpm"]
async fn the_real_helper_enrolls_a_tpm_approver_against_swtpm() {
    let fixture = Fixture::new().await;
    let (binary, tcti) = real_helper();
    set_dictionary_attack(&tcti, 32, 600);
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
    let set = |interval: u32| set_dictionary_attack(&tcti, 32, interval);
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

// ---- Asking an enrolled TPM approver: owner presence and the two-call approval --------------------------------------------

/// The PIN typed for a TPM approver whose answer the stand-in decides.
const WRONG_PIN: &str = "wrong-pin-7731";
/// The key `replace` is given.
const NEW_SECRET: &str = "REPLACE-SECRET-91c7e4";

const PRESENCE: [u8; 4] = *b"IVPP";
const APPROVAL: [u8; 4] = *b"IVAP";

/// The service `ready` starts, with the handles a test needs to stop and restart it.
struct Running {
    service: Arc<ServiceContext>,
    path: PathBuf,
    stop: tokio::sync::oneshot::Sender<()>,
}

/// A service whose helper socket is `socket`, with a TPM approver enrolled under [`PIN`] beside the software one, which
/// signed the active approval.
async fn with_tpm_approver(fixture: &Fixture, socket: &Path) -> (Running, ApproverId) {
    let (service, path, stop) = ready(fixture, socket).await;
    let id = enrolled(&enroll(&path, [PIN, PIN]).await);
    (Running { service, path, stop }, id)
}

/// `config approve` for `config`, answering the prompts in turn.
async fn approve_config(path: &Path, config: &str, answers: &[Answer<'_>]) -> Exchanged {
    let mut stream = UnixStream::connect(path).await.unwrap();
    send(&mut stream, &approve_request(config)).await;
    converse_switching(&mut stream, answers).await
}

/// The TPM approver is second in the approver order while the software one signed the active approval, so the owner switches.
fn via_tpm<'a>(pin: &'a str) -> [Answer<'a>; 3] {
    [Answer::Input("yes"), Answer::Switch, Answer::Input(pin)]
}

fn approved_version(exchanged: &Exchanged) -> u64 {
    match &exchanged.response {
        AdminResponse::ConfigApprove(result) => result.version,
        other => panic!("expected an approval, got {other:?}\n{}", exchanged.notices),
    }
}

fn error_message(exchanged: &Exchanged) -> &str {
    match &exchanged.response {
        AdminResponse::Error { message, .. } => message,
        other => panic!("expected an error, got {other:?}"),
    }
}

/// Stops `running` and waits for the handlers to drop the service, which releases its directory locks, then starts another on
/// the same directories.
async fn restart(fixture: &Fixture, running: Running) -> Arc<ServiceContext> {
    let _ = running.stop.send(());
    running.service.stop().await;
    let mut service = running.service;
    for _ in 0..500 {
        match Arc::try_unwrap(service) {
            Ok(owned) => {
                drop(owned);
                return fixture.ready().await;
            }
            Err(shared) => {
                service = shared;
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }
    panic!("something still holds the service");
}

/// The published config's signature envelope names `approver`, signs with ECDSA P-256 (algorithm `02`) and verifies against
/// the approval state, as the config check does.
fn assert_signed_by_tpm(fixture: &Fixture, approver: ApproverId) {
    let [config, signature] = fixture.published_pair();
    let state = open_approval_state(&identity(), &fs::read(fixture.path("state/approval.age")).unwrap()).unwrap();
    let envelope = ApprovalEnvelope::decode(&signature).unwrap();
    assert_eq!((envelope.approver_id(), envelope.algorithm().id()), (approver, 2));
    assert_eq!(verify_approval(&state, &config, &signature).unwrap().approver(), approver);
}

fn tpm_prompt() -> iron_vault::admin::protocol::Prompt {
    iron_vault::admin::protocol::Prompt {
        label: "TPM approval PIN for \"laptop TPM\"".to_owned(),
        secret: true,
        switchable: true,
    }
}

/// `config approve` with the TPM approver commits the next version, signed by the TPM key, and a restarted service activates
/// it.
async fn assert_approves_and_restarts(fixture: &Fixture, running: Running, tpm: ApproverId) {
    let logs = captured_logs();
    let config = fixture.config("rates");

    let approved = approve_config(&running.path, &config, &via_tpm(PIN)).await;

    assert_eq!(approved_version(&approved), 2);
    assert_eq!(approved.prompts[2], tpm_prompt());
    assert_signed_by_tpm(fixture, tpm);
    assert_eq!(counters(fixture), (2, Some(2)));
    assert!(!logs.text().contains(PIN));
    let restarted = restart(fixture, running).await;
    assert_eq!(restarted.state().await, ServiceState::Ready);
    assert_eq!(common::approval_harness::versions(&restarted).await, (Some(2), 2));
}

#[tokio::test]
async fn config_approve_with_a_tpm_approver_commits_a_version_signed_in_two_helper_calls() {
    let fixture = Fixture::new().await;
    let stub = serve_stub(&fixture.path("helper.sock"), Script::default());
    let (running, tpm) = with_tpm_approver(&fixture, &fixture.path("helper.sock")).await;

    assert_approves_and_restarts(&fixture, running, tpm).await;

    assert_eq!(stub.signed_magics(), [PRESENCE, PRESENCE, APPROVAL]);
}

/// `replace fx_key`, permitted at the fixture's upstream.
fn replace_request(fixture: &Fixture) -> Frame {
    let origin = RequestedOrigin {
        host: "localhost".to_owned(),
        port: Port::try_from(fixture.upstream().port()).unwrap(),
    };
    Frame::Request(AdminRequest::Replace {
        name: "fx_key".to_owned(),
        kind: CredentialKind::Static,
        origins: vec![origin],
    })
}

/// `replace` asking the TPM approver for owner presence changes the credential.
async fn assert_replaces(fixture: &Fixture, path: &Path) {
    let mut stream = UnixStream::connect(path).await.unwrap();
    send(&mut stream, &replace_request(fixture)).await;

    let replaced = converse_switching(&mut stream, &[Answer::Switch, Answer::Input(PIN), Answer::Input(NEW_SECRET)]).await;

    assert!(matches!(replaced.response, AdminResponse::Replace { .. }), "{replaced:?}");
    assert_eq!(replaced.prompts[1], tpm_prompt());
    assert!(!captured_logs().text().contains(NEW_SECRET));
}

#[tokio::test]
async fn replace_with_a_tpm_approver_proves_presence_and_reserves_nothing() {
    let fixture = Fixture::new().await;
    let stub = serve_stub(&fixture.path("helper.sock"), Script::default());
    let (running, _) = with_tpm_approver(&fixture, &fixture.path("helper.sock")).await;
    let before = counters(&fixture);

    assert_replaces(&fixture, &running.path).await;

    assert_eq!((counters(&fixture), stub.signed_magics()), (before, vec![PRESENCE, PRESENCE]));
}

/// The refusal events of the TPM approver `id` in `event`, by `tpm_status`.
fn tpm_statuses(logs: &Captured, event: &str, id: ApproverId) -> Vec<String> {
    logs.events(event)
        .iter()
        .filter(|record| record["approver_id"] == id.to_string().as_str())
        .map(|record| record["tpm_status"].as_str().unwrap().to_owned())
        .collect()
}

/// A wrong PIN is `approval-denied`: no other approver is asked, no version is reserved, and the message says each wrong PIN
/// counts against the TPM's lockout.
async fn assert_wrong_pin_is_denied(fixture: &Fixture, path: &Path, tpm: ApproverId) {
    let logs = captured_logs();
    let before = counters(fixture);

    let denied = approve_config(path, &fixture.config("rates"), &via_tpm(WRONG_PIN)).await;

    assert_eq!(error_code(&denied.response), ErrorCode::ApprovalDenied, "{denied:?}");
    assert!(error_message(&denied).contains("counts against the TPM's lockout"), "{denied:?}");
    assert_eq!(denied.prompts.len(), 3, "no approver was asked after the wrong PIN");
    assert_eq!(counters(fixture), before);
    assert_eq!(tpm_statuses(&logs, "config.approval-refused", tpm), ["wrong_pin"]);
    assert!(logs.has_field("config.approval-refused", "refusal", "wrong_pin"));
    assert!(!logs.text().contains(WRONG_PIN));
}

#[tokio::test]
async fn a_wrong_pin_is_denied_without_falling_through_or_reserving_a_version() {
    let fixture = Fixture::new().await;
    let stub = serve_stub(&fixture.path("helper.sock"), Script::default());
    let (running, tpm) = with_tpm_approver(&fixture, &fixture.path("helper.sock")).await;
    stub.answer_next_signs([Some(Response::WrongPin)]);

    assert_wrong_pin_is_denied(&fixture, &running.path, tpm).await;

    assert_eq!(stub.signed_magics(), [PRESENCE, PRESENCE]);
}

#[tokio::test]
async fn a_wrong_pin_at_owner_presence_is_a_presence_refusal_with_the_helper_status() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let stub = serve_stub(&fixture.path("helper.sock"), Script::default());
    let (running, tpm) = with_tpm_approver(&fixture, &fixture.path("helper.sock")).await;
    stub.answer_next_signs([Some(Response::WrongPin)]);
    let mut stream = UnixStream::connect(&running.path).await.unwrap();
    send(&mut stream, &replace_request(&fixture)).await;

    let denied = converse_switching(&mut stream, &[Answer::Switch, Answer::Input(WRONG_PIN)]).await;

    assert_eq!(error_code(&denied.response), ErrorCode::ApprovalDenied, "{denied:?}");
    assert_eq!(tpm_statuses(&logs, "vault.presence-refused", tpm), ["wrong_pin"]);
    assert!(!logs.text().contains(WRONG_PIN));
}

#[tokio::test]
async fn a_step_3_failure_consumes_the_version() {
    let fixture = Fixture::new().await;
    let stub = serve_stub(&fixture.path("helper.sock"), Script::default());
    let (running, _) = with_tpm_approver(&fixture, &fixture.path("helper.sock")).await;
    stub.answer_next_signs([None, Some(Response::TpmError { code: 0x921 })]);

    let failed = approve_config(&running.path, &fixture.config("rates"), &via_tpm(PIN)).await;

    assert_eq!(error_code(&failed.response), ErrorCode::ApprovalFailed, "{failed:?}");
    assert!(error_message(&failed).contains("version 2 is consumed"), "{failed:?}");
    assert_eq!(counters(&fixture), (2, Some(1)));
}

/// Step 3 waits for the helper off the runtime thread: while the helper holds back the approval signature, a proxied request
/// on the config's own listener still completes, and the approval commits once the helper answers.
#[tokio::test]
async fn a_stalled_step_3_does_not_stop_the_proxy() {
    let fixture = Fixture::new().await;
    let stub = serve_stub(&fixture.path("helper.sock"), Script::default());
    let (running, tpm) = with_tpm_approver(&fixture, &fixture.path("helper.sock")).await;
    let release = stub.stall_next_approval();
    let started = std::time::Instant::now();
    let approving = tokio::spawn({
        let (path, config) = (running.path.clone(), fixture.config("rates"));
        async move { approve_config(&path, &config, &via_tpm(PIN)).await }
    });
    while !stub.signed_magics().contains(&APPROVAL) {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let proxied = common::approval_harness::get(&fixture, "fx").await;

    assert_eq!(proxied.status, 200);
    assert!(started.elapsed() < Duration::from_secs(10), "{:?}", started.elapsed());
    drop(release);
    assert_eq!(approved_version(&approving.await.unwrap()), 2);
    assert_signed_by_tpm(&fixture, tpm);
}

/// The `(refusal, tpm_status)` of each refusal event of the TPM approver `id` in `event`.
fn refusals(logs: &Captured, event: &str, id: ApproverId) -> Vec<(String, Option<String>)> {
    logs.events(event)
        .iter()
        .filter(|record| record["approver_id"] == id.to_string().as_str())
        .map(|record| {
            (
                record["refusal"].as_str().unwrap().to_owned(),
                record["tpm_status"].as_str().map(str::to_owned),
            )
        })
        .collect()
}

#[tokio::test]
async fn a_pin_too_short_to_be_enrolled_is_denied_without_asking_the_helper() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let stub = serve_stub(&fixture.path("helper.sock"), Script::default());
    let (running, tpm) = with_tpm_approver(&fixture, &fixture.path("helper.sock")).await;
    let (calls, before) = (stub.calls(), counters(&fixture));

    let denied = approve_config(&running.path, &fixture.config("rates"), &via_tpm("12345")).await;

    assert_eq!(error_code(&denied.response), ErrorCode::ApprovalDenied, "{denied:?}");
    assert_eq!(denied.prompts.len(), 3, "no approver was asked after the short PIN");
    assert_eq!((stub.calls(), counters(&fixture)), (calls, before));
    assert_eq!(refusals(&logs, "config.approval-refused", tpm), [("wrong_pin".to_owned(), None)]);
}

#[tokio::test]
async fn an_empty_pin_at_owner_presence_is_a_presence_refusal_without_a_helper_status() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let stub = serve_stub(&fixture.path("helper.sock"), Script::default());
    let (running, tpm) = with_tpm_approver(&fixture, &fixture.path("helper.sock")).await;
    let calls = stub.calls();
    let mut stream = UnixStream::connect(&running.path).await.unwrap();
    send(&mut stream, &replace_request(&fixture)).await;

    let denied = converse_switching(&mut stream, &[Answer::Switch, Answer::Input("")]).await;

    assert_eq!(error_code(&denied.response), ErrorCode::ApprovalDenied, "{denied:?}");
    assert_eq!(stub.calls(), calls);
    assert_eq!(refusals(&logs, "vault.presence-refused", tpm), [("wrong_pin".to_owned(), None)]);
}

#[tokio::test]
async fn a_lockout_is_tpm_locked_out_and_a_software_approver_still_approves() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let stub = serve_stub(&fixture.path("helper.sock"), Script::default());
    let (running, tpm) = with_tpm_approver(&fixture, &fixture.path("helper.sock")).await;
    assert_eq!(
        approved_version(&approve_config(&running.path, &fixture.config("rates"), &via_tpm(PIN)).await),
        2
    );
    stub.answer_next_signs([Some(Response::LockedOut { wait_seconds: 1200 })]);

    let locked = approve_config(&running.path, &fixture.config("other"), &[Answer::Input("yes"), Answer::Input(PIN)]).await;

    assert_eq!(error_code(&locked.response), ErrorCode::TpmLockedOut, "{locked:?}");
    assert!(error_message(&locked).contains("1200 seconds"), "{locked:?}");
    assert_eq!((locked.prompts.len(), counters(&fixture)), (2, (2, Some(2))));
    assert_eq!(tpm_statuses(&logs, "config.approval-refused", tpm), ["locked_out"]);
    let software = [Answer::Input("yes"), Answer::Switch, Answer::Input(APPROVAL_PASSPHRASE)];
    let approved = approve_config(&running.path, &fixture.config("other"), &software).await;
    assert_eq!(approved_version(&approved), 3);
}

#[tokio::test]
async fn any_other_helper_failure_is_unavailable_and_names_its_status() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let stub = serve_stub(&fixture.path("helper.sock"), Script::default());
    let (running, tpm) = with_tpm_approver(&fixture, &fixture.path("helper.sock")).await;
    stub.answer_next_signs([Some(Response::NotThisTpm)]);

    let unavailable = approve_config(&running.path, &fixture.config("rates"), &via_tpm(PIN)).await;

    assert_eq!(error_code(&unavailable.response), ErrorCode::ApprovalUnavailable, "{unavailable:?}");
    assert!(error_message(&unavailable).contains("not this TPM"), "{unavailable:?}");
    assert!(!error_message(&unavailable).contains(PIN));
    assert_eq!(counters(&fixture), (1, Some(1)));
    assert_eq!(tpm_statuses(&logs, "config.approval-refused", tpm), ["not_this_tpm"]);
}

/// The first prompt of an approval is the software approver's, and the only one: the TPM approver cannot be asked.
fn assert_starts_at_software(approved: &Exchanged) {
    assert_eq!(approved.prompts[1].label, "Approval passphrase for \"approval passphrase\"");
    assert!(!approved.prompts[1].switchable, "{approved:?}");
}

#[tokio::test]
async fn the_approver_order_leaves_out_a_tpm_approver_with_no_key_file() {
    let fixture = Fixture::new().await;
    serve_stub(&fixture.path("helper.sock"), Script::default());
    let (running, tpm) = with_tpm_approver(&fixture, &fixture.path("helper.sock")).await;
    approve_config(&running.path, &fixture.config("rates"), &via_tpm(PIN)).await;
    fs::remove_file(fixture.path(&format!("state/approver-{tpm}.tpm"))).unwrap();

    let approved = approve_config(
        &running.path,
        &fixture.config("other"),
        &[Answer::Input("yes"), Answer::Input(APPROVAL_PASSPHRASE)],
    )
    .await;

    assert_starts_at_software(&approved);
    assert_eq!(approved_version(&approved), 3);
}

#[tokio::test]
async fn the_approver_order_leaves_out_every_tpm_approver_while_the_socket_is_missing() {
    let fixture = Fixture::new().await;
    serve_stub(&fixture.path("helper.sock"), Script::default());
    let (running, tpm) = with_tpm_approver(&fixture, &fixture.path("helper.sock")).await;
    approve_config(&running.path, &fixture.config("rates"), &via_tpm(PIN)).await;
    let restarted = restart(&fixture, running).await;
    let (path, _stop) = serve_admin(&restarted);

    let approved = approve_config(
        &path,
        &fixture.config("other"),
        &[Answer::Input("yes"), Answer::Input(APPROVAL_PASSPHRASE)],
    )
    .await;

    assert_starts_at_software(&approved);
    assert!(fixture.path(&format!("state/approver-{tpm}.tpm")).exists());
}

#[tokio::test]
async fn no_approver_that_can_be_asked_is_approval_unavailable() {
    let fixture = Fixture::new().await;
    serve_stub(&fixture.path("helper.sock"), Script::default());
    let software = fixture.approver_id();
    let (running, tpm) = with_tpm_approver(&fixture, &fixture.path("helper.sock")).await;
    approve_config(&running.path, &fixture.config("rates"), &via_tpm(PIN)).await;
    let mut stream = UnixStream::connect(&running.path).await.unwrap();
    send(
        &mut stream,
        &Frame::Request(AdminRequest::ApproverRemove {
            approver: *software.as_bytes(),
        }),
    )
    .await;
    let removed = converse(&mut stream, &[PIN]).await;
    assert!(
        matches!(removed.response, AdminResponse::ApproverRemove { approvers: 1 }),
        "{removed:?}"
    );
    fs::remove_file(fixture.path(&format!("state/approver-{tpm}.tpm"))).unwrap();

    let refused = approve_config(&running.path, &fixture.config("other"), &[]).await;

    assert_eq!(error_code(&refused.response), ErrorCode::ApprovalUnavailable, "{refused:?}");
    assert!(error_message(&refused).contains("no pinned approver can be asked"), "{refused:?}");
    assert!(refused.prompts.is_empty());
}

/// A vault whose only approver is a TPM one cannot export: its bundle could not be approved on the destination. The refusal
/// comes before the summary notice, any prompt or the migration challenge, and nothing is written. The stand-in helper
/// harness is local to this module, which is why this test is here rather than in `lifecycle/export.rs`.
#[tokio::test]
async fn export_of_a_vault_with_only_a_tpm_approver_is_refused_before_any_prompt_or_challenge() {
    let fixture = Fixture::new().await;
    serve_stub(&fixture.path("helper.sock"), Script::default());
    let software = fixture.approver_id();
    let (running, _) = with_tpm_approver(&fixture, &fixture.path("helper.sock")).await;
    approve_config(&running.path, &fixture.config("rates"), &via_tpm(PIN)).await;
    let mut stream = UnixStream::connect(&running.path).await.unwrap();
    send(
        &mut stream,
        &Frame::Request(AdminRequest::ApproverRemove {
            approver: *software.as_bytes(),
        }),
    )
    .await;
    assert!(matches!(
        converse(&mut stream, &[PIN]).await.response,
        AdminResponse::ApproverRemove { approvers: 1 }
    ));
    let logs = captured_logs();
    let export_records = |event: &str| -> Vec<serde_json::Value> {
        logs.events(event)
            .into_iter()
            .filter(|record| record["operation"] == "export" || record["error_kind"] == "no_software_approver")
            .collect()
    };

    let mut stream = UnixStream::connect(&running.path).await.unwrap();
    send(&mut stream, &Frame::Request(AdminRequest::Export)).await;
    let refused = converse_switching(&mut stream, &[]).await;

    assert_eq!(error_code(&refused.response), ErrorCode::ApproverSetInvalid, "{refused:?}");
    assert!(error_message(&refused).contains("enroll a software approver first"), "{refused:?}");
    assert!(refused.notices.is_empty() && refused.prompts.is_empty(), "{refused:?}");
    assert!(export_records("migration.challenge-issued").is_empty());
    let failed = export_records("migration.export-failed");
    assert_eq!(failed.len(), 1, "{failed:?}");
    assert_eq!(
        (failed[0]["step"].as_str(), failed[0]["error_kind"].as_str()),
        (Some("check"), Some("no_software_approver"))
    );
    let leftovers = fs::read_dir(fixture.path("."))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".bundle") || name.ends_with(".partial"))
        .collect::<Vec<_>>();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

#[tokio::test]
async fn a_tpm_approver_authorizes_an_approver_change_and_a_lockout_there_is_tpm_locked_out() {
    let fixture = Fixture::new().await;
    let stub = serve_stub(&fixture.path("helper.sock"), Script::default());
    let (running, _) = with_tpm_approver(&fixture, &fixture.path("helper.sock")).await;
    approve_config(&running.path, &fixture.config("rates"), &via_tpm(PIN)).await;
    stub.answer_next_signs([Some(Response::LockedOut { wait_seconds: 600 })]);

    let locked = add_tpm(&running.path, &[Answer::Input(PIN)]).await;

    assert_eq!(error_code(&locked.response), ErrorCode::TpmLockedOut, "{locked:?}");
    assert!(error_message(&locked).contains("600 seconds"), "{locked:?}");
    assert_eq!(pinned_kinds(&fixture).len(), 2);
}

// ---- The same flows against the real helper and swtpm ------------------------------------------------------------------------

/// A service on the real helper and the emulator, with a TPM approver enrolled under [`PIN`] and `max_tries` tries.
async fn with_real_tpm_approver(fixture: &Fixture, max_tries: u32) -> (Running, ApproverId) {
    let (binary, tcti) = real_helper();
    set_dictionary_attack(&tcti, max_tries, 600);
    serve_real(&fixture.path("helper.sock"), binary, tcti);
    with_tpm_approver(fixture, &fixture.path("helper.sock")).await
}

#[tokio::test]
#[ignore = "needs swtpm named by IRON_VAULT_SWTPM and the helper built with --features tpm"]
async fn the_real_helper_approves_a_config_and_the_service_activates_it_after_a_restart() {
    let fixture = Fixture::new().await;
    let (running, tpm) = with_real_tpm_approver(&fixture, 32).await;

    assert_approves_and_restarts(&fixture, running, tpm).await;
}

#[tokio::test]
#[ignore = "needs swtpm named by IRON_VAULT_SWTPM and the helper built with --features tpm"]
async fn the_real_helper_proves_presence_for_replace() {
    let fixture = Fixture::new().await;
    let (running, _) = with_real_tpm_approver(&fixture, 32).await;

    assert_replaces(&fixture, &running.path).await;
}

#[tokio::test]
#[ignore = "needs swtpm named by IRON_VAULT_SWTPM and the helper built with --features tpm"]
async fn the_real_tpm_refuses_a_wrong_pin_and_the_right_one_still_works() {
    let fixture = Fixture::new().await;
    let (running, tpm) = with_real_tpm_approver(&fixture, 32).await;

    assert_wrong_pin_is_denied(&fixture, &running.path, tpm).await;

    let approved = approve_config(&running.path, &fixture.config("rates"), &via_tpm(PIN)).await;
    assert_eq!(approved_version(&approved), 2);
}

/// Two tries leave the helper a share of one: the first wrong PIN spends it, and the next request is withheld by the reserve.
#[tokio::test]
#[ignore = "needs swtpm named by IRON_VAULT_SWTPM and the helper built with --features tpm"]
async fn the_real_lockout_reserve_withholds_the_try_and_a_software_approver_still_approves() {
    let fixture = Fixture::new().await;
    let (running, tpm) = with_real_tpm_approver(&fixture, 2).await;
    let before = counters(&fixture);
    let denied = approve_config(&running.path, &fixture.config("rates"), &via_tpm(WRONG_PIN)).await;
    assert_eq!(error_code(&denied.response), ErrorCode::ApprovalDenied, "{denied:?}");

    let locked = approve_config(&running.path, &fixture.config("rates"), &via_tpm(PIN)).await;

    assert_eq!(error_code(&locked.response), ErrorCode::TpmLockedOut, "{locked:?}");
    assert!(error_message(&locked).contains("600 seconds"), "{locked:?}");
    assert_eq!(counters(&fixture), before);
    assert_eq!(
        tpm_statuses(&captured_logs(), "config.approval-refused", tpm),
        ["wrong_pin", "locked_out"]
    );
    let software = [Answer::Input("yes"), Answer::Input(APPROVAL_PASSPHRASE)];
    assert_eq!(
        approved_version(&approve_config(&running.path, &fixture.config("rates"), &software).await),
        2
    );
    let (_, tcti) = real_helper();
    set_dictionary_attack(&tcti, 32, 600);
}
