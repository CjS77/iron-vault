// SPDX-License-Identifier: MPL-2.0
//! A `tpm` approver's TPM approval PIN as a migration authorization method (`design/migration-authorization.md`, "Which
//! method is asked"; `design/tpm-approval-signer.md`, "Migration"). Over a real admin socket, `recipient add` asks the vault
//! passphrase first, switches to the TPM approver, and is authorized by the TPM's signature over the challenge's migration
//! proof payload; `export` runs the same authorization step. In the service context, a PIN answer takes its challenge
//! once and only before it expires.
//!
//! A stand-in for the TPM signing helper runs in the default suite. The same flow against the real helper and `swtpm` is
//! `#[ignore]`d (see the module documentation of `crates/iron-vault-tpm-signer/tests/swtpm.rs` for starting the emulator).
//! The emulator is shared, so the ignored tests run one at a time:
//!
//! ```sh
//! cargo build -p iron-vault-tpm-signer --features tpm
//! IRON_VAULT_SWTPM=swtpm:host=127.0.0.1,port=2321 cargo test -p iron-vault --test lifecycle -- migration_tpm_pin --ignored \
//!     --test-threads=1
//! ```
//! `IRON_VAULT_TPM_SIGNER` names the helper binary when it is not `target/debug/iron-vault-tpm-signer`.

#![cfg(target_os = "linux")]

use crate::common;

use std::path::PathBuf;
use std::sync::Arc;

use common::approval_harness::{Answer, Captured, Exchanged, captured_logs, converse_switching, send, spawn_admin};
use common::migration_source;
use common::recipient_harness::{self, APPROVAL_PASSPHRASE, Fixture, VAULT_PASSPHRASE};
use common::tpm_helper::{Script, Stub, serve_real, serve_stub};
use iron_vault::admin::protocol::{AdminRequest, AdminResponse, ErrorCode, Frame, OwnerInput, Prompt, RequestedSignerKind};
use iron_vault::attempt_limit::FAILURE_THRESHOLD;
use iron_vault::migration_authorization::{AskableMethod, AskableMethods, CHALLENGE_LIFETIME, MigrationOperation, MigrationRefusal};
use iron_vault::service_context::ServiceContext;
use iron_vault_store::migration_bundle::{BundleDecoder, EntryName};
use iron_vault_store::{ApproverId, RecipientKey, RecoveryKey};
use iron_vault_tpm_protocol::Response;
use p256::ecdsa::{Signature, SigningKey};
use tokio::net::UnixStream;
use tokio::sync::oneshot;
use tokio::time::Instant;
use zeroize::Zeroizing;

const PIN: &str = "correct horse";
const WRONG_PIN: &str = "wrong horse";
const TPM_LABEL: &str = "laptop TPM";
const EXPORT_PASSPHRASE: &str = "EXPORT-chosen-7c2e-correct";

/// An unlocked vault with a `tpm` approver enrolled through the helper socket, its admin socket served until the test ends.
struct TpmVault {
    fixture: Fixture,
    service: Arc<ServiceContext>,
    stub: Option<Stub>,
    approver: ApproverId,
    logs: Captured,
    path: PathBuf,
    stop: Option<oneshot::Sender<()>>,
}

impl TpmVault {
    async fn with_stub() -> Self {
        let fixture = Fixture::new();
        let stub = serve_stub(&fixture.path("helper.sock"), Script::default());
        Self::enrolled(fixture, Some(stub)).await
    }

    async fn enrolled(fixture: Fixture, stub: Option<Stub>) -> Self {
        let logs = captured_logs();
        let service = fixture.start_offering_tpm(&fixture.path("helper.sock"));
        recipient_harness::init(&service).await;
        recipient_harness::unlock(&service).await;
        let request = AdminRequest::ApproverAdd {
            kind: RequestedSignerKind::Tpm,
            label: TPM_LABEL.to_owned(),
        };
        let answers = [APPROVAL_PASSPHRASE, PIN, PIN].map(str::as_bytes);
        let approver = match recipient_harness::exchange(&service, request, &answers).await.0 {
            AdminResponse::ApproverAdd { approver, .. } => approver,
            other => panic!("expected an enrolled approver, got {other:?}"),
        };
        let (path, stop, _) = spawn_admin(&service);
        Self {
            fixture,
            service,
            stub,
            approver,
            logs,
            path,
            stop: Some(stop),
        }
    }

    fn stub(&self) -> &Stub {
        self.stub.as_ref().unwrap()
    }

    async fn run(&self, request: AdminRequest, answers: &[Answer<'_>]) -> Exchanged {
        let mut stream = UnixStream::connect(&self.path).await.unwrap();
        send(&mut stream, &Frame::Request(request)).await;
        converse_switching(&mut stream, answers).await
    }

    /// `recipient add` for `key`, answered with `answers`.
    async fn add(&self, key: &RecipientKey, answers: &[Answer<'_>]) -> Exchanged {
        let request = AdminRequest::RecipientAdd {
            recipient: key.to_string(),
            label: "new laptop".to_owned(),
        };
        self.run(request, answers).await
    }

    /// The one `event` record that names `key` as its destination.
    fn event_for(&self, event: &str, key: &RecipientKey) -> serde_json::Value {
        let records: Vec<_> = self
            .logs
            .events(event)
            .into_iter()
            .filter(|record| record["destination_recipient"] == key.to_string().as_str())
            .collect();
        assert_eq!(records.len(), 1, "{records:?}");
        records[0].clone()
    }

    fn assert_refused(&self, key: &RecipientKey, refusal: &str) {
        let refused = self.event_for("migration.authorization-refused", key);
        assert_eq!(
            (
                refused["method"].as_str(),
                refused["approver_id"].as_str(),
                refused["refusal"].as_str()
            ),
            (Some("tpm_pin"), Some(self.approver.to_string().as_str()), Some(refusal)),
            "{refused}"
        );
    }
}

impl Drop for TpmVault {
    fn drop(&mut self) {
        self.stop.take().into_iter().for_each(|stop| {
            let _ = stop.send(());
        });
    }
}

fn new_key() -> RecipientKey {
    RecoveryKey::generate().1
}

fn prompt(label: &str, switchable: bool) -> Prompt {
    Prompt {
        label: label.to_owned(),
        secret: true,
        switchable,
    }
}

fn pin_prompt(switchable: bool) -> Prompt {
    prompt(&format!("TPM approval PIN for \"{TPM_LABEL}\""), switchable)
}

/// The vault passphrase asked first, then the switch to the TPM approver and its PIN.
fn switch_to(pin: &str) -> [Answer<'_>; 2] {
    [Answer::Switch, Answer::Input(pin)]
}

fn error_of(response: &AdminResponse) -> (ErrorCode, &str) {
    match response {
        AdminResponse::Error { code, message } => (*code, message),
        other => panic!("expected an error, got {other:?}"),
    }
}

/// Answers `count` wrong vault passphrases short of a cooldown, counted straight into the attempt limit.
async fn fail(service: &ServiceContext, count: u32) {
    let mut limiter = service.attempt_limiter().await;
    (0..count).for_each(|_| limiter.record_failure(Instant::now()));
}

fn assert_added(exchanged: &Exchanged, key: &RecipientKey) {
    assert!(
        matches!(&exchanged.response, AdminResponse::RecipientAdd { recipient, .. } if recipient == key),
        "{exchanged:?}"
    );
}

async fn assert_pin_authorizes_a_recipient_add(vault: &TpmVault) {
    let key = new_key();

    let exchanged = vault.add(&key, &switch_to(PIN)).await;

    assert_added(&exchanged, &key);
    assert_eq!(exchanged.prompts, [prompt("Vault passphrase", true), pin_prompt(true)]);
    assert!(
        exchanged.notices.contains("authorize with: the vault passphrase\n"),
        "{}",
        exchanged.notices
    );
    let issued = vault.event_for("migration.challenge-issued", &key);
    assert_eq!(issued["method"], "vault_passphrase");
    let authorized = vault.event_for("migration.authorized", &key);
    assert_eq!(
        (authorized["method"].as_str(), authorized["approver_id"].as_str()),
        (Some("tpm_pin"), Some(vault.approver.to_string().as_str())),
        "{authorized}"
    );
    assert!(!vault.logs.text().contains(PIN));
}

#[tokio::test]
async fn a_tpm_approval_pin_authorizes_a_recipient_add_with_a_migration_proof_signature() {
    let vault = TpmVault::with_stub().await;

    assert_pin_authorizes_a_recipient_add(&vault).await;

    assert_eq!(vault.stub().signed_magics().last(), Some(b"IVMA"));
}

#[tokio::test]
async fn a_wrong_pin_is_denied_writes_nothing_and_does_not_count_toward_the_attempt_limit() {
    let vault = TpmVault::with_stub().await;
    fail(&vault.service, FAILURE_THRESHOLD - 1).await;
    vault.stub().answer_next_signs([Some(Response::WrongPin)]);
    let before = vault.fixture.state_files();
    let key = new_key();

    let denied = vault.add(&key, &switch_to(WRONG_PIN)).await;

    let (code, message) = error_of(&denied.response);
    assert_eq!(code, ErrorCode::MigrationDenied);
    assert!(message.contains("TPM approval PIN is wrong"), "{message}");
    assert_eq!(vault.fixture.state_files(), before);
    vault.assert_refused(&key, "wrong_pin");
    assert!(
        vault.service.check_migration_attempts().await.is_ok(),
        "a wrong PIN counted toward the attempt limit"
    );
    assert!(!vault.logs.text().contains(WRONG_PIN));
}

#[tokio::test]
async fn a_tpm_lockout_is_tpm_locked_out() {
    let vault = TpmVault::with_stub().await;
    vault.stub().answer_next_signs([Some(Response::LockedOut { wait_seconds: 600 })]);
    let key = new_key();

    let refused = vault.add(&key, &switch_to(PIN)).await;

    let (code, message) = error_of(&refused.response);
    assert_eq!(code, ErrorCode::TpmLockedOut);
    assert!(
        message.contains("600 seconds") && message.contains("nothing was exported or rewrapped"),
        "{message}"
    );
    vault.assert_refused(&key, "tpm_locked_out");
}

#[tokio::test]
async fn a_helper_refusal_other_than_the_pin_is_migration_unavailable() {
    let vault = TpmVault::with_stub().await;
    vault.stub().answer_next_signs([Some(Response::NotThisTpm)]);
    let key = new_key();

    let refused = vault.add(&key, &switch_to(PIN)).await;

    let (code, message) = error_of(&refused.response);
    assert_eq!(code, ErrorCode::MigrationUnavailable);
    assert!(message.contains("not_this_tpm"), "{message}");
    vault.assert_refused(&key, "unavailable");
}

/// A signature by the approver's key over anything but this challenge's migration proof payload, such as a presence
/// payload or an approval payload, never authorizes: it does not verify over the payload the service built.
#[tokio::test]
async fn a_signature_over_another_message_never_authorizes() {
    let vault = TpmVault::with_stub().await;
    let presence = [b"IVPP".as_slice(), &[1], &[0; 64]].concat();
    let approval = [b"IVAP".as_slice(), &[1], &[0; 84]].concat();

    assert_signature_never_authorizes(&vault, &presence).await;
    assert_signature_never_authorizes(&vault, &approval).await;
}

/// Has the stub answer the next sign request with its key's signature over `message`, and checks the PIN answered with it
/// is refused as a signature that does not verify.
async fn assert_signature_never_authorizes(vault: &TpmVault, message: &[u8]) {
    let signature: Signature = p256::ecdsa::signature::Signer::sign(&SigningKey::from_slice(&[7; 32]).unwrap(), message);
    let signed = Response::Signed {
        signature: signature.normalize_s().unwrap_or(signature).to_bytes().into(),
    };
    vault.stub().answer_next_signs([Some(signed)]);
    let key = new_key();

    let refused = vault.add(&key, &switch_to(PIN)).await;

    let (code, message) = error_of(&refused.response);
    assert_eq!(code, ErrorCode::MigrationUnavailable);
    assert!(message.contains("bad_signature"), "{message}");
    vault.assert_refused(&key, "unavailable");
}

/// The TPM approver's method among those step 6 asks.
fn pin_method(methods: &AskableMethods) -> &AskableMethod {
    methods
        .asked()
        .iter()
        .find(|method| matches!(method, AskableMethod::TpmPin(_)))
        .unwrap()
}

fn pin_input() -> OwnerInput {
    OwnerInput::new(Zeroizing::new(PIN.as_bytes().to_vec()))
}

/// The PIN method takes its challenge without the passphrase attempt limit, so the challenge itself must refuse a replay.
#[tokio::test]
async fn a_pin_answer_takes_its_challenge_once() {
    let vault = TpmVault::with_stub().await;
    let methods = vault.service.migration_methods().await.unwrap();
    let digest = vault.service.issue_migration_challenge(MigrationOperation::Export).await.unwrap();
    let signed = vault.stub().signed_magics().len();

    let first = vault.service.authorize_migration(&digest, pin_method(&methods), pin_input()).await;
    let replayed = vault.service.authorize_migration(&digest, pin_method(&methods), pin_input()).await;

    assert_eq!(first.err(), None);
    assert_eq!(replayed.err(), Some(MigrationRefusal::NotPending));
    assert_eq!(vault.stub().signed_magics().len(), signed + 1, "the replay reached the TPM");
}

#[tokio::test]
async fn a_pin_answer_after_the_challenge_expires_is_refused_before_the_tpm_signs() {
    let vault = TpmVault::with_stub().await;
    let methods = vault.service.migration_methods().await.unwrap();
    let digest = vault.service.issue_migration_challenge(MigrationOperation::Export).await.unwrap();
    let signed = vault.stub().signed_magics().len();
    tokio::time::pause();
    tokio::time::advance(CHALLENGE_LIFETIME).await;

    let refused = vault.service.authorize_migration(&digest, pin_method(&methods), pin_input()).await;

    assert_eq!(refused.err(), Some(MigrationRefusal::Expired));
    assert_eq!(
        vault.stub().signed_magics().len(),
        signed,
        "the TPM signed for an expired challenge"
    );
}

#[tokio::test]
async fn during_a_cooldown_the_prompt_asks_only_the_tpm_approver() {
    let vault = TpmVault::with_stub().await;
    fail(&vault.service, FAILURE_THRESHOLD).await;
    let key = new_key();

    let exchanged = vault.add(&key, &[Answer::Input(PIN)]).await;

    assert_added(&exchanged, &key);
    assert_eq!(exchanged.prompts, [pin_prompt(false)]);
    let named = format!("authorize with: the TPM approval PIN for \"{TPM_LABEL}\"\n");
    assert!(exchanged.notices.contains(&named), "{}", exchanged.notices);
    assert_eq!(vault.event_for("migration.challenge-issued", &key)["method"], "tpm_pin");
}

#[tokio::test]
async fn the_vault_passphrase_still_authorizes_where_a_tpm_approver_is_enrolled() {
    let vault = TpmVault::with_stub().await;
    let key = new_key();

    let exchanged = vault.add(&key, &[Answer::Input(VAULT_PASSPHRASE)]).await;

    assert_added(&exchanged, &key);
    assert_eq!(exchanged.prompts, [prompt("Vault passphrase", true)]);
    let authorized = vault.event_for("migration.authorized", &key);
    assert_eq!(authorized["method"], "vault_passphrase");
    assert!(authorized.get("approver_id").is_none(), "{authorized}");
}

#[tokio::test]
async fn with_the_helper_socket_gone_the_tpm_approver_is_not_asked() {
    let vault = TpmVault::with_stub().await;
    std::fs::remove_file(vault.fixture.path("helper.sock")).unwrap();
    let key = new_key();

    let exchanged = vault.add(&key, &[Answer::Input(VAULT_PASSPHRASE)]).await;

    assert_added(&exchanged, &key);
    assert_eq!(exchanged.prompts, [prompt("Vault passphrase", false)]);
}

/// `export` answered with `answers`, and the bundle bytes the service streamed before its response.
async fn export(vault: &TpmVault, answers: &[Answer<'_>]) -> (Exchanged, Vec<u8>) {
    let _one = super::export::one_at_a_time().await;
    let mut stream = UnixStream::connect(&vault.path).await.unwrap();
    send(&mut stream, &Frame::Request(AdminRequest::Export)).await;
    let (mut notices, mut prompts, mut bundle) = (String::new(), Vec::new(), Vec::new());
    let mut answers = answers.iter();
    loop {
        match migration_source::next_frame(&mut stream).await {
            Frame::Response(response) => {
                return (
                    Exchanged {
                        notices,
                        prompts,
                        response,
                    },
                    bundle,
                );
            }
            Frame::Notice(notice) => notices.push_str(&notice.text),
            Frame::BundleData(chunk) => bundle.extend_from_slice(chunk.bytes()),
            Frame::Prompt(prompt) => {
                prompts.push(prompt);
                let reply = match answers.next().expect("a prompt beyond the answers given") {
                    Answer::Input(text) => Frame::OwnerInput(OwnerInput::new(Zeroizing::new(text.as_bytes().to_vec()))),
                    Answer::Switch => Frame::Switch,
                };
                send(&mut stream, &reply).await;
            }
            other => panic!("unexpected frame {other:?}"),
        }
    }
}

/// The approver IDs of the bundle's `approver-<id>.age` entries. The format has no entry name for a TPM approver's key.
fn bundled_approvers(bundle: &[u8]) -> Vec<ApproverId> {
    let mut decoder = BundleDecoder::new();
    decoder.push(bundle).unwrap();
    decoder
        .finish()
        .unwrap()
        .entries()
        .filter_map(|(name, _)| match name {
            EntryName::Approver(id) => Some(id),
            _ => None,
        })
        .collect()
}

/// The audit records of `event` for an export that the TPM approver `id` answered. The approver ID is unique to a vault, so
/// it keeps a sibling test's export out of the count in the log every test shares.
fn export_records_of(vault: &TpmVault, event: &str) -> Vec<serde_json::Value> {
    let id = vault.approver.to_string();
    vault
        .logs
        .events(event)
        .into_iter()
        .filter(|record| record["approver_id"] == id.as_str() && record["operation"] == "export")
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tpm_approval_pin_authorizes_an_export_whose_bundle_holds_only_the_software_approvers_key() {
    let vault = TpmVault::with_stub().await;
    let AdminResponse::ApproverList { entries } = vault.run(AdminRequest::ApproverList, &[]).await.response else {
        panic!("expected the approver list");
    };
    let software: Vec<_> = entries.iter().filter(|e| e.id != vault.approver).map(|e| e.id).collect();
    assert_eq!(software.len(), 1, "{entries:?}");
    let answers = [
        Answer::Switch,
        Answer::Input(PIN),
        Answer::Input(EXPORT_PASSPHRASE),
        Answer::Input(EXPORT_PASSPHRASE),
    ];

    let (exchanged, bundle) = export(&vault, &answers).await;

    assert!(matches!(exchanged.response, AdminResponse::Export { .. }), "{exchanged:?}");
    assert_eq!(exchanged.prompts.first(), Some(&prompt("Vault passphrase", true)));
    assert_eq!(exchanged.prompts.get(1), Some(&pin_prompt(true)));
    let authorized = export_records_of(&vault, "migration.authorized");
    assert_eq!(authorized.len(), 1, "{authorized:?}");
    assert_eq!(authorized[0]["method"], "tpm_pin");
    assert_eq!(bundled_approvers(&bundle), software);
    assert_eq!(vault.stub().signed_magics().last(), Some(b"IVMA"));
    assert!(!vault.logs.text().contains(PIN));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_pin_on_export_is_denied_and_no_bundle_is_written() {
    let vault = TpmVault::with_stub().await;
    vault.stub().answer_next_signs([Some(Response::WrongPin)]);
    let before = vault.fixture.state_files();
    let answers = [Answer::Switch, Answer::Input(WRONG_PIN)];

    let (denied, bundle) = export(&vault, &answers).await;

    let (code, message) = error_of(&denied.response);
    assert_eq!(code, ErrorCode::MigrationDenied);
    assert!(message.contains("TPM approval PIN is wrong"), "{message}");
    assert!(bundle.is_empty(), "{} bundle bytes were sent", bundle.len());
    assert_eq!(vault.fixture.state_files(), before);
    let refused = export_records_of(&vault, "migration.authorization-refused");
    assert_eq!(
        (refused.len(), refused[0]["refusal"].as_str()),
        (1, Some("wrong_pin")),
        "{refused:?}"
    );
    assert!(!vault.logs.text().contains(WRONG_PIN));
}

fn real_helper() -> (PathBuf, String) {
    let tcti = std::env::var("IRON_VAULT_SWTPM").expect("IRON_VAULT_SWTPM names the swtpm TCTI");
    let binary = std::env::var_os("IRON_VAULT_TPM_SIGNER").map(PathBuf::from).unwrap_or_else(|| {
        let exe = std::env::current_exe().unwrap();
        exe.parent().unwrap().parent().unwrap().join("iron-vault-tpm-signer")
    });
    (binary, tcti)
}

/// Gives the emulator `max_tries` tries with the lockout counter cleared. The emulator is shared, so run the ignored tests
/// one at a time.
fn set_dictionary_attack(tcti: &str, max_tries: u32) {
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
        "--recovery-time=600",
        "--lockout-recovery-time=1",
    ]);
}

#[tokio::test]
#[ignore = "needs swtpm named by IRON_VAULT_SWTPM and the helper built with --features tpm"]
async fn the_real_helper_authorizes_a_migration_by_pin_and_denies_a_wrong_one() {
    let fixture = Fixture::new();
    let (binary, tcti) = real_helper();
    set_dictionary_attack(&tcti, 32);
    serve_real(&fixture.path("helper.sock"), binary, tcti);
    let vault = TpmVault::enrolled(fixture, None).await;

    assert_pin_authorizes_a_recipient_add(&vault).await;
    let key = new_key();
    let denied = vault.add(&key, &switch_to(WRONG_PIN)).await;

    assert_eq!(error_of(&denied.response).0, ErrorCode::MigrationDenied, "{denied:?}");
    vault.assert_refused(&key, "wrong_pin");
}
