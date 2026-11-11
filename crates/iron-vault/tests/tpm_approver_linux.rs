//! The TPM approver's release checks that an emulated TPM can show (`design/tpm-approval-signer.md`, "Release checks"), one test
//! per item, with the real helper binary started per connection against `swtpm`, as the socket unit would. The items that need the
//! installed package, systemd or a firmware TPM are in `scripts/release/tpm-signer-check.sh`.
//!
//! The tests are `#[ignore]`d. They change the emulator's dictionary-attack settings and clear it, so never point
//! `IRON_VAULT_SWTPM` at a real TPM, and run them one at a time:
//!
//! ```sh
//! swtpm socket --tpm2 --tpmstate dir="$state" --server type=tcp,port=2321 --ctrl type=tcp,port=2322 \
//!     --flags not-need-init,startup-clear &
//! cargo build -p iron-vault-tpm-signer --features tpm
//! IRON_VAULT_SWTPM=swtpm:host=127.0.0.1,port=2321 cargo test -p iron-vault --test tpm_approver_linux -- --ignored --test-threads=1
//! ```
//! `IRON_VAULT_TPM_SIGNER` names the helper binary when it is not `target/debug/iron-vault-tpm-signer`.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

use common::approval_harness::{
    APPROVAL_PASSPHRASE, Answer, Captured, Exchanged, Fixture, approve_request, captured_logs, converse_switching, error_code, identity,
    read_frame, send, serve_admin,
};
use common::recipient_harness;
use common::tpm_helper::serve_real;
use iron_vault::admin::protocol::{AdminRequest, AdminResponse, ErrorCode, Frame, OwnerInput, RequestedOrigin, RequestedSignerKind};
use iron_vault::deployment::DeploymentProfile;
use iron_vault::hardening::MemoryProtection;
use iron_vault::logging::LogSwitch;
use iron_vault::path_metadata::invoking_user;
use iron_vault::service_context::ServiceContext;
use iron_vault::service_state::ServiceState;
use iron_vault_kinds::CredentialMaterial;
use iron_vault_policy::Port;
use iron_vault_store::{ApprovalEnvelope, ApproverId, OsFs, PermittedOrigins, RecipientKey, RecoveryKey, SignerKind, open_approval_state};
use iron_vault_tpm_protocol::{TpmApprovalPin, TpmAuthValue};
use tokio::net::UnixStream;
use zeroize::Zeroizing;

const PIN: &str = "correct horse";
const WRONG_PIN: &str = "wrong horse";
const NEW_PASSPHRASE: &str = "BACKUP-approver-passphrase-7a31";
const EXPORT_PASSPHRASE: &str = "EXPORT-chosen-7c2e-correct";

// ---- The emulator ------------------------------------------------------------------------------------------------------------

fn tcti() -> String {
    std::env::var("IRON_VAULT_SWTPM").expect("IRON_VAULT_SWTPM names the swtpm TCTI")
}

fn helper_binary() -> PathBuf {
    std::env::var_os("IRON_VAULT_TPM_SIGNER").map(PathBuf::from).unwrap_or_else(|| {
        let exe = std::env::current_exe().unwrap();
        exe.parent().unwrap().parent().unwrap().join("iron-vault-tpm-signer")
    })
}

/// Runs a tpm2-tools program against the emulator and returns its standard output.
fn tool(program: &str, args: &[&str], dir: Option<&Path>) -> String {
    let mut command = Command::new(program);
    command.args(args).env("TPM2TOOLS_TCTI", tcti());
    dir.into_iter().for_each(|dir| {
        command.current_dir(dir);
    });
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{program} {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

/// Gives the emulator `max_tries` tries and a recovery interval of `interval` seconds, with the lockout counter cleared.
fn set_dictionary_attack(max_tries: u32, interval: u32) {
    // The emulator has no resource manager, so an object an earlier test's tools left loaded would exhaust its three slots.
    tool("tpm2_flushcontext", &["--transient-object"], None);
    tool("tpm2_dictionarylockout", &["--clear-lockout"], None);
    let (max_tries, interval) = (format!("--max-tries={max_tries}"), format!("--recovery-time={interval}"));
    tool(
        "tpm2_dictionarylockout",
        &["--setup-parameters", &max_tries, &interval, "--lockout-recovery-time=1"],
        None,
    );
}

/// `TPM2_PT_LOCKOUT_COUNTER`: the failed tries the emulator holds against its maximum.
fn lockout_counter() -> u32 {
    let properties = tool("tpm2_getcap", &["properties-variable"], None);
    let line = properties
        .lines()
        .find(|line| line.starts_with("TPM2_PT_LOCKOUT_COUNTER:"))
        .expect("the lockout counter");
    u32::from_str_radix(line.rsplit("0x").next().unwrap().trim(), 16).unwrap()
}

// ---- A service on the real helper --------------------------------------------------------------------------------------------

/// A service in Ready whose `tpm` kind is offered through the real helper, with a TPM approver enrolled under [`PIN`] beside the
/// software one, which signed the active approval.
struct Machine {
    fixture: Fixture,
    service: Arc<ServiceContext>,
    path: PathBuf,
    _stop: tokio::sync::oneshot::Sender<()>,
    software: ApproverId,
    tpm: ApproverId,
}

async fn unenrolled(max_tries: u32) -> Machine {
    set_dictionary_attack(max_tries, 600);
    let fixture = Fixture::new().await;
    let software = fixture.approver_id();
    serve_real(&fixture.path("helper.sock"), helper_binary(), tcti());
    let log = LogSwitch::stdout_for_tests(invoking_user().unwrap()).unwrap();
    let service = fixture.start_as(OsFs, log, DeploymentProfile::Development, MemoryProtection::Unsupported);
    let service = Arc::new(service.with_tpm_socket(fixture.path("helper.sock")));
    service.enter_checking(identity()).await.unwrap();
    let (path, stop) = serve_admin(&service);
    Machine {
        fixture,
        service,
        path,
        _stop: stop,
        software,
        tpm: software,
    }
}

async fn enrolled(max_tries: u32) -> Machine {
    let mut machine = unenrolled(max_tries).await;
    machine.tpm = enrolled_id(&machine.enroll(PIN, PIN).await);
    machine
}

fn enrolled_id(exchanged: &Exchanged) -> ApproverId {
    match exchanged.response {
        AdminResponse::ApproverAdd { approver, .. } => approver,
        ref other => panic!("expected an enrolled approver, got {other:?}\n{}", exchanged.notices),
    }
}

impl Machine {
    async fn run(&self, request: AdminRequest, answers: &[Answer<'_>]) -> Exchanged {
        let mut stream = UnixStream::connect(&self.path).await.unwrap();
        send(&mut stream, &Frame::Request(request)).await;
        converse_switching(&mut stream, answers).await
    }

    /// `approver add --kind tpm`, authorized by the software approver's passphrase.
    async fn enroll(&self, new: &str, repeat: &str) -> Exchanged {
        let request = AdminRequest::ApproverAdd {
            kind: RequestedSignerKind::Tpm,
            label: "laptop TPM".to_owned(),
        };
        self.run(
            request,
            &[Answer::Input(APPROVAL_PASSPHRASE), Answer::Input(new), Answer::Input(repeat)],
        )
        .await
    }

    /// `config approve` of the `route` config, answering "yes" and then the prompts in turn.
    async fn approve(&self, route: &str, answers: &[Answer<'_>]) -> Exchanged {
        let mut stream = UnixStream::connect(&self.path).await.unwrap();
        send(&mut stream, &approve_request(&self.fixture.config(route))).await;
        let all = [&[Answer::Input("yes")][..], answers].concat();
        converse_switching(&mut stream, &all).await
    }

    /// `approver remove`, answering its prompts.
    async fn remove(&self, id: ApproverId, answers: &[Answer<'_>]) -> Exchanged {
        self.run(AdminRequest::ApproverRemove { approver: *id.as_bytes() }, answers).await
    }

    /// `approver add --kind software`, answering its prompts.
    async fn add_software(&self, answers: &[Answer<'_>]) -> Exchanged {
        let request = AdminRequest::ApproverAdd {
            kind: RequestedSignerKind::Software,
            label: "backup".to_owned(),
        };
        self.run(request, answers).await
    }

    fn blob(&self, id: ApproverId) -> PathBuf {
        self.fixture.path(&format!("state/approver-{id}.tpm"))
    }

    /// The reserved and committed approval versions on disk.
    fn counters(&self) -> (u64, Option<u64>) {
        let state = open_approval_state(&identity(), &fs::read(self.fixture.path("state/approval.age")).unwrap()).unwrap();
        (state.highest_reserved(), state.committed().map(|(version, _)| version.get()))
    }

    fn pinned_kinds(&self) -> Vec<SignerKind> {
        let state = open_approval_state(&identity(), &fs::read(self.fixture.path("state/approval.age")).unwrap()).unwrap();
        state.approvers().iter().map(|approver| approver.kind()).collect()
    }
}

/// The TPM approver is second in the approver order while another signed the active approval, so the owner switches to it.
fn via_tpm(pin: &str) -> [Answer<'_>; 2] {
    [Answer::Switch, Answer::Input(pin)]
}

fn version_of(exchanged: &Exchanged) -> u64 {
    match &exchanged.response {
        AdminResponse::ConfigApprove(result) => result.version,
        other => panic!("expected an approval, got {other:?}\n{}", exchanged.notices),
    }
}

fn message_of(exchanged: &Exchanged) -> &str {
    match &exchanged.response {
        AdminResponse::Error { message, .. } => message,
        other => panic!("expected an error, got {other:?}"),
    }
}

// ---- Release checks 3 to 5: enroll, approve, owner presence ----------------------------------------------------------------

/// Check 3.
#[tokio::test]
#[ignore = "needs swtpm named by IRON_VAULT_SWTPM and the helper built with --features tpm"]
async fn enrolling_pins_a_tpm_key_with_a_private_blob_and_keeps_the_counters() {
    let machine = unenrolled(32).await;
    let before = machine.counters();

    let added = machine.enroll(PIN, PIN).await;

    let id = enrolled_id(&added);
    assert!(added.notices.contains("  kind: tpm\n"), "{}", added.notices);
    // Both approvers are enrolled within one second, so their order in the state follows their random IDs.
    let kinds = machine.pinned_kinds();
    assert!(
        kinds.len() == 2 && kinds.contains(&SignerKind::Software) && kinds.contains(&SignerKind::Tpm),
        "{kinds:?}"
    );
    assert_eq!(fs::metadata(machine.blob(id)).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(machine.counters(), before);
    let listed = machine.run(AdminRequest::ApproverList, &[]).await;
    assert!(
        matches!(&listed.response, AdminResponse::ApproverList { entries } if entries.iter().any(|entry| entry.kind == SignerKind::Tpm)),
        "{listed:?}"
    );
}

/// Check 4: a 191-byte envelope with algorithm `02` that verifies against the pinned key, and again after a restart.
#[tokio::test]
#[ignore = "needs swtpm named by IRON_VAULT_SWTPM and the helper built with --features tpm"]
async fn a_config_approved_with_the_tpm_is_a_191_byte_envelope_that_verifies_after_a_restart() {
    let machine = enrolled(32).await;

    let approved = machine.approve("rates", &via_tpm(PIN)).await;

    assert_eq!(version_of(&approved), 2);
    let [_, signature] = machine.fixture.published_pair();
    let envelope = ApprovalEnvelope::decode(&signature).unwrap();
    assert_eq!(
        (signature.len(), envelope.approver_id(), envelope.algorithm().id()),
        (191, machine.tpm, 2)
    );
    assert_restart_activates(machine, 2).await;
}

/// Stops the service, waits for its handlers to let go of it, and starts another on the same directories: it verifies the TPM's
/// signature on the published config and reaches Ready at `version`.
async fn assert_restart_activates(machine: Machine, version: u64) {
    let Machine {
        fixture, service, _stop, ..
    } = machine;
    let _ = _stop.send(());
    service.stop().await;
    let mut service = service;
    for _ in 0..500 {
        match Arc::try_unwrap(service) {
            Ok(owned) => {
                drop(owned);
                let restarted = fixture.ready().await;
                assert_eq!(restarted.state().await, ServiceState::Ready);
                assert_eq!(common::approval_harness::versions(&restarted).await, (Some(version), version));
                return;
            }
            Err(shared) => {
                service = shared;
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }
    }
    panic!("something still holds the service");
}

/// Check 5: `replace` and `rm` take the PIN as owner presence.
#[tokio::test]
#[ignore = "needs swtpm named by IRON_VAULT_SWTPM and the helper built with --features tpm"]
async fn replace_and_rm_accept_the_pin_as_owner_presence() {
    let machine = enrolled(32).await;
    let origins = PermittedOrigins::new([("old.example".parse().unwrap(), Port::HTTPS)].into()).unwrap();
    let material = CredentialMaterial::Static { key: "old-secret".into() };
    machine
        .service
        .add_credential("old_key".parse().unwrap(), material, origins)
        .await
        .unwrap();

    let removed = machine
        .run(
            AdminRequest::Rm {
                name: "old_key".to_owned(),
            },
            &via_tpm(PIN),
        )
        .await;
    let replaced = replace_fx_key(&machine, &via_tpm_then(PIN, "NEW-SECRET-91c7e4")).await;

    assert!(matches!(removed.response, AdminResponse::Success), "{removed:?}");
    assert!(matches!(replaced.response, AdminResponse::Replace { .. }), "{replaced:?}");
    assert!(!captured_logs().text().contains("NEW-SECRET-91c7e4"));
}

fn via_tpm_then<'a>(pin: &'a str, material: &'a str) -> [Answer<'a>; 3] {
    [Answer::Switch, Answer::Input(pin), Answer::Input(material)]
}

async fn replace_fx_key(machine: &Machine, answers: &[Answer<'_>]) -> Exchanged {
    let origin = RequestedOrigin {
        host: "localhost".to_owned(),
        port: Port::try_from(machine.fixture.upstream().port()).unwrap(),
    };
    let request = AdminRequest::Replace {
        name: "fx_key".to_owned(),
        kind: iron_vault_policy::CredentialKind::Static,
        origins: vec![origin],
    };
    machine.run(request, answers).await
}

// ---- Checks 6 and 7: a wrong PIN, lockout and the reserve --------------------------------------------------------------------

/// Check 6.
#[tokio::test]
#[ignore = "needs swtpm named by IRON_VAULT_SWTPM and the helper built with --features tpm"]
async fn a_wrong_pin_is_denied_and_spends_exactly_one_try() {
    let machine = enrolled(32).await;
    let before = (lockout_counter(), machine.counters());

    let denied = machine.approve("rates", &via_tpm(WRONG_PIN)).await;

    assert_eq!(error_code(&denied.response), ErrorCode::ApprovalDenied, "{denied:?}");
    assert_eq!((lockout_counter(), machine.counters()), (before.0 + 1, before.1));
    assert_eq!(version_of(&machine.approve("rates", &via_tpm(PIN)).await), 2);
}

/// Check 7 on the emulator: two tries leave the helper a share of one. Once it is spent the helper answers `tpm-locked-out` and
/// the counter stops, so a PIN-protected key outside Iron Vault still authorizes, and the software approver still approves.
#[tokio::test]
#[ignore = "needs swtpm named by IRON_VAULT_SWTPM and the helper built with --features tpm"]
async fn the_reserve_keeps_the_counter_at_the_share_and_other_keys_working() {
    let machine = enrolled(2).await;
    let denied = machine.approve("rates", &via_tpm(WRONG_PIN)).await;
    assert_eq!(error_code(&denied.response), ErrorCode::ApprovalDenied, "{denied:?}");

    let locked = machine.approve("rates", &via_tpm(PIN)).await;
    let again = machine.approve("rates", &via_tpm(WRONG_PIN)).await;

    assert_eq!(error_code(&locked.response), ErrorCode::TpmLockedOut, "{locked:?}");
    assert_eq!(error_code(&again.response), ErrorCode::TpmLockedOut, "{again:?}");
    assert!(message_of(&locked).contains("600 seconds"), "{locked:?}");
    assert_eq!(lockout_counter(), 1);
    assert_throwaway_key_signs(&machine);
    let software = machine
        .approve("rates", &[Answer::Switch, Answer::Switch, Answer::Input(APPROVAL_PASSPHRASE)])
        .await;
    assert_eq!(version_of(&software), 2);
}

/// A key with its own authorization value, made and used with tpm2-tools, signs while Iron Vault's approver is held back.
fn assert_throwaway_key_signs(machine: &Machine) {
    let dir = machine.fixture.path("throwaway");
    fs::create_dir(&dir).unwrap();
    let run = |program: &str, args: &[&str]| tool(program, args, Some(&dir));
    run("tpm2_createprimary", &["-C", "o", "-c", "primary.ctx"]);
    run("tpm2_flushcontext", &["--transient-object"]);
    run(
        "tpm2_create",
        &[
            "-C",
            "primary.ctx",
            "-G",
            "ecc256:ecdsa-sha256",
            "-p",
            "throwaway",
            "-u",
            "k.pub",
            "-r",
            "k.priv",
        ],
    );
    run("tpm2_load", &["-C", "primary.ctx", "-u", "k.pub", "-r", "k.priv", "-c", "k.ctx"]);
    run("tpm2_flushcontext", &["--transient-object"]);
    fs::write(dir.join("message"), b"unrelated").unwrap();
    run(
        "tpm2_sign",
        &["-c", "k.ctx", "-p", "throwaway", "-g", "sha256", "-o", "signature", "message"],
    );
    assert!(dir.join("signature").exists());
    run("tpm2_flushcontext", &["--transient-object"]);
}

/// Check 7, last sentence: an interval under 600 seconds, or a maximum of 1, makes the approver unavailable, and no try is spent.
#[tokio::test]
#[ignore = "needs swtpm named by IRON_VAULT_SWTPM and the helper built with --features tpm"]
async fn weak_dictionary_attack_settings_make_the_approver_unavailable_without_spending_a_try() {
    let machine = enrolled(32).await;

    for (max_tries, interval) in [(32, 599), (1, 600)] {
        set_dictionary_attack(max_tries, interval);
        let refused = machine.approve("rates", &via_tpm(PIN)).await;
        assert_eq!(error_code(&refused.response), ErrorCode::ApprovalUnavailable, "{refused:?}");
        assert_eq!(lockout_counter(), 0);
    }
}

// ---- Check 8: migration methods ----------------------------------------------------------------------------------------------

/// A real vault, initialized and unlocked through the admin socket, with a TPM approver enrolled through the real helper.
struct Migrating {
    fixture: recipient_harness::Fixture,
    service: Arc<ServiceContext>,
    approver: ApproverId,
    logs: Captured,
}

async fn migrating() -> Migrating {
    set_dictionary_attack(32, 600);
    let logs = captured_logs();
    let fixture = recipient_harness::Fixture::new();
    serve_real(&fixture.path("helper.sock"), helper_binary(), tcti());
    let service = fixture.start_offering_tpm(&fixture.path("helper.sock"));
    recipient_harness::init(&service).await;
    recipient_harness::unlock(&service).await;
    let request = AdminRequest::ApproverAdd {
        kind: RequestedSignerKind::Tpm,
        label: "laptop TPM".to_owned(),
    };
    let answers = [recipient_harness::APPROVAL_PASSPHRASE, PIN, PIN].map(str::as_bytes);
    let approver = match recipient_harness::exchange(&service, request, &answers).await.0 {
        AdminResponse::ApproverAdd { approver, .. } => approver,
        other => panic!("expected an enrolled approver, got {other:?}"),
    };
    Migrating {
        fixture,
        service,
        approver,
        logs,
    }
}

impl Migrating {
    /// Sends `request` and answers its prompts with `answers`, taking the bundle frames an export sends.
    async fn run(&self, request: AdminRequest, answers: &[Answer<'_>]) -> AdminResponse {
        let (path, stop, task) = common::approval_harness::spawn_admin(&self.service);
        let mut stream = UnixStream::connect(path).await.unwrap();
        send(&mut stream, &Frame::Request(request)).await;
        let mut answers = answers.iter();
        let response = loop {
            match read_frame(&mut stream).await {
                Frame::Response(response) => break response,
                Frame::Notice(_) | Frame::BundleData(_) => {}
                Frame::Prompt(_) => send(&mut stream, &answer(answers.next().expect("a prompt beyond the answers"))).await,
                other => panic!("unexpected frame {other:?}"),
            }
        };
        let _ = stop.send(());
        task.await.unwrap();
        response
    }

    /// The `migration.authorized` records that name the TPM approver and the method `tpm_pin`.
    fn authorized_by_pin(&self) -> usize {
        self.logs
            .events("migration.authorized")
            .iter()
            .filter(|record| record["method"] == "tpm_pin" && record["approver_id"] == self.approver.to_string().as_str())
            .count()
    }
}

fn answer(answer: &Answer<'_>) -> Frame {
    match answer {
        Answer::Input(text) => Frame::OwnerInput(OwnerInput::new(Zeroizing::new(text.as_bytes().to_vec()))),
        Answer::Switch => Frame::Switch,
    }
}

/// Checks 5 (`recipient remove`) and 8: `recipient add` and `export` switch from the vault passphrase to the TPM approver, the audit
/// log names `tpm_pin` and the approver, and `recipient remove` takes the PIN as owner presence.
#[tokio::test]
#[ignore = "needs swtpm named by IRON_VAULT_SWTPM and the helper built with --features tpm"]
async fn recipient_add_export_and_recipient_remove_accept_the_pin() {
    let vault = migrating().await;
    let key: RecipientKey = RecoveryKey::generate().1;
    let by_pin = [Answer::Switch, Answer::Input(PIN)];

    let added = vault
        .run(
            AdminRequest::RecipientAdd {
                recipient: key.to_string(),
                label: "new laptop".to_owned(),
            },
            &by_pin,
        )
        .await;
    let exported = vault
        .run(
            AdminRequest::Export,
            &[
                Answer::Switch,
                Answer::Input(PIN),
                Answer::Input(EXPORT_PASSPHRASE),
                Answer::Input(EXPORT_PASSPHRASE),
            ],
        )
        .await;
    let removed = vault
        .run(
            AdminRequest::RecipientRemove {
                recipient: key.to_string(),
            },
            &by_pin,
        )
        .await;

    assert!(matches!(added, AdminResponse::RecipientAdd { .. }), "{added:?}");
    assert!(matches!(exported, AdminResponse::Export { .. }), "{exported:?}");
    assert!(matches!(removed, AdminResponse::RecipientRemove { .. }), "{removed:?}");
    assert_eq!(vault.authorized_by_pin(), 2, "recipient add and export");
    assert!(!vault.logs.events("recipient.removed").is_empty());
    assert!(!vault.logs.text().contains(PIN));
    drop(vault.fixture);
}

// ---- Check 9: the protected session ------------------------------------------------------------------------------------------

/// Check 9: a TCTI trace of an enrollment and an approval holds neither the PIN nor the authorization value. The trace is the
/// helper's own standard error, with `TSS2_LOG=tcti+trace`, and the test checks that it holds the TPM's traffic at all.
#[tokio::test]
#[ignore = "needs swtpm named by IRON_VAULT_SWTPM and the helper built with --features tpm"]
async fn a_recorded_tcti_trace_holds_neither_the_pin_nor_the_authorization_value() {
    set_dictionary_attack(32, 600);
    let fixture = Fixture::new().await;
    let trace = fixture.path("trace.log");
    serve_traced(&fixture.path("helper.sock"), &trace);
    let log = LogSwitch::stdout_for_tests(invoking_user().unwrap()).unwrap();
    let service = fixture.start_as(OsFs, log, DeploymentProfile::Development, MemoryProtection::Unsupported);
    let service = Arc::new(service.with_tpm_socket(fixture.path("helper.sock")));
    service.enter_checking(identity()).await.unwrap();
    let (path, _stop) = serve_admin(&service);
    let machine = Machine {
        fixture,
        service,
        path,
        _stop,
        software: ApproverId::generate(),
        tpm: ApproverId::generate(),
    };

    let id = enrolled_id(&machine.enroll(PIN, PIN).await);
    assert_eq!(version_of(&machine.approve("rates", &via_tpm(PIN)).await), 2);

    let hex = hex_digits(&fs::read(&trace).unwrap());
    let value = TpmAuthValue::derive(id.as_bytes(), &TpmApprovalPin::new(PIN.to_owned()));
    let public_key = open_approval_state(&identity(), &fs::read(machine.fixture.path("state/approval.age")).unwrap()).unwrap();
    let key = public_key
        .approvers()
        .iter()
        .find(|approver| approver.id() == id)
        .unwrap()
        .public_key()
        .as_bytes()
        .to_vec();
    assert!(
        hex.contains(&hex_string(&key[1..33])),
        "the trace holds no TPM traffic, so it proves nothing"
    );
    assert!(!hex.contains(&hex_string(PIN.as_bytes())), "the PIN is in the trace");
    assert!(
        !hex.contains(&hex_string(value.as_bytes())),
        "the authorization value is in the trace"
    );
}

/// The helper per connection with the TSS library's TCTI trace on its standard error, appended to `trace`.
fn serve_traced(path: &Path, trace: &Path) {
    use std::os::fd::OwnedFd;
    let listener = std::os::unix::net::UnixListener::bind(path).unwrap();
    let (trace, tcti, binary) = (trace.to_owned(), tcti(), helper_binary());
    let user = common::tpm_helper::current_user();
    std::thread::spawn(move || {
        listener.incoming().flatten().for_each(|stream| {
            let log = fs::OpenOptions::new().create(true).append(true).open(&trace).unwrap();
            let child = Command::new(&binary)
                .args(["--tcti", &tcti, "--peer-user", &user])
                .env("TSS2_LOG", "tcti+trace")
                .stdin(Stdio::from(OwnedFd::from(stream.try_clone().unwrap())))
                .stdout(Stdio::from(OwnedFd::from(stream)))
                .stderr(Stdio::from(log))
                .spawn()
                .unwrap();
            let _ = child.wait_with_output();
        });
    });
}

/// The bytes the TCTI trace dumps, concatenated as hexadecimal digits: each dump line is `0000: <hex>  <text>`, and the offset and
/// the text column would otherwise look like digits.
fn hex_digits(trace: &[u8]) -> String {
    String::from_utf8_lossy(trace)
        .lines()
        .filter_map(|line| line.split_once(": "))
        .filter(|(offset, _)| offset.len() == 4 && offset.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .filter_map(|(_, rest)| rest.split_whitespace().next())
        .collect()
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

// ---- Checks 10 and 11, rotation and a forgotten PIN --------------------------------------------------------------------------

/// Check 10: after a clear (the stand-in for a copied blob or a replaced board) the helper answers `not this TPM`, which the
/// service reports as unavailable. The TPM approver signed the active approval, so it is asked first and refused; the software
/// approver then approves, and from then on the approver order starts at it.
#[tokio::test]
#[ignore = "needs swtpm named by IRON_VAULT_SWTPM and the helper built with --features tpm"]
async fn a_cleared_tpm_is_not_this_tpm_and_the_software_approver_still_approves() {
    let machine = enrolled(32).await;
    assert_eq!(version_of(&machine.approve("rates", &via_tpm(PIN)).await), 2);
    tool("tpm2_clear", &["--auth-hierarchy=l"], None);
    set_dictionary_attack(32, 600);

    let unavailable = machine.approve("rates", &[Answer::Input(PIN)]).await;

    assert_eq!(error_code(&unavailable.response), ErrorCode::ApprovalUnavailable, "{unavailable:?}");
    assert!(message_of(&unavailable).contains("not this TPM"), "{unavailable:?}");
    assert_eq!(lockout_counter(), 0);
    let software = machine
        .approve("rates", &[Answer::Switch, Answer::Input(APPROVAL_PASSPHRASE)])
        .await;
    assert_eq!(version_of(&software), 3);
    let starts_at_software = machine.approve("other", &[Answer::Input(APPROVAL_PASSPHRASE)]).await;
    assert_eq!(version_of(&starts_at_software), 4);
}

/// Checks 3, 4 and 11 together: software to TPM and back. Each change is authorized by the approver the other direction needs, and
/// removing the TPM approver deletes its blob.
#[tokio::test]
#[ignore = "needs swtpm named by IRON_VAULT_SWTPM and the helper built with --features tpm"]
async fn rotating_from_software_to_tpm_and_back() {
    let machine = enrolled(32).await;
    assert_eq!(version_of(&machine.approve("rates", &via_tpm(PIN)).await), 2);

    let removed = machine.remove(machine.software, &[Answer::Input(PIN)]).await;
    let added = machine
        .add_software(&[Answer::Input(PIN), Answer::Input(NEW_PASSPHRASE), Answer::Input(NEW_PASSPHRASE)])
        .await;
    let software = enrolled_id(&added);
    let approved = machine.approve("other", &[Answer::Input(PIN)]).await;

    assert!(
        matches!(removed.response, AdminResponse::ApproverRemove { approvers: 1 }),
        "{removed:?}"
    );
    assert_eq!(version_of(&approved), 3);
    let [config, signature] = machine.fixture.published_pair();
    assert_eq!(ApprovalEnvelope::decode(&signature).unwrap().approver_id(), machine.tpm);
    assert!(!config.is_empty());
    let handed_back = machine.approve("third", &[Answer::Switch, Answer::Input(NEW_PASSPHRASE)]).await;
    assert_eq!(version_of(&handed_back), 4);
    let dropped = machine.remove(machine.tpm, &[Answer::Input(NEW_PASSPHRASE)]).await;
    assert!(
        matches!(dropped.response, AdminResponse::ApproverRemove { approvers: 1 }),
        "{dropped:?}"
    );
    assert!(!machine.blob(machine.tpm).exists(), "removing a TPM approver leaves its blob");
    assert_eq!(machine.pinned_kinds(), [SignerKind::Software]);
    assert_eq!(
        ApprovalEnvelope::decode(&machine.fixture.published_pair()[1])
            .unwrap()
            .approver_id(),
        software
    );
}

/// A forgotten PIN is recovered through another approver, and both counters carry over: nothing the recovery does lowers a version.
#[tokio::test]
#[ignore = "needs swtpm named by IRON_VAULT_SWTPM and the helper built with --features tpm"]
async fn a_forgotten_pin_is_recovered_through_another_approver_with_the_counters_kept() {
    let machine = enrolled(32).await;
    assert_eq!(version_of(&machine.approve("rates", &via_tpm(PIN)).await), 2);
    let denied = machine.approve("other", &[Answer::Input(WRONG_PIN)]).await;
    assert_eq!(error_code(&denied.response), ErrorCode::ApprovalDenied, "{denied:?}");
    let before = machine.counters();

    let added = machine
        .add_software(&[
            Answer::Switch,
            Answer::Input(APPROVAL_PASSPHRASE),
            Answer::Input(NEW_PASSPHRASE),
            Answer::Input(NEW_PASSPHRASE),
        ])
        .await;
    let backup = enrolled_id(&added);
    assert_eq!(machine.counters(), before);
    // The lost approver signed the active approval, so a remaining approver approves again before the lost one goes.
    let approved = machine
        .approve("third", &[Answer::Switch, Answer::Input(APPROVAL_PASSPHRASE)])
        .await;
    assert_eq!(version_of(&approved), 3);
    let removed = machine.remove(machine.tpm, &[Answer::Input(APPROVAL_PASSPHRASE)]).await;

    assert!(
        matches!(removed.response, AdminResponse::ApproverRemove { approvers: 2 }),
        "{removed:?}"
    );
    assert_eq!(machine.counters(), (3, Some(3)));
    assert!(!machine.blob(machine.tpm).exists());
    assert_ne!(backup, machine.software);
}

// ---- No PIN in the log -------------------------------------------------------------------------------------------------------

/// Neither a right nor a wrong PIN, nor the authorization value derived from one, reaches the audit log through enrollment, an
/// approval, a refusal and a lockout.
#[tokio::test]
#[ignore = "needs swtpm named by IRON_VAULT_SWTPM and the helper built with --features tpm"]
async fn no_pin_reaches_the_log() {
    let logs = captured_logs();
    let machine = enrolled(2).await;
    machine.approve("rates", &via_tpm(WRONG_PIN)).await;
    machine.approve("rates", &via_tpm(PIN)).await;

    let text = logs.text();

    let value = TpmAuthValue::derive(machine.tpm.as_bytes(), &TpmApprovalPin::new(PIN.to_owned()));
    [PIN, WRONG_PIN]
        .iter()
        .for_each(|pin| assert!(!text.contains(pin), "{pin} reached the log"));
    assert!(!text.to_ascii_lowercase().contains(&hex_string(value.as_bytes())));
    assert!(logs.has_field("config.approval-refused", "tpm_status", "wrong_pin"));
}
