//! `init` end to end over a real admin socket against a running service context on a fresh state directory
//! (specification §5, §12, §14, §15, §16; design/vault-initialization.md): the refusals before any prompt, the
//! passphrase rules, the recovery key shown once and confirmed before anything is written, the vault `unlock` then
//! opens at approval version 1, and the development MVP path through `add`, `config approve` and a proxied request.
//!
//! The service runs the development profile with the test's own account as its service account, so the invoking user
//! is the admin principal. The store seals at the real work factor. Every test's log goes to one captured buffer at
//! TRACE, which must never hold a passphrase, a secret or a recovery key.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use common::admin_response::assert_response;
use common::approval_harness::{Captured, assert_audit_record, captured_logs, mkdir, read_frame, send, spawn_admin};
use common::mock_upstream::{MockUpstream, Reply, TestCa};
use common::proxy_harness::{CallerRequest, Response, TOKEN_BYTES, TOKEN_HEADER, TempDir, Via, token_hash};
use iron_vault::admin::dispatch::Handlers;
use iron_vault::admin::principal::AdminPrincipals;
use iron_vault::admin::protocol::{
    AdminRequest, AdminResponse, ErrorCode, Frame, OwnerInput, Prompt, ProposedConfig, RequestedOrigin, StatusReport, VaultStatus,
};
use iron_vault::admin::server::{AdminServer, Limits};
use iron_vault::admin::socket::AdminSocket;
use iron_vault::clock::WallClock;
use iron_vault::config_check::UpstreamSettings;
use iron_vault::deployment::{Accounts, DeploymentProfile, PasswdDirectory};
use iron_vault::hardening::{CoreDumps, HardeningReport, MemoryProtection};
use iron_vault::path_metadata::invoking_user;
use iron_vault::service_context::{InitRefusal, ServiceContext, ServiceLocks, ServiceSetup, UnlockRefusal};
use iron_vault::service_state::{ServiceState, UnavailableReason};
use iron_vault::serving_snapshot::Admission;
use iron_vault::socket_activation::PassedSockets;
use iron_vault::trusted_path_report::ServicePaths;
use iron_vault::upstream::client::TransportLimits;
use iron_vault_policy::{Capabilities, CredentialKind};
use iron_vault_store::{
    ApprovalEnvelope, ApprovalPassphrase, INITIAL_CONFIG, InitPassphrases, NewVaultKeys, OsFs, Passphrase, RecoveryKeySecret, SealingKeys,
    UnlockError, UtcSecond, UtcSecondError, VaultId, unwrap_identity,
};
use secrecy::SecretString;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use zeroize::Zeroizing;

/// Distinctive, so a search of the logs and messages cannot match anything else.
const VAULT_PASSPHRASE: &str = "INIT-vault-passphrase-41c7";
const APPROVAL_PASSPHRASE: &str = "INIT-approval-passphrase-9d2e";
const SECRET: &str = "INIT-fx-secret-6b03";

const PROMPTS: [(&str, bool); 5] = [
    ("Vault passphrase", true),
    ("Repeat the vault passphrase", true),
    ("Approval passphrase", true),
    ("Repeat the approval passphrase", true),
    ("Type yes once you have saved the recovery key", false),
];

/// The answers of an owner who chooses both passphrases and confirms the recovery key.
const COMPLETE: [&[u8]; 5] = [
    VAULT_PASSPHRASE.as_bytes(),
    VAULT_PASSPHRASE.as_bytes(),
    APPROVAL_PASSPHRASE.as_bytes(),
    APPROVAL_PASSPHRASE.as_bytes(),
    b"yes",
];

/// Empty state and config directories in a temporary directory that is also the runtime directory, and a test upstream
/// for the MVP path.
struct Fixture {
    dir: TempDir,
    ca: TestCa,
    upstream: MockUpstream,
}

impl Fixture {
    async fn new() -> Self {
        let dir = TempDir::new();
        mkdir(&dir.path().join("state"));
        mkdir(&dir.path().join("etc"));
        let ca = TestCa::new("init test CA");
        let reply = Reply::Respond {
            status: 200,
            headers: Vec::new(),
            body: b"ok".to_vec(),
        };
        let upstream = MockUpstream::start(&ca, reply).await;
        Self { dir, ca, upstream }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn socket(&self) -> PathBuf {
        self.path("proxy.sock")
    }

    /// Starts the service as `serve` does, without systemd sockets: Locked, waiting for an unlock or an init.
    fn start(&self) -> Arc<ServiceContext> {
        Arc::new(self.context())
    }

    fn context(&self) -> ServiceContext {
        let paths = ServicePaths {
            profile: DeploymentProfile::Development,
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
            upstream: UpstreamSettings::new(DeploymentProfile::Development, invoking_user().unwrap(), TransportLimits::default())
                .with_pinned_trust(self.ca.trust()),
            hardening: HardeningReport {
                core_dumps: CoreDumps::Disabled,
                memory: MemoryProtection::Unsupported,
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

    /// The config with the Unix listener `local`, its token caller granted `rates`, a route through credential `fx`.
    fn config(&self) -> String {
        format!(
            r#"schema_version = 1

[listeners.local]
unix_socket = "{socket}"
token_header = "{TOKEN_HEADER}"

[callers.agent]
listener = "local"
token_hash = "{hash}"
routes = ["rates"]

[routes.rates]
prefix = "/rates"
upstream = "https://localhost:{port}/v1"
ca_file = "/etc/iron-vault/ca/test.pem"
credential = "fx"
slot = {{ header = "X-Api-Key" }}
methods = ["GET"]
paths = ["/**"]
rate_limit = {{ requests = 100000, per_seconds = 1, burst = 100000 }}
"#,
            socket = self.socket().display(),
            hash = token_hash(TOKEN_BYTES),
            port = self.upstream.port(),
        )
    }
}

/// What one exchange showed the owner and how it ended.
#[derive(Debug)]
struct Exchanged {
    notices: String,
    prompts: Vec<Prompt>,
    reveals: Vec<String>,
    response: AdminResponse,
}

impl Exchanged {
    /// The one recovery key shown.
    fn recovery_key(&self) -> &str {
        match self.reveals.as_slice() {
            [key] => key,
            other => panic!("expected one reveal, got {}", other.len()),
        }
    }

    fn error(&self) -> (ErrorCode, &str) {
        match &self.response {
            AdminResponse::Error { code, message } => (*code, message),
            other => panic!("expected an error, got {other:?}"),
        }
    }

    fn vault_id(&self) -> VaultId {
        match self.response {
            AdminResponse::Init { vault_id, version: 1, .. } => vault_id,
            ref other => panic!("expected init at version 1, got {other:?}"),
        }
    }
}

/// Sends `request` over the service's admin socket and answers the prompts in turn with `answers`.
async fn exchange(service: &Arc<ServiceContext>, request: AdminRequest, answers: &[&[u8]]) -> Exchanged {
    let (path, stop, task) = spawn_admin(service);
    let mut stream = UnixStream::connect(path).await.unwrap();
    send(&mut stream, &Frame::Request(request)).await;
    let exchanged = converse(&mut stream, answers).await;
    let _ = stop.send(());
    // The next exchange binds the admin socket again, and the handlers hold the service until the server ends.
    task.await.unwrap();
    exchanged
}

async fn init(service: &Arc<ServiceContext>, answers: &[&[u8]]) -> Exchanged {
    exchange(service, AdminRequest::Init { host_unlock: false }, answers).await
}

async fn unlock(service: &Arc<ServiceContext>) -> AdminResponse {
    exchange(service, AdminRequest::Unlock, &[VAULT_PASSPHRASE.as_bytes()])
        .await
        .response
}

/// Reads frames until the response, answering each prompt with the next of `answers`.
async fn converse(stream: &mut UnixStream, answers: &[&[u8]]) -> Exchanged {
    let mut answers = answers.iter();
    let mut exchanged = Exchanged {
        notices: String::new(),
        prompts: Vec::new(),
        reveals: Vec::new(),
        response: AdminResponse::Success,
    };
    loop {
        match read_frame(stream).await {
            Frame::Response(response) => return Exchanged { response, ..exchanged },
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
}

fn prompts(count: usize) -> Vec<Prompt> {
    PROMPTS[..count]
        .iter()
        .map(|(label, secret)| Prompt {
            label: (*label).to_owned(),
            secret: *secret,
            switchable: false,
        })
        .collect()
}

/// The open vault `status` reports.
async fn unlocked(service: &Arc<ServiceContext>) -> iron_vault::admin::protocol::UnlockedVault {
    match service.status().await {
        StatusReport {
            state: ServiceState::Ready,
            vault: VaultStatus::Unlocked(vault),
            ..
        } => vault,
        other => panic!("not Ready with an open vault: {other:?}"),
    }
}

/// Neither passphrase, the credential secret nor any recovery key shown reached the log, in any case.
fn assert_no_secret_logged(logs: &Captured, recovery_keys: &[&str]) {
    let text = logs.text();
    [VAULT_PASSPHRASE, APPROVAL_PASSPHRASE, SECRET]
        .iter()
        .chain(recovery_keys)
        .flat_map(|secret| [secret.to_string(), secret.to_lowercase()])
        .for_each(|secret| assert!(!text.contains(&secret), "a secret reached the log:\n{text}"));
}

#[tokio::test]
async fn init_writes_a_vault_that_stays_locked_and_unlocks_to_ready_at_version_1() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let service = fixture.start();
    assert_eq!(service.status().await.vault, VaultStatus::NotInitialized);

    let exchanged = init(&service, &COMPLETE).await;

    let vault_id = exchanged.vault_id();
    assert_eq!(exchanged.prompts, prompts(5));
    assert!(exchanged.notices.contains("shown this once"), "{}", exchanged.notices);
    assert!(!exchanged.notices.contains("unfinished"), "{}", exchanged.notices);
    let report = service.status().await;
    assert_eq!((report.state, report.vault), (ServiceState::Locked, VaultStatus::Locked));
    assert!(matches!(service.holder().load(), Admission::Refuse(UnavailableReason::Locked)));

    assert_response(&unlock(&service).await, &AdminResponse::Success);
    let vault = unlocked(&service).await;
    assert_eq!((vault.id, vault.committed, vault.highest_reserved), (vault_id, Some(1), 1));
    assert!(vault.credentials.is_empty() && vault.route_faults.is_empty());
    assert!(service.listener_names().await.is_empty());

    let recovery = RecoveryKeySecret::parse(SecretString::from(exchanged.recovery_key())).unwrap();
    let recovered = unwrap_identity(&fs::read(fixture.path("state/identity.age")).unwrap(), &recovery).unwrap();
    let kept = service.identity_probe().await.unwrap().upgrade().unwrap();
    assert_eq!(recovered.public_key(), kept.public_key());
    assert_eq!(fs::read(fixture.path("etc/config.toml")).unwrap(), INITIAL_CONFIG);

    let text = logs.text();
    assert!(logs.has_field("vault.initialized", "vault_id", &vault_id.to_string()), "{text}");
    ["config.version-reserved", "config.approval-completed"]
        .iter()
        .for_each(|event| assert!(logs.has_field(event, "version", "1"), "{event}"));
    assert_no_secret_logged(&logs, &[exchanged.recovery_key()]);
}

#[tokio::test]
async fn after_a_restart_init_is_already_initialized_before_any_prompt_and_wrong_state_once_ready() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let service = fixture.start();
    let first = init(&service, &COMPLETE).await;
    first.vault_id();
    service.stop().await;
    drop(service);

    let service = fixture.start();
    let again = init(&service, &COMPLETE).await;
    assert!((again.prompts.is_empty() && again.reveals.is_empty()), "{again:?}");
    let (code, message) = again.error();
    assert_eq!(code, ErrorCode::AlreadyInitialized);
    assert!(message.contains("Initialized") && !message.contains("discard"), "{message}");

    assert_response(&unlock(&service).await, &AdminResponse::Success);
    let ready = init(&service, &COMPLETE).await;
    assert!(ready.prompts.is_empty(), "{ready:?}");
    assert_eq!(
        ready.error(),
        (
            ErrorCode::WrongState,
            "`init` is allowed only while the service is Locked; it is Ready"
        )
    );
    assert_no_secret_logged(&logs, &[first.recovery_key()]);
}

#[tokio::test]
async fn a_file_init_did_not_write_is_named_before_any_prompt() {
    let fixture = Fixture::new().await;
    fs::write(fixture.path("state/stray.txt"), b"x").unwrap();
    let service = fixture.start();

    let exchanged = init(&service, &COMPLETE).await;

    assert!(exchanged.prompts.is_empty(), "{exchanged:?}");
    let (code, message) = exchanged.error();
    assert_eq!(code, ErrorCode::AlreadyInitialized);
    assert!(message.contains("Unrecognized") && message.contains("stray.txt"), "{message}");
}

#[tokio::test]
async fn declining_the_recovery_key_writes_nothing() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let service = fixture.start();
    let [vault, repeat, approval, approval_repeat, _] = COMPLETE;

    let exchanged = init(&service, &[vault, repeat, approval, approval_repeat, b"no"]).await;

    assert_eq!(exchanged.prompts, prompts(5));
    let (code, message) = exchanged.error();
    assert_eq!(code, ErrorCode::Declined);
    assert!(message.ends_with("the recovery key shown opens nothing: discard it"), "{message}");
    fixture.assert_only_lock_files();
    assert_eq!(service.state().await, ServiceState::Locked);
    assert_no_secret_logged(&logs, &[exchanged.recovery_key()]);
}

/// A clock that cannot be read.
#[derive(Debug)]
struct BrokenClock;

impl WallClock for BrokenClock {
    fn now(&self) -> Result<UtcSecond, UtcSecondError> {
        UtcSecond::from_unix_seconds(u64::MAX)
    }
}

#[tokio::test]
async fn an_unreadable_clock_after_the_reveal_writes_nothing_and_says_the_key_is_dead() {
    let fixture = Fixture::new().await;
    let service = Arc::new(fixture.context().with_clock(Arc::new(BrokenClock)));

    let exchanged = init(&service, &COMPLETE).await;

    let (code, message) = exchanged.error();
    assert_eq!(code, ErrorCode::InitFailed);
    assert!(
        message.contains("service clock") && message.ends_with("the recovery key shown opens nothing: discard it"),
        "{message}"
    );
    fixture.assert_only_lock_files();
    assert_eq!(service.state().await, ServiceState::Locked);
}

#[tokio::test]
async fn a_passphrase_breaking_a_rule_is_rejected_by_name_and_nothing_is_written() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let service = fixture.start();
    let vault = VAULT_PASSPHRASE.as_bytes();
    let cases: [(&[&[u8]], &str); 5] = [
        (
            &[vault, b"INIT-vault-passphrase-41c8"],
            "the two entries of the vault passphrase differ",
        ),
        (
            &[b"INIT-short!", b"INIT-short!"],
            "the vault passphrase is shorter than 12 characters",
        ),
        (
            &[b"\xffINIT-not-utf8", b"\xffINIT-not-utf8"],
            "the vault passphrase is not valid UTF-8",
        ),
        (
            &[vault, vault, b"INIT-short!", b"INIT-short!"],
            "the approval passphrase is shorter than 12 characters",
        ),
        (&[vault, vault, vault, vault], "the vault and approval passphrases must differ"),
    ];
    for (answers, rule) in cases {
        let exchanged = init(&service, answers).await;
        assert_eq!(exchanged.prompts, prompts(answers.len()), "{rule}");
        assert!(exchanged.reveals.is_empty(), "{rule}");
        assert_eq!(exchanged.error(), (ErrorCode::PassphraseRejected, rule));
        fixture.assert_only_lock_files();
    }
    assert!(!logs.text().contains("INIT-short") && !logs.text().contains("not-utf8"));
    assert_no_secret_logged(&logs, &[]);
}

#[tokio::test]
async fn unlock_on_a_fresh_directory_is_refused_without_a_prompt() {
    let fixture = Fixture::new().await;
    let service = fixture.start();

    let refused = exchange(&service, AdminRequest::Unlock, &[VAULT_PASSPHRASE.as_bytes()]).await;

    assert!(refused.prompts.is_empty(), "{refused:?}");
    let (code, message) = refused.error();
    assert_eq!(code, ErrorCode::UnlockFailed);
    assert!(message.contains("iron-vault init"), "{message}");
    fixture.assert_only_lock_files();
}

#[tokio::test]
async fn the_context_reads_the_initialization_state_again_before_it_unlocks() {
    let fixture = Fixture::new().await;
    let service = fixture.start();

    let refusal = service
        .unlock(Passphrase::new(SecretString::from(VAULT_PASSPHRASE)).unwrap())
        .await
        .unwrap_err();

    assert!(matches!(refusal, UnlockRefusal::Failed(UnlockError::NotInitialized)), "{refusal:?}");
    assert_eq!(service.state().await, ServiceState::Locked);
}

#[tokio::test]
async fn unlock_on_unrecognized_files_names_them_and_prompts_for_nothing() {
    let fixture = Fixture::new().await;
    fs::write(fixture.path("state/operational.age"), b"x").unwrap();
    let service = fixture.start();

    let refused = exchange(&service, AdminRequest::Unlock, &[VAULT_PASSPHRASE.as_bytes()]).await;

    assert!(refused.prompts.is_empty(), "{refused:?}");
    let (code, message) = refused.error();
    assert_eq!(code, ErrorCode::UnlockFailed);
    assert!(
        message.contains("operational.age") && message.contains("did not write"),
        "{message}"
    );
}

#[tokio::test]
async fn a_foreign_file_beside_the_manifest_is_logged_by_name_and_unlock_goes_on() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let service = fixture.start();
    init(&service, &COMPLETE).await.vault_id();
    fs::write(fixture.path("state/editor-backup-9f3a\u{e9}.txt~"), b"SECRET-CONTENT").unwrap();

    let unlocked = exchange(&service, AdminRequest::Unlock, &[VAULT_PASSPHRASE.as_bytes()]).await;

    assert_eq!(unlocked.prompts.len(), 1, "{unlocked:?}");
    assert_response(&unlocked.response, &AdminResponse::Success);
    let warned: Vec<_> = logs
        .events("vault.foreign-file")
        .into_iter()
        .filter(|record| record["file"] == "editor-backup-9f3a\\u{e9}.txt~")
        .collect();
    assert_eq!(warned.len(), 1, "{}", logs.text());
    assert_audit_record(&warned[0], "WARN", &["file"]);
    assert!(!logs.text().contains("SECRET-CONTENT"), "{}", logs.text());
}

#[tokio::test]
async fn an_unfinished_initialization_refuses_unlock_and_the_next_init_discards_it() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    ["init.unfinished", "identity.age", "operational.age"]
        .iter()
        .for_each(|name| fs::write(fixture.path(&format!("state/{name}")), b"").unwrap());
    fs::write(fixture.path("etc/config.toml"), INITIAL_CONFIG).unwrap();
    let service = fixture.start();
    assert_eq!(service.status().await.vault, VaultStatus::InitializationUnfinished);

    let refused = exchange(&service, AdminRequest::Unlock, &[VAULT_PASSPHRASE.as_bytes()]).await;
    let (code, message) = refused.error();
    assert_eq!(code, ErrorCode::UnlockFailed);
    assert!(message.contains("iron-vault init"), "{message}");
    assert!(refused.prompts.is_empty(), "{refused:?}");

    let exchanged = init(&service, &COMPLETE).await;
    exchanged.vault_id();
    assert!(
        exchanged.notices.starts_with("An unfinished initialization"),
        "{}",
        exchanged.notices
    );
    let discarded: Vec<_> = logs
        .events("vault.init-discarded")
        .into_iter()
        .filter(|record| record["files"].as_str().is_some_and(|files| files.contains("operational.age")))
        .collect();
    assert_eq!(discarded.len(), 1, "{}", logs.text());
    assert_audit_record(&discarded[0], "WARN", &["files"]);
    let files: Vec<&str> = discarded[0]["files"].as_str().unwrap().split(',').collect();
    ["config.toml", "operational.age", "identity.age"]
        .iter()
        .for_each(|name| assert!(files.contains(name), "{name} not in {files:?}"));
    assert_response(&unlock(&service).await, &AdminResponse::Success);
    assert_no_secret_logged(&logs, &[exchanged.recovery_key()]);
}

/// Drives one init over `stream` up to its confirmation prompt, with the recovery key shown.
async fn to_confirmation(stream: &mut UnixStream) -> String {
    send(stream, &Frame::Request(AdminRequest::Init { host_unlock: false })).await;
    let mut answers = COMPLETE.iter();
    let mut recovery = None;
    loop {
        match read_frame(stream).await {
            Frame::Prompt(prompt) if prompt.label == PROMPTS[4].0 => return recovery.unwrap(),
            Frame::Prompt(_) => {
                let answer = answers.next().unwrap();
                send(stream, &Frame::OwnerInput(OwnerInput::new(Zeroizing::new(answer.to_vec())))).await;
            }
            Frame::Reveal(secret) => recovery = Some(String::from_utf8(secret.expose_secret().to_vec()).unwrap()),
            Frame::Notice(_) => {}
            other => panic!("unexpected frame {other:?}"),
        }
    }
}

async fn confirm(stream: &mut UnixStream) -> AdminResponse {
    send(stream, &Frame::OwnerInput(OwnerInput::new(Zeroizing::new(b"yes".to_vec())))).await;
    match read_frame(stream).await {
        Frame::Response(response) => response,
        other => panic!("unexpected frame {other:?}"),
    }
}

#[tokio::test]
async fn of_two_inits_confirmed_together_one_writes_and_the_other_is_busy() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let service = fixture.start();
    let (path, stop, task) = spawn_admin(&service);
    let (mut first, mut second) = (UnixStream::connect(&path).await.unwrap(), UnixStream::connect(&path).await.unwrap());
    let keys = [to_confirmation(&mut first).await, to_confirmation(&mut second).await];

    let (one, other) = tokio::join!(confirm(&mut first), confirm(&mut second));

    let busy = match (&one, &other) {
        (AdminResponse::Init { version: 1, .. }, busy) | (busy, AdminResponse::Init { version: 1, .. }) => busy,
        _ => panic!("expected one init: {one:?}, {other:?}"),
    };
    let AdminResponse::Error {
        code: ErrorCode::Busy,
        message,
    } = busy
    else {
        panic!("expected busy: {busy:?}");
    };
    assert!(message.ends_with("the recovery key shown opens nothing: discard it"), "{message}");
    let _ = stop.send(());
    task.await.unwrap();
    assert_response(&unlock(&service).await, &AdminResponse::Success);
    assert_no_secret_logged(&logs, &[&keys[0], &keys[1]]);
}

/// A second init that passed its first check confirms only after the first has finished: the re-check under the lock
/// finds Initialized, writes nothing, and says the key it showed is dead.
#[tokio::test]
async fn a_second_init_confirmed_after_the_first_finished_is_already_initialized() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let service = fixture.start();
    let (path, stop, task) = spawn_admin(&service);
    let (mut first, mut second) = (UnixStream::connect(&path).await.unwrap(), UnixStream::connect(&path).await.unwrap());
    let keys = [to_confirmation(&mut first).await, to_confirmation(&mut second).await];

    let AdminResponse::Init { vault_id, version: 1, .. } = confirm(&mut first).await else {
        panic!("the first init writes the vault");
    };
    let refused = confirm(&mut second).await;

    let AdminResponse::Error {
        code: ErrorCode::AlreadyInitialized,
        message,
    } = &refused
    else {
        panic!("expected already-initialized: {refused:?}");
    };
    assert!(message.contains("Initialized"), "{message}");
    assert!(message.ends_with("the recovery key shown opens nothing: discard it"), "{message}");
    let _ = stop.send(());
    task.await.unwrap();
    assert_response(&unlock(&service).await, &AdminResponse::Success);
    assert_eq!(unlocked(&service).await.id, vault_id);
    assert_no_secret_logged(&logs, &[&keys[0], &keys[1]]);
}

/// Waits until `done` holds, polling, for at most [`common::WAIT`].
async fn wait_until(done: impl Fn() -> bool) {
    tokio::time::timeout(common::WAIT, async {
        while !done() {
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("the condition holds in time");
}

fn sealing_keys() -> SealingKeys {
    NewVaultKeys::generate().unwrap().into_sealing()
}

fn init_passphrases() -> InitPassphrases {
    let vault = Passphrase::new(SecretString::from(VAULT_PASSPHRASE)).unwrap();
    let approval = ApprovalPassphrase::new(SecretString::from(APPROVAL_PASSPHRASE)).unwrap();
    InitPassphrases::new(vault, approval).unwrap()
}

/// Dropping the write step's future, as `abort_all` does at shutdown, leaves both locks with the blocking task that is
/// still writing: another init is `busy` until it ends, the task still logs `vault.initialized`, and the vault it writes
/// unlocks.
#[tokio::test]
async fn an_init_dropped_while_writing_keeps_its_locks_until_the_writes_end() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let service = fixture.start();
    let marker = fixture.path("state/init.unfinished");
    let writing = tokio::spawn({
        let service = Arc::clone(&service);
        async move { service.initialize(sealing_keys(), init_passphrases()).await.map(drop) }
    });
    wait_until(|| marker.exists()).await;
    writing.abort();
    assert!(writing.await.unwrap_err().is_cancelled());

    let second = service.initialize(sealing_keys(), init_passphrases()).await;
    assert!(matches!(second, Err(InitRefusal::Busy)), "{second:?}");
    wait_until(|| !marker.exists()).await;
    assert_response(&unlock(&service).await, &AdminResponse::Success);
    let initialized = unlocked(&service).await.id.to_string();
    assert!(logs.has_field("vault.initialized", "vault_id", &initialized), "{}", logs.text());
}

#[tokio::test]
async fn a_peer_that_is_not_an_admin_principal_is_refused_and_nothing_is_written() {
    let me = invoking_user().unwrap();
    if me.uid == 0 {
        // Root is an admin principal of every protected install, so there is no refusal to see.
        return;
    }
    let fixture = Fixture::new().await;
    let service = fixture.start();
    let socket = AdminSocket::bind(fixture.dir.path(), me).unwrap();
    let principals = AdminPrincipals::new(DeploymentProfile::Protected, me.uid + 1);
    let server = AdminServer::new(principals, Handlers::for_service(&service), Limits::default());
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let served = tokio::spawn(async move {
        server
            .serve(socket, async {
                let _ = stopped.await;
            })
            .await
    });

    // The refusal is written before the server reads anything, so no request is sent.
    let mut stream = UnixStream::connect(fixture.path("admin.sock")).await.unwrap();
    let exchanged = converse(&mut stream, &[]).await;

    assert_eq!(exchanged.error().0, ErrorCode::NotAdminPrincipal);
    let _ = stop.send(());
    served.await.unwrap().unwrap();
    fixture.assert_only_lock_files();
}

/// The names in the state directory that start `approver`, sorted, so a stray `approver.age` shows too.
fn approver_key_files(fixture: &Fixture) -> Vec<String> {
    let mut names: Vec<_> = fs::read_dir(fixture.path("state"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.starts_with("approver"))
        .collect();
    names.sort();
    names
}

/// The token caller's `GET /rates/latest` through the Unix listener.
async fn get_rates(fixture: &Fixture) -> Response {
    let request = CallerRequest::get("/rates/latest").signed(Via::Unix);
    let mut stream = UnixStream::connect(fixture.socket()).await.unwrap();
    stream.write_all(&request.to_bytes()).await.unwrap();
    let mut raw = Vec::new();
    tokio::time::timeout(common::WAIT, stream.read_to_end(&mut raw))
        .await
        .unwrap()
        .unwrap();
    Response::parse(&String::from_utf8(raw).unwrap())
}

/// The development MVP path: a fresh service is initialized, unlocked, given a credential and a route that uses it, and
/// a caller's request reaches the upstream with the secret injected.
#[tokio::test]
async fn init_unlock_add_and_approve_lead_to_a_request_carrying_the_secret() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let service = fixture.start();
    let initialized = init(&service, &COMPLETE).await;
    initialized.vault_id();
    assert_response(&unlock(&service).await, &AdminResponse::Success);

    let add = AdminRequest::Add {
        name: "fx".to_owned(),
        kind: CredentialKind::Static,
        origins: vec![RequestedOrigin {
            host: "localhost".to_owned(),
            port: fixture.upstream.port().to_string().parse().unwrap(),
        }],
    };
    let added = exchange(&service, add, &[SECRET.as_bytes()]).await;
    assert!(matches!(added.response, AdminResponse::Add { .. }), "{added:?}");
    let config = ProposedConfig::new(fixture.config().into_bytes()).unwrap();
    let approved = exchange(
        &service,
        AdminRequest::ConfigApprove(config),
        &[b"yes", APPROVAL_PASSPHRASE.as_bytes()],
    )
    .await;
    assert!(
        matches!(approved.response, AdminResponse::ConfigApprove(ref result) if result.version == 2),
        "{approved:?}"
    );
    let signature = ApprovalEnvelope::decode(&fs::read(fixture.path("etc/config.toml.sig")).unwrap()).unwrap();
    assert_eq!(
        approver_key_files(&fixture),
        [format!("approver-{}.age", signature.approver_id())],
        "init's approver signed version 2 from its own key file"
    );

    assert_eq!(get_rates(&fixture).await.status, 200);
    let injected = fixture.upstream.requests().last().unwrap().headers();
    assert!(
        injected
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("x-api-key") && value == SECRET),
        "{injected:?}"
    );
    assert_no_secret_logged(&logs, &[initialized.recovery_key()]);
}
