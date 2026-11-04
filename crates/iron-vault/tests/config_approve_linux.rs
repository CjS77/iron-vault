//! `config approve` end to end over a real admin socket against a running service context (specification §3.9, §3.2,
//! §3.13): the summary as notices, the confirmation, the approval passphrase, then the transaction, the admission pause
//! and the config check. Every test's log goes to one captured buffer, which must never hold an approval passphrase.
//!
//! Each test builds a vault holding `fx_key`, pins a software approver whose key is sealed in `approver.age` under
//! [`APPROVAL_PASSPHRASE`], and approves the base config through the store, then releases both locks so the service
//! takes them. The service account is the test's own uid.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use common::mock_upstream::{MockUpstream, Reply, TestCa};
use common::proxy_harness::{CallerRequest, Response, TOKEN_BYTES, TOKEN_HEADER, TempDir, Via, WAIT, token_hash};
use iron_vault::admin::ADMIN_SOCKET_NAME;
use iron_vault::admin::dispatch::Handlers;
use iron_vault::admin::principal::AdminPrincipals;
use iron_vault::admin::protocol::{
    self, AdminRequest, AdminResponse, ApprovalResult, Decoded, ErrorCode, Frame, OwnerInput, Prompt, ProposedConfig, StatusReport,
    VaultStatus,
};
use iron_vault::admin::server::{AdminServer, Limits};
use iron_vault::admin::socket::AdminSocket;
use iron_vault::config_check::UpstreamSettings;
use iron_vault::deployment::{Accounts, DeploymentProfile, PasswdDirectory};
use iron_vault::hardening::{CoreDumps, HardeningReport, MemoryProtection};
use iron_vault::path_metadata::invoking_user;
use iron_vault::service_context::{ServiceContext, ServiceLocks, ServiceSetup};
use iron_vault::service_state::UnavailableReason;
use iron_vault::service_state::{FailureReason, ServiceEvent, ServiceState};
use iron_vault::serving_snapshot::SnapshotHolder;
use iron_vault::trusted_path_report::ServicePaths;
use iron_vault::upstream::client::TransportLimits;
use iron_vault_kinds::CredentialMaterial;
use iron_vault_policy::Capabilities;
use iron_vault_store::{
    ApprovalPassphrase, ApprovalState, ApprovalStorage, ConfigDigest, ConfigDirLock, OsFs, PendingConfig, PermittedOrigins, SoftwareSigner,
    StateDirLock, Vault, VaultIdentity, open_signer_key, seal_signer_key_for_tests, write_signer_key,
};
use secrecy::SecretString;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::oneshot;
use tracing_subscriber::fmt::MakeWriter;
use zeroize::Zeroizing;

const IDENTITY: &str = "AGE-SECRET-KEY-1QYPQXPQ9QCRSSZG2PVXQ6RS0ZQG3YYC5Z5TPWXQERGD3C8G7RUSQGPQYEE";
/// The approval passphrase, and a wrong one; distinctive, so a search of the logs cannot match anything else.
const APPROVAL_PASSPHRASE: &str = "APPROVAL-correct-3e8b";
const WRONG_PASSPHRASE: &str = "APPROVAL-wrong-6f04";
const CONFIRM: &str = "Approve this config as version";

fn identity() -> VaultIdentity {
    VaultIdentity::from_secret(IDENTITY)
}

fn approval_passphrase(text: &str) -> ApprovalPassphrase {
    ApprovalPassphrase::new(SecretString::from(text)).unwrap()
}

fn mkdir(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

/// A vault holding `fx_key` with a software approver, in a temporary directory that is also the runtime directory, and
/// the base config approved as version 1. No lock is held between steps.
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
        let ca = TestCa::new("approve test CA");
        let reply = Reply::Respond {
            status: 200,
            headers: Vec::new(),
            body: b"ok".to_vec(),
        };
        let upstream = MockUpstream::start(&ca, reply).await;
        let fixture = Self { dir, ca, upstream };
        let mut state = fixture.create_vault();
        fixture.approve_through_store(&mut state, &fixture.config("fx"));
        fixture
    }

    /// The vault, `approver.age` and the approval state pinning its key.
    fn create_vault(&self) -> ApprovalState {
        let lock = StateDirLock::acquire(&self.path("state")).unwrap();
        let mut vault = Vault::create(&lock, &OsFs, identity()).unwrap();
        let port = self.upstream.port().to_string().parse().unwrap();
        let origins = PermittedOrigins::new([("localhost".parse().unwrap(), port)].into()).unwrap();
        let material = CredentialMaterial::Static { key: "fx-secret".into() };
        vault.add(&lock, &OsFs, "fx_key".parse().unwrap(), material, origins).unwrap();
        let (key, pinned) = SoftwareSigner::generate().unwrap();
        let sealed = seal_signer_key_for_tests(&key, &approval_passphrase(APPROVAL_PASSPHRASE)).unwrap();
        write_signer_key(&lock, &OsFs, &sealed).unwrap();
        vault.create_approval_state(&lock, &OsFs, pinned).unwrap().0
    }

    /// Approves and publishes `config` through the store's transaction, as `config approve` would.
    fn approve_through_store(&self, state: &mut ApprovalState, config: &str) {
        let state_dir = StateDirLock::acquire(&self.path("state")).unwrap();
        let config_dir = ConfigDirLock::acquire(&self.path("etc")).unwrap();
        let identity = identity();
        let storage = ApprovalStorage {
            state_dir: &state_dir,
            config_dir: &config_dir,
            identity: &identity,
            fs: &OsFs,
        };
        let envelope = iron_vault_store::read_signer_key(&state_dir, &OsFs).unwrap();
        let signer = open_signer_key(&envelope, &approval_passphrase(APPROVAL_PASSPHRASE), state.approver()).unwrap();
        let holder = SnapshotHolder::refusing(UnavailableReason::Checking);
        let pending = PendingConfig::write(&storage, config.as_bytes().to_vec()).unwrap();
        let prepared = pending.prepare(&storage, state, signer).unwrap();
        prepared.commit(&storage, &holder.pause()).unwrap();
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn socket(&self) -> PathBuf {
        self.path("proxy.sock")
    }

    /// The config with the Unix listener `local`, its token caller granted the route `route` on `fx_key`.
    fn config(&self, route: &str) -> String {
        self.config_with(route, "fx_key")
    }

    fn config_with(&self, route: &str, credential: &str) -> String {
        format!(
            r#"schema_version = 1

[listeners.local]
unix_socket = "{socket}"
token_header = "{TOKEN_HEADER}"

[callers.agent]
listener = "local"
token_hash = "{hash}"
routes = ["{route}"]

[routes.{route}]
prefix = "/{route}"
upstream = "https://localhost:{port}/v1"
ca_file = "/etc/iron-vault/ca/test.pem"
credential = "{credential}"
slot = {{ header = "X-Api-Key" }}
methods = ["GET"]
paths = ["/v1/**"]
rate_limit = {{ requests = 100000, per_seconds = 1, burst = 100000 }}
"#,
            socket = self.socket().display(),
            hash = token_hash(TOKEN_BYTES),
            port = self.upstream.port(),
        )
    }

    /// Starts the service on this fixture's directories and enters Checking with the vault identity.
    async fn start(&self) -> Arc<ServiceContext> {
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
        };
        let service = Arc::new(ServiceContext::start(locks, setup, &provisional, BTreeMap::new()).unwrap());
        service.enter_checking(identity()).await.unwrap();
        service
    }

    /// [`start`](Self::start), checked to have reached Ready.
    async fn ready(&self) -> Arc<ServiceContext> {
        let service = self.start().await;
        assert_eq!(service.state().await, ServiceState::Ready);
        service
    }
}

/// The token caller's `GET /<route>/latest`.
async fn get(fixture: &Fixture, route: &str) -> Response {
    let request = CallerRequest::get(&format!("/{route}/latest")).signed(Via::Unix);
    let mut stream = UnixStream::connect(fixture.socket()).await.unwrap();
    stream.write_all(&request.to_bytes()).await.unwrap();
    let mut raw = Vec::new();
    tokio::time::timeout(WAIT, stream.read_to_end(&mut raw)).await.unwrap().unwrap();
    Response::parse(&String::from_utf8(raw).unwrap())
}

/// What one exchange showed the owner and how it ended.
#[derive(Debug)]
struct Exchanged {
    notices: String,
    prompts: Vec<Prompt>,
    response: AdminResponse,
}

/// The admin server with the service's handlers on its runtime directory, until `stop` is sent.
fn serve_admin(service: &Arc<ServiceContext>) -> (PathBuf, oneshot::Sender<()>) {
    let paths = service.paths().clone();
    let runtime_dir = paths.runtime_dir.clone().unwrap();
    let socket = AdminSocket::bind(&runtime_dir, paths.owner).unwrap();
    let server = AdminServer::new(
        AdminPrincipals::new(paths.profile, paths.owner.uid),
        Handlers::for_service(service),
        Limits::default(),
    );
    let (stop, stopped) = oneshot::channel::<()>();
    tokio::spawn(async move {
        server
            .serve(socket, async {
                let _ = stopped.await;
            })
            .await
    });
    (runtime_dir.join(ADMIN_SOCKET_NAME), stop)
}

fn approve_request(config: &str) -> Frame {
    Frame::Request(AdminRequest::ConfigApprove(
        ProposedConfig::new(config.as_bytes().to_vec()).unwrap(),
    ))
}

/// Sends `config approve` for `config` and answers the prompts in turn with `answers`.
async fn approve(service: &Arc<ServiceContext>, config: &str, answers: &[&str]) -> Exchanged {
    let (path, stop) = serve_admin(service);
    let mut stream = UnixStream::connect(path).await.unwrap();
    send(&mut stream, &approve_request(config)).await;
    let exchanged = converse(&mut stream, answers).await;
    let _ = stop.send(());
    exchanged
}

/// Reads frames until the response, answering each prompt with the next of `answers`.
async fn converse(stream: &mut UnixStream, answers: &[&str]) -> Exchanged {
    let (mut notices, mut prompts) = (String::new(), Vec::new());
    let mut answers = answers.iter();
    loop {
        match read_frame(stream).await {
            Frame::Response(response) => {
                return Exchanged {
                    notices,
                    prompts,
                    response,
                };
            }
            Frame::Notice(notice) => notices.push_str(&notice.text),
            Frame::Prompt(prompt) => {
                prompts.push(prompt);
                let answer = answers.next().expect("a prompt beyond the answers given");
                send(
                    stream,
                    &Frame::OwnerInput(OwnerInput::new(Zeroizing::new(answer.as_bytes().to_vec()))),
                )
                .await;
            }
            other => panic!("unexpected frame {other:?}"),
        }
    }
}

async fn send(stream: &mut UnixStream, frame: &Frame) {
    let mut bytes = Vec::new();
    protocol::encode(frame, &mut bytes).unwrap();
    stream.write_all(&bytes).await.unwrap();
}

/// Reads one frame a byte at a time, so nothing of the next frame is consumed.
async fn read_frame(stream: &mut UnixStream) -> Frame {
    let mut bytes = Vec::new();
    loop {
        if let Decoded::Frame { frame, .. } = protocol::decode(&bytes).unwrap() {
            return frame;
        }
        let mut chunk = [0; 1];
        let read = tokio::time::timeout(WAIT, stream.read(&mut chunk)).await.unwrap().unwrap();
        assert_eq!(read, 1, "the service closed mid-frame");
        bytes.extend_from_slice(&chunk);
    }
}

/// The committed and highest reserved versions `status` reports.
async fn versions(service: &Arc<ServiceContext>) -> (Option<u64>, u64) {
    match service.status().await {
        StatusReport {
            vault: VaultStatus::Unlocked(vault),
            ..
        } => (vault.committed, vault.highest_reserved),
        other => panic!("no open vault: {other:?}"),
    }
}

fn error_code(response: &AdminResponse) -> ErrorCode {
    match response {
        AdminResponse::Error { code, .. } => *code,
        other => panic!("expected an error, got {other:?}"),
    }
}

fn the_two_prompts(version: u64) -> Vec<Prompt> {
    vec![
        Prompt {
            label: format!("{CONFIRM} {version}? Type yes to approve"),
            secret: false,
        },
        Prompt {
            label: "Approval passphrase".to_owned(),
            secret: true,
        },
    ]
}

/// Everything this test binary logs, from a global subscriber installed on first use.
fn captured_logs() -> Captured {
    static CAPTURED: OnceLock<Captured> = OnceLock::new();
    CAPTURED
        .get_or_init(|| {
            let captured = Captured::default();
            let subscriber = tracing_subscriber::fmt().with_writer(captured.clone()).with_ansi(false).finish();
            tracing::subscriber::set_global_default(subscriber).unwrap();
            captured
        })
        .clone()
}

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Captured {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap_or_else(PoisonError::into_inner)).into_owned()
    }

    fn assert_no_passphrase(&self) {
        let text = self.text();
        [APPROVAL_PASSPHRASE, WRONG_PASSPHRASE]
            .iter()
            .for_each(|passphrase| assert!(!text.contains(passphrase), "a passphrase reached the log:\n{text}"));
    }
}

impl io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Captured {
    type Writer = Captured;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[tokio::test]
async fn a_valid_change_is_active_when_the_response_arrives_and_the_old_pair_no_longer_verifies() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    let old_pair = ["config.toml", "config.toml.sig"].map(|file| fs::read(fixture.path(&format!("etc/{file}"))).unwrap());
    let proposed = fixture.config("rates");

    let exchanged = approve(&service, &proposed, &["yes", APPROVAL_PASSPHRASE]).await;

    let digest = *ConfigDigest::of(proposed.as_bytes()).as_bytes();
    match &exchanged.response {
        AdminResponse::ConfigApprove(ApprovalResult {
            version: 2,
            digest: got,
            headline,
        }) => {
            assert_eq!(*got, digest);
            assert!(headline.contains("routes: 1 added, 1 removed"), "{headline}");
        }
        other => panic!("expected an approval, got {other:?}"),
    }
    assert_eq!(exchanged.prompts, the_two_prompts(2));
    assert!(exchanged.notices.contains("version to commit: 2\n"), "{}", exchanged.notices);
    assert!(exchanged.notices.contains("committed version: 1\n"), "{}", exchanged.notices);
    assert!(exchanged.notices.contains("+ rates"), "{}", exchanged.notices);
    assert_eq!(service.state().await, ServiceState::Ready);
    assert_eq!(get(&fixture, "rates").await.status, 200);
    assert_eq!(get(&fixture, "fx").await.status, 404);
    assert_eq!(fs::read(fixture.path("etc/config.toml")).unwrap(), proposed.as_bytes());
    assert_eq!(versions(&service).await, (Some(2), 2));

    // Putting the version 1 pair back is a rollback, which the config check refuses.
    ["config.toml", "config.toml.sig"]
        .iter()
        .zip(&old_pair)
        .for_each(|(file, bytes)| fs::write(fixture.path(&format!("etc/{file}")), bytes).unwrap());
    let reloaded = service.recheck(ServiceEvent::Reload).await;
    assert_eq!(reloaded, Ok(ServiceState::Unavailable(FailureReason::PolicyInvalid)));
    logs.assert_no_passphrase();
}

#[tokio::test]
async fn declining_the_summary_consumes_no_version_and_keeps_the_active_pair() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    let active = fs::read(fixture.path("etc/config.toml")).unwrap();

    let exchanged = approve(&service, &fixture.config("rates"), &["no"]).await;

    assert_eq!(error_code(&exchanged.response), ErrorCode::Declined);
    assert_eq!(exchanged.prompts.len(), 1, "no passphrase is asked for after a decline");
    assert_eq!(versions(&service).await, (Some(1), 1));
    assert_eq!(fs::read(fixture.path("etc/config.toml")).unwrap(), active);
    assert!(!fixture.path("etc/config.toml.pending").exists());
    assert_eq!(get(&fixture, "fx").await.status, 200);
}

#[tokio::test]
async fn a_wrong_approval_passphrase_consumes_no_version() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;

    let exchanged = approve(&service, &fixture.config("rates"), &["yes", WRONG_PASSPHRASE]).await;

    assert_eq!(error_code(&exchanged.response), ErrorCode::ApprovalDenied);
    assert_eq!(exchanged.prompts, the_two_prompts(2));
    assert_eq!(versions(&service).await, (Some(1), 1));
    assert!(!fixture.path("etc/config.toml.pending").exists());
    assert_eq!(get(&fixture, "fx").await.status, 200);
    logs.assert_no_passphrase();
}

#[tokio::test]
async fn a_failure_after_the_reservation_consumes_the_version_and_the_next_approval_gets_a_higher_one() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    // A leftover temp file makes the durable write of the staged approval (step 4) refuse.
    let blocker = fixture.path("etc/.config.toml.sig.staged.tmp");
    fs::write(&blocker, b"").unwrap();

    let failed = approve(&service, &fixture.config("rates"), &["yes", APPROVAL_PASSPHRASE]).await;

    assert_eq!(error_code(&failed.response), ErrorCode::ApprovalFailed);
    assert_eq!(versions(&service).await, (Some(1), 2));
    assert_eq!(service.state().await, ServiceState::Ready);
    assert_eq!(get(&fixture, "fx").await.status, 200);

    fs::remove_file(blocker).unwrap();
    let approved = approve(&service, &fixture.config("rates"), &["yes", APPROVAL_PASSPHRASE]).await;

    assert_eq!(approved.prompts, the_two_prompts(3));
    assert!(matches!(
        approved.response,
        AdminResponse::ConfigApprove(ApprovalResult { version: 3, .. })
    ));
    assert_eq!(versions(&service).await, (Some(3), 3));
}

#[tokio::test]
async fn a_second_approval_while_one_waits_at_its_prompt_is_busy() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    let (path, stop) = serve_admin(&service);
    let mut first = UnixStream::connect(&path).await.unwrap();
    send(&mut first, &approve_request(&fixture.config("rates"))).await;
    while !matches!(read_frame(&mut first).await, Frame::Prompt(_)) {}

    let second = approve(&service, &fixture.config("other"), &[]).await;

    assert_eq!(error_code(&second.response), ErrorCode::Busy);
    assert!(second.prompts.is_empty() && second.notices.is_empty());
    send(&mut first, &Frame::OwnerInput(OwnerInput::new(Zeroizing::new(b"no".to_vec())))).await;
    assert_eq!(error_code(&converse(&mut first, &[]).await.response), ErrorCode::Declined);
    let _ = stop.send(());
}

#[tokio::test]
async fn an_unknown_credential_is_refused_before_any_prompt() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;

    let exchanged = approve(&service, &fixture.config_with("rates", "nope_key"), &[]).await;

    match &exchanged.response {
        AdminResponse::Error {
            code: ErrorCode::ConfigInvalid,
            message,
        } => assert!(message.contains("nope_key"), "{message}"),
        other => panic!("expected config-invalid, got {other:?}"),
    }
    assert!(exchanged.prompts.is_empty() && exchanged.notices.is_empty());
    assert_eq!(versions(&service).await, (Some(1), 1));
    assert!(!fixture.path("etc/config.toml.pending").exists());
}

#[tokio::test]
async fn an_approval_out_of_an_invalid_policy_makes_the_service_ready() {
    let fixture = Fixture::new().await;
    fs::write(fixture.path("etc/config.toml"), fixture.config("edited")).unwrap();
    let service = fixture.start().await;
    assert_eq!(service.state().await, ServiceState::Unavailable(FailureReason::PolicyInvalid));

    let exchanged = approve(&service, &fixture.config("rates"), &["yes", APPROVAL_PASSPHRASE]).await;

    assert!(matches!(
        exchanged.response,
        AdminResponse::ConfigApprove(ApprovalResult { version: 2, .. })
    ));
    assert!(exchanged.notices.contains("no active config"), "{}", exchanged.notices);
    assert_eq!(service.state().await, ServiceState::Ready);
    assert_eq!(get(&fixture, "rates").await.status, 200);
}

#[tokio::test]
async fn a_locked_service_cannot_approve() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    service.lock(WAIT).await.unwrap();

    let exchanged = approve(&service, &fixture.config("rates"), &[]).await;

    assert_eq!(error_code(&exchanged.response), ErrorCode::ApprovalUnavailable);
    assert!(exchanged.prompts.is_empty());
    assert!(!fixture.path("etc/config.toml.pending").exists());
}
