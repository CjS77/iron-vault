//! The service context end to end: startup Locked with provisional listeners from the unverified config, entering
//! Checking with a known vault identity (no prompt), the listener rebuild on entry to Ready, and stop (specification
//! §3.1, §3.4, §3.9, §3.11, §3.12).
//!
//! `unlock` runs over the admin protocol against the same fixture, with the passphrase envelope in place, and every
//! test's log goes to one captured buffer, which must never hold a passphrase.
//!
//! Each test builds a vault and an approval state in a temporary state directory and approves a config through the
//! approval transaction, then releases both locks so the service takes them. The service account is the test's own uid.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, mpsc};
use std::time::{Duration, Instant};

use common::mock_upstream::{MockUpstream, Reply, TestCa};
use common::proxy_harness::{CallerRequest, Response, TOKEN_BYTES, TOKEN_HEADER, TempDir, Via, WAIT, next_free_port, token_hash};
use ed25519_dalek::{Signer, SigningKey};
use iron_vault::admin::ADMIN_SOCKET_NAME;
use iron_vault::admin::dispatch::Handlers;
use iron_vault::admin::principal::AdminPrincipals;
use iron_vault::admin::protocol::{
    self, AdminRequest, AdminResponse, Decoded, ErrorCode, Frame, MemoryStatus, OwnerInput, Prompt, StatusReport, VaultStatus,
};
use iron_vault::admin::server::{AdminServer, Limits};
use iron_vault::admin::socket::AdminSocket;
use iron_vault::config_check::UpstreamSettings;
use iron_vault::deployment::{Accounts, DeploymentProfile, PasswdDirectory};
use iron_vault::hardening::{CoreDumps, HardeningReport, MemoryProtection};
use iron_vault::path_metadata::invoking_user;
use iron_vault::service_context::{LockOutcome, ServiceContext, ServiceLocks, ServiceSetup, StartError};
use iron_vault::service_state::{FailureReason, IllegalTransition, ListenerProvenance, ServiceEvent, ServiceState, UnavailableReason};
use iron_vault::serving_snapshot::{Admission, SnapshotHolder};
use iron_vault::standing::{CredentialStanding, Standing};
use iron_vault::trusted_path_report::ServicePaths;
use iron_vault::upstream::client::TransportLimits;
use iron_vault_kinds::CredentialMaterial;
use iron_vault_policy::{Capabilities, ListenerName};
use iron_vault_store::{
    ApprovalEnvelope, ApprovalPayload, ApprovalSigner, ApprovalState, ApprovalStorage, ConfigDirLock, LockError, OperationalIdentity, OsFs,
    Passphrase, PendingConfig, PermittedOrigins, PinnedApprover, RecipientSet, RecordDamage, SignError, SignatureAlgorithm, StateDirLock,
    StoreFs, Vault, VaultIdentity, seal_passphrase_envelope_for_tests, wrap_identity, write_identity_envelope, write_passphrase_envelope,
};
use secrecy::SecretString;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};
use tokio::sync::oneshot;
use tracing_subscriber::fmt::MakeWriter;
use zeroize::Zeroizing;

const IDENTITY: &str = "AGE-SECRET-KEY-1QYPQXPQ9QCRSSZG2PVXQ6RS0ZQG3YYC5Z5TPWXQERGD3C8G7RUSQGPQYEE";
const SECRET: &str = "fx-secret-4b1d";
/// The vault passphrase, and a wrong one; distinctive, so a search of the logs cannot match anything else.
const PASSPHRASE: &str = "PASSPHRASE-correct-7c2e";
const WRONG_PASSPHRASE: &str = "PASSPHRASE-wrong-91af";

fn identity() -> VaultIdentity {
    VaultIdentity::from_secret(IDENTITY)
}

/// An Ed25519 signer with a fixed key.
struct TestSigner(SigningKey);

impl ApprovalSigner for TestSigner {
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Ed25519
    }

    fn pinned(&self) -> PinnedApprover {
        PinnedApprover::new(SignatureAlgorithm::Ed25519, self.0.verifying_key().to_bytes().to_vec()).unwrap()
    }

    fn sign(&self, payload: &ApprovalPayload) -> Result<ApprovalEnvelope, SignError> {
        let signature = self.0.sign(&payload.encode()).to_bytes().to_vec();
        ApprovalEnvelope::new(SignatureAlgorithm::Ed25519, *payload, signature).map_err(SignError::Signature)
    }
}

fn signer() -> TestSigner {
    TestSigner(SigningKey::from_bytes(&[7; 32]))
}

fn record_files(state_dir: &Path) -> Vec<PathBuf> {
    let mut files = fs::read_dir(state_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.file_name().unwrap().to_string_lossy().starts_with("record-"))
        .collect::<Vec<_>>();
    files.sort();
    files
}

fn mkdir(path: &Path, mode: u32) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

/// A vault holding `fx_key`, which may reach the test upstream, with an approval state pinning the test signer, in a
/// temporary directory that is also the runtime directory. No lock is held between steps.
struct Fixture {
    dir: TempDir,
    ca: TestCa,
    upstream: MockUpstream,
    state: ApprovalState,
    /// The record file of `brave_key`, a second credential that no caller is granted, to damage in a test.
    brave_record: PathBuf,
}

impl Fixture {
    async fn new() -> Self {
        let reply = Reply::Respond {
            status: 200,
            headers: Vec::new(),
            body: b"ok".to_vec(),
        };
        Self::with_reply(reply).await
    }

    /// A fixture whose upstream answers every request with `reply`.
    async fn with_reply(reply: Reply) -> Self {
        let dir = TempDir::new();
        mkdir(&dir.path().join("state"), 0o700);
        mkdir(&dir.path().join("etc"), 0o700);
        let ca = TestCa::new("service test CA");
        let upstream = MockUpstream::start(&ca, reply).await;
        let lock = StateDirLock::acquire(&dir.path().join("state")).unwrap();
        let mut vault = Vault::create(&lock, &OsFs, identity()).unwrap();
        let port = upstream.port().to_string().parse().unwrap();
        let origins = PermittedOrigins::new([("localhost".parse().unwrap(), port)].into()).unwrap();
        let material = || CredentialMaterial::Static { key: SECRET.into() };
        vault
            .add(&lock, &OsFs, "fx_key".parse().unwrap(), material(), origins.clone())
            .unwrap();
        let before = record_files(&dir.path().join("state"));
        vault.add(&lock, &OsFs, "brave_key".parse().unwrap(), material(), origins).unwrap();
        let brave_record = record_files(&dir.path().join("state"))
            .into_iter()
            .find(|file| !before.contains(file))
            .unwrap();
        let (state, _) = vault.create_approval_state(&lock, &OsFs, signer().pinned()).unwrap();
        write_unlock_envelopes(&lock);
        Self {
            dir,
            ca,
            upstream,
            state,
            brave_record,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn socket(&self) -> PathBuf {
        self.path("proxy.sock")
    }

    fn paths(&self) -> ServicePaths {
        ServicePaths {
            profile: DeploymentProfile::Development,
            owner: invoking_user().unwrap(),
            config: self.path("etc/config.toml"),
            state_dir: self.path("state"),
            runtime_dir: Some(self.dir.path().to_path_buf()),
        }
    }

    /// The config with the Unix listener `local`, its token caller granted `fx`, and `extra` appended (more listeners
    /// and callers).
    fn config(&self, extra: &str) -> String {
        format!(
            r#"schema_version = 1

[listeners.local]
unix_socket = "{socket}"
token_header = "{TOKEN_HEADER}"

[callers.agent]
listener = "local"
token_hash = "{hash}"
routes = ["fx"]

[routes.fx]
prefix = "/fx"
upstream = "https://localhost:{port}/v1"
ca_file = "/etc/iron-vault/ca/test.pem"
credential = "fx_key"
slot = {{ header = "X-Api-Key" }}
methods = ["GET"]
paths = ["/v1/**"]
rate_limit = {{ requests = 100000, per_seconds = 1, burst = 100000 }}
{extra}"#,
            socket = self.socket().display(),
            hash = token_hash(TOKEN_BYTES),
            port = self.upstream.port(),
        )
    }

    /// Approves and publishes `config` through the approval transaction.
    fn approve(&mut self, config: &str) {
        let state_dir = StateDirLock::acquire(&self.path("state")).unwrap();
        let config_dir = ConfigDirLock::acquire(&self.path("etc")).unwrap();
        let identity = identity();
        let storage = ApprovalStorage {
            state_dir: &state_dir,
            config_dir: &config_dir,
            identity: &identity,
            fs: &OsFs,
        };
        let holder = SnapshotHolder::refusing(UnavailableReason::Checking);
        let pending = PendingConfig::write(&storage, config.as_bytes().to_vec()).unwrap();
        let prepared = pending.prepare(&storage, &mut self.state, signer()).unwrap();
        prepared.commit(&storage, &holder.pause()).unwrap();
    }

    /// Replaces the published `config.toml` with `swapped`, keeping the approved bytes as `config.toml.pending`, where
    /// the config check's recovery finds them and publishes them again (a half-published approval, recovery row 3).
    fn swap_config(&self, swapped: &str) {
        fs::rename(self.path("etc/config.toml"), self.path("etc/config.toml.pending")).unwrap();
        fs::write(self.path("etc/config.toml"), swapped).unwrap();
    }

    /// Starts the service on this fixture's directories, as `serve` does, without systemd sockets.
    fn start(&self) -> Result<Arc<ServiceContext>, StartError> {
        self.start_on(OsFs)
    }

    /// [`start`](Self::start) with the vault and config files read through `fs`.
    fn start_on<F: StoreFs + Send + Sync + 'static>(&self, fs: F) -> Result<Arc<ServiceContext<F>>, StartError> {
        let paths = self.paths();
        let locks = ServiceLocks::acquire(&paths)?;
        locks.sweep_stale_temps(&OsFs);
        let provisional = locks.unverified_listeners(&OsFs);
        let setup = ServiceSetup {
            accounts: PasswdDirectory::new(Accounts::parse(""), &paths, Path::new("/nonexistent")).unwrap(),
            paths,
            fs,
            capabilities: Capabilities::default(),
            upstream: UpstreamSettings::new(DeploymentProfile::Development, invoking_user().unwrap(), TransportLimits::default())
                .with_pinned_trust(self.ca.trust()),
            hardening: HardeningReport {
                core_dumps: CoreDumps::Disabled,
                memory: MemoryProtection::Unsupported,
            },
        };
        Ok(Arc::new(
            ServiceContext::start(locks, setup, &provisional, BTreeMap::new()).unwrap(),
        ))
    }
}

/// `identity.age` for the operational identity and a second recipient, and `operational.age` sealing the operational
/// identity to [`PASSPHRASE`], as initialization will write them.
fn write_unlock_envelopes(lock: &StateDirLock) {
    let (operational, operational_key) = OperationalIdentity::generate();
    let recipients = RecipientSet::new([operational_key, OperationalIdentity::generate().1]).unwrap();
    write_identity_envelope(lock, &OsFs, &wrap_identity(&identity(), &recipients).unwrap()).unwrap();
    let passphrase = Passphrase::new(SecretString::from(PASSPHRASE)).unwrap();
    write_passphrase_envelope(lock, &OsFs, &seal_passphrase_envelope_for_tests(&operational, &passphrase).unwrap()).unwrap();
}

fn listener(name: &str) -> ListenerName {
    ListenerName::try_from(name).unwrap()
}

/// A TCP listener on loopback, with its token caller granted `fx`; the caller sends its token in `Proxy-Authorization`.
fn tcp_listener(name: &str, port: u16) -> String {
    format!(
        r#"
[listeners.{name}]
address = "127.0.0.1:{port}"

[callers.{name}-caller]
listener = "{name}"
token_hash = "{hash}"
routes = ["fx"]
"#,
        hash = token_hash(TOKEN_BYTES),
    )
}

async fn exchange(mut stream: impl AsyncReadExt + AsyncWriteExt + Unpin, request: &CallerRequest) -> Response {
    stream.write_all(&request.to_bytes()).await.unwrap();
    let mut raw = Vec::new();
    tokio::time::timeout(WAIT, stream.read_to_end(&mut raw)).await.unwrap().unwrap();
    Response::parse(&String::from_utf8(raw).unwrap())
}

/// The token caller's `GET /fx/latest` on the Unix listener, signed or not.
async fn get_unix(socket: &Path, signed: bool) -> Response {
    let request = CallerRequest::get("/fx/latest");
    let request = if signed { request.signed(Via::Unix) } else { request };
    exchange(UnixStream::connect(socket).await.unwrap(), &request).await
}

/// The TCP caller's signed `GET /fx/latest` on `127.0.0.1:port`.
async fn get_tcp(port: u16) -> Response {
    exchange(
        TcpStream::connect(("127.0.0.1", port)).await.unwrap(),
        &CallerRequest::get("/fx/latest").signed(Via::Tcp),
    )
    .await
}

/// The upstream's `ok`, relayed with chunked framing.
fn assert_served(response: &Response) {
    assert_eq!((response.status, response.body.as_str()), (200, "2\r\nok\r\n0\r\n\r\n"));
}

fn assert_refused(response: &Response, reason: UnavailableReason) {
    assert_eq!((response.status, response.body.as_str()), (503, reason.as_str()));
}

/// `ping`, which never prompts.
async fn ping(service: &Arc<ServiceContext>) -> AdminResponse {
    admin(service, AdminRequest::Ping, "").await.2
}

/// Sends `status` over the admin protocol and returns the response frame's bytes with the decoded report.
async fn status(service: &Arc<ServiceContext>) -> (Vec<u8>, StatusReport) {
    match admin(service, AdminRequest::Status, "").await {
        (bytes, _, AdminResponse::Status(report)) => (bytes, *report),
        (_, _, other) => panic!("expected a status report, got {other:?}"),
    }
}

/// Serves `service`'s admin handlers on its runtime directory and sends `request` over the admin protocol, answering
/// each prompt with `answer`. Returns the response frame's bytes, the prompts and the response.
async fn admin(service: &Arc<ServiceContext>, request: AdminRequest, answer: &str) -> (Vec<u8>, Vec<Prompt>, AdminResponse) {
    admin_with(service, Handlers::for_service(service), request, answer).await
}

/// [`admin`] with `handlers` in place of the service's own. It does not run the CLI binary: a child forked while another
/// test holds a directory lock would hold that lock too until it execs.
async fn admin_with(
    service: &Arc<ServiceContext>,
    handlers: Handlers,
    request: AdminRequest,
    answer: &str,
) -> (Vec<u8>, Vec<Prompt>, AdminResponse) {
    let paths = service.paths().clone();
    let runtime_dir = paths.runtime_dir.clone().unwrap();
    let socket = AdminSocket::bind(&runtime_dir, paths.owner).unwrap();
    let server = AdminServer::new(AdminPrincipals::new(paths.profile, paths.owner.uid), handlers, Limits::default());
    let (stop, stopped) = oneshot::channel::<()>();
    let served = tokio::spawn(async move {
        server
            .serve(socket, async {
                let _ = stopped.await;
            })
            .await
    });
    let exchanged = converse(&runtime_dir.join(ADMIN_SOCKET_NAME), request, answer.to_owned()).await;
    let _ = stop.send(());
    served.await.unwrap().unwrap();
    exchanged
}

/// Sends `request` on a new connection to the admin socket at `socket`, answering each prompt with `answer`. Returns
/// the response frame's bytes, the prompts and the response.
async fn converse(socket: &Path, request: AdminRequest, answer: String) -> (Vec<u8>, Vec<Prompt>, AdminResponse) {
    let mut stream = UnixStream::connect(socket).await.unwrap();
    send(&mut stream, &Frame::Request(request)).await;
    let mut prompts = Vec::new();
    let (bytes, response) = loop {
        match read_frame(&mut stream).await {
            (bytes, Frame::Response(response)) => break (bytes, response),
            (_, Frame::Prompt(prompt)) => {
                prompts.push(prompt);
                let input = OwnerInput::new(Zeroizing::new(answer.as_bytes().to_vec()));
                send(&mut stream, &Frame::OwnerInput(input)).await;
            }
            (_, other) => panic!("unexpected frame {other:?}"),
        }
    };
    (bytes, prompts, response)
}

async fn send(stream: &mut UnixStream, frame: &Frame) {
    let mut bytes = Vec::new();
    protocol::encode(frame, &mut bytes).unwrap();
    stream.write_all(&bytes).await.unwrap();
}

/// Reads one frame a byte at a time, so nothing of the next frame is consumed; returns its bytes with the frame.
async fn read_frame(stream: &mut UnixStream) -> (Vec<u8>, Frame) {
    let mut bytes = Vec::new();
    loop {
        if let Decoded::Frame { frame, .. } = protocol::decode(&bytes).unwrap() {
            return (bytes, frame);
        }
        let mut chunk = [0; 1];
        let read = tokio::time::timeout(WAIT, stream.read(&mut chunk)).await.unwrap().unwrap();
        assert_eq!(read, 1, "the service closed mid-frame");
        bytes.extend_from_slice(&chunk);
    }
}
/// `unlock`, answering its prompt with `passphrase`; the service must send exactly the secret passphrase prompt.
async fn unlock(service: &Arc<ServiceContext>, passphrase: &str) -> AdminResponse {
    let (_, prompts, response) = admin(service, AdminRequest::Unlock, passphrase).await;
    let expected = Prompt {
        label: "Vault passphrase".to_owned(),
        secret: true,
    };
    assert_eq!(prompts, [expected]);
    response
}

/// Everything this test binary logs, from a global subscriber installed on first use.
///
/// Global, not per thread: tracing caches each callsite's interest process-wide, so a thread-local subscriber can miss
/// an event whose callsite another test's thread registered first with no subscriber.
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

/// A log writer that keeps everything written to it.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Captured {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap_or_else(PoisonError::into_inner)).into_owned()
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

fn assert_no_passphrase_logged(logs: &Captured) {
    let text = logs.text();
    [PASSPHRASE, WRONG_PASSPHRASE]
        .iter()
        .for_each(|passphrase| assert!(!text.contains(passphrase), "a passphrase reached the log:\n{text}"));
}

fn error_response(code: ErrorCode, message: &str) -> AdminResponse {
    AdminResponse::Error {
        code,
        message: message.to_owned(),
    }
}

/// What `ping` answers: the service's profile, unchanged by the context.
const PONG: AdminResponse = AdminResponse::Ping {
    profile: DeploymentProfile::Development,
};

/// A fixture with the base config approved and published.
async fn approved() -> Fixture {
    let mut fixture = Fixture::new().await;
    fixture.approve(&fixture.config(""));
    fixture
}

#[tokio::test]
async fn startup_without_an_unlock_is_locked_and_answers_503_before_reaching_the_upstream() {
    let fixture = approved().await;
    let service = fixture.start().unwrap();

    assert_eq!(service.state().await, ServiceState::Locked);
    assert_eq!(service.state().await.listener_provenance(), Some(ListenerProvenance::Provisional));
    assert_refused(&get_unix(&fixture.socket(), false).await, UnavailableReason::Locked);
    assert!(fixture.upstream.requests().is_empty());
    assert_eq!(ping(&service).await, PONG);
}

#[tokio::test]
async fn a_valid_token_on_a_granted_route_still_gets_503_while_not_ready() {
    let fixture = approved().await;
    let _service = fixture.start().unwrap();

    assert_refused(&get_unix(&fixture.socket(), true).await, UnavailableReason::Locked);
    // Nothing reached the upstream, so no credential was resolved or sent.
    assert_eq!(fixture.upstream.connections(), 0);
}

#[tokio::test]
async fn a_valid_vault_unlocks_to_ready_and_its_route_reaches_the_upstream() {
    let fixture = approved().await;
    let service = fixture.start().unwrap();

    assert_eq!(service.enter_checking(identity()).await, Ok(ServiceState::Ready));

    assert_eq!(service.state().await.listener_provenance(), Some(ListenerProvenance::Approved));
    let response = get_unix(&fixture.socket(), true).await;
    assert_served(&response);
    let requests = fixture.upstream.requests();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].request_line().starts_with("GET /v1/latest "), "{}", requests[0].head);
    assert!(requests[0].headers().contains(&("x-api-key".to_owned(), SECRET.to_owned())));
}

#[tokio::test]
async fn an_invalid_approval_leaves_the_service_unavailable_with_its_listeners_bound() {
    let fixture = approved().await;
    // A config that parses but is not the approved one.
    fs::write(fixture.path("etc/config.toml"), fixture.config("# edited after approval\n")).unwrap();
    let service = fixture.start().unwrap();

    let state = service.enter_checking(identity()).await;

    assert_eq!(state, Ok(ServiceState::Unavailable(FailureReason::PolicyInvalid)));
    assert_eq!(service.listener_names().await, [listener("local")]);
    assert_refused(&get_unix(&fixture.socket(), true).await, UnavailableReason::PolicyInvalid);
    assert!(fixture.upstream.requests().is_empty());
}

#[tokio::test]
async fn damaged_shared_state_leaves_the_service_unavailable_needing_recovery() {
    let fixture = approved().await;
    fs::write(fixture.path("state/approval.age"), b"damaged").unwrap();
    let service = fixture.start().unwrap();

    let state = service.enter_checking(identity()).await;

    assert_eq!(state, Ok(ServiceState::Unavailable(FailureReason::RecoveryNeeded)));
    assert_refused(&get_unix(&fixture.socket(), true).await, UnavailableReason::RecoveryNeeded);
}

#[tokio::test]
async fn a_listener_the_signed_config_lacks_is_closed_on_entering_ready() {
    let fixture = approved().await;
    let port = next_free_port();
    fixture.swap_config(&fixture.config(&tcp_listener("extra", port)));
    let service = fixture.start().unwrap();
    assert_eq!(service.listener_names().await, [listener("extra"), listener("local")]);
    assert_refused(&get_tcp(port).await, UnavailableReason::Locked);

    assert_eq!(service.enter_checking(identity()).await, Ok(ServiceState::Ready));

    assert_eq!(service.listener_names().await, [listener("local")]);
    let refused = TcpStream::connect(("127.0.0.1", port)).await.map(|_| ()).unwrap_err();
    assert_eq!(refused.kind(), std::io::ErrorKind::ConnectionRefused);
    assert_served(&get_unix(&fixture.socket(), true).await);
}

#[tokio::test]
async fn a_verified_listener_the_provisional_set_lacked_is_bound_before_ready() {
    let mut fixture = approved().await;
    let port = next_free_port();
    fixture.approve(&fixture.config(&tcp_listener("wide", port)));
    fixture.swap_config(&fixture.config(""));
    let service = fixture.start().unwrap();
    assert_eq!(service.listener_names().await, [listener("local")]);

    assert_eq!(service.enter_checking(identity()).await, Ok(ServiceState::Ready));

    assert_eq!(service.listener_names().await, [listener("local"), listener("wide")]);
    let response = get_tcp(port).await;
    assert_served(&response);
}

#[tokio::test]
async fn a_verified_listener_that_cannot_be_bound_stays_missing_and_the_service_still_enters_ready() {
    let mut fixture = approved().await;
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = taken.local_addr().unwrap().port();
    fixture.approve(&fixture.config(&tcp_listener("wide", port)));
    let service = fixture.start().unwrap();

    assert_eq!(service.enter_checking(identity()).await, Ok(ServiceState::Ready));

    assert_eq!(service.listener_names().await, [listener("local")]);
    assert_served(&get_unix(&fixture.socket(), true).await);
}

#[tokio::test]
async fn an_unparsable_config_starts_locked_with_no_request_listeners_and_a_working_admin_socket() {
    let fixture = Fixture::new().await;
    fs::write(fixture.path("etc/config.toml"), "schema_version = [").unwrap();
    let service = fixture.start().unwrap();

    assert_eq!(service.state().await, ServiceState::Locked);
    assert_eq!(service.listener_names().await, []);
    assert!(!fixture.socket().exists());
    assert_eq!(ping(&service).await, PONG);
}

#[tokio::test]
async fn a_second_service_on_the_same_state_directory_fails_to_start() {
    let fixture = approved().await;
    let _first = fixture.start().unwrap();

    let second = fixture.start().map(|_| ());

    assert!(matches!(second, Err(StartError::StateLock(LockError::Held { .. }))), "{second:?}");
}

#[tokio::test]
async fn stop_drops_the_vault_and_closes_the_listeners() {
    let fixture = approved().await;
    let service = fixture.start().unwrap();
    service.enter_checking(identity()).await.unwrap();
    let Admission::Serve(snapshot) = service.holder().load() else {
        panic!("a Ready service serves a snapshot");
    };
    let vault = Arc::downgrade(&snapshot);
    drop(snapshot);
    let identity = service.identity_probe().await.unwrap();

    service.stop().await;

    assert_eq!(service.state().await, ServiceState::Stopped);
    assert!(vault.upgrade().is_none(), "the snapshot holding the vault outlived stop");
    assert!(identity.upgrade().is_none(), "the vault identity outlived stop");
    assert!(!fixture.socket().exists());
}

/// The stale temp files a crash mid-write can leave, in the config directory and the state directory.
const STALE_TEMPS: [&str; 4] = [
    "etc/.config.toml.pending.tmp",
    "etc/.config.toml.sig.staged.tmp",
    "state/.approval.age.tmp",
    "state/.identity.age.tmp",
];

/// The files a sweep must leave as they were: the active config and its approval, the pending and staged files, and
/// the approval state.
const SWEEP_BYSTANDERS: [&str; 5] = [
    "etc/config.toml",
    "etc/config.toml.sig",
    "etc/config.toml.pending",
    "etc/config.toml.sig.staged",
    "state/approval.age",
];

fn read_all(fixture: &Fixture, files: &[&str]) -> Vec<Vec<u8>> {
    files.iter().map(|file| fs::read(fixture.path(file)).unwrap()).collect()
}

/// An approved fixture with a pending config, a staged approval and every stale temp in place.
async fn with_stale_temps() -> Fixture {
    let fixture = approved().await;
    fs::write(fixture.path("etc/config.toml.pending"), "pending").unwrap();
    fs::write(fixture.path("etc/config.toml.sig.staged"), "staged").unwrap();
    STALE_TEMPS
        .iter()
        .for_each(|temp| fs::write(fixture.path(temp), "partial").unwrap());
    fixture
}

#[tokio::test]
async fn startup_sweeps_stale_temps_in_both_directories_and_leaves_every_other_file() {
    let logs = captured_logs();
    let fixture = with_stale_temps().await;
    let before = read_all(&fixture, &SWEEP_BYSTANDERS);

    let service = fixture.start().unwrap();

    assert_eq!(service.state().await, ServiceState::Locked);
    STALE_TEMPS
        .iter()
        .for_each(|temp| assert!(!fixture.path(temp).exists(), "{temp} survived the sweep"));
    assert_eq!(read_all(&fixture, &SWEEP_BYSTANDERS), before);
    let text = logs.text();
    [
        ".config.toml.pending.tmp",
        ".config.toml.sig.staged.tmp",
        ".approval.age.tmp",
        ".identity.age.tmp",
    ]
    .iter()
    .for_each(|name| {
        assert!(
            text.contains(&format!("removed stale temp file {name} ")),
            "{name} not logged:\n{text}"
        )
    });
    assert!(
        !text.contains(fixture.dir.path().to_str().unwrap()),
        "a sweep log named a path:\n{text}"
    );
}

#[tokio::test]
async fn a_sweep_that_fails_on_one_file_still_starts_the_service() {
    let logs = captured_logs();
    let fixture = with_stale_temps().await;
    // A directory under a temp name cannot be unlinked as a file, so the config sweep fails on it.
    let stuck = fixture.path("etc/.config.toml.pending.tmp");
    fs::remove_file(&stuck).unwrap();
    fs::create_dir(&stuck).unwrap();

    let service = fixture.start().unwrap();

    assert_eq!(service.state().await, ServiceState::Locked);
    assert_eq!(ping(&service).await, PONG);
    assert!(stuck.is_dir());
    assert!(!fixture.path("state/.approval.age.tmp").exists(), "the state sweep did not run");
    assert!(
        logs.text()
            .contains("stale temp sweep of the config directory failed, starting anyway")
    );
}

/// The route `brave`, which uses the `brave_key` credential. No caller is granted it: status does not need one.
fn brave_route(upstream_port: u16) -> String {
    format!(
        r#"
[routes.brave]
prefix = "/brave"
upstream = "https://localhost:{upstream_port}/v1"
ca_file = "/etc/iron-vault/ca/test.pem"
credential = "brave_key"
slot = {{ header = "X-Api-Key" }}
methods = ["GET"]
paths = ["/v1/**"]
rate_limit = {{ requests = 100000, per_seconds = 1, burst = 100000 }}
"#
    )
}

fn standing(report: &StatusReport) -> Vec<(String, Standing, Vec<String>)> {
    let VaultStatus::Unlocked(vault) = &report.vault else {
        panic!("the vault should be unlocked: {report:?}");
    };
    vault
        .credentials
        .iter()
        .map(
            |CredentialStanding {
                 name,
                 standing,
                 unavailable_routes,
             }| {
                (
                    name.to_string(),
                    *standing,
                    unavailable_routes.iter().map(ToString::to_string).collect(),
                )
            },
        )
        .collect()
}

#[tokio::test]
async fn status_while_locked_reports_the_sealed_values_as_unknown() {
    let fixture = approved().await;
    let service = fixture.start().unwrap();

    let (_, report) = status(&service).await;

    assert_eq!(report.state, ServiceState::Locked);
    assert_eq!(report.profile, DeploymentProfile::Development);
    assert_eq!(report.vault, VaultStatus::Locked);
    assert_eq!(report.memory, MemoryStatus::Unsupported);
}

#[tokio::test]
async fn status_when_ready_reports_the_vault_approval_and_every_credential() {
    let mut fixture = Fixture::new().await;
    fixture.approve(&fixture.config(&brave_route(fixture.upstream.port())));
    let service = fixture.start().unwrap();
    service.enter_checking(identity()).await.unwrap();

    let (_, report) = status(&service).await;

    assert_eq!(report.state, ServiceState::Ready);
    let VaultStatus::Unlocked(vault) = &report.vault else {
        panic!("{report:?}")
    };
    assert_eq!((vault.committed, vault.highest_reserved), (Some(1), 1));
    assert_eq!(vault.id, fixture.state.vault_id());
    assert_eq!(
        standing(&report),
        [
            ("brave_key".to_owned(), Standing::Healthy, Vec::new()),
            ("fx_key".to_owned(), Standing::Healthy, Vec::new())
        ]
    );
}

#[tokio::test]
async fn a_damaged_record_is_damaged_with_its_routes_unavailable_and_the_others_stay_healthy() {
    let damages = [
        (None, RecordDamage::Missing),
        (Some(b"not the record".as_slice()), RecordDamage::Substituted),
    ];
    for (replacement, damage) in damages {
        let mut fixture = Fixture::new().await;
        fixture.approve(&fixture.config(&brave_route(fixture.upstream.port())));
        match replacement {
            None => fs::remove_file(&fixture.brave_record).unwrap(),
            Some(bytes) => fs::write(&fixture.brave_record, bytes).unwrap(),
        }
        let service = fixture.start().unwrap();
        assert_eq!(service.enter_checking(identity()).await, Ok(ServiceState::Ready));

        let (_, report) = status(&service).await;

        assert_eq!(
            standing(&report),
            [
                ("brave_key".to_owned(), Standing::Damaged(damage), vec!["brave".to_owned()]),
                ("fx_key".to_owned(), Standing::Healthy, Vec::new())
            ]
        );
    }
}

#[tokio::test]
async fn status_when_unavailable_gives_each_reason_and_reports_the_dropped_vault_as_unknown() {
    let policy_invalid = approved().await;
    fs::write(
        policy_invalid.path("etc/config.toml"),
        policy_invalid.config("# edited after approval\n"),
    )
    .unwrap();
    let recovery_needed = approved().await;
    fs::write(recovery_needed.path("state/approval.age"), b"damaged").unwrap();
    let cases = [
        (policy_invalid, FailureReason::PolicyInvalid),
        (recovery_needed, FailureReason::RecoveryNeeded),
    ];
    for (fixture, reason) in cases {
        let service = fixture.start().unwrap();
        service.enter_checking(identity()).await.unwrap();

        let (_, report) = status(&service).await;

        assert_eq!(report.state, ServiceState::Unavailable(reason));
        assert_eq!(report.vault, VaultStatus::Locked);
    }
}

#[tokio::test]
async fn status_is_byte_identical_across_runs_and_holds_no_secret() {
    let mut fixture = Fixture::new().await;
    fixture.approve(&fixture.config(&brave_route(fixture.upstream.port())));
    let service = fixture.start().unwrap();
    service.enter_checking(identity()).await.unwrap();

    let (first, _) = status(&service).await;
    let (second, _) = status(&service).await;

    assert_eq!(first, second);
    let secret = SECRET.as_bytes();
    assert!(!first.windows(secret.len()).any(|window| window == secret));
}

#[tokio::test]
async fn unlock_with_the_right_passphrase_reaches_ready_and_a_request_reaches_the_upstream() {
    let logs = captured_logs();
    let fixture = approved().await;
    let service = fixture.start().unwrap();

    assert_eq!(unlock(&service, PASSPHRASE).await, AdminResponse::Success);

    assert_eq!(service.state().await, ServiceState::Ready);
    assert_served(&get_unix(&fixture.socket(), true).await);
    assert_eq!(fixture.upstream.requests().len(), 1);
    let text = logs.text();
    let transitions = ["lock transition: Locked to Checking", "lock transition: Checking to Ready"];
    transitions
        .iter()
        .for_each(|line| assert!(text.contains(line), "{line} missing from:\n{text}"));
    assert!(text.contains("iron_vault::lock_transition"), "{text}");
    assert_no_passphrase_logged(&logs);
}

#[tokio::test]
async fn a_wrong_passphrase_leaves_the_service_locked() {
    let logs = captured_logs();
    let fixture = approved().await;
    let service = fixture.start().unwrap();

    let response = unlock(&service, WRONG_PASSPHRASE).await;

    assert_eq!(response, error_response(ErrorCode::UnlockDenied, "wrong passphrase"));
    assert_eq!(service.state().await, ServiceState::Locked);
    assert_refused(&get_unix(&fixture.socket(), true).await, UnavailableReason::Locked);
    assert!(fixture.upstream.requests().is_empty());
    // A later unlock with the right passphrase still works: the refusal changed nothing.
    assert_eq!(unlock(&service, PASSPHRASE).await, AdminResponse::Success);
    assert_no_passphrase_logged(&logs);
}

#[tokio::test]
async fn empty_input_is_a_wrong_passphrase() {
    let fixture = approved().await;
    let service = fixture.start().unwrap();

    assert_eq!(
        unlock(&service, "").await,
        error_response(ErrorCode::UnlockDenied, "wrong passphrase")
    );
    assert_eq!(service.state().await, ServiceState::Locked);
}

#[tokio::test]
async fn unlock_while_ready_is_refused_before_any_prompt_and_changes_nothing() {
    let logs = captured_logs();
    let fixture = approved().await;
    let service = fixture.start().unwrap();
    service.enter_checking(identity()).await.unwrap();

    let (_, prompts, response) = admin(&service, AdminRequest::Unlock, PASSPHRASE).await;

    assert_eq!(prompts, []);
    let message = "`unlock` is allowed only while the service is Locked; it is Ready";
    assert_eq!(response, error_response(ErrorCode::WrongState, message));
    assert_eq!(service.state().await, ServiceState::Ready);
    assert_served(&get_unix(&fixture.socket(), true).await);
    assert_no_passphrase_logged(&logs);
}

#[tokio::test]
async fn unlock_with_an_invalid_approval_ends_unavailable_and_names_the_redacted_reason() {
    let logs = captured_logs();
    let fixture = approved().await;
    fs::write(fixture.path("etc/config.toml"), fixture.config("# edited after approval\n")).unwrap();
    let service = fixture.start().unwrap();

    let response = unlock(&service, PASSPHRASE).await;

    let message = "the vault unlocked, but the config check failed: the service is Unavailable (policy invalid)";
    assert_eq!(response, error_response(ErrorCode::UnlockedUnavailable, message));
    assert_eq!(service.state().await, ServiceState::Unavailable(FailureReason::PolicyInvalid));
    assert_refused(&get_unix(&fixture.socket(), true).await, UnavailableReason::PolicyInvalid);
    assert!(
        logs.text().contains("lock transition: Checking to Unavailable(PolicyInvalid)"),
        "{}",
        logs.text()
    );
    assert_no_passphrase_logged(&logs);
}

#[tokio::test]
async fn an_unreadable_passphrase_envelope_leaves_the_service_locked() {
    let fixture = approved().await;
    fs::remove_file(fixture.path("state/operational.age")).unwrap();
    let service = fixture.start().unwrap();

    let response = unlock(&service, PASSPHRASE).await;

    let AdminResponse::Error { code, message } = response else {
        panic!("expected an error, got {response:?}");
    };
    assert_eq!(code, ErrorCode::UnlockFailed);
    assert!(message.ends_with("; the service stays Locked"), "{message}");
    assert_eq!(service.state().await, ServiceState::Locked);
}

/// The lock drain tests that expect the wait to end at once give a request this long to unwind; the ones that expect it
/// to expire give it only a moment.
const DRAIN: Duration = Duration::from_secs(10);
const SHORT_DRAIN: Duration = Duration::from_millis(200);

async fn ready_service(fixture: &Fixture) -> Arc<ServiceContext> {
    let service = fixture.start().unwrap();
    assert_eq!(service.enter_checking(identity()).await, Ok(ServiceState::Ready));
    service
}

/// A weak reference to the snapshot the Ready service serves, which the test does not keep alive.
fn served_snapshot(service: &ServiceContext) -> std::sync::Weak<iron_vault::serving_snapshot::ServingSnapshot> {
    match service.holder().load() {
        Admission::Serve(snapshot) => Arc::downgrade(&snapshot),
        Admission::Refuse(reason) => panic!("expected a served snapshot, got {reason:?}"),
    }
}

async fn wait_for_requests(upstream: &MockUpstream, count: usize) {
    tokio::time::timeout(WAIT, async {
        while upstream.requests().len() < count {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn lock_over_the_admin_socket_leaves_the_service_locked_answering_503_until_it_is_unlocked() {
    let logs = captured_logs();
    let fixture = approved().await;
    let service = ready_service(&fixture).await;
    assert_served(&get_unix(&fixture.socket(), true).await);
    let snapshot = served_snapshot(&service);
    assert!(matches!(status(&service).await.1.vault, VaultStatus::Unlocked(_)));

    let response = admin(&service, AdminRequest::Lock, "").await.2;

    assert_eq!(response, AdminResponse::Lock { cleared: true });
    assert_eq!(service.state().await, ServiceState::Locked);
    // The approval state and the credential report go with the vault: status reports no vault and no credentials.
    let report = status(&service).await.1;
    assert_eq!((report.state, report.vault), (ServiceState::Locked, VaultStatus::Locked));
    assert!(snapshot.upgrade().is_none(), "the snapshot holding the vault outlived lock");
    assert_refused(&get_unix(&fixture.socket(), true).await, UnavailableReason::Locked);
    assert_eq!(fixture.upstream.requests().len(), 1, "the locked service sent nothing upstream");
    assert!(logs.text().contains("lock transition: Ready to Locked"), "{}", logs.text());
    assert_eq!(unlock(&service, PASSPHRASE).await, AdminResponse::Success);
    assert_eq!(service.state().await, ServiceState::Ready);
    assert_served(&get_unix(&fixture.socket(), true).await);
}

#[tokio::test]
async fn a_request_in_flight_is_cancelled_and_its_snapshot_is_gone_before_lock_answers() {
    let mut fixture = Fixture::with_reply(Reply::Stall).await;
    fixture.approve(&fixture.config(""));
    let service = ready_service(&fixture).await;
    let snapshot = served_snapshot(&service);
    let socket = fixture.socket();
    let waiting = tokio::spawn(async move { get_unix(&socket, true).await });
    wait_for_requests(&fixture.upstream, 1).await;
    assert_eq!(
        snapshot.strong_count(),
        2,
        "the holder and the in-flight request should hold the snapshot"
    );

    let outcome = service.lock(DRAIN).await;

    assert_eq!(outcome, Ok(LockOutcome::Cleared));
    assert_eq!(snapshot.strong_count(), 0);
    let response = waiting.await.unwrap();
    assert_eq!(response.status, 503);
}

#[tokio::test]
async fn lock_is_refused_while_the_service_is_locked() {
    let fixture = approved().await;
    let service = fixture.start().unwrap();

    let locked = admin(&service, AdminRequest::Lock, "").await.2;

    let AdminResponse::Error { code, message } = locked else {
        panic!("expected an error, got {locked:?}");
    };
    assert_eq!(code, ErrorCode::WrongState);
    assert!(message.contains("Locked"), "{message}");
    assert_eq!(service.state().await, ServiceState::Locked);
}

/// A service started on `fixture` with its config edited after approval, unlocked into Unavailable with the identity
/// kept; returns the probe of that identity.
async fn unavailable_service(fixture: &Fixture) -> (Arc<ServiceContext>, std::sync::Weak<VaultIdentity>) {
    fs::write(fixture.path("etc/config.toml"), fixture.config("# edited after approval\n")).unwrap();
    let service = fixture.start().unwrap();
    assert_eq!(
        service.enter_checking(identity()).await,
        Ok(ServiceState::Unavailable(FailureReason::PolicyInvalid))
    );
    let kept = service.identity_probe().await.unwrap();
    assert!(kept.upgrade().is_some(), "the failed check dropped the vault identity");
    (service, kept)
}

#[tokio::test]
async fn lock_from_unavailable_clears_the_kept_vault_identity() {
    let logs = captured_logs();
    let fixture = approved().await;
    let (service, kept) = unavailable_service(&fixture).await;
    assert_refused(&get_unix(&fixture.socket(), true).await, UnavailableReason::PolicyInvalid);

    let response = admin(&service, AdminRequest::Lock, "").await.2;

    assert_eq!(response, AdminResponse::Lock { cleared: true });
    assert!(kept.upgrade().is_none(), "the vault identity outlived the lock");
    assert!(service.identity_probe().await.is_none());
    let report = status(&service).await.1;
    assert_eq!((report.state, report.vault), (ServiceState::Locked, VaultStatus::Locked));
    assert_refused(&get_unix(&fixture.socket(), true).await, UnavailableReason::Locked);
    assert!(
        logs.text().contains("lock transition: Unavailable(PolicyInvalid) to Locked"),
        "{}",
        logs.text()
    );
}

#[tokio::test]
async fn unlock_after_a_lock_from_unavailable_rechecks_and_reaches_ready_once_the_config_is_fixed() {
    let fixture = approved().await;
    let (service, _) = unavailable_service(&fixture).await;
    assert_eq!(service.lock(DRAIN).await, Ok(LockOutcome::Cleared));
    fs::write(fixture.path("etc/config.toml"), fixture.config("")).unwrap();

    assert_eq!(unlock(&service, PASSPHRASE).await, AdminResponse::Success);

    assert_eq!(service.state().await, ServiceState::Ready);
    assert_served(&get_unix(&fixture.socket(), true).await);
}

#[tokio::test]
async fn lock_from_unavailable_says_the_identity_is_not_cleared_while_an_old_snapshot_holds_it() {
    let fixture = approved().await;
    let service = ready_service(&fixture).await;
    let kept = service.identity_probe().await.unwrap();
    let Admission::Serve(stubborn) = service.holder().load() else {
        panic!("a Ready service serves a snapshot");
    };
    fs::write(fixture.path("etc/config.toml"), fixture.config("# edited after approval\n")).unwrap();
    assert_eq!(service.reload().await, Ok(ServiceState::Unavailable(FailureReason::PolicyInvalid)));

    assert_eq!(service.lock(SHORT_DRAIN).await, Ok(LockOutcome::IdentityHeld));

    assert_eq!(service.state().await, ServiceState::Locked);
    assert!(kept.upgrade().is_some(), "the held vault lost its identity");
    drop(stubborn);
    assert!(kept.upgrade().is_none(), "the vault identity outlived the last snapshot");
}

#[tokio::test]
async fn a_request_that_ignores_cancellation_makes_lock_say_the_secrets_are_not_confirmed_cleared() {
    let fixture = approved().await;
    let service = ready_service(&fixture).await;
    let Admission::Serve(stubborn) = service.holder().load() else {
        panic!("a Ready service serves a snapshot");
    };
    let handlers = Handlers::standard(DeploymentProfile::Development).with_lock_drain(&service, SHORT_DRAIN);

    let response = admin_with(&service, handlers, AdminRequest::Lock, "").await.2;

    assert_eq!(response, AdminResponse::Lock { cleared: false });
    assert_eq!(service.state().await, ServiceState::Locked);
    assert_refused(&get_unix(&fixture.socket(), true).await, UnavailableReason::Locked);
    assert!(
        stubborn.policy().is_available(&"fx".parse().unwrap()),
        "the stubborn request still holds its snapshot"
    );
    drop(stubborn);
}

#[tokio::test]
async fn the_expired_drain_counts_the_snapshots_still_held() {
    let fixture = approved().await;
    let service = ready_service(&fixture).await;
    let Admission::Serve(stubborn) = service.holder().load() else {
        panic!("a Ready service serves a snapshot");
    };

    let outcome = service.lock(SHORT_DRAIN).await;

    assert_eq!(outcome, Ok(LockOutcome::Held { snapshots: 1 }));
    drop(stubborn);
}

/// Sends the token caller's `GET /fx/latest` on the Unix listener and reads until `wanted` has arrived, leaving the
/// response streaming.
async fn start_streaming(socket: &Path, wanted: &str) -> (UnixStream, String) {
    let mut stream = UnixStream::connect(socket).await.unwrap();
    stream
        .write_all(&CallerRequest::get("/fx/latest").signed(Via::Unix).to_bytes())
        .await
        .unwrap();
    let mut raw = Vec::new();
    while !String::from_utf8_lossy(&raw).contains(wanted) {
        let mut buf = [0u8; 256];
        let read = tokio::time::timeout(WAIT, stream.read(&mut buf)).await.unwrap().unwrap();
        assert!(read > 0, "the connection closed before {wanted:?} arrived");
        raw.extend_from_slice(&buf[..read]);
    }
    (stream, String::from_utf8(raw).unwrap())
}

#[tokio::test]
async fn a_response_streaming_when_lock_runs_holds_the_snapshot_until_its_body_is_dropped() {
    let gate = Arc::new(tokio::sync::Notify::new());
    let reply = Reply::TwoChunks {
        first: "data: first\n\n".to_owned(),
        second: "data: second\n\n".to_owned(),
        gate: Arc::clone(&gate),
    };
    let mut fixture = Fixture::with_reply(reply).await;
    fixture.approve(&fixture.config(""));
    let service = ready_service(&fixture).await;
    let snapshot = served_snapshot(&service);
    let (mut stream, mut raw) = start_streaming(&fixture.socket(), "data: first\n\n").await;
    // The handler has returned the response head, so beside the holder only the streaming body can still hold the
    // snapshot, with the scrubber's copies of the injected credential.
    assert_eq!(
        snapshot.strong_count(),
        2,
        "the holder and the streaming body should hold the snapshot"
    );

    let outcome = service.lock(DRAIN).await;

    assert_eq!(outcome, Ok(LockOutcome::Cleared));
    assert_eq!(snapshot.strong_count(), 0, "lock answered while the body still held the snapshot");
    let mut rest = Vec::new();
    let _ = tokio::time::timeout(WAIT, stream.read_to_end(&mut rest)).await.unwrap();
    raw.push_str(&String::from_utf8_lossy(&rest));
    assert!(!raw.ends_with("0\r\n\r\n"), "the withdrawn body ended cleanly: {raw}");
    assert!(!raw.contains("data: second"), "{raw}");
}

#[tokio::test]
async fn a_failed_check_keeps_the_identity_and_a_repair_reaches_ready_without_a_second_unlock() {
    let fixture = approved().await;
    fs::write(fixture.path("etc/config.toml"), fixture.config("# edited after approval\n")).unwrap();
    let service = fixture.start().unwrap();
    assert!(
        service.recheck(ServiceEvent::Repaired).await.is_err(),
        "a Locked service has no identity to check with"
    );
    assert_eq!(
        service.enter_checking(identity()).await,
        Ok(ServiceState::Unavailable(FailureReason::PolicyInvalid))
    );
    let kept = service.identity_probe().await.unwrap();
    assert!(kept.upgrade().is_some(), "the failed check dropped the vault identity");
    assert_eq!(status(&service).await.1.vault, VaultStatus::Locked);

    fs::write(fixture.path("etc/config.toml"), fixture.config("")).unwrap();
    let state = service.recheck(ServiceEvent::Repaired).await;

    assert_eq!(state, Ok(ServiceState::Ready));
    assert!(std::sync::Weak::ptr_eq(&kept, &service.identity_probe().await.unwrap()));
    assert_served(&get_unix(&fixture.socket(), true).await);
}

#[tokio::test]
async fn a_reload_from_ready_opens_a_new_vault_from_the_kept_identity() {
    let fixture = approved().await;
    let service = ready_service(&fixture).await;
    let old = served_snapshot(&service);
    let kept = service.identity_probe().await.unwrap();

    let state = service.recheck(ServiceEvent::Reload).await;

    assert_eq!(state, Ok(ServiceState::Ready));
    assert!(old.upgrade().is_none(), "the reload kept the old snapshot and its vault");
    assert!(served_snapshot(&service).upgrade().is_some());
    assert!(std::sync::Weak::ptr_eq(&kept, &service.identity_probe().await.unwrap()));
    assert!(matches!(status(&service).await.1.vault, VaultStatus::Unlocked(_)));
    assert_served(&get_unix(&fixture.socket(), true).await);
}

#[tokio::test]
async fn lock_clears_the_vault_identity_once_its_drain_releases_the_last_snapshot() {
    let fixture = approved().await;
    let service = ready_service(&fixture).await;
    let identity = service.identity_probe().await.unwrap();

    assert_eq!(service.lock(DRAIN).await, Ok(LockOutcome::Cleared));

    assert!(identity.upgrade().is_none(), "the vault identity outlived the lock drain");
    assert!(service.identity_probe().await.is_none());
}

#[tokio::test]
async fn a_snapshot_held_past_the_lock_drain_keeps_the_identity_until_it_is_dropped() {
    let fixture = approved().await;
    let service = ready_service(&fixture).await;
    let identity = service.identity_probe().await.unwrap();
    let Admission::Serve(stubborn) = service.holder().load() else {
        panic!("a Ready service serves a snapshot");
    };

    assert_eq!(service.lock(SHORT_DRAIN).await, Ok(LockOutcome::Held { snapshots: 1 }));

    assert!(identity.upgrade().is_some(), "the held vault lost its identity");
    drop(stubborn);
    assert!(identity.upgrade().is_none(), "the vault identity outlived the last snapshot");
}

#[tokio::test]
async fn recheck_refuses_an_event_that_does_not_lead_to_checking_and_changes_nothing() {
    let fixture = approved().await;
    let service = ready_service(&fixture).await;
    let snapshot = served_snapshot(&service);
    let kept = service.identity_probe().await.unwrap();

    let lock = service.recheck(ServiceEvent::Lock).await;
    let stop = service.recheck(ServiceEvent::Stop).await;

    let refused = |event| {
        Err(IllegalTransition {
            state: ServiceState::Ready,
            event,
        })
    };
    assert_eq!(lock, refused(ServiceEvent::Lock));
    assert_eq!(stop, refused(ServiceEvent::Stop));

    assert_eq!(service.state().await, ServiceState::Ready);
    assert!(
        std::sync::Weak::ptr_eq(&snapshot, &served_snapshot(&service)),
        "the served snapshot changed"
    );
    assert!(std::sync::Weak::ptr_eq(&kept, &service.identity_probe().await.unwrap()));
    assert_served(&get_unix(&fixture.socket(), true).await);
}

/// The bytes of the approval state file, which no reload may write.
fn approval_state_bytes(fixture: &Fixture) -> Vec<u8> {
    fs::read(fixture.path("state/approval.age")).unwrap()
}

/// The published config and its signature.
fn published_pair(fixture: &Fixture) -> (Vec<u8>, Vec<u8>) {
    (
        fs::read(fixture.path("etc/config.toml")).unwrap(),
        fs::read(fixture.path("etc/config.toml.sig")).unwrap(),
    )
}

fn publish_pair(fixture: &Fixture, (config, signature): &(Vec<u8>, Vec<u8>)) {
    fs::write(fixture.path("etc/config.toml"), config).unwrap();
    fs::write(fixture.path("etc/config.toml.sig"), signature).unwrap();
}

/// Reloads and asserts the service is Unavailable with a policy-invalid `503`, the approval state untouched.
async fn assert_reload_fails(fixture: &Fixture, service: &Arc<ServiceContext>, state_before: &[u8]) {
    assert_eq!(service.reload().await, Ok(ServiceState::Unavailable(FailureReason::PolicyInvalid)));
    assert_refused(&get_unix(&fixture.socket(), true).await, UnavailableReason::PolicyInvalid);
    assert!(fixture.upstream.requests().is_empty());
    assert_eq!(approval_state_bytes(fixture), state_before, "a reload wrote the approval state");
}

#[tokio::test]
async fn a_reload_with_nothing_edited_stays_ready_on_the_same_committed_version() {
    let fixture = approved().await;
    let service = ready_service(&fixture).await;
    let before = approval_state_bytes(&fixture);
    let committed = status(&service).await.1.vault;

    assert_eq!(service.reload().await, Ok(ServiceState::Ready));

    assert_eq!(status(&service).await.1.vault, committed);
    assert_served(&get_unix(&fixture.socket(), true).await);
    assert_eq!(approval_state_bytes(&fixture), before);
}

#[tokio::test]
async fn a_failed_reload_after_ready_reports_the_vault_as_not_open() {
    let fixture = approved().await;
    let service = ready_service(&fixture).await;
    assert!(matches!(status(&service).await.1.vault, VaultStatus::Unlocked(_)));
    let before = approval_state_bytes(&fixture);
    fs::write(fixture.path("etc/config.toml"), fixture.config("# edited after approval\n")).unwrap();

    assert_reload_fails(&fixture, &service, &before).await;

    let (_, report) = status(&service).await;
    assert_eq!(report.state, ServiceState::Unavailable(FailureReason::PolicyInvalid));
    assert_eq!(report.vault, VaultStatus::Locked);
}

#[tokio::test]
async fn a_reload_to_an_older_committed_pair_goes_unavailable_and_the_old_policy_is_not_served() {
    let mut fixture = approved().await;
    let older = published_pair(&fixture);
    fixture.approve(&fixture.config("# version two\n"));
    let service = ready_service(&fixture).await;
    let before = approval_state_bytes(&fixture);
    let logs = captured_logs();
    publish_pair(&fixture, &older);

    assert_reload_fails(&fixture, &service, &before).await;

    let text = logs.text();
    assert!(text.contains("config.reload-failed"), "{text}");
    assert!(!text.contains(SECRET), "{text}");
}

#[tokio::test]
async fn a_reload_to_a_validly_signed_uncommitted_higher_version_goes_unavailable() {
    let mut fixture = approved().await;
    let (committed_state, first) = (approval_state_bytes(&fixture), published_pair(&fixture));
    fixture.approve(&fixture.config("# version two\n"));
    let higher = published_pair(&fixture);
    // Roll the protected state and the published pair back to version one: the signature on the higher pair is valid,
    // but that version was never committed.
    fs::write(fixture.path("state/approval.age"), &committed_state).unwrap();
    publish_pair(&fixture, &first);
    let service = ready_service(&fixture).await;
    publish_pair(&fixture, &higher);

    assert_reload_fails(&fixture, &service, &committed_state).await;
}

#[tokio::test]
async fn a_reload_after_one_byte_of_whitespace_goes_unavailable_on_a_digest_mismatch() {
    let fixture = approved().await;
    let service = ready_service(&fixture).await;
    let before = approval_state_bytes(&fixture);
    let mut edited = fs::read(fixture.path("etc/config.toml")).unwrap();
    edited.push(b'\n');
    fs::write(fixture.path("etc/config.toml"), edited).unwrap();

    assert_reload_fails(&fixture, &service, &before).await;
}

#[tokio::test]
async fn a_request_in_flight_during_a_failed_reload_is_cancelled() {
    let gate = Arc::new(tokio::sync::Notify::new());
    let reply = Reply::TwoChunks {
        first: "data: first\n\n".to_owned(),
        second: "data: second\n\n".to_owned(),
        gate: Arc::clone(&gate),
    };
    let mut fixture = Fixture::with_reply(reply).await;
    fixture.approve(&fixture.config(""));
    let service = ready_service(&fixture).await;
    let (mut stream, mut raw) = start_streaming(&fixture.socket(), "data: first\n\n").await;
    let before = approval_state_bytes(&fixture);
    let mut edited = fs::read(fixture.path("etc/config.toml")).unwrap();
    edited.push(b'\n');
    fs::write(fixture.path("etc/config.toml"), edited).unwrap();

    assert_eq!(service.reload().await, Ok(ServiceState::Unavailable(FailureReason::PolicyInvalid)));

    let mut rest = Vec::new();
    let _ = tokio::time::timeout(WAIT, stream.read_to_end(&mut rest)).await.unwrap();
    raw.push_str(&String::from_utf8_lossy(&rest));
    assert!(!raw.ends_with("0\r\n\r\n"), "the withdrawn body ended cleanly: {raw}");
    assert!(!raw.contains("data: second"), "{raw}");
    assert_eq!(approval_state_bytes(&fixture), before);
}

#[tokio::test]
async fn sighup_outside_ready_changes_nothing_and_never_repairs_unavailable() {
    let fixture = approved().await;
    let service = fixture.start().unwrap();
    let refused = |state| {
        Err(IllegalTransition {
            state,
            event: ServiceEvent::Reload,
        })
    };
    assert_eq!(service.reload().await, refused(ServiceState::Locked));

    let mut edited = fs::read(fixture.path("etc/config.toml")).unwrap();
    edited.push(b'\n');
    fs::write(fixture.path("etc/config.toml"), edited).unwrap();
    let unavailable = ServiceState::Unavailable(FailureReason::PolicyInvalid);
    assert_eq!(service.enter_checking(identity()).await, Ok(unavailable));
    // Even after the file is mended, a reload does not leave Unavailable.
    fs::write(fixture.path("etc/config.toml"), fixture.config("")).unwrap();

    assert_eq!(service.reload().await, refused(unavailable));
    assert_eq!(service.state().await, unavailable);
}

/// How soon an answer that must not wait for a blocking task arrives. Far below [`WAIT`], which a gate holds a task for
/// at most, so a gated task on the runtime thread would fail the test rather than hang it.
const PROMPTLY: Duration = Duration::from_secs(2);

/// One armed stop: the file whose first read blocks, the signal that a read reached it, and the release.
struct Gate {
    file: &'static str,
    reached: oneshot::Sender<()>,
    release: mpsc::Receiver<()>,
}

/// The real filesystem, except that the first read of an armed file blocks until the test releases it (or [`WAIT`]
/// passes), so a test can hold the unlock or the config check mid-way.
#[derive(Clone, Default)]
struct GatedFs(Arc<Mutex<Option<Gate>>>);

impl GatedFs {
    /// Arms the gate on `file`; returns the signal that a read reached it and its release.
    fn arm(&self, file: &'static str) -> (oneshot::Receiver<()>, mpsc::Sender<()>) {
        let (reached, on_reached) = oneshot::channel();
        let (release, on_release) = mpsc::channel();
        *self.0.lock().unwrap() = Some(Gate {
            file,
            reached,
            release: on_release,
        });
        (on_reached, release)
    }

    /// Blocks the calling thread on the gate if it is armed on `path`'s file, disarming it.
    fn pass(&self, path: &Path) {
        let mut armed = self.0.lock().unwrap();
        if !armed.as_ref().is_some_and(|gate| path.file_name() == Some(gate.file.as_ref())) {
            return;
        }
        let gate = armed.take().unwrap();
        drop(armed);
        let _ = gate.reached.send(());
        let _ = gate.release.recv_timeout(WAIT);
    }
}

impl StoreFs for GatedFs {
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
        OsFs.remove_file(path)
    }

    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        OsFs.sync_dir(dir)
    }

    fn list_dir(&self, dir: &Path) -> io::Result<Vec<OsString>> {
        OsFs.list_dir(dir)
    }

    fn read_bounded(&self, path: &Path, max_len: u64) -> io::Result<Vec<u8>> {
        self.pass(path);
        OsFs.read_bounded(path, max_len)
    }
}

/// The service's admin handlers served on its runtime directory until closed, so several commands can overlap.
struct AdminSession {
    socket: PathBuf,
    stop: oneshot::Sender<()>,
    served: tokio::task::JoinHandle<io::Result<()>>,
}

impl AdminSession {
    fn open<F: StoreFs + Send + Sync + 'static>(service: &Arc<ServiceContext<F>>) -> Self {
        let paths = service.paths().clone();
        let runtime_dir = paths.runtime_dir.clone().unwrap();
        let socket = AdminSocket::bind(&runtime_dir, paths.owner).unwrap();
        let handlers = Handlers::for_service(service);
        let server = AdminServer::new(AdminPrincipals::new(paths.profile, paths.owner.uid), handlers, Limits::default());
        let (stop, stopped) = oneshot::channel::<()>();
        let served = tokio::spawn(async move {
            server
                .serve(socket, async {
                    let _ = stopped.await;
                })
                .await
        });
        Self {
            socket: runtime_dir.join(ADMIN_SOCKET_NAME),
            stop,
            served,
        }
    }

    /// Sends `request` on its own connection, in a task of its own, answering each prompt with `answer`.
    fn send(&self, request: AdminRequest, answer: &str) -> tokio::task::JoinHandle<AdminResponse> {
        let (socket, answer) = (self.socket.clone(), answer.to_owned());
        tokio::spawn(async move { converse(&socket, request, answer).await.2 })
    }

    async fn close(self) {
        let _ = self.stop.send(());
        self.served.await.unwrap().unwrap();
    }
}

/// A service started on a [`GatedFs`] armed on `operational.age`, with an `unlock` sent and held in its blocking task,
/// where scrypt runs. Returns the service, the admin session, the pending unlock and the gate's release.
async fn unlock_held_in_its_task(
    fixture: &Fixture,
) -> (
    Arc<ServiceContext<GatedFs>>,
    AdminSession,
    tokio::task::JoinHandle<AdminResponse>,
    mpsc::Sender<()>,
) {
    let fs = GatedFs::default();
    let (reached, release) = fs.arm("operational.age");
    let service = fixture.start_on(fs).unwrap();
    let session = AdminSession::open(&service);
    let unlocking = session.send(AdminRequest::Unlock, PASSPHRASE);
    tokio::time::timeout(WAIT, reached).await.unwrap().unwrap();
    (service, session, unlocking, release)
}

#[tokio::test]
async fn a_request_gets_503_locked_at_once_while_an_unlock_is_in_scrypt() {
    let fixture = approved().await;
    let (service, session, unlocking, release) = unlock_held_in_its_task(&fixture).await;

    let started = Instant::now();
    let response = get_unix(&fixture.socket(), true).await;

    assert!(started.elapsed() < PROMPTLY, "the refusal took {:?}", started.elapsed());
    assert_refused(&response, UnavailableReason::Locked);
    release.send(()).unwrap();
    assert_eq!(unlocking.await.unwrap(), AdminResponse::Success);
    assert_eq!(service.state().await, ServiceState::Ready);
    session.close().await;
}

#[tokio::test]
async fn ping_answers_at_once_and_status_waits_for_an_unlock_in_scrypt() {
    let fixture = approved().await;
    let (_service, session, unlocking, release) = unlock_held_in_its_task(&fixture).await;

    let started = Instant::now();
    assert_eq!(session.send(AdminRequest::Ping, "").await.unwrap(), PONG);
    assert!(started.elapsed() < PROMPTLY, "ping took {:?}", started.elapsed());
    let status = session.send(AdminRequest::Status, "");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!status.is_finished(), "status did not wait for the unlock");

    release.send(()).unwrap();
    assert_eq!(unlocking.await.unwrap(), AdminResponse::Success);
    let AdminResponse::Status(report) = status.await.unwrap() else {
        panic!("expected a status report");
    };
    assert_eq!(report.state, ServiceState::Ready);
    session.close().await;
}

#[tokio::test]
async fn a_cancelled_check_still_drops_the_vault_its_task_opened() {
    let fixture = approved().await;
    let fs = GatedFs::default();
    let service = fixture.start_on(fs.clone()).unwrap();
    assert_eq!(service.enter_checking(identity()).await, Ok(ServiceState::Ready));
    let identity = service.identity_probe().await.unwrap();
    let (reached, release) = fs.arm("config.toml");
    let recheck = tokio::spawn({
        let service = Arc::clone(&service);
        async move { service.recheck(ServiceEvent::Reload).await }
    });
    tokio::time::timeout(WAIT, reached).await.unwrap().unwrap();
    // The context's copy, and the vault the held task opened.
    assert_eq!(identity.strong_count(), 2);

    recheck.abort();
    assert!(recheck.await.unwrap_err().is_cancelled());
    release.send(()).unwrap();

    tokio::time::timeout(WAIT, async {
        while identity.strong_count() > 1 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the cancelled check's task kept its vault");
}

// Safe states (specification §3.12, §3.15): each failure the service can meet at startup or while serving ends in an
// explicit state. In every one the request interface answers a fixed redacted `503`, `status` names the state, `ping`
// still answers, and nothing reaches the upstream.

/// A signed `GET` of `path` on the Unix listener.
async fn get_path(socket: &Path, path: &str) -> Response {
    exchange(
        UnixStream::connect(socket).await.unwrap(),
        &CallerRequest::get(path).signed(Via::Unix),
    )
    .await
}

/// Asserts the answers a safe state gives and that no path, version, secret or config byte leaks into them.
///
/// `connections` is how many connections the upstream has accepted so far: a safe state adds none.
async fn assert_safe_state(
    fixture: &Fixture,
    service: &Arc<ServiceContext>,
    expected: ServiceState,
    reason: UnavailableReason,
    connections: usize,
) {
    assert_eq!(service.state().await, expected);
    let response = get_unix(&fixture.socket(), true).await;
    assert_refused(&response, reason);
    assert_eq!(fixture.upstream.connections(), connections, "a safe state sent a request upstream");
    let (bytes, report) = status(service).await;
    assert_eq!(report.state, expected);
    assert_eq!(report.vault, VaultStatus::Locked, "a safe state kept the vault in view");
    let dir = fixture.dir.path().to_string_lossy().into_owned();
    [SECRET, dir.as_str()]
        .iter()
        .for_each(|leak| assert!(!String::from_utf8_lossy(&bytes).contains(leak), "status leaked {leak}"));
    assert_eq!(ping(service).await, PONG);
}

#[tokio::test]
async fn locked_startup_stays_locked_after_a_wrong_passphrase() {
    let fixture = approved().await;
    let service = fixture.start().unwrap();

    assert_safe_state(&fixture, &service, ServiceState::Locked, UnavailableReason::Locked, 0).await;
    assert_eq!(
        unlock(&service, WRONG_PASSPHRASE).await,
        error_response(ErrorCode::UnlockDenied, "wrong passphrase")
    );
    assert_safe_state(&fixture, &service, ServiceState::Locked, UnavailableReason::Locked, 0).await;
}

/// Unlocks a service whose approved policy does not verify, and asserts the Unavailable (policy invalid) safe state.
async fn unlocked_with_invalid_policy(fixture: &Fixture) {
    let service = fixture.start().unwrap();
    let message = "the vault unlocked, but the config check failed: the service is Unavailable (policy invalid)";
    assert_eq!(
        unlock(&service, PASSPHRASE).await,
        error_response(ErrorCode::UnlockedUnavailable, message)
    );
    let unavailable = ServiceState::Unavailable(FailureReason::PolicyInvalid);
    assert_safe_state(fixture, &service, unavailable, UnavailableReason::PolicyInvalid, 0).await;
}

#[tokio::test]
async fn a_bad_signature_at_startup_is_unavailable_with_policy_invalid() {
    let fixture = approved().await;
    let mut signature = fs::read(fixture.path("etc/config.toml.sig")).unwrap();
    // The signature is the envelope's last field: one flipped bit leaves a well-formed envelope whose signature fails.
    *signature.last_mut().unwrap() ^= 0x01;
    ApprovalEnvelope::decode(&signature).expect("the tampered envelope must still decode");
    fs::write(fixture.path("etc/config.toml.sig"), signature).unwrap();

    unlocked_with_invalid_policy(&fixture).await;
}

#[tokio::test]
async fn an_older_committed_pair_at_startup_is_unavailable_and_the_old_policy_is_not_served() {
    let mut fixture = approved().await;
    let older = published_pair(&fixture);
    fixture.approve(&fixture.config("# version two\n"));
    publish_pair(&fixture, &older);

    unlocked_with_invalid_policy(&fixture).await;
}

#[tokio::test]
async fn an_uncommitted_higher_version_at_startup_is_unavailable() {
    let mut fixture = approved().await;
    let (committed_state, first) = (approval_state_bytes(&fixture), published_pair(&fixture));
    fixture.approve(&fixture.config("# version two\n"));
    // The signature on version two is valid, but the protected state never committed it.
    fs::write(fixture.path("state/approval.age"), committed_state).unwrap();
    assert_ne!(published_pair(&fixture), first);

    unlocked_with_invalid_policy(&fixture).await;
}

#[tokio::test]
async fn a_route_naming_an_unknown_credential_at_startup_is_unavailable() {
    let mut fixture = Fixture::new().await;
    let ghost = brave_route(fixture.upstream.port()).replace("brave_key", "ghost_key");
    fixture.approve(&fixture.config(&ghost));

    unlocked_with_invalid_policy(&fixture).await;
}

#[tokio::test]
async fn damaged_shared_state_after_unlock_is_unavailable_needing_recovery_and_does_not_crash() {
    for file in ["manifest.age", "approval.age"] {
        for damage in [b"damaged".to_vec(), Vec::new()] {
            let fixture = approved().await;
            fs::write(fixture.path("state").join(file), damage).unwrap();
            let service = fixture.start().unwrap();

            let response = unlock(&service, PASSPHRASE).await;

            let AdminResponse::Error { code, message } = response else {
                panic!("{file}: expected an error, got {response:?}");
            };
            assert_eq!(code, ErrorCode::UnlockedUnavailable, "{file}: {message}");
            let unavailable = ServiceState::Unavailable(FailureReason::RecoveryNeeded);
            assert_safe_state(&fixture, &service, unavailable, UnavailableReason::RecoveryNeeded, 0).await;
        }
    }
}

#[tokio::test]
async fn one_damaged_credential_record_gives_503_on_its_routes_while_unrelated_routes_reach_the_upstream() {
    let mut fixture = Fixture::new().await;
    let config = fixture.config(&brave_route(fixture.upstream.port()));
    fixture.approve(&config.replace("routes = [\"fx\"]", "routes = [\"fx\", \"brave\"]"));
    fs::write(&fixture.brave_record, b"not the record").unwrap();
    let service = fixture.start().unwrap();
    assert_eq!(unlock(&service, PASSPHRASE).await, AdminResponse::Success);

    let damaged = get_path(&fixture.socket(), "/brave/latest").await;

    assert_eq!((damaged.status, damaged.body.as_str()), (503, "service unavailable"));
    assert_eq!(
        fixture.upstream.requests().len(),
        0,
        "the damaged credential's route sent a request"
    );
    assert_served(&get_unix(&fixture.socket(), true).await);
    assert_eq!(fixture.upstream.requests().len(), 1);
    let (bytes, report) = status(&service).await;
    assert_eq!(report.state, ServiceState::Ready);
    assert_eq!(
        standing(&report),
        [
            (
                "brave_key".to_owned(),
                Standing::Damaged(RecordDamage::Substituted),
                vec!["brave".to_owned()]
            ),
            ("fx_key".to_owned(), Standing::Healthy, Vec::new())
        ]
    );
    assert!(!String::from_utf8_lossy(&bytes).contains(SECRET));
    assert_eq!(ping(&service).await, PONG);
}

#[tokio::test]
async fn locking_while_serving_gives_503_locked_and_unlock_restores_serving_at_the_same_committed_version() {
    let fixture = approved().await;
    let service = fixture.start().unwrap();
    assert_eq!(unlock(&service, PASSPHRASE).await, AdminResponse::Success);
    assert_served(&get_unix(&fixture.socket(), true).await);
    let served = fixture.upstream.connections();
    let VaultStatus::Unlocked(before) = status(&service).await.1.vault else {
        panic!("the serving vault should be unlocked");
    };

    assert_eq!(
        admin(&service, AdminRequest::Lock, "").await.2,
        AdminResponse::Lock { cleared: true }
    );
    assert_safe_state(&fixture, &service, ServiceState::Locked, UnavailableReason::Locked, served).await;

    assert_eq!(unlock(&service, PASSPHRASE).await, AdminResponse::Success);
    assert_served(&get_unix(&fixture.socket(), true).await);
    let VaultStatus::Unlocked(after) = status(&service).await.1.vault else {
        panic!("the restored vault should be unlocked");
    };
    assert_eq!(
        (after.committed, after.highest_reserved),
        (before.committed, before.highest_reserved)
    );
    assert_eq!(after.id, before.id);
}
