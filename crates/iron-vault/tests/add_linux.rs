//! `add` end to end over a real admin socket against a running service context (specification §3.3, §3.10, §3.12,
//! §3.13): the state and argument checks before any prompt, the prompts by kind, the vault write through a vault opened
//! for it alone, and a later `config approve` that routes through the new credential. Every test's log goes to one
//! captured buffer at TRACE, which must never hold a secret, username or password typed at a prompt.
//!
//! Each test builds a vault holding `fx_key`, pins a software approver whose key is sealed in `approver.age`, and
//! approves the base config through the store, then releases both locks so the service takes them.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use common::WAIT;
use common::mock_upstream::{MockUpstream, Reply, TestCa};
use common::proxy_harness::{CallerRequest, Response, TOKEN_BYTES, TOKEN_HEADER, TempDir, Via, token_hash};
use iron_vault::admin::ADMIN_SOCKET_NAME;
use iron_vault::admin::dispatch::Handlers;
use iron_vault::admin::principal::AdminPrincipals;
use iron_vault::admin::protocol::{
    self, AdminRequest, AdminResponse, Decoded, ErrorCode, Frame, OwnerInput, Prompt, ProposedConfig, RequestedOrigin, StatusReport,
    VaultStatus,
};
use iron_vault::admin::server::{AdminServer, Limits};
use iron_vault::admin::socket::AdminSocket;
use iron_vault::config_check::UpstreamSettings;
use iron_vault::deployment::{Accounts, DeploymentProfile, PasswdDirectory};
use iron_vault::hardening::{CoreDumps, HardeningReport, MemoryProtection};
use iron_vault::path_metadata::invoking_user;
use iron_vault::service_context::{ServiceContext, ServiceLocks, ServiceSetup};
use iron_vault::service_state::{FailureReason, ServiceState, UnavailableReason};
use iron_vault::serving_snapshot::{Admission, SnapshotHolder};
use iron_vault::socket_activation::PassedSockets;
use iron_vault::standing::{CredentialStanding, Standing};
use iron_vault::trusted_path_report::ServicePaths;
use iron_vault::upstream::client::TransportLimits;
use iron_vault_kinds::CredentialMaterial;
use iron_vault_policy::{Capabilities, CredentialKind};
use iron_vault_store::{
    ApprovalPassphrase, ApprovalState, ApprovalStorage, ConfigDirLock, CredentialRecord, OsFs, PendingConfig, PermittedOrigins, RecordId,
    SoftwareSigner, StateDirLock, StateFileName, StoreFs, Vault, VaultIdentity, VaultManifest, decode, open_manifest, open_signer_key,
    seal_signer_key_for_tests, write_signer_key,
};
use secrecy::{ExposeSecret, SecretString};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::oneshot;
use tracing_subscriber::fmt::MakeWriter;
use zeroize::Zeroizing;

const IDENTITY: &str = "AGE-SECRET-KEY-1QYPQXPQ9QCRSSZG2PVXQ6RS0ZQG3YYC5Z5TPWXQERGD3C8G7RUSQGPQYEE";
const APPROVAL_PASSPHRASE: &str = "APPROVAL-correct-3e8b";
/// The material typed at `add`'s prompts; distinctive, so a search of the logs and messages cannot match anything else.
const SECRET: &str = "ADD-SECRET-7d41c2";
const USERNAME: &str = "ADD-USER-5a90e1";
const PASSWORD: &str = "ADD-PASS-b38f06";

fn identity() -> VaultIdentity {
    VaultIdentity::from_secret(IDENTITY)
}

fn approval_passphrase() -> ApprovalPassphrase {
    ApprovalPassphrase::new(SecretString::from(APPROVAL_PASSPHRASE)).unwrap()
}

fn mkdir(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

/// A vault holding `fx_key` with a software approver and the base config approved as version 1. No lock is held.
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
        let ca = TestCa::new("add test CA");
        let reply = Reply::Respond {
            status: 200,
            headers: Vec::new(),
            body: b"ok".to_vec(),
        };
        let upstream = MockUpstream::start(&ca, reply).await;
        let fixture = Self { dir, ca, upstream };
        let mut state = fixture.create_vault();
        fixture.approve_through_store(&mut state, &fixture.config(&[("fx", "fx_key")]));
        fixture
    }

    fn create_vault(&self) -> ApprovalState {
        let lock = StateDirLock::acquire(&self.path("state")).unwrap();
        let mut vault = Vault::create(&lock, &OsFs, identity()).unwrap();
        let material = CredentialMaterial::Static { key: "fx-secret".into() };
        vault
            .add(&lock, &OsFs, "fx_key".parse().unwrap(), material, self.origins())
            .unwrap();
        let (key, pinned) = SoftwareSigner::generate().unwrap();
        let sealed = seal_signer_key_for_tests(&key, &approval_passphrase()).unwrap();
        write_signer_key(&lock, &OsFs, &sealed).unwrap();
        vault.create_approval_state(&lock, &OsFs, pinned).unwrap().0
    }

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
        let signer = open_signer_key(&envelope, &approval_passphrase(), state.approver()).unwrap();
        let holder = SnapshotHolder::refusing(UnavailableReason::Checking);
        let pending = PendingConfig::write(&storage, config.as_bytes().to_vec()).unwrap();
        let prepared = pending.prepare(&storage, state, signer).unwrap();
        prepared.commit(&storage, &holder.pause()).unwrap();
    }

    /// The mock upstream's origin.
    fn origins(&self) -> PermittedOrigins {
        let port = self.upstream.port().to_string().parse().unwrap();
        PermittedOrigins::new([("localhost".parse().unwrap(), port)].into()).unwrap()
    }

    fn requested_origins(&self) -> Vec<RequestedOrigin> {
        vec![RequestedOrigin {
            host: "localhost".to_owned(),
            port: self.upstream.port().to_string().parse().unwrap(),
        }]
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn socket(&self) -> PathBuf {
        self.path("proxy.sock")
    }

    /// The config with the Unix listener `local` and one route per `(route, credential)`, all granted to one caller.
    fn config(&self, routes: &[(&str, &str)]) -> String {
        let names = routes
            .iter()
            .map(|(route, _)| format!("\"{route}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let tables = routes
            .iter()
            .map(|(route, credential)| self.route(route, credential))
            .collect::<String>();
        format!(
            r#"schema_version = 1

[listeners.local]
unix_socket = "{socket}"
token_header = "{TOKEN_HEADER}"

[callers.agent]
listener = "local"
token_hash = "{hash}"
routes = [{names}]
{tables}"#,
            socket = self.socket().display(),
            hash = token_hash(TOKEN_BYTES),
        )
    }

    fn route(&self, route: &str, credential: &str) -> String {
        format!(
            r#"
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
            port = self.upstream.port(),
        )
    }

    /// Starts the service on this fixture's directories with `fs` and enters Checking with the vault identity.
    async fn start_with<F: StoreFs + Send + Sync + 'static>(&self, fs: F) -> Arc<ServiceContext<F>> {
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
            fs,
            capabilities: Capabilities::default(),
            upstream: UpstreamSettings::new(DeploymentProfile::Development, invoking_user().unwrap(), TransportLimits::default())
                .with_pinned_trust(self.ca.trust()),
            hardening: HardeningReport {
                core_dumps: CoreDumps::Disabled,
                memory: MemoryProtection::Unsupported,
            },
        };
        let service = Arc::new(ServiceContext::start(locks, setup, &provisional, PassedSockets::default()).unwrap());
        service.enter_checking(identity()).await.unwrap();
        service
    }

    async fn ready_with<F: StoreFs + Send + Sync + 'static>(&self, fs: F) -> Arc<ServiceContext<F>> {
        let service = self.start_with(fs).await;
        assert_eq!(service.state().await, ServiceState::Ready);
        service
    }

    async fn ready(&self) -> Arc<ServiceContext> {
        self.ready_with(OsFs).await
    }

    fn manifest_bytes(&self) -> Vec<u8> {
        fs::read(self.path("state/manifest.age")).unwrap()
    }

    /// The manifest on disk, opened without the state-directory lock the service holds.
    fn manifest(&self) -> VaultManifest {
        open_manifest(&identity(), &self.manifest_bytes()).unwrap()
    }

    fn record_id(&self, name: &str) -> Option<RecordId> {
        self.manifest()
            .entries()
            .iter()
            .find(|(_, entry)| entry.name().as_str() == name)
            .map(|(id, _)| *id)
    }

    fn record_path(&self, id: &RecordId) -> PathBuf {
        self.path(&format!("state/{}", StateFileName::record(id)))
    }

    /// The record file `id`, decrypted.
    fn record(&self, id: &RecordId) -> CredentialRecord {
        let sealed = fs::read(self.record_path(id)).unwrap();
        decode(&iron_vault_store::open(&identity(), &sealed, 1 << 20).unwrap()).unwrap()
    }

    /// The `record-*.age` files in the state directory, in name order.
    fn record_files(&self) -> Vec<OsString> {
        let mut files = fs::read_dir(self.path("state"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name.to_string_lossy().starts_with("record-"))
            .collect::<Vec<_>>();
        files.sort();
        files
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
    prompts: Vec<Prompt>,
    response: AdminResponse,
}

/// The admin server with the service's handlers on its runtime directory, until `stop` is sent.
fn serve_admin<F: StoreFs + Send + Sync + 'static>(service: &Arc<ServiceContext<F>>) -> (PathBuf, oneshot::Sender<()>) {
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

/// Sends `request` and answers the prompts in turn with `answers`.
async fn exchange<F: StoreFs + Send + Sync + 'static>(
    service: &Arc<ServiceContext<F>>,
    request: AdminRequest,
    answers: &[&str],
) -> Exchanged {
    let (path, stop) = serve_admin(service);
    let mut stream = UnixStream::connect(path).await.unwrap();
    send(&mut stream, &Frame::Request(request)).await;
    let exchanged = converse(&mut stream, answers).await;
    let _ = stop.send(());
    exchanged
}

fn add_request(fixture: &Fixture, name: &str, kind: CredentialKind) -> AdminRequest {
    AdminRequest::Add {
        name: name.to_owned(),
        kind,
        origins: fixture.requested_origins(),
    }
}

/// `add` of a static credential `name` with [`SECRET`].
async fn add<F: StoreFs + Send + Sync + 'static>(fixture: &Fixture, service: &Arc<ServiceContext<F>>, name: &str) -> Exchanged {
    exchange(service, add_request(fixture, name, CredentialKind::Static), &[SECRET]).await
}

/// Reads frames until the response, answering each prompt with the next of `answers`.
async fn converse(stream: &mut UnixStream, answers: &[&str]) -> Exchanged {
    let mut prompts = Vec::new();
    let mut answers = answers.iter();
    loop {
        match read_frame(stream).await {
            Frame::Response(response) => return Exchanged { prompts, response },
            Frame::Notice(_) => {}
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

/// The error code and message of an error response; never a secret typed at a prompt.
fn error_of(response: &AdminResponse) -> (ErrorCode, String) {
    match response {
        AdminResponse::Error { code, message } => {
            [SECRET, USERNAME, PASSWORD]
                .iter()
                .for_each(|typed| assert!(!message.contains(typed), "a typed value reached the message: {message}"));
            (*code, message.clone())
        }
        other => panic!("expected an error, got {other:?}"),
    }
}

fn added(response: &AdminResponse) -> RecordId {
    match response {
        AdminResponse::Add { record_id } => *record_id,
        other => panic!("expected `add` to succeed, got {other:?}"),
    }
}

async fn credentials<F: StoreFs + Send + Sync + 'static>(service: &Arc<ServiceContext<F>>) -> Vec<CredentialStanding> {
    match service.status().await {
        StatusReport {
            vault: VaultStatus::Unlocked(vault),
            ..
        } => vault
            .credentials
            .into_iter()
            .map(|credential| CredentialStanding {
                summary: None,
                ..credential
            })
            .collect(),
        other => panic!("no open vault: {other:?}"),
    }
}

fn healthy(name: &str) -> CredentialStanding {
    CredentialStanding {
        name: name.parse().unwrap(),
        standing: Standing::Healthy,
        unavailable_routes: Vec::new(),
        summary: None,
    }
}

fn secret_prompt(label: &str) -> Prompt {
    Prompt {
        label: label.to_owned(),
        secret: true,
    }
}

/// Everything this test binary logs at TRACE, from a global subscriber installed on first use.
fn captured_logs() -> Captured {
    static CAPTURED: OnceLock<Captured> = OnceLock::new();
    CAPTURED
        .get_or_init(|| {
            let captured = Captured::default();
            let subscriber = tracing_subscriber::fmt()
                .with_max_level(tracing::Level::TRACE)
                .with_writer(captured.clone())
                .with_ansi(false)
                .finish();
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

    fn assert_no_secret(&self) {
        let text = self.text();
        [SECRET, USERNAME, PASSWORD, APPROVAL_PASSPHRASE]
            .iter()
            .for_each(|typed| assert!(!text.contains(typed), "a typed value reached the log:\n{text}"));
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

/// Which step of the next vault write fails; the last two stages are reached only through the one before each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    /// The rename that puts a new record file in place.
    RecordRename,
    /// The rename that commits the manifest, and then the removal of the new record file, so it is left unindexed.
    ManifestRename,
    /// The state directory fsync after the manifest rename: the commit is uncertain.
    ManifestSyncDir,
    /// [`Fault::ManifestRename`] fired: the next removal of a record file fails.
    KeepRecord,
    /// The manifest was renamed under [`Fault::ManifestSyncDir`]: the next directory fsync fails.
    SyncDirAfterManifest,
}

/// The real filesystem, except for one armed [`Fault`], which fires once.
#[derive(Clone, Default)]
struct FailingFs(Arc<Mutex<Option<Fault>>>);

impl FailingFs {
    fn arm(&self, fault: Fault) {
        *self.0.lock().unwrap() = Some(fault);
    }

    /// Whether `stage` is armed and `reached`; if so, moves on to `next`.
    fn advance(&self, stage: Fault, reached: bool, next: Option<Fault>) -> bool {
        let mut armed = self.0.lock().unwrap();
        let fires = *armed == Some(stage) && reached;
        if fires {
            *armed = next;
        }
        fires
    }
}

fn injected() -> io::Error {
    io::Error::other("injected fault")
}

fn named(path: &Path, prefix: &str) -> bool {
    path.file_name().is_some_and(|name| name.to_string_lossy().starts_with(prefix))
}

impl StoreFs for FailingFs {
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
        let manifest = named(to, "manifest.age");
        if self.advance(Fault::RecordRename, named(to, "record-"), None)
            || self.advance(Fault::ManifestRename, manifest, Some(Fault::KeepRecord))
        {
            return Err(injected());
        }
        OsFs.rename(from, to)?;
        self.advance(Fault::ManifestSyncDir, manifest, Some(Fault::SyncDirAfterManifest));
        Ok(())
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        match self.advance(Fault::KeepRecord, named(path, "record-"), None) {
            true => Err(injected()),
            false => OsFs.remove_file(path),
        }
    }

    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        match self.advance(Fault::SyncDirAfterManifest, true, None) {
            true => Err(injected()),
            false => OsFs.sync_dir(dir),
        }
    }

    fn list_dir(&self, dir: &Path) -> io::Result<Vec<OsString>> {
        OsFs.list_dir(dir)
    }

    fn read_bounded(&self, path: &Path, max_len: u64) -> io::Result<Vec<u8>> {
        OsFs.read_bounded(path, max_len)
    }
}

#[tokio::test]
async fn an_add_in_ready_writes_a_record_and_leaves_the_served_snapshot_alone() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    let Admission::Serve(before) = service.holder().load() else {
        panic!("a Ready service serves a snapshot");
    };

    let exchanged = add(&fixture, &service, "fx").await;

    let record_id = added(&exchanged.response);
    assert_eq!(exchanged.prompts, vec![secret_prompt("Secret for fx")]);
    assert_eq!(fixture.record_id("fx"), Some(record_id));
    let record = fixture.record(&record_id);
    assert_eq!(record.kind(), CredentialKind::Static);
    assert_eq!(record.origins(), &fixture.origins());
    match record.material() {
        CredentialMaterial::Static { key } => assert_eq!(key.expose_secret(), SECRET),
        other => panic!("expected a static key, got {other:?}"),
    }
    assert_eq!(credentials(&service).await, vec![healthy("fx"), healthy("fx_key")]);
    let Admission::Serve(after) = service.holder().load() else {
        panic!("the service still serves");
    };
    assert!(Arc::ptr_eq(&before, &after), "the add replaced the served snapshot");
    assert!(
        tokio::time::timeout(Duration::from_millis(50), before.withdrawn()).await.is_err(),
        "the add withdrew the served snapshot"
    );
    assert_eq!(get(&fixture, "fx").await.status, 200);
    let line = format!("record_id={record_id}");
    assert!(
        logs.text()
            .lines()
            .any(|l| l.contains("credential.added") && l.contains(&line) && l.contains("kind=\"static\"")),
        "{}",
        logs.text()
    );
    logs.assert_no_secret();
}

#[tokio::test]
async fn a_basic_credential_is_prompted_for_its_username_then_its_password() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;

    let request = add_request(&fixture, "billing", CredentialKind::Basic);
    let exchanged = exchange(&service, request, &[USERNAME, PASSWORD]).await;

    let record_id = added(&exchanged.response);
    assert_eq!(
        exchanged.prompts,
        vec![secret_prompt("Username for billing"), secret_prompt("Password for billing")]
    );
    match fixture.record(&record_id).material() {
        CredentialMaterial::Basic { username, password } => {
            assert_eq!((username.expose_secret(), password.expose_secret()), (USERNAME, PASSWORD));
        }
        other => panic!("expected a Basic credential, got {other:?}"),
    }
    logs.assert_no_secret();
}

#[tokio::test]
async fn an_existing_name_is_taken_whether_its_record_is_healthy_or_damaged() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    let manifest = fixture.manifest_bytes();

    let healthy = add(&fixture, &service, "fx_key").await;

    assert_eq!(error_of(&healthy.response).0, ErrorCode::NameTaken);
    assert_eq!(fixture.manifest_bytes(), manifest);

    fs::remove_file(fixture.record_path(&fixture.record_id("fx_key").unwrap())).unwrap();
    let damaged = add(&fixture, &service, "fx_key").await;

    assert_eq!(error_of(&damaged.response).0, ErrorCode::NameTaken);
    assert_eq!(fixture.manifest_bytes(), manifest);
}

#[tokio::test]
async fn invalid_names_origins_and_material_are_refused_without_echoing_them() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    let manifest = fixture.manifest_bytes();
    let bad_origin = |host: &str| AdminRequest::Add {
        name: "fx".to_owned(),
        kind: CredentialKind::Static,
        origins: vec![RequestedOrigin {
            host: host.to_owned(),
            port: 443.try_into().unwrap(),
        }],
    };

    let name = exchange(&service, add_request(&fixture, "Q-name", CredentialKind::Static), &[]).await;
    let (code, message) = error_of(&name.response);
    assert_eq!((code, name.prompts.len()), (ErrorCode::CredentialInvalid, 0));
    assert!(!message.contains("Q-name") && !message.contains("'Q'"), "{message}");
    for host in ["api.example:8443", "api.example/v1", "https://api.example", "bad host"] {
        let origin = exchange(&service, bad_origin(host), &[]).await;
        assert_eq!(
            (error_of(&origin.response).0, origin.prompts.len()),
            (ErrorCode::CredentialInvalid, 0),
            "{host}"
        );
    }
    let material = exchange(&service, add_request(&fixture, "fx", CredentialKind::Static), &[""]).await;
    assert_eq!(error_of(&material.response).0, ErrorCode::CredentialInvalid);
    let colon = exchange(
        &service,
        add_request(&fixture, "fx", CredentialKind::Basic),
        &["ADD-USER:x", PASSWORD],
    )
    .await;
    let (code, message) = error_of(&colon.response);
    assert_eq!(code, ErrorCode::CredentialInvalid);
    assert!(!message.contains("ADD-USER"), "{message}");
    assert_eq!(fixture.manifest_bytes(), manifest);
}

#[tokio::test]
async fn a_locked_or_unavailable_service_refuses_before_any_prompt() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    service.lock(WAIT).await.unwrap();

    let locked = add(&fixture, &service, "fx").await;

    assert_eq!(error_of(&locked.response).0, ErrorCode::WrongState);
    assert!(locked.prompts.is_empty());
    drop(service);

    let fixture = Fixture::new().await;
    fs::write(fixture.path("etc/config.toml"), fixture.config(&[("edited", "fx_key")])).unwrap();
    let service = fixture.start_with(OsFs).await;
    assert_eq!(service.state().await, ServiceState::Unavailable(FailureReason::PolicyInvalid));

    let unavailable = add(&fixture, &service, "fx").await;

    let (code, message) = error_of(&unavailable.response);
    assert_eq!(code, ErrorCode::WrongState);
    assert!(message.contains("Unavailable (policy invalid)"), "{message}");
    assert!(unavailable.prompts.is_empty());
    assert_eq!(fixture.record_id("fx"), None);
}

#[tokio::test]
async fn a_failed_record_write_changes_nothing_and_the_next_add_succeeds() {
    let fixture = Fixture::new().await;
    let fs = FailingFs::default();
    let service = fixture.ready_with(fs.clone()).await;
    let manifest = fixture.manifest_bytes();
    let records = fixture.record_files();
    fs.arm(Fault::RecordRename);

    let failed = add(&fixture, &service, "fx").await;

    let (code, message) = error_of(&failed.response);
    assert_eq!(code, ErrorCode::VaultWriteFailed);
    assert!(message.contains("nothing changed"), "{message}");
    assert_eq!(fixture.manifest_bytes(), manifest);
    assert_eq!(fixture.record_files(), records);
    assert_eq!(credentials(&service).await, vec![healthy("fx_key")]);

    added(&add(&fixture, &service, "fx").await.response);
    assert!(fixture.record_id("fx").is_some());
}

#[tokio::test]
async fn a_failed_manifest_rename_changes_nothing_and_the_next_add_sweeps_the_unindexed_file() {
    let fixture = Fixture::new().await;
    let fs = FailingFs::default();
    let service = fixture.ready_with(fs.clone()).await;
    let manifest = fixture.manifest_bytes();
    let records = fixture.record_files();
    fs.arm(Fault::ManifestRename);

    let failed = add(&fixture, &service, "fx").await;

    let (code, message) = error_of(&failed.response);
    assert_eq!(code, ErrorCode::VaultWriteFailed);
    assert!(message.contains("nothing changed"), "{message}");
    assert_eq!(fixture.manifest_bytes(), manifest);
    let unindexed = fixture
        .record_files()
        .into_iter()
        .filter(|file| !records.contains(file))
        .collect::<Vec<_>>();
    assert_eq!(unindexed.len(), 1, "the injected fault keeps the new record file, unindexed");

    let record_id = added(&add(&fixture, &service, "fx").await.response);
    assert!(
        !fixture.path("state").join(&unindexed[0]).exists(),
        "the next add sweeps the unindexed file"
    );
    assert_eq!(fixture.record_files().len(), records.len() + 1);
    assert_eq!(fixture.record_id("fx"), Some(record_id));
}

#[tokio::test]
async fn an_uncertain_commit_reports_what_the_reopened_vault_shows() {
    let fixture = Fixture::new().await;
    let fs = FailingFs::default();
    let service = fixture.ready_with(fs.clone()).await;
    fs.arm(Fault::ManifestSyncDir);

    let uncertain = add(&fixture, &service, "fx").await;

    let (code, message) = error_of(&uncertain.response);
    assert_eq!(code, ErrorCode::VaultWriteFailed);
    assert!(
        message.contains("may not survive power loss") && message.contains("so it was added"),
        "{message}"
    );
    assert!(fixture.record_id("fx").is_some());
    assert_eq!(credentials(&service).await, vec![healthy("fx"), healthy("fx_key")]);
}

#[tokio::test]
async fn an_add_while_an_approval_waits_at_its_prompt_is_busy() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    let manifest = fixture.manifest_bytes();
    let (path, stop) = serve_admin(&service);
    let mut approval = UnixStream::connect(&path).await.unwrap();
    let config = fixture.config(&[("rates", "fx_key")]).into_bytes();
    send(
        &mut approval,
        &Frame::Request(AdminRequest::ConfigApprove(ProposedConfig::new(config).unwrap())),
    )
    .await;
    while !matches!(read_frame(&mut approval).await, Frame::Prompt(_)) {}

    let busy = add(&fixture, &service, "fx").await;

    assert_eq!(error_of(&busy.response).0, ErrorCode::Busy);
    assert_eq!(fixture.manifest_bytes(), manifest);
    send(&mut approval, &Frame::OwnerInput(OwnerInput::new(Zeroizing::new(b"no".to_vec())))).await;
    assert_eq!(error_of(&converse(&mut approval, &[]).await.response).0, ErrorCode::Declined);
    let _ = stop.send(());
}

#[tokio::test]
async fn an_added_credential_serves_once_a_route_using_it_is_approved() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    added(&add(&fixture, &service, "fx").await.response);
    assert_eq!(
        get(&fixture, "rates").await.status,
        404,
        "no route uses the new credential before an approval"
    );

    let config = fixture.config(&[("fx", "fx_key"), ("rates", "fx")]).into_bytes();
    let request = AdminRequest::ConfigApprove(ProposedConfig::new(config).unwrap());
    let approved = exchange(&service, request, &["yes", APPROVAL_PASSPHRASE]).await;

    assert!(
        matches!(approved.response, AdminResponse::ConfigApprove(_)),
        "{:?}",
        approved.response
    );
    assert_eq!(service.state().await, ServiceState::Ready);
    assert_eq!(get(&fixture, "rates").await.status, 200);
    let injected = fixture.upstream.requests().last().unwrap().headers();
    assert!(
        injected
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("x-api-key") && value == SECRET),
        "{injected:?}"
    );
    logs.assert_no_secret();
}

#[tokio::test]
async fn a_credential_added_to_a_running_service_is_listed_with_its_kind_and_origins_without_a_reload() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    let added_origins = fixture.origins().iter().cloned().collect::<Vec<_>>();

    added(&add(&fixture, &service, "fx").await.response);

    let listed = service.list().await.unwrap();
    let entry = listed.iter().find(|credential| credential.name.as_str() == "fx").unwrap();
    assert_eq!(entry.standing, Standing::Healthy);
    let summary = entry.summary.as_ref().unwrap();
    assert_eq!((summary.kind, &summary.origins), (CredentialKind::Static, &added_origins));
    assert_eq!(
        listed.iter().map(|credential| credential.name.as_str()).collect::<Vec<_>>(),
        ["fx", "fx_key"]
    );
}
