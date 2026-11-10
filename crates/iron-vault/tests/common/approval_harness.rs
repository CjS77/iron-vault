//! The `config approve` test harness: a vault holding `fx_key` with a software approver, a running service context on it
//! (over the real filesystem or any [`StoreFs`]), the admin conversation that drives `config approve`, and a captured
//! log that must never hold an approval passphrase.
//!
//! The vault is built in a temporary directory that is also the runtime directory, with its base config approved as
//! version 1. The service account is the test's own uid.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use super::mock_upstream::{MockUpstream, Reply, TestCa};
use super::proxy_harness::{CallerRequest, Response, TOKEN_BYTES, TOKEN_HEADER, TempDir, Via, WAIT, token_hash};
use iron_vault::admin::ADMIN_SOCKET_NAME;
use iron_vault::admin::dispatch::Handlers;
use iron_vault::admin::principal::AdminPrincipals;
use iron_vault::admin::protocol::{
    self, AdminRequest, AdminResponse, Decoded, ErrorCode, Frame, OwnerInput, Prompt, ProposedConfig, RevealedSecret, StatusReport,
    VaultStatus,
};
use iron_vault::admin::server::{AdminServer, Limits};
use iron_vault::admin::socket::AdminSocket;
use iron_vault::clock::{SystemClock, TestClock, WallClock};
use iron_vault::config_check::UpstreamSettings;
use iron_vault::deployment::{Accounts, DeploymentProfile, PasswdDirectory};
use iron_vault::hardening::{CoreDumps, HardeningReport, MemoryProtection};
use iron_vault::logging::LogSwitch;
use iron_vault::path_metadata::invoking_user;
use iron_vault::service_context::{ServiceContext, ServiceLocks, ServiceSetup, StartError};
use iron_vault::service_state::ServiceState;
use iron_vault::service_state::UnavailableReason;
use iron_vault::serving_snapshot::SnapshotHolder;
use iron_vault::socket_activation::PassedSockets;
use iron_vault::trusted_path_report::ServicePaths;
use iron_vault::upstream::client::TransportLimits;
use iron_vault_kinds::CredentialMaterial;
use iron_vault_policy::Capabilities;
use iron_vault_store::{
    ApprovalPassphrase, ApprovalState, ApprovalStorage, ApproverId, ConfigDigest, ConfigDirLock, LockError, OsFs, PendingConfig,
    PermittedOrigins, PinnedApprover, SoftwareSigner, StateDirLock, StoreFs, Vault, VaultIdentity, open_signer_key,
    seal_signer_key_for_tests, write_signer_key,
};
use secrecy::SecretString;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing_subscriber::fmt::MakeWriter;
use zeroize::Zeroizing;

pub const IDENTITY: &str = "AGE-SECRET-KEY-1QYPQXPQ9QCRSSZG2PVXQ6RS0ZQG3YYC5Z5TPWXQERGD3C8G7RUSQGPQYEE";
/// The approval passphrase, and a wrong one; distinctive, so a search of the logs cannot match anything else.
pub const APPROVAL_PASSPHRASE: &str = "APPROVAL-correct-3e8b";
pub const WRONG_PASSPHRASE: &str = "APPROVAL-wrong-6f04";
pub const CONFIRM: &str = "Approve this config as version";

pub fn identity() -> VaultIdentity {
    VaultIdentity::from_secret(IDENTITY)
}

pub fn approval_passphrase(text: &str) -> ApprovalPassphrase {
    ApprovalPassphrase::new(SecretString::from(text)).unwrap()
}

pub fn mkdir(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

/// A vault holding `fx_key` with a software approver, in a temporary directory that is also the runtime directory, and
/// the base config approved as version 1. No lock is held between steps, so a step that takes one waits out a lock the
/// last step dropped but a child mid-exec still shares ([`LOCK_PATIENCE`]).
pub struct Fixture {
    dir: TempDir,
    ca: TestCa,
    upstream: MockUpstream,
}

impl Fixture {
    pub async fn new() -> Self {
        Self::with_reply(Reply::Respond {
            status: 200,
            headers: Vec::new(),
            body: b"ok".to_vec(),
        })
        .await
    }

    /// [`new`](Self::new) with an upstream that answers every request with `reply`.
    pub async fn with_reply(reply: Reply) -> Self {
        let dir = TempDir::new();
        mkdir(&dir.path().join("state"));
        mkdir(&dir.path().join("etc"));
        let ca = TestCa::new("approve test CA");
        let upstream = MockUpstream::start(&ca, reply).await;
        let fixture = Self { dir, ca, upstream };
        let mut state = fixture.create_vault();
        fixture.approve_through_store(&mut state, &fixture.config("fx"));
        fixture
    }

    /// The vault, `approver.age` and the approval state pinning its key.
    pub fn create_vault(&self) -> ApprovalState {
        let lock = self.state_lock();
        let mut vault = Vault::create(&lock, &OsFs, identity()).unwrap();
        let port = self.upstream.port().to_string().parse().unwrap();
        let origins = PermittedOrigins::new([("localhost".parse().unwrap(), port)].into()).unwrap();
        let material = CredentialMaterial::Static { key: "fx-secret".into() };
        vault.add(&lock, &OsFs, "fx_key".parse().unwrap(), material, origins).unwrap();
        let (key, pinned) = SoftwareSigner::generate().unwrap();
        let sealed = seal_signer_key_for_tests(&key, &approval_passphrase(APPROVAL_PASSPHRASE)).unwrap();
        write_signer_key(&lock, &OsFs, &sealed).unwrap();
        vault
            .create_approval_state(&lock, &OsFs, PinnedApprover::for_tests(pinned))
            .unwrap()
            .0
    }

    /// The ID of the one approver the vault pins. Read under the state-directory lock, so call it before the service
    /// starts.
    pub fn approver_id(&self) -> ApproverId {
        let lock = self.state_lock();
        let (vault, _) = Vault::open(&lock, &OsFs, identity()).unwrap();
        vault.load_approval_state(&lock, &OsFs).unwrap().approvers()[0].id()
    }

    fn state_lock(&self) -> StateDirLock {
        wait_out_held(|| StateDirLock::acquire(&self.path("state")), is_held, "the state-directory lock")
    }

    /// Approves and publishes `config` through the store's transaction, as `config approve` would.
    pub fn approve_through_store(&self, state: &mut ApprovalState, config: &str) {
        let state_dir = self.state_lock();
        let config_dir = wait_out_held(|| ConfigDirLock::acquire(&self.path("etc")), is_held, "the config-directory lock");
        let identity = identity();
        let storage = ApprovalStorage {
            state_dir: &state_dir,
            config_dir: &config_dir,
            identity: &identity,
            fs: &OsFs,
        };
        let envelope = iron_vault_store::read_signer_key(&state_dir, &OsFs).unwrap();
        let signer = open_signer_key(&envelope, &approval_passphrase(APPROVAL_PASSPHRASE), state.approvers()).unwrap();
        let holder = SnapshotHolder::refusing(UnavailableReason::Checking);
        let pending = PendingConfig::write(&storage, config.as_bytes().to_vec()).unwrap();
        let prepared = pending.prepare(&storage, state, signer).unwrap();
        prepared.commit(&storage, &holder.pause()).unwrap();
    }

    /// The upstream every route of [`config`](Self::config) forwards to.
    pub fn upstream(&self) -> &MockUpstream {
        &self.upstream
    }

    /// The CA the service pins for upstreams, so a second test upstream it issues is trusted too.
    pub fn ca(&self) -> &TestCa {
        &self.ca
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// The service's two config files, `config.toml` then `config.toml.sig`.
    pub fn published_pair(&self) -> [Vec<u8>; 2] {
        ["config.toml", "config.toml.sig"].map(|file| fs::read(self.path(&format!("etc/{file}"))).unwrap())
    }

    /// Writes `pair` back over the service's two config files, as someone rolling back an approval would.
    pub fn put_back(&self, pair: &[Vec<u8>; 2]) {
        ["config.toml", "config.toml.sig"]
            .iter()
            .zip(pair)
            .for_each(|(file, bytes)| fs::write(self.path(&format!("etc/{file}")), bytes).unwrap());
    }

    pub fn socket(&self) -> PathBuf {
        self.path("proxy.sock")
    }

    /// The config with the Unix listener `local`, its token caller granted the route `route` on `fx_key`.
    pub fn config(&self, route: &str) -> String {
        self.config_with(route, "fx_key")
    }

    pub fn config_with(&self, route: &str, credential: &str) -> String {
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
paths = ["/**"]
rate_limit = {{ requests = 100000, per_seconds = 1, burst = 100000 }}
"#,
            socket = self.socket().display(),
            hash = token_hash(TOKEN_BYTES),
            port = self.upstream.port(),
        )
    }

    /// Starts the service on this fixture's directories, over the real filesystem, and enters Checking with the vault
    /// identity.
    pub async fn start(&self) -> Arc<ServiceContext> {
        self.start_on(OsFs).await
    }

    /// [`start`](Self::start) with every vault and config file going through `fs`.
    pub async fn start_on<F: StoreFs + Send + Sync + 'static>(&self, fs: F) -> Arc<ServiceContext<F>> {
        self.start_logging(fs, LogSwitch::stdout_for_tests(invoking_user().unwrap()).unwrap())
            .await
    }

    /// [`start_on`](Self::start_on), with the service moving its log through `log`.
    pub async fn start_logging<F: StoreFs + Send + Sync + 'static>(&self, fs: F, log: LogSwitch) -> Arc<ServiceContext<F>> {
        self.start_clocked(fs, log, Arc::new(SystemClock)).await
    }

    /// [`start`](Self::start), checked to have reached Ready, with the service reading the time from `clock`.
    pub async fn ready_at(&self, clock: Arc<TestClock>) -> Arc<ServiceContext> {
        let log = LogSwitch::stdout_for_tests(invoking_user().unwrap()).unwrap();
        let service = self.start_clocked(OsFs, log, clock).await;
        assert_eq!(service.state().await, ServiceState::Ready);
        service
    }

    async fn start_clocked<F: StoreFs + Send + Sync + 'static>(
        &self,
        fs: F,
        log: LogSwitch,
        clock: Arc<dyn WallClock>,
    ) -> Arc<ServiceContext<F>> {
        let service = self.start_as(fs, log, DeploymentProfile::Development, MemoryProtection::Unsupported);
        let service = Arc::new(service.with_clock(clock));
        service.enter_checking(identity()).await.unwrap();
        service
    }

    /// The service started as a `profile` install whose hardening left `memory`, as `start` leaves it: no unlock.
    pub fn start_as<F: StoreFs + Send + Sync + 'static>(
        &self,
        fs: F,
        log: LogSwitch,
        profile: DeploymentProfile,
        memory: MemoryProtection,
    ) -> ServiceContext<F> {
        let paths = ServicePaths {
            profile,
            owner: invoking_user().unwrap(),
            config: self.path("etc/config.toml"),
            state_dir: self.path("state"),
            runtime_dir: Some(self.dir.path().to_path_buf()),
        };
        let locks = wait_out_held(|| ServiceLocks::acquire(&paths), start_is_held, "the service's locks");
        let provisional = locks.unverified_listeners(&fs);
        let setup = ServiceSetup {
            accounts: PasswdDirectory::new(Accounts::parse(""), &paths, Path::new("/nonexistent")).unwrap(),
            paths,
            fs,
            capabilities: Capabilities::default(),
            upstream: UpstreamSettings::new(DeploymentProfile::Development, invoking_user().unwrap(), TransportLimits::default())
                .with_pinned_trust(self.ca.trust()),
            hardening: HardeningReport {
                core_dumps: CoreDumps::Disabled,
                memory,
            },
            log,
        };
        ServiceContext::start(locks, setup, &provisional, PassedSockets::default()).unwrap()
    }

    /// [`start`](Self::start), checked to have reached Ready.
    pub async fn ready(&self) -> Arc<ServiceContext> {
        self.ready_on(OsFs).await
    }

    /// [`start_on`](Self::start_on), checked to have reached Ready.
    pub async fn ready_on<F: StoreFs + Send + Sync + 'static>(&self, fs: F) -> Arc<ServiceContext<F>> {
        let service = self.start_on(fs).await;
        assert_eq!(service.state().await, ServiceState::Ready);
        service
    }
}

/// How long the harness waits out `Held` on a lock it dropped. A test thread that spawns a child shares every open file
/// with it from fork until exec, so a lock this thread dropped can stay held for that long by a process about to exec;
/// exec takes milliseconds, so a lock still held after this is a real conflict.
const LOCK_PATIENCE: Duration = Duration::from_secs(5);
const LOCK_RETRY: Duration = Duration::from_millis(10);

/// The result of `acquire`, retried while it fails with `held` until [`LOCK_PATIENCE`] has passed; then the last error
/// fails the test, naming `what`.
fn wait_out_held<T, E: std::fmt::Debug>(acquire: impl Fn() -> Result<T, E>, held: fn(&E) -> bool, what: &str) -> T {
    let deadline = Instant::now() + LOCK_PATIENCE;
    loop {
        match acquire() {
            Err(e) if held(&e) && Instant::now() < deadline => thread::sleep(LOCK_RETRY),
            result => return result.unwrap_or_else(|e| panic!("cannot take {what}: {e:?}")),
        }
    }
}

fn is_held(e: &LockError) -> bool {
    matches!(e, LockError::Held { .. })
}

fn start_is_held(e: &StartError) -> bool {
    matches!(e, StartError::StateLock(held) | StartError::ConfigLock(held) if is_held(held))
}

/// The token caller's `GET /<route>/latest`.
pub async fn get(fixture: &Fixture, route: &str) -> Response {
    let request = CallerRequest::get(&format!("/{route}/latest")).signed(Via::Unix);
    let mut stream = UnixStream::connect(fixture.socket()).await.unwrap();
    stream.write_all(&request.to_bytes()).await.unwrap();
    let mut raw = Vec::new();
    tokio::time::timeout(WAIT, stream.read_to_end(&mut raw)).await.unwrap().unwrap();
    Response::parse(&String::from_utf8(raw).unwrap())
}

/// What one exchange showed the owner and how it ended.
#[derive(Debug)]
pub struct Exchanged {
    pub notices: String,
    pub prompts: Vec<Prompt>,
    pub response: AdminResponse,
}

/// The admin server with the service's handlers on its runtime directory, until `stop` is sent.
pub fn serve_admin<F: StoreFs + Send + Sync + 'static>(service: &Arc<ServiceContext<F>>) -> (PathBuf, oneshot::Sender<()>) {
    let (path, stop, _) = spawn_admin(service);
    (path, stop)
}

/// [`serve_admin`], with the server's task, which ends once the handlers' references to the service are dropped.
pub fn spawn_admin<F: StoreFs + Send + Sync + 'static>(service: &Arc<ServiceContext<F>>) -> (PathBuf, oneshot::Sender<()>, JoinHandle<()>) {
    let paths = service.paths().clone();
    let runtime_dir = paths.runtime_dir.clone().unwrap();
    let socket = AdminSocket::bind(&runtime_dir, paths.owner).unwrap();
    let server = AdminServer::new(
        AdminPrincipals::new(paths.profile, paths.owner.uid),
        Handlers::for_service(service),
        Limits::default(),
    );
    let (stop, stopped) = oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        let _ = server
            .serve(socket, async {
                let _ = stopped.await;
            })
            .await;
    });
    (runtime_dir.join(ADMIN_SOCKET_NAME), stop, task)
}

pub fn approve_request(config: &str) -> Frame {
    Frame::Request(AdminRequest::ConfigApprove(
        ProposedConfig::new(config.as_bytes().to_vec()).unwrap(),
    ))
}

/// Sends `config approve` for `config` and answers the prompts in turn with `answers`.
pub async fn approve<F: StoreFs + Send + Sync + 'static>(service: &Arc<ServiceContext<F>>, config: &str, answers: &[&str]) -> Exchanged {
    let (path, stop, task) = spawn_admin(service);
    let mut stream = UnixStream::connect(path).await.unwrap();
    send(&mut stream, &approve_request(config)).await;
    let exchanged = converse(&mut stream, answers).await;
    let _ = stop.send(());
    // The admin socket is bound again by the next approval, and its handlers hold the service until the server ends.
    let _ = task.await;
    exchanged
}

/// Reads frames until the response, answering each prompt with the next of `answers`. Panics if the service reveals a
/// secret, so a command that should never show one cannot start doing so unnoticed.
pub async fn converse(stream: &mut UnixStream, answers: &[&str]) -> Exchanged {
    let (exchanged, revealed) = converse_revealing(stream, answers).await;
    assert!(revealed.is_empty(), "unexpected reveal: {} secret(s) revealed", revealed.len());
    exchanged
}

/// [`converse`] for a command that reveals secrets (`init`'s recovery key), returning them with the exchange.
pub async fn converse_revealing(stream: &mut UnixStream, answers: &[&str]) -> (Exchanged, Vec<RevealedSecret>) {
    let (mut notices, mut prompts, mut revealed) = (String::new(), Vec::new(), Vec::new());
    let mut answers = answers.iter();
    loop {
        match read_frame(stream).await {
            Frame::Response(response) => {
                return (
                    Exchanged {
                        notices,
                        prompts,
                        response,
                    },
                    revealed,
                );
            }
            Frame::Notice(notice) => notices.push_str(&notice.text),
            Frame::Reveal(secret) => revealed.push(secret),
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

pub async fn send(stream: &mut UnixStream, frame: &Frame) {
    let mut bytes = Vec::new();
    protocol::encode(frame, &mut bytes).unwrap();
    stream.write_all(&bytes).await.unwrap();
}

/// Reads one frame a byte at a time, so nothing of the next frame is consumed.
pub async fn read_frame(stream: &mut UnixStream) -> Frame {
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
pub async fn versions<F: StoreFs + Send + Sync + 'static>(service: &Arc<ServiceContext<F>>) -> (Option<u64>, u64) {
    match service.status().await {
        StatusReport {
            vault: VaultStatus::Unlocked(vault),
            ..
        } => (vault.committed, vault.highest_reserved),
        other => panic!("no open vault: {other:?}"),
    }
}

pub fn error_code(response: &AdminResponse) -> ErrorCode {
    match response {
        AdminResponse::Error { code, .. } => *code,
        other => panic!("expected an error, got {other:?}"),
    }
}

pub fn the_two_prompts(version: u64) -> Vec<Prompt> {
    the_two_prompts_for(version, "approval passphrase")
}

/// The confirmation, then the passphrase prompt naming the approver labelled `approver`.
pub fn the_two_prompts_for(version: u64, approver: &str) -> Vec<Prompt> {
    vec![
        Prompt {
            label: format!("{CONFIRM} {version}? Type yes to approve"),
            secret: false,
        },
        Prompt {
            label: format!("Approval passphrase for \"{approver}\""),
            secret: true,
        },
    ]
}

/// Everything this test binary logs, from a global subscriber installed on first use.
pub fn captured_logs() -> Captured {
    static CAPTURED: OnceLock<Captured> = OnceLock::new();
    CAPTURED
        .get_or_init(|| {
            let captured = Captured::default();
            let subscriber = iron_vault::logging::subscriber(captured.clone(), DeploymentProfile::current());
            tracing::subscriber::set_global_default(subscriber).unwrap();
            captured
        })
        .clone()
}

/// Checks that `record` is an audit record of `level` whose own fields, besides the keys every record has, are exactly
/// `own`.
pub fn assert_audit_record(record: &serde_json::Value, level: &str, own: &[&str]) {
    const SHARED: [&str; 9] = [
        "timestamp",
        "level",
        "target",
        "message",
        "event",
        "service",
        "service_version",
        "schema_version",
        "deployment_profile",
    ];
    let mut keys: Vec<&str> = record
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .filter(|k| !SHARED.contains(k))
        .collect();
    keys.sort_unstable();
    let mut expected = own.to_vec();
    expected.sort_unstable();
    assert_eq!(
        (record["level"].as_str(), record["target"].as_str()),
        (Some(level), Some("iron-vault.audit")),
        "{record}"
    );
    assert_eq!(keys, expected, "{record}");
}

/// Asserts `record` names the approver `id` with the label `init` gives the software signer.
pub fn assert_names_approver(record: &serde_json::Value, id: ApproverId) {
    assert_eq!(record["approver_id"], id.to_string().as_str(), "{record}");
    assert_eq!(record["approver_label"], "approval passphrase", "{record}");
}

#[derive(Clone, Default)]
pub struct Captured(Arc<Mutex<Vec<u8>>>);

impl Captured {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap_or_else(PoisonError::into_inner)).into_owned()
    }

    /// Every record whose `event` is `event`.
    pub fn events(&self, event: &str) -> Vec<serde_json::Value> {
        self.text()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .filter(|record| record["event"] == event)
            .collect()
    }

    /// Whether a record of `event` has `field` equal to `value`, written as a string or a number.
    pub fn has_field(&self, event: &str, field: &str, value: &str) -> bool {
        self.events(event)
            .iter()
            .any(|record| record[field].as_str() == Some(value) || value.parse::<u64>().is_ok_and(|number| record[field] == number))
    }

    /// Whether a record of `event` names `version` and `digest`. The digest tells this test's approval apart from
    /// another test's at the same version, since every test logs into this one buffer.
    ///
    /// The store's own records still write the version as a string and the digest as `digest`, until their facts move
    /// to the binary's audit events; the binary's events write a number and `config_digest`.
    pub fn has_event(&self, event: &str, version: u64, digest: &ConfigDigest) -> bool {
        let digest = digest.to_string();
        self.events(event).iter().any(|record| {
            let version_matches = record["version"] == version || record["version"] == version.to_string().as_str();
            version_matches && (record["config_digest"] == digest.as_str() || record["digest"] == digest.as_str())
        })
    }

    pub fn assert_no_passphrase(&self) {
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
