//! The service context end to end: startup Locked with provisional listeners from the unverified config, entering
//! Checking with a known vault identity (no prompt), the listener rebuild on entry to Ready, and stop (specification
//! §3.1, §3.4, §3.9, §3.11, §3.12).
//!
//! Each test builds a vault and an approval state in a temporary state directory and approves a config through the
//! approval transaction, then releases both locks so the service takes them. The service account is the test's own uid.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use common::mock_upstream::{MockUpstream, Reply, TestCa};
use common::proxy_harness::{CallerRequest, Response, TOKEN_BYTES, TOKEN_HEADER, TempDir, Via, WAIT, next_free_port, token_hash};
use ed25519_dalek::{Signer, SigningKey};
use iron_vault::admin::ADMIN_SOCKET_NAME;
use iron_vault::admin::dispatch::Handlers;
use iron_vault::admin::principal::AdminPrincipals;
use iron_vault::admin::protocol::{
    self, AdminRequest, AdminResponse, CredentialStatus, Decoded, Frame, MemoryStatus, Standing, StatusReport, VaultStatus,
};
use iron_vault::admin::server::{AdminServer, Limits};
use iron_vault::admin::socket::AdminSocket;
use iron_vault::config_check::UpstreamSettings;
use iron_vault::deployment::{Accounts, DeploymentProfile, PasswdDirectory};
use iron_vault::hardening::{CoreDumps, HardeningReport, MemoryProtection};
use iron_vault::path_metadata::invoking_user;
use iron_vault::service_context::{ServiceContext, ServiceLocks, ServiceSetup, StartError};
use iron_vault::service_state::{FailureReason, ListenerProvenance, ServiceState, UnavailableReason};
use iron_vault::serving_snapshot::{Admission, SnapshotHolder};
use iron_vault::trusted_path_report::ServicePaths;
use iron_vault::upstream::client::TransportLimits;
use iron_vault_kinds::CredentialMaterial;
use iron_vault_policy::{Capabilities, ListenerName};
use iron_vault_store::{
    ApprovalEnvelope, ApprovalPayload, ApprovalSigner, ApprovalState, ApprovalStorage, ConfigDirLock, LockError, OsFs, PendingConfig,
    PermittedOrigins, PinnedApprover, RecordDamage, SignError, SignatureAlgorithm, StateDirLock, Vault, VaultIdentity,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};
use tokio::sync::oneshot;

const IDENTITY: &str = "AGE-SECRET-KEY-1QYPQXPQ9QCRSSZG2PVXQ6RS0ZQG3YYC5Z5TPWXQERGD3C8G7RUSQGPQYEE";
const SECRET: &str = "fx-secret-4b1d";

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
        let dir = TempDir::new();
        mkdir(&dir.path().join("state"), 0o700);
        mkdir(&dir.path().join("etc"), 0o700);
        let ca = TestCa::new("service test CA");
        let reply = Reply::Respond {
            status: 200,
            headers: Vec::new(),
            body: b"ok".to_vec(),
        };
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
        let paths = self.paths();
        let locks = ServiceLocks::acquire(&paths)?;
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
        Ok(Arc::new(
            ServiceContext::start(locks, setup, &provisional, BTreeMap::new()).unwrap(),
        ))
    }
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

/// Serves `service`'s admin handlers on its runtime directory and sends `ping` over the admin protocol. It does not run
/// the CLI binary: a child forked while another test holds a directory lock would hold that lock too until it execs.
async fn ping(service: &Arc<ServiceContext>) -> AdminResponse {
    admin(service, AdminRequest::Ping).await.1
}

/// Sends `status` over the admin protocol and returns the response frame's bytes with the decoded report.
async fn status(service: &Arc<ServiceContext>) -> (Vec<u8>, StatusReport) {
    match admin(service, AdminRequest::Status).await {
        (bytes, AdminResponse::Status(report)) => (bytes, *report),
        (_, other) => panic!("expected a status report, got {other:?}"),
    }
}

async fn admin(service: &Arc<ServiceContext>, request_frame: AdminRequest) -> (Vec<u8>, AdminResponse) {
    let paths = service.paths().clone();
    let runtime_dir = paths.runtime_dir.clone().unwrap();
    let socket = AdminSocket::bind(&runtime_dir, paths.owner).unwrap();
    let server = AdminServer::new(
        AdminPrincipals::new(paths.profile, paths.owner.uid),
        Handlers::for_service(service),
        Limits::default(),
    );
    let (stop, stopped) = oneshot::channel::<()>();
    let served = tokio::spawn(async move {
        server
            .serve(socket, async {
                let _ = stopped.await;
            })
            .await
    });
    let mut stream = UnixStream::connect(runtime_dir.join(ADMIN_SOCKET_NAME)).await.unwrap();
    let mut sent = Vec::new();
    protocol::encode(&Frame::Request(request_frame), &mut sent).unwrap();
    stream.write_all(&sent).await.unwrap();
    let mut bytes = Vec::new();
    tokio::time::timeout(WAIT, stream.read_to_end(&mut bytes)).await.unwrap().unwrap();
    let _ = stop.send(());
    served.await.unwrap().unwrap();
    match protocol::decode(&bytes).unwrap() {
        Decoded::Frame {
            frame: Frame::Response(response),
            ..
        } => (bytes, response),
        other => panic!("expected a response, got {other:?}"),
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

    service.stop().await;

    assert_eq!(service.state().await, ServiceState::Stopped);
    assert!(vault.upgrade().is_none(), "the snapshot holding the vault outlived stop");
    assert!(!fixture.socket().exists());
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
            |CredentialStatus {
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
