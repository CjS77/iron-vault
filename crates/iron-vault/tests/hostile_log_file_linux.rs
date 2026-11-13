//! The whole log file after a hostile run holds none of the never-log values (specification §18; `design/audit-logging.md`,
//! "Never logged"; K-85 and K-95 do the same for the stderr log of the upstream client).
//!
//! The service logs through the rolling-file destination (`LogFile` in a verified directory) with the production
//! subscriber at global `TRACE` (`subscriber_at`), where the service itself installs `INFO` and ignores `RUST_LOG`.
//! The binary runs with `RUST_LOG=trace` too. The run first initializes a vault and unlocks it, after a wrong
//! passphrase. Then it sends requests that use a header slot, a query slot and Basic, with a caller token, a query string,
//! a `Proxy-Authorization` and header values the caller chose, and one POST with a body, to an upstream that echoes the
//! credential, to one that fails mid-body (HTTP/2: resets the stream), to one nobody listens on and to three that
//! redirect. It types a credential and approval passphrases at the binary's prompts, and passes `config approve` a
//! config file holding a comment. Then every file in the log directory is read.
//!
//! The subscriber is the process-wide default. One test runs the HTTP/1.1 session and then the HTTP/2 session, because a
//! global default can be installed once per process.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use common::WAIT;
use common::approval_harness::{
    APPROVAL_PASSPHRASE, Fixture, IDENTITY, WRONG_PASSPHRASE, get, mkdir, read_frame, send, serve_admin, spawn_admin,
};
use common::mock_upstream::{MockUpstream, Reply, TestCa};
use common::mock_upstream_h2::{H2Reply, MockH2Upstream};
use common::proxy_harness::{CallerRequest, Credential, Proxy, RefusingPort, Setup, TOKEN_BYTES, TempDir, Via, token_hash, token_of};
use common::scrub_stream::url_forms;
use iron_vault::admin::protocol::{AdminRequest, AdminResponse, Frame, OwnerInput};
use iron_vault::config_check::UpstreamSettings;
use iron_vault::deployment::{Accounts, DeploymentProfile, PasswdDirectory};
use iron_vault::hardening::{CoreDumps, HardeningReport, MemoryProtection};
use iron_vault::logging::{LogDir, LogFailure, LogFile, LogSwitch, subscriber_at};
use iron_vault::path_metadata::invoking_user;
use iron_vault::service_context::{ServiceContext, ServiceLocks, ServiceSetup};
use iron_vault::service_state::ServiceState;
use iron_vault::socket_activation::PassedSockets;
use iron_vault::trusted_path_report::ServicePaths;
use iron_vault_kinds::CredentialMaterial;
use iron_vault_store::OsFs;
use tokio::net::UnixStream;
use tracing_subscriber::filter::LevelFilter;
use zeroize::Zeroizing;

const HEADER_KEY: &str = "hdr-key-Vq7e2c91";
/// Characters that percent-encoding and the query slot both change.
const QUERY_KEY: &str = "qry/key+7d1=f3&x";
const BASIC_USER: &str = "basic-user-4a9";
const BASIC_PASSWORD: &str = "p@ss/w0rd+8c2";
const CUT_KEY: &str = "cut-key-61fb08d4";
const DEAD_KEY: &str = "dead-key-c3a5e7b0";
const ADDED_KEY: &str = "ADDED-key/typed+5e0b=";
const FIXTURE_KEY: &str = "fx-secret";
/// In the body every upstream sends; a log never holds a response body.
const BODY_MARKER: &str = "UPSTREAMBODY-marker-4d2e";
const MOVED_KEY: &str = "moved-key-0c6e93";
const ASTRAY_KEY: &str = "astray-key-b71f25";
const REWRITE_KEY: &str = "rewrite-key-4e90a7";
/// The `Location` of a cross-origin redirect, which the proxy relays; of one outside the route's base, which it refuses;
/// and of one inside the base, which it rewrites under the route's prefix.
const RELAYED_LOCATION: &str = "https://moved.example/redirmark-relayed-2b8d?to=redirmark-query-0e41";
const REFUSED_LOCATION: &str = "/redirmark-refused-6a3c";
const REWRITTEN_LOCATION: &str = "/v1/redirmark-rewritten-85f2?to=redirmark-rwquery-3a6c";
/// [`REWRITTEN_LOCATION`] as the proxy rebuilds it under the `rewrite` route's prefix.
const REBUILT_LOCATION: &str = "/rewrite/redirmark-rewritten-85f2?to=redirmark-rwquery-3a6c";
/// In the body of the caller's POST; a log never holds a request body.
const REQUEST_BODY_MARKER: &str = "REQBODY-marker-9e5f";
/// In a comment of the config `config approve` approves; a log holds its digest, never its bytes.
const CONFIG_MARKER: &str = "CFGCOMMENT-marker-1d7b";
/// The passphrases `init` is given, and a wrong one typed at `unlock` before the right one.
const VAULT_PASSPHRASE: &str = "INIT-vault-hostile-58a0";
const INIT_APPROVAL_PASSPHRASE: &str = "INIT-approval-hostile-c42d";
const WRONG_UNLOCK_PASSPHRASE: &str = "UNLOCK-wrong-hostile-7f13";

/// What the caller chooses: a query string, header values, and credentials of its own that the service replaces.
const CALLER_QUERY: &str = "callerqs-3f9a1c";
const CALLER_HEADERS: [(&str, &str); 4] = [
    ("X-Caller-Note", "callerhdr-note-82d1"),
    ("User-Agent", "callerhdr-agent-5b07"),
    ("Referer", "https://caller.example/callerhdr-ref-19ce"),
    ("Cookie", "session=callerhdr-cookie-a4f8"),
];
const CALLER_AUTHORIZATION: &str = "Bearer callerhdr-auth-7e63";
/// The user and password of the caller's own `Proxy-Authorization: Basic`, which the service never forwards.
const PROXY_USER: &str = "callerproxy-user-61c0";
const PROXY_PASSWORD: &str = "callerhdr-proxyauth-d3e7";
const WRONG_TOKEN_BYTES: [u8; 32] = [9; 32];

/// Fixed fields of every record, and the values the constant ones hold.
const FIXED_FIELDS: [&str; 8] = [
    "timestamp",
    "level",
    "target",
    "service",
    "service_version",
    "schema_version",
    "deployment_profile",
    "message",
];

#[derive(Clone, Copy, Debug)]
enum Upstream {
    Http1,
    Http2,
}

// ---- The log -----------------------------------------------------------------------------------------------------

/// A fresh log directory under cargo's scratch space, removed on drop.
struct LogDirectory(PathBuf);

impl LogDirectory {
    fn new(name: &str) -> Self {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("hostile-log-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
        Self(dir)
    }

    /// Every file in the directory, as text, in name order.
    fn files(&self) -> Vec<(String, String)> {
        let mut names: Vec<_> = fs::read_dir(&self.0).unwrap().map(|entry| entry.unwrap().path()).collect();
        names.sort();
        names
            .iter()
            .map(|path| {
                (
                    path.display().to_string(),
                    String::from_utf8_lossy(&fs::read(path).unwrap()).into_owned(),
                )
            })
            .collect()
    }

    /// Every line of every file, parsed; a line that is not a JSON object fails the test.
    fn records(&self) -> Vec<serde_json::Value> {
        self.files()
            .iter()
            .flat_map(|(name, text)| {
                text.lines().map(move |line| {
                    let record: serde_json::Value = serde_json::from_str(line).unwrap_or_else(|e| panic!("{name}: not JSON ({e}): {line}"));
                    assert!(record.is_object(), "{name}: {line}");
                    record
                })
            })
            .collect()
    }

    /// The records written so far, leaving out a last line still being written.
    fn finished_records(&self) -> Vec<serde_json::Value> {
        self.files()
            .iter()
            .flat_map(|(_, text)| {
                text.rsplit_once('\n')
                    .map_or("", |(done, _)| done)
                    .lines()
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .map(|line| serde_json::from_str(&line).unwrap_or_else(|e| panic!("not JSON ({e}): {line}")))
            .collect()
    }

    fn text(&self) -> String {
        self.files().into_iter().map(|(_, text)| text).collect()
    }
}

impl Drop for LogDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Installs the process-wide subscriber: the production one at global `TRACE`, writing to the log file in `dir`.
fn log_to_file(dir: &LogDirectory) {
    let owner = invoking_user().unwrap();
    let file = LogFile::open(LogDir::open_leaf_only(&dir.0, owner).unwrap(), owner, LogFailure::default()).unwrap();
    let subscriber = subscriber_at(file, DeploymentProfile::Development, LevelFilter::TRACE);
    tracing::subscriber::set_global_default(subscriber).unwrap();
}

// ---- What must not appear ------------------------------------------------------------------------------------------

/// Every form of `secret` the scrubber recognises that a log could hold: plain, base64 (standard and URL-safe, with
/// and without padding) and percent-encoded.
fn forms(secret: &str) -> Vec<String> {
    let bytes = secret.as_bytes();
    vec![
        secret.to_owned(),
        STANDARD.encode(bytes),
        STANDARD_NO_PAD.encode(bytes),
        URL_SAFE.encode(bytes),
        URL_SAFE_NO_PAD.encode(bytes),
    ]
    .into_iter()
    .chain(url_forms(secret))
    .collect()
}

/// Everything the log must not hold, as `(what, text)`, with every form of each secret and the pieces of the upstream URL.
fn forbidden(ports: &[u16], recovery_key: &str) -> Vec<(String, String)> {
    let basic = format!("{BASIC_USER}:{BASIC_PASSWORD}");
    let proxy_credentials = proxy_credentials();
    let secrets = [
        HEADER_KEY,
        QUERY_KEY,
        BASIC_USER,
        BASIC_PASSWORD,
        basic.as_str(),
        CUT_KEY,
        DEAD_KEY,
        ADDED_KEY,
        FIXTURE_KEY,
        APPROVAL_PASSPHRASE,
        WRONG_PASSPHRASE,
        IDENTITY,
        BODY_MARKER,
        MOVED_KEY,
        ASTRAY_KEY,
        REWRITE_KEY,
        REWRITTEN_LOCATION,
        REBUILT_LOCATION,
        PROXY_USER,
        PROXY_PASSWORD,
        &proxy_credentials,
        RELAYED_LOCATION,
        REFUSED_LOCATION,
        "redirmark-",
        "moved.example",
        REQUEST_BODY_MARKER,
        CONFIG_MARKER,
        VAULT_PASSPHRASE,
        INIT_APPROVAL_PASSPHRASE,
        WRONG_UNLOCK_PASSPHRASE,
        recovery_key,
    ];
    // Each marker alone, since a leak need not carry the whole header value or query string.
    let caller_values =
        CALLER_HEADERS
            .iter()
            .map(|(_, value)| *value)
            .chain([CALLER_QUERY, CALLER_AUTHORIZATION, "callerhdr-", "callerqs-"]);
    let tokens = [token_of(TOKEN_BYTES), token_of(WRONG_TOKEN_BYTES)];
    // The log names the upstream host and, in an approval summary, the configured origin and route paths; it never names
    // a request's own path or query, nor the credential's query parameter.
    let url_parts = [
        "127.0.0.1",
        "access_key",
        "/v1/rates",
        "/v1/ledger",
        "/v1/stream",
        "/latest",
        "rates",
        "ledger",
        "tail-x9",
        "base=USD",
    ];
    let ports = ports.iter().map(|port| format!("localhost:{port}/"));
    secrets
        .into_iter()
        .map(str::to_owned)
        .chain(caller_values.map(str::to_owned))
        .chain(tokens)
        .flat_map(|secret| forms(&secret).into_iter().map(move |form| (secret.clone(), form)))
        .chain(url_parts.iter().map(|part| ((*part).to_owned(), (*part).to_owned())))
        .chain(ports.map(|port| (port.clone(), port)))
        .collect()
}

/// A body that shows `key` the ways an upstream echoes one: plain, base64 and percent-encoded.
fn echo_of(key: &str) -> String {
    format!(
        "{{\"key\":\"{key}\",\"b64\":\"{}\",\"url\":\"{}\",\"note\":\"{BODY_MARKER}\"}}",
        STANDARD.encode(key),
        url_forms(key)[1]
    )
}

// ---- The proxy run -----------------------------------------------------------------------------------------------

/// Ports of the eight upstreams.
struct Ports {
    header: u16,
    query: u16,
    basic: u16,
    cut: u16,
    dead: u16,
    moved: u16,
    astray: u16,
    rewrite: u16,
}

impl Ports {
    fn all(&self) -> [u16; 8] {
        [
            self.header,
            self.query,
            self.basic,
            self.cut,
            self.dead,
            self.moved,
            self.astray,
            self.rewrite,
        ]
    }
}

fn route(name: &str, upstream: &str, slot: &str, paths: &str, port: u16, credential: &str, methods: &str) -> String {
    format!(
        "[routes.{name}]\nprefix = \"/{name}\"\nupstream = \"https://localhost:{port}{upstream}\"\n\
         ca_file = \"/etc/iron-vault/ca/test.pem\"\n\
         credential = \"{credential}\"\nslot = {slot}\nmethods = {methods}\npaths = [\"{paths}\"]\n\
         rate_limit = {{ requests = 1000, per_seconds = 1, burst = 1000 }}\n\n"
    )
}

fn callers_and_routes(ports: &Ports) -> String {
    let hash = token_hash(TOKEN_BYTES);
    let header = "{ header = \"X-Api-Key\" }";
    let get = "[\"GET\"]";
    let routes = "[\"hdr\", \"qry\", \"basic\", \"cut\", \"dead\", \"moved\", \"astray\", \"rewrite\"]";
    [
        format!("[callers.agent]\nlistener = \"local\"\ntoken_hash = \"{hash}\"\nroutes = {routes}\n\n"),
        route("hdr", "/v1", header, "/**", ports.header, "hdr_key", "[\"GET\", \"POST\"]"),
        route("qry", "", "{ query = \"access_key\" }", "/latest", ports.query, "qry_key", get),
        route("basic", "/v1", "\"basic\"", "/**", ports.basic, "basic_cred", get),
        route("cut", "/v1", header, "/**", ports.cut, "cut_key", get),
        route("dead", "/v1", header, "/**", ports.dead, "dead_key", get),
        route("moved", "/v1", header, "/**", ports.moved, "moved_key", get),
        route("astray", "/v1", header, "/**", ports.astray, "astray_key", get),
        route("rewrite", "/v1", header, "/**", ports.rewrite, "rewrite_key", get),
    ]
    .concat()
}

fn credentials(ports: &Ports) -> Vec<Credential> {
    let fixed = |name, key: &str, port| Credential {
        name,
        material: CredentialMaterial::Static { key: key.into() },
        port,
    };
    vec![
        fixed("hdr_key", HEADER_KEY, ports.header),
        fixed("qry_key", QUERY_KEY, ports.query),
        Credential {
            name: "basic_cred",
            material: CredentialMaterial::Basic {
                username: BASIC_USER.into(),
                password: BASIC_PASSWORD.into(),
            },
            port: ports.basic,
        },
        fixed("cut_key", CUT_KEY, ports.cut),
        fixed("dead_key", DEAD_KEY, ports.dead),
        fixed("moved_key", MOVED_KEY, ports.moved),
        fixed("astray_key", ASTRAY_KEY, ports.astray),
        fixed("rewrite_key", REWRITE_KEY, ports.rewrite),
    ]
}

/// The upstreams, kept alive for the run.
#[allow(dead_code)] // Held only so the servers keep running.
enum Upstreams {
    Http1(Vec<MockUpstream>),
    Http2(Vec<MockH2Upstream>),
}

/// The three redirecting upstreams, kept alive for the run. They speak HTTP/1.1 in both sessions, since the HTTP/2 test
/// upstream sends no headers of a test's choosing.
#[allow(dead_code)] // Held only so the servers keep running.
struct Redirects([MockUpstream; 3]);

impl Redirects {
    async fn start(ca: &TestCa) -> Self {
        Self([
            MockUpstream::start(ca, Reply::redirect(RELAYED_LOCATION)).await,
            MockUpstream::start(ca, Reply::redirect(REFUSED_LOCATION)).await,
            MockUpstream::start(ca, Reply::redirect(REWRITTEN_LOCATION)).await,
        ])
    }
}

/// Starts the three redirecting upstreams, then the three echoing upstreams and the one that fails mid-body, in
/// `protocol`; the fifth port refuses connections, and is held for the run so that nothing else can take it.
async fn start_upstreams(ca: &TestCa, protocol: Upstream) -> ((Upstreams, Redirects, RefusingPort), Ports) {
    let redirects = Redirects::start(ca).await;
    let dead = RefusingPort::bind();
    let (upstreams, ports) = start_protocol_upstreams(ca, protocol, &redirects, dead.port()).await;
    ((upstreams, redirects, dead), ports)
}

/// The upstreams of [`start_upstreams`] that speak `protocol`, and every port of the run, with `dead` as the fifth.
async fn start_protocol_upstreams(ca: &TestCa, protocol: Upstream, redirects: &Redirects, dead: u16) -> (Upstreams, Ports) {
    let echoes = [HEADER_KEY, QUERY_KEY, BASIC_PASSWORD].map(echo_of);
    let [moved, astray, rewrite] = redirects.0.each_ref().map(MockUpstream::port);
    match protocol {
        Upstream::Http1 => {
            let mut servers = Vec::new();
            for body in &echoes {
                servers.push(MockUpstream::start(ca, echoing(body)).await);
            }
            servers.push(MockUpstream::start(ca, Reply::Truncated { sent: BODY_MARKER.into() }).await);
            let p = |at: usize| servers[at].port();
            let ports = Ports {
                header: p(0),
                query: p(1),
                basic: p(2),
                cut: p(3),
                dead,
                moved,
                astray,
                rewrite,
            };
            (Upstreams::Http1(servers), ports)
        }
        Upstream::Http2 => {
            let mut servers = Vec::new();
            for body in &echoes {
                servers.push(MockH2Upstream::start(ca, H2Reply::ok(body)).await);
            }
            servers.push(MockH2Upstream::start(ca, H2Reply::Reset(h2::Reason::INTERNAL_ERROR)).await);
            let p = |at: usize| servers[at].port();
            let ports = Ports {
                header: p(0),
                query: p(1),
                basic: p(2),
                cut: p(3),
                dead,
                moved,
                astray,
                rewrite,
            };
            (Upstreams::Http2(servers), ports)
        }
    }
}

/// A reply that echoes the credential in the body and in a header.
fn echoing(body: &str) -> Reply {
    Reply::Respond {
        status: 200,
        headers: vec![("x-echo".to_owned(), HEADER_KEY.to_owned())],
        body: body.as_bytes().to_vec(),
    }
}

/// The `user:password` of the caller's own `Proxy-Authorization: Basic`.
fn proxy_credentials() -> String {
    format!("{PROXY_USER}:{PROXY_PASSWORD}")
}

/// `request` with the caller's own header values, a `Proxy-Authorization` and an `Authorization` of its own.
fn hostile(request: CallerRequest) -> CallerRequest {
    let proxy_authorization = format!("Basic {}", STANDARD.encode(proxy_credentials()));
    CALLER_HEADERS
        .iter()
        .fold(request, |request, (name, value)| request.header(name, value))
        .header("Proxy-Authorization", &proxy_authorization)
        .header("Authorization", CALLER_AUTHORIZATION)
        .header("X-Api-Key", CALLER_AUTHORIZATION)
}

/// A caller's `GET target`, made [`hostile`].
fn hostile_get(target: &str) -> CallerRequest {
    hostile(CallerRequest::get(target))
}

/// Sends every request of the proxy run and returns how many it sent.
async fn hostile_requests(proxy: &Proxy) -> usize {
    let endpoints = proxy.endpoints();
    let query = format!("callerqs={CALLER_QUERY}&base=USD");
    let signed = |target: &str| hostile_get(&format!("{target}?{query}")).signed(Via::Unix);
    let wrong_token = hostile_get(&format!("/hdr/v1/rates?{query}")).with_token(Via::Unix, WRONG_TOKEN_BYTES);
    let body = format!("{{\"note\":\"{REQUEST_BODY_MARKER}\"}}");
    let post = hostile(CallerRequest::post(&format!("/hdr/v1/rates?{query}"), body.as_bytes())).signed(Via::Unix);
    let requests = [
        signed("/hdr/v1/rates"),
        post,
        signed("/moved/v1/rates"),
        signed("/astray/v1/rates"),
        signed("/rewrite/v1/rates"),
        signed("/qry/latest"),
        signed("/basic/v1/ledger"),
        signed("/cut/v1/tail-x9"),
        signed("/dead/v1/rates"),
        wrong_token,
        signed("/nowhere/v1/rates"),
    ];
    for request in &requests {
        endpoints.send_raw(Via::Unix, request).await;
    }
    requests.len()
}

// ---- The administrative run --------------------------------------------------------------------------------------

/// Runs the binary against `socket` with `RUST_LOG=trace`, typing `input` at its prompts, and returns its exit code.
async fn cli(socket: &Path, args: &[&str], input: &str) -> Option<i32> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_iron-vault"));
    command
        .args(args)
        .arg("--admin-socket")
        .arg(socket)
        .env("RUST_LOG", "trace")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let input = input.to_owned();
    tokio::task::spawn_blocking(move || {
        let mut child = command.spawn().unwrap();
        std::io::Write::write_all(&mut child.stdin.take().unwrap(), input.as_bytes()).unwrap();
        child.wait().unwrap().code()
    })
    .await
    .unwrap()
}

/// `add` with a typed key, a refused approval with a wrong passphrase, then an approval with the right one of a config
/// holding a comment marker; returns the fixture, whose upstream port the approval summary logs, and the number of
/// requests the run sent.
async fn administrative_run() -> (Fixture, usize) {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    let (socket, stop) = serve_admin(&service);
    let origin = format!("localhost:{}", fixture.upstream().port());
    assert_eq!(
        cli(&socket, &["add", "added_key", "--origin", &origin], &format!("{ADDED_KEY}\n")).await,
        Some(0)
    );
    let proposed = fixture.path("proposed.toml");
    fs::write(&proposed, format!("# {CONFIG_MARKER}\n{}", fixture.config("fx2"))).unwrap();
    let approve = |passphrase: &str| (["config", "approve"], format!("yes\n{passphrase}\n"));
    let (args, answers) = approve(WRONG_PASSPHRASE);
    assert_eq!(
        cli(&socket, &[args[0], args[1], proposed.to_str().unwrap()], &answers).await,
        Some(1)
    );
    let (args, answers) = approve(APPROVAL_PASSPHRASE);
    assert_eq!(
        cli(&socket, &[args[0], args[1], proposed.to_str().unwrap()], &answers).await,
        Some(0)
    );
    assert_eq!(get(&fixture, "fx2").await.status, 200);
    let _ = stop.send(());
    (fixture, 1)
}

// ---- The vault lifecycle run ---------------------------------------------------------------------------------------

/// Starts the service on empty state and config directories in `dir`, which is also the runtime directory, as `serve`
/// does without systemd sockets: Locked, waiting for an `init`.
fn uninitialized_service(dir: &TempDir, ca: &TestCa) -> Arc<ServiceContext> {
    ["state", "etc"].iter().for_each(|name| mkdir(&dir.path().join(name)));
    let paths = ServicePaths {
        profile: DeploymentProfile::Development,
        owner: invoking_user().unwrap(),
        config: dir.path().join("etc/config.toml"),
        state_dir: dir.path().join("state"),
        runtime_dir: Some(dir.path().to_path_buf()),
    };
    let locks = ServiceLocks::acquire(&paths).unwrap();
    let provisional = locks.unverified_listeners(&OsFs);
    let setup = ServiceSetup {
        accounts: PasswdDirectory::new(Accounts::parse(""), &paths, Path::new("/nonexistent")).unwrap(),
        paths,
        fs: OsFs,
        upstream: UpstreamSettings::new(DeploymentProfile::Development, invoking_user().unwrap()).with_pinned_trust(ca.trust()),
        hardening: HardeningReport {
            core_dumps: CoreDumps::Disabled,
            memory: MemoryProtection::Unsupported,
        },
        log: LogSwitch::stdout_for_tests(invoking_user().unwrap()).unwrap(),
    };
    Arc::new(ServiceContext::start(locks, setup, &provisional, PassedSockets::default()).unwrap())
}

/// Sends `init` over the admin socket at `socket`, answers its prompts with the two passphrases and `yes`, and returns
/// the recovery key shown. The binary's `init` shows the key on a controlling terminal only, which a test has not got.
async fn init(socket: &Path) -> String {
    let mut answers = [
        VAULT_PASSPHRASE,
        VAULT_PASSPHRASE,
        INIT_APPROVAL_PASSPHRASE,
        INIT_APPROVAL_PASSPHRASE,
        "yes",
    ]
    .into_iter();
    let mut stream = UnixStream::connect(socket).await.unwrap();
    send(&mut stream, &Frame::Request(AdminRequest::Init { host_unlock: false })).await;
    let mut recovery_key = None;
    loop {
        match read_frame(&mut stream).await {
            Frame::Response(AdminResponse::Init { version: 1, .. }) => return recovery_key.expect("no recovery key was shown"),
            Frame::Notice(_) => {}
            Frame::Reveal(secret) => recovery_key = Some(String::from_utf8(secret.expose_secret().to_vec()).unwrap()),
            Frame::Prompt(_) => {
                let answer = answers.next().expect("a prompt beyond the answers given");
                send(
                    &mut stream,
                    &Frame::OwnerInput(OwnerInput::new(Zeroizing::new(answer.as_bytes().to_vec()))),
                )
                .await;
            }
            other => panic!("unexpected frame {other:?}"),
        }
    }
}

/// `init` with unique passphrases, then through the binary an `unlock` with a wrong passphrase and one with the right
/// one; returns the recovery key `init` showed.
async fn vault_lifecycle_run() -> String {
    let dir = TempDir::new();
    let ca = TestCa::new("hostile log lifecycle CA");
    let service = uninitialized_service(&dir, &ca);
    let (socket, stop, task) = spawn_admin(&service);
    let recovery_key = init(&socket).await;
    assert_eq!(service.state().await, ServiceState::Locked);
    assert_eq!(cli(&socket, &["unlock"], &format!("{WRONG_UNLOCK_PASSPHRASE}\n")).await, Some(1));
    assert_eq!(cli(&socket, &["unlock"], &format!("{VAULT_PASSPHRASE}\n")).await, Some(0));
    assert_eq!(service.state().await, ServiceState::Ready);
    let _ = stop.send(());
    task.await.unwrap();
    service.stop().await;
    recovery_key
}

/// Checks that the lifecycle run's paths ran: `init` wrote the vault and approved version 1, the wrong passphrase was
/// refused, and the right one took the service from Locked through Checking to Ready.
fn assert_lifecycle_ran(records: &[serde_json::Value]) {
    let has = |event: &str, field: &str, value: &str| records.iter().any(|r| r["event"] == event && r[field] == value);
    let has_number = |event: &str, field: &str, value: u64| records.iter().any(|r| r["event"] == event && r[field] == value);
    ["init", "unlock"]
        .iter()
        .for_each(|command| assert!(has("admin.command", "command", command), "{command}: {records:?}"));
    assert!(records.iter().any(|r| r["event"] == "vault.initialized"), "{records:?}");
    assert!(has_number("config.approval-completed", "version", 1), "{records:?}");
    assert_names_the_software_signer(records, &["config.version-reserved", "config.approval-completed"]);
    assert!(has("vault.unlock-refused", "refusal", "wrong_passphrase"), "{records:?}");
    let transition = |from: &str, to: &str| {
        records
            .iter()
            .any(|r| r["event"] == "service.lock-transition" && r["from_state"] == from && r["to_state"] == to)
    };
    assert!(transition("locked", "checking") && transition("checking", "ready"), "{records:?}");
}

// ---- The checks --------------------------------------------------------------------------------------------------

/// How many request events are in the log, counting finished lines only.
fn request_events_written(dir: &LogDirectory) -> usize {
    dir.finished_records()
        .iter()
        .filter(|record| record["target"] == "iron-vault.request")
        .count()
}

/// Waits until `expected` request events are in the log, then until a pause shows no more come.
async fn wait_for_request_events(dir: &LogDirectory, expected: usize) {
    tokio::time::timeout(WAIT, async {
        while request_events_written(dir) < expected {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{} of {expected} request events: {}", request_events_written(dir), dir.text()));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(request_events_written(dir), expected, "{}", dir.text());
}

fn assert_fixed_fields(record: &serde_json::Value) {
    FIXED_FIELDS
        .iter()
        .for_each(|field| assert!(!record[field].is_null(), "{field} missing: {record}"));
    assert_eq!(record["service"], "iron-vault", "{record}");
    assert_eq!(record["service_version"], env!("CARGO_PKG_VERSION"), "{record}");
    assert_eq!(record["schema_version"], 1, "{record}");
    assert_eq!(record["deployment_profile"], "development", "{record}");
    assert!(record["timestamp"].as_str().is_some_and(|stamp| stamp.ends_with('Z')), "{record}");
    assert!(
        ["ERROR", "WARN", "INFO", "DEBUG", "TRACE"].contains(&record["level"].as_str().unwrap()),
        "{record}"
    );
}

fn assert_one_request_event_each(records: &[serde_json::Value], requests: usize) {
    let events: Vec<_> = records.iter().filter(|record| record["target"] == "iron-vault.request").collect();
    assert_eq!(events.len(), requests);
    let ids: BTreeSet<_> = events.iter().map(|event| event["request_id"].to_string()).collect();
    assert_eq!(ids.len(), requests, "a request id repeats: {events:?}");
    records
        .iter()
        .filter(|record| record["event"] == "response.scrubbed")
        .for_each(|scrub| assert!(ids.contains(&scrub["request_id"].to_string()), "no request event for {scrub}"));
}

/// `(route, outcome, reason)` of each request event, in order of route then reason.
fn endings(records: &[serde_json::Value]) -> Vec<(Option<String>, String, Option<String>)> {
    let text = |value: &serde_json::Value| value.as_str().map(str::to_owned);
    let mut endings: Vec<_> = records
        .iter()
        .filter(|record| record["target"] == "iron-vault.request")
        .map(|event| {
            (
                text(&event["route"]),
                text(&event["outcome"]).unwrap_or_default(),
                text(&event["reason"]),
            )
        })
        .collect();
    endings.sort();
    endings
}

/// Checks that each hostile path ran and ended the way it should: the routes answered, the POST's body was read, the
/// cross-origin redirect was relayed, the one inside the base rewritten and the one outside it refused, the failing
/// upstreams failed with their reasons, both refusals were refused, and each echo was scrubbed once for each request that
/// drew it.
fn assert_hostile_paths_ran(records: &[serde_json::Value], protocol: Upstream) {
    let cut = match protocol {
        Upstream::Http1 => "upstream_body",
        Upstream::Http2 => "upstream_protocol",
    };
    let ending = |route: Option<&str>, outcome: &str, reason: Option<&str>| {
        (route.map(str::to_owned), outcome.to_owned(), reason.map(str::to_owned))
    };
    let mut expected = vec![
        ending(Some("hdr"), "success", None),
        ending(Some("hdr"), "success", None),
        ending(Some("moved"), "success", None),
        ending(Some("astray"), "failure", Some("redirect_refused")),
        ending(Some("rewrite"), "success", None),
        ending(Some("qry"), "success", None),
        ending(Some("basic"), "success", None),
        ending(Some("fx2"), "success", None),
        ending(Some("cut"), "failure", Some(cut)),
        ending(Some("dead"), "failure", Some("upstream_connect")),
        ending(None, "failure", Some("unauthenticated")),
        ending(None, "failure", Some("no_route")),
    ];
    expected.sort();
    assert_eq!(endings(records), expected, "{records:?}");
    [("hdr", 2), ("qry", 1), ("basic", 1)].iter().for_each(|(route, expected)| {
        let scrubs = records
            .iter()
            .filter(|r| r["event"] == "response.scrubbed" && r["route"] == *route)
            .count();
        assert_eq!(scrubs, *expected, "{route}: {records:?}");
    });
    let request = |route: &str, method: &str| {
        records
            .iter()
            .find(|r| r["target"] == "iron-vault.request" && r["route"] == route && r["http_method"] == method)
            .unwrap_or_else(|| panic!("no {method} request event on {route}: {records:?}"))
    };
    assert!(
        request("hdr", "POST")["request_bytes"].as_u64().is_some_and(|bytes| bytes > 0),
        "{records:?}"
    );
    ["moved", "rewrite"]
        .iter()
        .for_each(|route| assert_eq!(request(route, "GET")["status"], 302, "{route}: {records:?}"));
    let events = |name: &str| records.iter().filter(|record| record["event"] == name).count();
    assert_eq!(events("credential.added"), 1, "{records:?}");
    assert_eq!(events("config.approval-completed"), 1, "{records:?}");
    assert_eq!(
        events("config.approval-refused"),
        1,
        "the wrong passphrase was not logged: {records:?}"
    );
    assert_names_the_software_signer(records, &["config.approval-refused", "config.approval-completed"]);
}

/// Checks that every record of `events` names the approver it asked or signed with: its approver ID, and the label `init`
/// gives the software signer. The whole-file scan checks the records hold no secret beside it.
fn assert_names_the_software_signer(records: &[serde_json::Value], events: &[&str]) {
    events.iter().for_each(|event| {
        let named: Vec<_> = records.iter().filter(|r| r["event"] == *event).collect();
        assert!(!named.is_empty(), "{event}: {records:?}");
        named.iter().for_each(|r| {
            assert!(r["approver_id"].as_str().is_some_and(|id| id.len() == 36), "{r}");
            assert_eq!(r["approver_label"], "approval passphrase", "{r}");
        });
    });
}

/// Every server a session started, held until the test ends. The approval summary of one session's administrative run
/// legitimately logs its fixture's port, while the other session's upstream ports must not be logged at all, so no port
/// may serve both; while these are held, the kernel cannot hand one session's port to the other.
#[allow(dead_code)] // Held only so the ports stay taken.
struct SessionServers((Upstreams, Redirects, RefusingPort), Fixture);

/// One session against `protocol` upstreams: the proxy run and the administrative run. Returns the upstream ports, the
/// number of requests sent and the session's servers.
async fn hostile_session(protocol: Upstream) -> (Ports, usize, SessionServers) {
    let ca = TestCa::new("hostile log CA");
    let (upstreams, ports) = start_upstreams(&ca, protocol).await;
    let proxy = Proxy::start(Setup {
        ca: &ca,
        callers_and_routes: callers_and_routes(&ports),
        credentials: credentials(&ports),
        tcp: false,
        request_timeout_secs: 30,
        limits: "",
    })
    .await;
    let proxied = hostile_requests(&proxy).await;
    let (fixture, administrative) = administrative_run().await;
    (ports, proxied + administrative, SessionServers(upstreams, fixture))
}

#[tokio::test]
async fn the_whole_log_file_holds_no_forbidden_value_after_a_hostile_run_over_http1_and_http2() {
    let dir = LogDirectory::new("both");
    log_to_file(&dir);
    let recovery_key = vault_lifecycle_run().await;
    let lifecycle = dir.records();
    assert_lifecycle_ran(&lifecycle);
    let (mut requests, mut seen, mut ports, mut servers) = (0, lifecycle.len(), Vec::new(), Vec::new());
    for protocol in [Upstream::Http1, Upstream::Http2] {
        let (session_ports, sent, session_servers) = hostile_session(protocol).await;
        requests += sent;
        servers.push(session_servers);
        ports.extend(session_ports.all());
        wait_for_request_events(&dir, requests).await;
        let records = dir.records();
        assert_hostile_paths_ran(&records[seen..], protocol);
        seen = records.len();
    }

    let records = dir.records();
    records.iter().for_each(assert_fixed_fields);
    assert_one_request_event_each(&records, requests);
    assert!(
        records
            .iter()
            .any(|record| ["DEBUG", "TRACE"].contains(&record["level"].as_str().unwrap())),
        "the log holds nothing below INFO, so the verbose setting was not exercised"
    );
    let text = dir.text();
    forbidden(&ports, &recovery_key).iter().for_each(|(what, form)| {
        assert!(!text.contains(form.as_str()), "{what} appears in the log as {form:?}:\n{text}");
    });
}
