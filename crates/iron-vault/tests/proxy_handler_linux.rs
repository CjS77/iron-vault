//! The proxy handler end to end: a caller on a Unix request socket, the real request server and pipeline, and a
//! recording TLS test upstream (specification §3.5 steps 9-10, §3.12).
//!
//! The service account is the test's own uid, and the caller authenticates with a token in a dedicated header, so an
//! upstream echoing that header back is the case the relay must strip.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use common::mock_upstream::{MockUpstream, Reply, TestCa};
use iron_vault::deployment::DeploymentProfile;
use iron_vault::path_metadata::invoking_user;
use iron_vault::proxy_handler::ProxyHandler;
use iron_vault::request_listeners::RequestListeners;
use iron_vault::request_server::RequestServer;
use iron_vault::serving_snapshot::{ServingSnapshot, SnapshotHolder};
use iron_vault::trusted_path_report::ServicePaths;
use iron_vault::upstream::client::TransportLimits;
use iron_vault::upstream::clients::UpstreamClients;
use iron_vault_kinds::CredentialMaterial;
use iron_vault_policy::{
    AccountDirectory, AccountName, CallerToken, Capabilities, ParsedConfig, RateLimiter, TokenHash, ValidatedConfig, activate,
};
use iron_vault_store::{OsFs, PermittedOrigins, StateDirLock, Vault, VaultIdentity};
use secrecy::ExposeSecret;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::task::JoinHandle;

const SECRET: &str = "fx-secret-9c2e";
const TOKEN_BYTES: [u8; 32] = [7; 32];
const TOKEN_HEADER: &str = "X-Iron-Vault-Token";
const WAIT: Duration = Duration::from_secs(10);

static NEXT: AtomicU32 = AtomicU32::new(0);

/// A fresh `0711` directory under the system temp directory, removed on drop. It holds the request socket and the
/// vault's state directory; its path stays short, because a socket path is limited to 108 bytes.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("iv-ph-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o711)).unwrap();
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// This config has no peer callers, so activation never looks an account up.
struct NoAccounts;

impl AccountDirectory for NoAccounts {
    fn uid(&self, _: &AccountName) -> Option<u32> {
        None
    }

    fn service_account_uid(&self) -> u32 {
        990
    }

    fn overflow_uid(&self) -> u32 {
        65534
    }
}

fn token() -> String {
    CallerToken::from_bytes(TOKEN_BYTES).expose_once().expose_secret().to_owned()
}

/// One token caller on a Unix listener, granted the `fx` route to `origin` under `/v1`, its key in `X-Api-Key`.
fn config(socket: &Path, origin: &str, request_timeout_secs: u64) -> ValidatedConfig {
    let hash = TokenHash::of(&CallerToken::from_bytes(TOKEN_BYTES));
    let toml = format!(
        r#"schema_version = 1

[limits]
request_timeout_secs = {request_timeout_secs}
upstream_timeout_secs = {request_timeout_secs}

[listeners.local]
unix_socket = "{}"
token_header = "{TOKEN_HEADER}"

[callers.agent]
listener = "local"
token_hash = "{hash}"
routes = ["fx"]

[routes.fx]
prefix = "/fx"
upstream = "{origin}/v1"
ca_file = "/etc/iron-vault/ca/test.pem"
credential = "fx_key"
slot = {{ header = "X-Api-Key" }}
methods = ["GET"]
paths = ["/v1/**"]
rate_limit = {{ requests = 60, per_seconds = 60, burst = 10 }}
"#,
        socket.display()
    );
    ValidatedConfig::try_from(ParsedConfig::from_toml(toml.as_bytes()).unwrap()).unwrap()
}

/// A vault holding the static `fx_key`, permitted to reach `localhost:port` only.
fn vault(state_dir: &Path, port: u16) -> Vault {
    fs::create_dir(state_dir).unwrap();
    let lock = StateDirLock::acquire(state_dir).unwrap();
    let mut vault = Vault::create(&lock, &OsFs, VaultIdentity::generate()).unwrap();
    let origins = PermittedOrigins::new([("localhost".parse().unwrap(), port.to_string().parse().unwrap())].into()).unwrap();
    let material = CredentialMaterial::Static { key: SECRET.into() };
    vault.add(&lock, &OsFs, "fx_key".parse().unwrap(), material, origins).unwrap();
    vault
}

/// The request server with the proxy handler on one Unix listener, stopped on drop.
struct Proxy {
    dir: TempDir,
    task: JoinHandle<()>,
}

impl Proxy {
    /// Serves the `fx` route to the upstream at `localhost:port`, pinning `ca`.
    async fn start(ca: &TestCa, port: u16, request_timeout_secs: u64) -> Self {
        let dir = TempDir::new();
        let config = config(
            &dir.0.join("proxy.sock"),
            &format!("https://localhost:{port}"),
            request_timeout_secs,
        );
        let vault = vault(&dir.0.join("state"), port);
        let policy = activate(&config, &Capabilities::default(), &vault, &NoAccounts).unwrap();
        let trust = ca.trust();
        let clients = UpstreamClients::with_pinned_loader(&policy, TransportLimits::default(), |_| Ok(trust.clone())).unwrap();
        // Buckets start empty; accounting from a minute ago fills them, so the test's requests are not rate limited.
        let limiter = RateLimiter::new(&policy, Instant::now().checked_sub(Duration::from_secs(60)).unwrap());
        let snapshot = ServingSnapshot::new(policy, vault, clients, limiter).unwrap();
        let listeners = RequestListeners::open(config.listeners(), &paths(&dir.0), BTreeMap::new()).unwrap();
        let server = RequestServer::new(*config.limits(), ProxyHandler::new(Arc::new(SnapshotHolder::new(snapshot))));
        let task = tokio::spawn(async move {
            let _ = server.serve(&listeners).await;
        });
        Self { dir, task }
    }

    async fn connect(&self) -> UnixStream {
        UnixStream::connect(self.dir.0.join("proxy.sock")).await.unwrap()
    }

    /// The caller's `GET target`, with its token, on a fresh connection; the whole raw response once it closes.
    async fn get(&self, target: &str) -> Response {
        let mut stream = self.connect().await;
        stream.write_all(get(target).as_bytes()).await.unwrap();
        let mut raw = Vec::new();
        tokio::time::timeout(WAIT, stream.read_to_end(&mut raw)).await.unwrap().unwrap();
        Response::parse(&String::from_utf8(raw).unwrap())
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn paths(dir: &Path) -> ServicePaths {
    ServicePaths {
        profile: DeploymentProfile::Development,
        owner: invoking_user().unwrap(),
        config: dir.join("config.toml"),
        state_dir: dir.join("state"),
        runtime_dir: Some(dir.to_path_buf()),
    }
}

fn get(target: &str) -> String {
    format!(
        "GET {target} HTTP/1.1\r\nHost: localhost\r\n{TOKEN_HEADER}: {}\r\nConnection: close\r\n\r\n",
        token()
    )
}

/// A response as the caller read it.
struct Response {
    status: u16,
    /// Header names lowercased, values trimmed, in arrival order.
    headers: Vec<(String, String)>,
    body: String,
}

impl Response {
    fn parse(raw: &str) -> Self {
        let (head, body) = raw.split_once("\r\n\r\n").unwrap();
        let mut lines = head.lines();
        let status = lines.next().unwrap().split(' ').nth(1).unwrap().parse().unwrap();
        let headers = lines
            .map(|line| {
                let (name, value) = line.split_once(':').unwrap();
                (name.to_ascii_lowercase(), value.trim().to_owned())
            })
            .collect();
        Self {
            status,
            headers,
            body: body.to_owned(),
        }
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
    }
}

fn reply(status: u16, headers: &[(&str, &str)], body: &str) -> Reply {
    Reply::Respond {
        status,
        headers: headers.iter().map(|(n, v)| ((*n).to_owned(), (*v).to_owned())).collect(),
        body: body.as_bytes().to_vec(),
    }
}

#[tokio::test]
async fn a_granted_get_carries_the_credential_and_gets_the_upstreams_response() {
    let ca = TestCa::new("proxy test CA");
    let upstream = MockUpstream::start(
        &ca,
        reply(201, &[("content-type", "application/json"), ("x-rate", "59")], r#"{"ok":1}"#),
    )
    .await;
    let proxy = Proxy::start(&ca, upstream.port(), 30).await;

    let response = proxy.get("/fx/latest?base=USD").await;

    assert_eq!(response.status, 201);
    assert_eq!(response.header("content-type"), Some("application/json"));
    assert_eq!(response.header("x-rate"), Some("59"));
    assert_eq!(response.header("content-length"), Some("8"));
    assert_eq!(response.body, r#"{"ok":1}"#);
    let sent = upstream.requests();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].request_line(), "GET /v1/latest?base=USD HTTP/1.1");
    let headers = sent[0].headers();
    assert!(headers.contains(&("x-api-key".to_owned(), SECRET.to_owned())), "{headers:?}");
    assert!(headers.iter().all(|(name, _)| name != "x-iron-vault-token"), "{headers:?}");
}

#[tokio::test]
async fn hop_by_hop_and_caller_auth_headers_from_the_upstream_never_reach_the_caller() {
    let ca = TestCa::new("proxy test CA");
    let echoed = [
        ("connection", "x-hop"),
        ("x-hop", "1"),
        ("proxy-authenticate", "Basic realm=\"upstream\""),
        ("x-iron-vault-token", "ivt_echoed"),
        ("x-kept", "1"),
    ];
    let upstream = MockUpstream::start(&ca, reply(200, &echoed, "ok")).await;
    let proxy = Proxy::start(&ca, upstream.port(), 30).await;

    let response = proxy.get("/fx/latest").await;

    assert_eq!(response.status, 200);
    assert_eq!(response.header("x-kept"), Some("1"));
    ["x-hop", "proxy-authenticate", "x-iron-vault-token"]
        .iter()
        .for_each(|name| assert_eq!(response.header(name), None, "{name} reached the caller"));
    // hyper's own `Connection: close`, answering the caller's, is the only one, and names nothing from the upstream.
    assert!(
        response
            .headers
            .iter()
            .filter(|(n, _)| n == "connection")
            .all(|(_, v)| v == "close"),
        "{:?}",
        response.headers
    );
    assert_eq!(response.body, "ok");
}

#[tokio::test]
async fn an_unreachable_upstream_is_502_without_its_url() {
    let ca = TestCa::new("proxy test CA");
    // A port nothing listens on: bound, read and closed.
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let proxy = Proxy::start(&ca, port, 30).await;

    let response = proxy.get("/fx/latest?base=USD").await;

    assert_eq!(response.status, 502);
    assert_eq!(response.body, "bad gateway");
    assert_no_upstream_detail(&response, port);
}

#[tokio::test]
async fn an_upstream_that_never_sends_headers_is_504_at_the_request_deadline() {
    let ca = TestCa::new("proxy test CA");
    let upstream = MockUpstream::start(&ca, Reply::Stall).await;
    let proxy = Proxy::start(&ca, upstream.port(), 1).await;

    let start = Instant::now();
    let response = proxy.get("/fx/latest?base=USD").await;

    assert_eq!(response.status, 504);
    assert_eq!(response.body, "gateway timeout");
    assert!(start.elapsed() >= Duration::from_secs(1), "answered after {:?}", start.elapsed());
    assert_eq!(upstream.requests().len(), 1, "the request did reach the upstream");
    assert_no_upstream_detail(&response, upstream.port());
}

#[tokio::test]
async fn a_streamed_body_reaches_the_caller_chunk_by_chunk() {
    let ca = TestCa::new("proxy test CA");
    let gate = Arc::new(tokio::sync::Notify::new());
    let chunks = Reply::TwoChunks {
        first: "data: first\n\n".to_owned(),
        second: "data: second\n\n".to_owned(),
        gate: Arc::clone(&gate),
    };
    let upstream = MockUpstream::start(&ca, chunks).await;
    let proxy = Proxy::start(&ca, upstream.port(), 30).await;
    let mut stream = proxy.connect().await;
    stream.write_all(get("/fx/stream").as_bytes()).await.unwrap();

    // The upstream sends the second chunk only after this sees the first, so a buffering relay would stall here.
    let mut raw = tokio::time::timeout(WAIT, read_until(&mut stream, "data: first\n\n"))
        .await
        .unwrap();
    assert!(!raw.contains("data: second"), "{raw}");
    gate.notify_one();
    let mut rest = Vec::new();
    tokio::time::timeout(WAIT, stream.read_to_end(&mut rest)).await.unwrap().unwrap();
    raw.push_str(&String::from_utf8(rest).unwrap());

    let response = Response::parse(&raw);
    assert_eq!(response.status, 200);
    assert_eq!(response.header("transfer-encoding"), Some("chunked"));
    assert!(response.body.contains("data: second\n\n"), "{raw}");
    assert!(response.body.ends_with("0\r\n\r\n"), "the chunked body did not end cleanly: {raw}");
}

#[tokio::test]
async fn a_body_cut_short_upstream_reaches_the_caller_cut_short_not_complete() {
    let ca = TestCa::new("proxy test CA");
    let truncated = Reply::Truncated {
        sent: "partial".to_owned(),
    };
    let upstream = MockUpstream::start(&ca, truncated).await;
    let proxy = Proxy::start(&ca, upstream.port(), 30).await;

    let response = proxy.get("/fx/latest").await;

    // The head and the chunk that arrived went out; the connection then closed without the last chunk.
    assert_eq!(response.status, 200);
    assert_eq!(response.header("transfer-encoding"), Some("chunked"));
    assert!(response.body.contains("partial"), "{:?}", response.body);
    assert!(
        !response.body.ends_with("0\r\n\r\n"),
        "the cut-short body ended cleanly: {:?}",
        response.body
    );
}

/// Reads from `stream` until what has arrived contains `wanted`, and returns all of it.
async fn read_until(stream: &mut UnixStream, wanted: &str) -> String {
    let mut raw = Vec::new();
    while !String::from_utf8_lossy(&raw).contains(wanted) {
        let mut buf = [0u8; 256];
        let read = stream.read(&mut buf).await.unwrap();
        assert!(read > 0, "the connection closed before {wanted:?} arrived");
        raw.extend_from_slice(&buf[..read]);
    }
    String::from_utf8(raw).unwrap()
}

/// The response names neither the upstream's origin nor the query the caller sent, and its body not even the port.
fn assert_no_upstream_detail(response: &Response, port: u16) {
    let text = format!("{:?}{}", response.headers, response.body);
    ["localhost", "https://", "base=USD"]
        .iter()
        .for_each(|detail| assert!(!text.contains(detail), "{detail} in {text}"));
    assert!(!response.body.contains(&port.to_string()), "{}", response.body);
}
