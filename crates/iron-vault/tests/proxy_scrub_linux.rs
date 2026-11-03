//! Response scrubbing through the proxy handler end to end: a caller on a Unix request socket, the real request server
//! and pipeline, a Basic credential and a recording TLS test upstream that echoes it back (specification §3.8, §3.12).
//!
//! The credential is Basic so one body can echo three of its forms at once: the password as stored, the `Basic` token
//! and the URL-encoded password. The password holds `/`, `+` and `=`, so its URL-encoded form differs from it.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use common::mock_upstream::{MockUpstream, Reply, TestCa};
use iron_vault::deployment::DeploymentProfile;
use iron_vault::path_metadata::invoking_user;
use iron_vault::proxy_handler::ProxyHandler;
use iron_vault::request_listeners::RequestListeners;
use iron_vault::request_server::RequestServer;
use iron_vault::scrub::SCRUB_REPLACEMENT;
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
use tracing_subscriber::fmt::MakeWriter;

const USERNAME: &str = "agent-user";
const PASSWORD: &str = "pa/ss+word=9f3e";
const PASSWORD_ENCODED: &str = "pa%2Fss%2Bword%3D9f3e";
const TOKEN_BYTES: [u8; 32] = [9; 32];
const TOKEN_HEADER: &str = "X-Iron-Vault-Token";
const WAIT: Duration = Duration::from_secs(10);

static NEXT: AtomicU32 = AtomicU32::new(0);

/// A fresh `0711` directory under the system temp directory, removed on drop; short, because a socket path is limited
/// to 108 bytes.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("iv-ps-{}-{n}", std::process::id()));
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

/// One token caller on a Unix listener, granted the `fx` route to `origin` with the Basic credential `fx_basic`.
fn config(socket: &Path, origin: &str) -> ValidatedConfig {
    let hash = TokenHash::of(&CallerToken::from_bytes(TOKEN_BYTES));
    let toml = format!(
        r#"schema_version = 1

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
credential = "fx_basic"
slot = "basic"
methods = ["GET", "HEAD"]
paths = ["/v1/**"]
rate_limit = {{ requests = 60, per_seconds = 60, burst = 10 }}
"#,
        socket.display()
    );
    ValidatedConfig::try_from(ParsedConfig::from_toml(toml.as_bytes()).unwrap()).unwrap()
}

/// A vault holding the Basic `fx_basic`, permitted to reach `localhost:port` only.
fn vault(state_dir: &Path, port: u16) -> Vault {
    fs::create_dir(state_dir).unwrap();
    let lock = StateDirLock::acquire(state_dir).unwrap();
    let mut vault = Vault::create(&lock, &OsFs, VaultIdentity::generate()).unwrap();
    let origins = PermittedOrigins::new([("localhost".parse().unwrap(), port.to_string().parse().unwrap())].into()).unwrap();
    let material = CredentialMaterial::Basic {
        username: USERNAME.into(),
        password: PASSWORD.into(),
    };
    vault.add(&lock, &OsFs, "fx_basic".parse().unwrap(), material, origins).unwrap();
    vault
}

/// The request server with the proxy handler on one Unix listener, stopped on drop.
struct Proxy {
    dir: TempDir,
    task: JoinHandle<()>,
}

impl Proxy {
    async fn start(ca: &TestCa, upstream: &MockUpstream) -> Self {
        let dir = TempDir::new();
        let config = config(&dir.0.join("proxy.sock"), &upstream.origin());
        let vault = vault(&dir.0.join("state"), upstream.port());
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

    /// The caller's `method target` with its token and `Accept-Encoding: gzip`, on a fresh connection; the whole raw
    /// response once it closes.
    async fn send(&self, method: &str, target: &str) -> Response {
        let mut stream = UnixStream::connect(self.dir.0.join("proxy.sock")).await.unwrap();
        let request = format!(
            "{method} {target} HTTP/1.1\r\nHost: localhost\r\n{TOKEN_HEADER}: {}\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n",
            token()
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut raw = Vec::new();
        tokio::time::timeout(WAIT, stream.read_to_end(&mut raw)).await.unwrap().unwrap();
        Response::parse(&raw)
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

/// A response as the caller read it, its body still in its transfer framing.
struct Response {
    status: u16,
    /// Header names lowercased, values trimmed, in arrival order.
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Response {
    fn parse(raw: &[u8]) -> Self {
        let split = raw.windows(4).position(|window| window == b"\r\n\r\n").unwrap();
        let head = std::str::from_utf8(&raw[..split]).unwrap();
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
            body: raw[split + 4..].to_vec(),
        }
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
    }

    /// The body with its chunked framing removed, or `None` if it does not end with the last chunk.
    fn dechunked(&self) -> Option<Vec<u8>> {
        let mut rest = self.body.as_slice();
        let mut out = Vec::new();
        loop {
            let line_end = rest.windows(2).position(|window| window == b"\r\n")?;
            let size = usize::from_str_radix(std::str::from_utf8(&rest[..line_end]).ok()?, 16).ok()?;
            rest = &rest[line_end + 2..];
            if size == 0 {
                return (rest == b"\r\n").then_some(out);
            }
            out.extend_from_slice(rest.get(..size)?);
            rest = rest.get(size + 2..)?;
        }
    }

    fn text(&self) -> String {
        String::from_utf8(self.dechunked().unwrap()).unwrap()
    }
}

fn reply(headers: &[(&str, &str)], body: &[u8]) -> Reply {
    Reply::Respond {
        status: 200,
        headers: headers.iter().map(|(n, v)| ((*n).to_owned(), (*v).to_owned())).collect(),
        body: body.to_vec(),
    }
}

/// The `Basic` token the upstream received in `Authorization`.
fn basic_token(upstream: &MockUpstream) -> String {
    let headers = upstream.requests()[0].headers();
    let (_, value) = headers.iter().find(|(name, _)| name == "authorization").unwrap();
    value.strip_prefix("Basic ").unwrap().to_owned()
}

/// Every form of the credential the test could see leak: the password, its URL-encoded form and `user:pass`.
fn leaked_forms() -> [String; 3] {
    [PASSWORD.to_owned(), PASSWORD_ENCODED.to_owned(), format!("{USERNAME}:{PASSWORD}")]
}

/// An upstream whose body and `X-Echo` header both echo the credential. The mock cannot know the `Basic` token ahead of
/// the request, so the body echoes `token` from a first exchange's `Authorization`: the token is the same every time.
async fn echoing_upstream(ca: &TestCa, token: &str) -> MockUpstream {
    let body = format!("raw={PASSWORD} auth=Basic {token} enc={PASSWORD_ENCODED} end");
    MockUpstream::start(ca, reply(&[("x-echo", PASSWORD), ("content-type", "text/plain")], body.as_bytes())).await
}

/// The `Basic` token the proxy injects for the test credential, learnt from one exchange with a plain upstream.
async fn injected_token(ca: &TestCa) -> String {
    let upstream = MockUpstream::start(ca, Reply::ok("ok")).await;
    let proxy = Proxy::start(ca, &upstream).await;
    proxy.send("GET", "/fx/latest").await;
    basic_token(&upstream)
}

#[tokio::test]
async fn the_secret_its_basic_token_and_its_url_encoded_form_are_all_replaced() {
    let ca = TestCa::new("scrub test CA");
    let token = injected_token(&ca).await;
    let upstream = echoing_upstream(&ca, &token).await;
    let proxy = Proxy::start(&ca, &upstream).await;

    let response = proxy.send("GET", "/fx/latest").await;

    let r = std::str::from_utf8(SCRUB_REPLACEMENT).unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.text(), format!("raw={r} auth={r} enc={r} end"));
    assert_eq!(response.header("x-echo"), Some(r));
    let raw = String::from_utf8_lossy(&response.body).into_owned() + &format!("{:?}", response.headers);
    leaked_forms()
        .iter()
        .chain([&token])
        .for_each(|form| assert!(!raw.contains(form.as_str()), "{form} reached the caller: {raw}"));
}

#[tokio::test]
async fn a_gzip_reply_is_502_and_its_body_is_not_returned() {
    let ca = TestCa::new("scrub test CA");
    let gzip_body = b"\x1f\x8b\x08\x00upstream-body-marker";
    let upstream = MockUpstream::start(&ca, reply(&[("content-encoding", "gzip")], gzip_body)).await;
    let proxy = Proxy::start(&ca, &upstream).await;

    let response = proxy.send("GET", "/fx/latest").await;

    assert_eq!(response.status, 502);
    assert_eq!(response.body, b"bad gateway");
    assert_eq!(response.header("content-encoding"), None);
    // The caller asked for gzip; the upstream was not told so.
    let sent = upstream.requests()[0].headers();
    assert!(sent.iter().all(|(name, _)| name != "accept-encoding"), "{sent:?}");
}

#[tokio::test]
async fn a_reply_without_the_secret_comes_back_unchanged_but_for_its_framing_and_integrity_headers() {
    let ca = TestCa::new("scrub test CA");
    let body = "{\"rates\":{\"EUR\":0.91},\"note\":\"pa/ss but not the password; Basic realm\"}\n\u{e9}\u{1f600}";
    let kept = [
        ("content-type", "application/json; charset=utf-8"),
        ("etag", "\"v1\""),
        ("cache-control", "max-age=60"),
        ("x-request-id", "req-77"),
    ];
    let removed = [
        ("content-digest", "sha-256=:AAAA:"),
        ("repr-digest", "sha-256=:AAAA:"),
        ("digest", "SHA-256=AAAA"),
    ];
    let headers: Vec<_> = kept.iter().chain(&removed).copied().collect();
    let upstream = MockUpstream::start(&ca, reply(&headers, body.as_bytes())).await;
    let proxy = Proxy::start(&ca, &upstream).await;

    let response = proxy.send("GET", "/fx/latest").await;

    assert_eq!(response.status, 200);
    assert_eq!(response.dechunked().unwrap(), body.as_bytes());
    kept.iter()
        .for_each(|(name, value)| assert_eq!(response.header(name), Some(*value), "{name}"));
    // Besides the kept headers, only the request server's own framing and date headers.
    let own = ["transfer-encoding", "connection", "date"];
    response
        .headers
        .iter()
        .filter(|(name, _)| !kept.iter().any(|(kept, _)| kept == name))
        .for_each(|(name, _)| assert!(own.contains(&name.as_str()), "{name} reached the caller"));
}

#[tokio::test]
async fn a_head_response_keeps_its_content_length() {
    let ca = TestCa::new("scrub test CA");
    let upstream = MockUpstream::start(&ca, Reply::ok("hello")).await;
    let proxy = Proxy::start(&ca, &upstream).await;

    let response = proxy.send("HEAD", "/fx/latest").await;

    assert_eq!(response.status, 200);
    assert_eq!(response.header("content-length"), Some("5"));
    assert_eq!(response.header("transfer-encoding"), None);
    assert!(response.body.is_empty());
}

#[tokio::test]
async fn a_body_cut_short_never_releases_a_held_secret_prefix() {
    let ca = TestCa::new("scrub test CA");
    let prefix = &PASSWORD[..PASSWORD.len() - 1];
    let truncated = Reply::Truncated {
        sent: format!("partial {prefix}"),
    };
    let upstream = MockUpstream::start(&ca, truncated).await;
    let proxy = Proxy::start(&ca, &upstream).await;

    let response = proxy.send("GET", "/fx/latest").await;

    let raw = String::from_utf8_lossy(&response.body).into_owned();
    assert_eq!(response.status, 200);
    assert!(raw.contains("partial "), "{raw:?}");
    assert!(!raw.contains("pa/"), "the held prefix reached the caller: {raw:?}");
    assert!(response.dechunked().is_none(), "the cut-short body ended cleanly: {raw:?}");
}

#[tokio::test]
async fn the_scrub_event_names_the_route_and_credential_and_holds_no_secret_form() {
    let ca = TestCa::new("scrub test CA");
    let token = injected_token(&ca).await;
    let upstream = echoing_upstream(&ca, &token).await;
    let proxy = Proxy::start(&ca, &upstream).await;
    let captured = Captured::default();
    let subscriber = tracing_subscriber::fmt().with_writer(captured.clone()).with_ansi(false).finish();

    // The test runtime has one thread, so the server's tasks log to this thread's subscriber.
    let response = {
        let _guard = tracing::subscriber::set_default(subscriber);
        proxy.send("GET", "/fx/latest").await
    };

    assert_eq!(response.status, 200);
    let logged = captured.text();
    let events: Vec<&str> = logged.lines().filter(|line| line.contains("scrubbed a secret")).collect();
    assert_eq!(events.len(), 1, "{logged}");
    let event = events[0];
    ["WARN", "route=fx", "credential=fx_basic", "matches=4"]
        .iter()
        .for_each(|wanted| assert!(event.contains(wanted), "{wanted} missing from {event}"));
    leaked_forms()
        .iter()
        .chain([&token])
        .for_each(|form| assert!(!logged.contains(form.as_str()), "{form} was logged: {logged}"));
}

/// A log writer that keeps everything written to it.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Captured {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap_or_else(PoisonError::into_inner).clone()).unwrap()
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
