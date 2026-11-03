//! The real request server and proxy handler on a Unix request socket and an optional loopback TCP listener, in front of
//! a vault holding test credentials, for the end-to-end tests that point routes at a recording test upstream.
//!
//! The service account is the test's own uid. Callers authenticate with a token: on the Unix listener in the dedicated
//! [`TOKEN_HEADER`], on the TCP listener in `Proxy-Authorization`, so an upstream that echoes the header back is the
//! case the relay must strip.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use iron_vault::deployment::DeploymentProfile;
use iron_vault::path_metadata::invoking_user;
use iron_vault::proxy_handler::ProxyHandler;
use iron_vault::request_listeners::{OpenError, RequestListeners};
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
use tokio::net::{TcpStream, UnixStream};
use tokio::task::JoinHandle;

use super::mock_upstream::TestCa;

/// The dedicated caller-token header of the Unix listener `local`.
pub const TOKEN_HEADER: &str = "X-Iron-Vault-Token";

/// The bytes of the token every test caller holds.
pub const TOKEN_BYTES: [u8; 32] = [7; 32];

/// How long a test waits for one response before failing.
pub const WAIT: Duration = Duration::from_secs(10);

static NEXT: AtomicU32 = AtomicU32::new(0);

/// A fresh `0711` directory under the system temp directory, removed on drop. It holds the request socket and the
/// vault's state directory; its path stays short, because a socket path is limited to 108 bytes.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new() -> Self {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("iv-ph-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o711)).unwrap();
        Self(dir)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// These configs have no peer callers, so activation never looks an account up.
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

/// The caller token made of `bytes`, as a caller presents it.
pub fn token_of(bytes: [u8; 32]) -> String {
    CallerToken::from_bytes(bytes).expose_once().expose_secret().to_owned()
}

/// The token every test caller holds.
pub fn token() -> String {
    token_of(TOKEN_BYTES)
}

/// The `token_hash` config value for the token made of `bytes`.
pub fn token_hash(bytes: [u8; 32]) -> String {
    TokenHash::of(&CallerToken::from_bytes(bytes)).to_string()
}

/// A credential the vault holds, and the one upstream port its record permits.
pub struct Credential {
    pub name: &'static str,
    pub material: CredentialMaterial,
    /// The record permits `localhost` on this port only.
    pub port: u16,
}

/// What a harness serves.
pub struct Setup<'a> {
    pub ca: &'a TestCa,
    /// The `[callers.*]` and `[routes.*]` sections. Callers name the listener `local` (Unix) or `loopback` (TCP).
    pub callers_and_routes: String,
    pub credentials: Vec<Credential>,
    /// Whether to configure the TCP listener `loopback`. The harness picks its port, retrying when another test takes it first.
    pub tcp: bool,
    pub request_timeout_secs: u64,
}

impl Setup<'_> {
    fn config(&self, socket: &Path, tcp_port: Option<u16>) -> ValidatedConfig {
        let tcp = tcp_port.map_or_else(String::new, |port| {
            format!("\n[listeners.loopback]\naddress = \"127.0.0.1:{port}\"\n")
        });
        let toml = format!(
            r#"schema_version = 1

[limits]
request_timeout_secs = {timeout}
upstream_timeout_secs = {timeout}

[listeners.local]
unix_socket = "{socket}"
token_header = "{TOKEN_HEADER}"
{tcp}
{rest}"#,
            timeout = self.request_timeout_secs,
            socket = socket.display(),
            rest = self.callers_and_routes,
        );
        ValidatedConfig::try_from(ParsedConfig::from_toml(toml.as_bytes()).unwrap()).unwrap()
    }
}

/// A vault holding every credential, each permitted to reach `localhost` on its own port only.
fn vault(credentials: Vec<Credential>, state_dir: &Path) -> Vault {
    fs::create_dir(state_dir).unwrap();
    let lock = StateDirLock::acquire(state_dir).unwrap();
    let mut vault = Vault::create(&lock, &OsFs, VaultIdentity::generate()).unwrap();
    credentials.into_iter().for_each(|credential| {
        let port = credential.port.to_string().parse().unwrap();
        let origins = PermittedOrigins::new([("localhost".parse().unwrap(), port)].into()).unwrap();
        vault
            .add(&lock, &OsFs, credential.name.parse().unwrap(), credential.material, origins)
            .unwrap();
    });
    vault
}

/// A free loopback port, bound, read and closed. Config rejects port 0, so a TCP listener needs a number up front.
/// Another process can take it before the caller binds it, so a caller that binds it retries on `AddrInUse`.
pub fn next_free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// The transport a caller connects over, which decides how its token travels.
#[derive(Clone, Copy, Debug)]
pub enum Via {
    Unix,
    Tcp,
}

impl Via {
    /// The header that carries a caller token made of `bytes` on this transport.
    pub fn auth_header(self, bytes: [u8; 32]) -> (String, String) {
        match self {
            Self::Unix => (TOKEN_HEADER.to_owned(), token_of(bytes)),
            Self::Tcp => ("Proxy-Authorization".to_owned(), format!("Bearer {}", token_of(bytes))),
        }
    }
}

/// One HTTP/1.1 request as a caller writes it to the socket, byte for byte.
#[derive(Clone, Debug)]
pub struct CallerRequest {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl CallerRequest {
    pub fn new(method: &str, target: &str) -> Self {
        Self {
            method: method.to_owned(),
            target: target.to_owned(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn get(target: &str) -> Self {
        Self::new("GET", target)
    }

    pub fn post(target: &str, body: &[u8]) -> Self {
        Self {
            body: body.to_vec(),
            ..Self::new("POST", target)
        }
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    /// Adds the token made of `bytes`, in the header `via` reads it from.
    pub fn with_token(self, via: Via, bytes: [u8; 32]) -> Self {
        let (name, value) = via.auth_header(bytes);
        self.header(&name, &value)
    }

    /// Adds the token every test caller holds.
    pub fn signed(self, via: Via) -> Self {
        self.with_token(via, TOKEN_BYTES)
    }

    /// The request as written: the request line, the headers (with `Host: localhost` unless the caller set one), a
    /// `Content-Length` for a body, `Connection: close` so the response ends at EOF, then the body.
    pub fn to_bytes(&self) -> Vec<u8> {
        let host = (!self.headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("host"))).then(|| "Host: localhost\r\n".to_owned());
        let length = (!self.body.is_empty()).then(|| format!("Content-Length: {}\r\n", self.body.len()));
        let headers: String = self.headers.iter().map(|(name, value)| format!("{name}: {value}\r\n")).collect();
        let head = format!(
            "{} {} HTTP/1.1\r\n{}{headers}{}Connection: close\r\n\r\n",
            self.method,
            self.target,
            host.unwrap_or_default(),
            length.unwrap_or_default()
        );
        [head.as_bytes(), &self.body].concat()
    }
}

/// A response as the caller read it.
pub struct Response {
    pub status: u16,
    /// Header names lowercased, values trimmed, in arrival order.
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Response {
    pub fn parse(raw: &str) -> Self {
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

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
    }
}

/// Where a caller reaches the proxy. Cheap to clone, so concurrent callers can each take one into a task.
#[derive(Clone, Debug)]
pub struct Endpoints {
    socket: PathBuf,
    tcp_port: Option<u16>,
}

impl Endpoints {
    /// A new connection on the Unix request socket.
    pub async fn connect(&self) -> UnixStream {
        UnixStream::connect(&self.socket).await.unwrap()
    }

    /// Sends `request` on a fresh connection over `via`; the whole response once the connection closes.
    pub async fn send(&self, via: Via, request: &CallerRequest) -> Response {
        Response::parse(&String::from_utf8(self.send_raw(via, request).await).unwrap())
    }

    /// Sends `request` on a fresh connection over `via`; every byte of the response once the connection closes, for a
    /// body that is not text.
    pub async fn send_raw(&self, via: Via, request: &CallerRequest) -> Vec<u8> {
        match via {
            Via::Unix => exchange(self.connect().await, request).await,
            Via::Tcp => exchange(TcpStream::connect(("127.0.0.1", self.tcp_port.unwrap())).await.unwrap(), request).await,
        }
    }
}

async fn exchange(mut stream: impl AsyncReadExt + AsyncWriteExt + Unpin, request: &CallerRequest) -> Vec<u8> {
    stream.write_all(&request.to_bytes()).await.unwrap();
    let mut raw = Vec::new();
    tokio::time::timeout(WAIT, stream.read_to_end(&mut raw)).await.unwrap().unwrap();
    raw
}

/// How many fresh ports [`open_listeners`] tries before giving up.
const BIND_ATTEMPTS: usize = 10;

/// True when opening the listeners failed because a TCP address was already bound.
fn address_in_use(error: &OpenError) -> bool {
    matches!(
        error,
        OpenError::Tcp {
            kind: io::ErrorKind::AddrInUse,
            ..
        }
    )
}

/// Opens `setup`'s listeners. The TCP port is picked before it is bound, so a parallel test can take it in between; each
/// `AddrInUse` retries with a freshly picked port, up to [`BIND_ATTEMPTS`] times. Returns the config that opened, and the port.
fn open_listeners(setup: &Setup<'_>, socket: &Path, dir: &Path) -> (ValidatedConfig, RequestListeners, Option<u16>) {
    let attempt = || {
        let port = setup.tcp.then(next_free_port);
        let config = setup.config(socket, port);
        let opened = RequestListeners::open(config.listeners(), &paths(dir), BTreeMap::new());
        opened.map(|listeners| (config, listeners, port))
    };
    let mut result = attempt();
    for _ in 1..BIND_ATTEMPTS {
        match result {
            Err(ref e) if setup.tcp && address_in_use(e) => result = attempt(),
            _ => break,
        }
    }
    result.unwrap()
}

/// The request server with the proxy handler on the configured listeners, stopped on drop.
pub struct Proxy {
    dir: TempDir,
    endpoints: Endpoints,
    task: JoinHandle<()>,
}

impl Proxy {
    /// Serves `setup`. Buckets start full: accounting from a minute ago fills them, so a request is rate limited only
    /// when a test spends a bucket.
    pub async fn start(setup: Setup<'_>) -> Self {
        let dir = TempDir::new();
        let socket = dir.path().join("proxy.sock");
        let (config, listeners, tcp_port) = open_listeners(&setup, &socket, dir.path());
        let ca = setup.ca;
        let vault = vault(setup.credentials, &dir.path().join("state"));
        let policy = activate(&config, &Capabilities::default(), &vault, &NoAccounts).unwrap();
        let trust = ca.trust();
        let clients = UpstreamClients::with_pinned_loader(&policy, TransportLimits::default(), |_| Ok(trust.clone())).unwrap();
        let limiter = RateLimiter::new(&policy, Instant::now().checked_sub(Duration::from_secs(60)).unwrap());
        let snapshot = ServingSnapshot::new(policy, vault, clients, limiter).unwrap();
        let server = RequestServer::new(*config.limits(), ProxyHandler::new(Arc::new(SnapshotHolder::new(snapshot))));
        let task = tokio::spawn(async move {
            let _ = server.serve(&listeners).await;
        });
        let endpoints = Endpoints { socket, tcp_port };
        Self { dir, endpoints, task }
    }

    /// Where callers reach this proxy.
    pub fn endpoints(&self) -> Endpoints {
        self.endpoints.clone()
    }

    /// A new connection on the Unix request socket.
    pub async fn connect(&self) -> UnixStream {
        self.endpoints.connect().await
    }

    /// The token caller's `GET target` on a fresh Unix connection.
    pub async fn get(&self, target: &str) -> Response {
        self.endpoints.send(Via::Unix, &CallerRequest::get(target).signed(Via::Unix)).await
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.task.abort();
        let _ = &self.dir;
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
