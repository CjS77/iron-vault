//! A TLS test upstream on loopback that records exactly what reaches it (specification §8: "use a mock upstream to
//! observe exactly which requests and credentials left the service").
//!
//! It speaks HTTP/1.1 only and records each request's head byte for byte, before any parsing could normalise it. It
//! counts TCP connections separately, so a test can prove a server saw no connection at all, not just no request.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iron_vault::upstream::trust::UpstreamTrust;
use rcgen::{BasicConstraints, Certificate, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

/// The name the test upstream's certificate is issued for, and the host every test URL names.
pub const UPSTREAM_HOST: &str = "localhost";

/// The largest request head the test upstream reads; no test sends one near this size.
const MAX_HEAD: usize = 64 * 1024;

/// A test CA that issues the test upstream's certificate.
pub struct TestCa {
    certificate: Certificate,
    issuer: Issuer<'static, KeyPair>,
}

impl TestCa {
    /// A fresh CA named `name`.
    pub fn new(name: &str) -> Self {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name.push(DnType::CommonName, name);
        let certificate = params.self_signed(&key).unwrap();
        Self {
            certificate,
            issuer: Issuer::new(params, key),
        }
    }

    /// The CA certificate as a pinned CA file holds it.
    pub fn pem(&self) -> String {
        self.certificate.pem()
    }

    /// Upstream trust that pins this CA.
    pub fn trust(&self) -> UpstreamTrust {
        UpstreamTrust::pinned_from_pem("/etc/iron-vault/ca/test.pem".as_ref(), self.pem().as_bytes()).unwrap()
    }

    /// A TLS server config presenting a leaf certificate for `dns_name`, offering HTTP/1.1 only.
    pub fn server_config(&self, dns_name: &str) -> Arc<ServerConfig> {
        let key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(vec![dns_name.to_owned()])
            .unwrap()
            .signed_by(&key, &self.issuer)
            .unwrap();
        let chain = vec![CertificateDer::from(leaf.der().to_vec())];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(config)
    }
}

/// What the test upstream does once it has recorded a request.
#[derive(Debug, Clone)]
pub enum Reply {
    /// Answers with this status, these extra headers and this body, then closes the connection.
    Respond {
        /// The status code.
        status: u16,
        /// Headers besides `content-length` and `connection`.
        headers: Vec<(String, String)>,
        /// The body.
        body: Vec<u8>,
    },
    /// Never answers, holding the connection open.
    Stall,
    /// Answers `200` with a chunked body: `first`, then `second` once `gate` is notified, so a test can prove the
    /// first chunk was relayed before the second existed.
    TwoChunks {
        /// The first chunk, sent with the head.
        first: String,
        /// The second chunk, sent after the gate opens.
        second: String,
        /// Opened by the test once it has seen the first chunk.
        gate: Arc<tokio::sync::Notify>,
    },
    /// Answers `200` with a chunked body, sends the one chunk `sent`, then closes the connection without the last
    /// chunk, so the body fails rather than ends.
    Truncated {
        /// The only chunk sent.
        sent: String,
    },
}

impl Reply {
    /// `200 OK` with `body`.
    pub fn ok(body: &str) -> Self {
        Self::Respond {
            status: 200,
            headers: Vec::new(),
            body: body.as_bytes().to_vec(),
        }
    }

    /// A `302` redirect to `location`.
    pub fn redirect(location: &str) -> Self {
        Self::Respond {
            status: 302,
            headers: vec![("location".to_owned(), location.to_owned())],
            body: Vec::new(),
        }
    }
}

/// One request head exactly as the test upstream received it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedRequest {
    /// The server name the client sent in the TLS handshake (SNI), if any.
    pub server_name: Option<String>,
    /// The request line and header lines, without the blank line that ends them.
    pub head: String,
    /// The body bytes that arrived, decoded from `Content-Length` or chunked framing.
    pub body: Vec<u8>,
    /// Whether the body arrived whole: all of its declared length, or every chunk through the terminating one. A client
    /// that aborts a request partway leaves this `false`.
    pub body_complete: bool,
}

impl RecordedRequest {
    /// The request line: method, target and version.
    pub fn request_line(&self) -> &str {
        self.head.lines().next().unwrap_or_default()
    }

    /// Each header line split at its first colon, the name lowercased and the value trimmed, in arrival order.
    pub fn headers(&self) -> Vec<(String, String)> {
        self.head
            .lines()
            .skip(1)
            .map(|line| {
                let (name, value) = line.split_once(':').unwrap();
                (name.to_ascii_lowercase(), value.trim().to_owned())
            })
            .collect()
    }
}

/// A recording TLS server on `127.0.0.1`, stopped when dropped.
pub struct MockUpstream {
    port: u16,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    connections: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl MockUpstream {
    /// Starts a server presenting a certificate for [`UPSTREAM_HOST`] from `ca`, answering every request with `reply`.
    pub async fn start(ca: &TestCa, reply: Reply) -> Self {
        Self::start_with(ca.server_config(UPSTREAM_HOST), reply).await
    }

    /// Starts a server with its own TLS config, such as one whose certificate names another host.
    pub async fn start_with(config: Arc<ServerConfig>, reply: Reply) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicUsize::new(0));
        let server = Server {
            acceptor: TlsAcceptor::from(config),
            reply: Arc::new(reply),
            requests: Arc::clone(&requests),
            connections: Arc::clone(&connections),
        };
        let task = tokio::spawn(server.run(listener));
        Self {
            port,
            requests,
            connections,
            task,
        }
    }

    /// The port the server listens on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// `https://localhost:<port>`, the origin test routes name.
    pub fn origin(&self) -> String {
        format!("https://{UPSTREAM_HOST}:{}", self.port)
    }

    /// Every request head received so far, in arrival order.
    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.requests.lock().unwrap().clone()
    }

    /// How many TCP connections the server has accepted, whether or not TLS or a request followed.
    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

impl Drop for MockUpstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The accept loop's state, shared with each connection's task.
#[derive(Clone)]
struct Server {
    acceptor: TlsAcceptor,
    reply: Arc<Reply>,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    connections: Arc<AtomicUsize>,
}

impl Server {
    async fn run(self, listener: TcpListener) {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            self.connections.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(self.clone().serve(stream));
        }
    }

    /// Records one request on `stream` and replies; a failed handshake or a cut-short head records nothing.
    async fn serve(self, stream: TcpStream) {
        let Ok(mut tls) = self.acceptor.accept(stream).await else {
            return;
        };
        let Some(head) = read_head(&mut tls).await else {
            return;
        };
        let server_name = tls.get_ref().1.server_name().map(str::to_owned);
        let (body, body_complete) = read_body(&mut tls, &head).await;
        self.requests.lock().unwrap().push(RecordedRequest {
            server_name,
            head,
            body,
            body_complete,
        });
        if !body_complete {
            return;
        }
        match &*self.reply {
            Reply::Stall => tokio::time::sleep(Duration::from_secs(3600)).await,
            Reply::Respond { status, headers, body } => {
                let _ = tls.write_all(&response(*status, headers, body)).await;
                let _ = tls.shutdown().await;
            }
            Reply::TwoChunks { first, second, gate } => {
                let head = "HTTP/1.1 200 Test\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n";
                let _ = tls.write_all(format!("{head}{}", chunk(first)).as_bytes()).await;
                let _ = tls.flush().await;
                gate.notified().await;
                let _ = tls.write_all(format!("{}0\r\n\r\n", chunk(second)).as_bytes()).await;
                let _ = tls.shutdown().await;
            }
            Reply::Truncated { sent } => {
                let head = "HTTP/1.1 200 Test\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n";
                let _ = tls.write_all(format!("{head}{}", chunk(sent)).as_bytes()).await;
                let _ = tls.shutdown().await;
            }
        }
    }
}

/// Reads up to the blank line ending a request head and returns the head before it.
async fn read_head(stream: &mut (impl AsyncReadExt + Unpin)) -> Option<String> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_HEAD || stream.read(&mut byte).await.ok()? == 0 {
            return None;
        }
        head.push(byte[0]);
    }
    head.truncate(head.len() - 4);
    String::from_utf8(head).ok()
}

/// Reads the body that follows `head`, framed by its `Content-Length` or `Transfer-Encoding: chunked`, and whether it
/// arrived whole. A head with neither has no body.
async fn read_body(stream: &mut (impl AsyncReadExt + Unpin), head: &str) -> (Vec<u8>, bool) {
    let header = |wanted: &str| {
        head.lines()
            .skip(1)
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case(wanted))
            .map(|(_, value)| value.trim().to_owned())
    };
    let mut body = Vec::new();
    let complete = if header("transfer-encoding").is_some_and(|value| value.eq_ignore_ascii_case("chunked")) {
        read_chunks(stream, &mut body).await.is_some()
    } else if let Some(length) = header("content-length").and_then(|value| value.parse::<usize>().ok()) {
        read_up_to(stream, length, &mut body).await == length
    } else {
        true
    };
    (body, complete)
}

/// Appends each chunk of a chunked body to `body`; `None` if the stream ends before the terminating chunk.
async fn read_chunks(stream: &mut (impl AsyncReadExt + Unpin), body: &mut Vec<u8>) -> Option<()> {
    loop {
        let line = read_line(stream).await?;
        let size = usize::from_str_radix(line.split(';').next()?.trim(), 16).ok()?;
        (read_up_to(stream, size, body).await == size).then_some(())?;
        // The CRLF after the chunk data, or after the last-chunk line when no trailers follow.
        read_line(stream).await?;
        if size == 0 {
            return Some(());
        }
    }
}

/// Appends up to `count` bytes from `stream` to `body` and returns how many arrived; fewer if the stream ended or failed.
async fn read_up_to(stream: &mut (impl AsyncReadExt + Unpin), count: usize, body: &mut Vec<u8>) -> usize {
    let before = body.len();
    let _ = stream.take(count as u64).read_to_end(body).await;
    body.len() - before
}

/// One line up to its LF, without the line ending; `None` at the end of the stream.
async fn read_line(stream: &mut (impl AsyncReadExt + Unpin)) -> Option<String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    while line.last() != Some(&b'\n') {
        if stream.read(&mut byte).await.ok()? == 0 {
            return None;
        }
        line.push(byte[0]);
    }
    Some(String::from_utf8(line).ok()?.trim_end().to_owned())
}

/// `data` as one chunk of a chunked body.
fn chunk(data: &str) -> String {
    format!("{:x}\r\n{data}\r\n", data.len())
}

fn response(status: u16, headers: &[(String, String)], body: &[u8]) -> Vec<u8> {
    let extra: String = headers.iter().map(|(name, value)| format!("{name}: {value}\r\n")).collect();
    let head = format!(
        "HTTP/1.1 {status} Test\r\ncontent-length: {}\r\nconnection: close\r\n{extra}\r\n",
        body.len()
    );
    [head.as_bytes(), body].concat()
}
