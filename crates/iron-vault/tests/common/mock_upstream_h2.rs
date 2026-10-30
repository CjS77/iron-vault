//! The HTTP/2 mode of the test upstream: a TLS server on loopback that offers ALPN `h2` only and records what each
//! request's HEADERS frame carried, including how HPACK encoded every field.
//!
//! [`MockUpstream`](super::mock_upstream::MockUpstream) stays the HTTP/1.1 default. This mode is its own type because
//! an HTTP/2 request has pseudo-headers and field representations that an HTTP/1.1 head does not.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Bytes;
use h2::Reason;
use h2::server::{Connection, SendResponse};
use http::{Request, Response};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

use super::h2_refusal::{Refusal, refuse};
use super::hpack_fields::{Field, first_header_fields};
use super::mock_upstream::{TestCa, UPSTREAM_HOST};

/// What the HTTP/2 test upstream does once it has recorded a request.
#[derive(Debug, Clone)]
pub enum H2Reply {
    /// Answers with this status and body, then shuts the connection down gracefully.
    Respond {
        /// The status code.
        status: u16,
        /// The body.
        body: Vec<u8>,
    },
    /// Resets the request's stream with this error code before any response.
    Reset(Reason),
    /// Sends GOAWAY with this error code before any response, then closes the connection.
    GoAway(Reason),
    /// Refuses every request before processing it, as reqwest's default retry policy treats as safe to re-send. The
    /// server answers in raw frames rather than through `h2`, so it records no [`RecordedH2Request`], only each request
    /// head in [`MockH2Upstream::request_heads`].
    Refuse(Refusal),
}

impl H2Reply {
    /// `200 OK` with `body`.
    pub fn ok(body: &str) -> Self {
        Self::Respond {
            status: 200,
            body: body.as_bytes().to_vec(),
        }
    }
}

/// One HTTP/2 request as the test upstream received it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedH2Request {
    /// The server name the client sent in the TLS handshake (SNI), if any.
    pub server_name: Option<String>,
    /// The protocol ALPN settled on.
    pub alpn: Option<Vec<u8>>,
    /// `:method`.
    pub method: String,
    /// `:scheme`.
    pub scheme: Option<String>,
    /// `:authority`.
    pub authority: Option<String>,
    /// `:path`, with its query.
    pub path: Option<String>,
    /// Each regular header, the name lowercased, in the order `http::HeaderMap` iterates them.
    pub headers: Vec<(String, String)>,
    /// Every field of the request's header block in wire order, pseudo-headers included, as HPACK encoded it. `None` if
    /// the raw block could not be read, which a test should treat as a failure.
    pub fields: Option<Vec<Field>>,
}

impl RecordedH2Request {
    /// The fields that are not pseudo-headers, in wire order.
    pub fn regular_fields(&self) -> Vec<Field> {
        self.fields.iter().flatten().filter(|field| !field.is_pseudo()).copied().collect()
    }
}

/// A recording HTTP/2 TLS server on `127.0.0.1`, stopped when dropped.
pub struct MockH2Upstream {
    port: u16,
    requests: Arc<Mutex<Vec<RecordedH2Request>>>,
    connections: Arc<AtomicUsize>,
    heads: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl MockH2Upstream {
    /// Starts a server presenting a certificate for [`UPSTREAM_HOST`] from `ca`, answering every request with `reply`.
    pub async fn start(ca: &TestCa, reply: H2Reply) -> Self {
        let mut config = Arc::unwrap_or_clone(ca.server_config(UPSTREAM_HOST));
        config.alpn_protocols = vec![b"h2".to_vec()];
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicUsize::new(0));
        let heads = Arc::new(AtomicUsize::new(0));
        let server = Server {
            acceptor: TlsAcceptor::from(Arc::new(config)),
            reply: Arc::new(reply),
            requests: Arc::clone(&requests),
            connections: Arc::clone(&connections),
            heads: Arc::clone(&heads),
        };
        let task = tokio::spawn(server.run(listener));
        Self {
            port,
            requests,
            connections,
            heads,
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

    /// Every request received so far, in arrival order.
    pub fn requests(&self) -> Vec<RecordedH2Request> {
        self.requests.lock().unwrap().clone()
    }

    /// How many TCP connections the server has accepted.
    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    /// How many request heads the server has received: each recorded request, plus each one a [`H2Reply::Refuse`]
    /// refused.
    pub fn request_heads(&self) -> usize {
        self.heads.load(Ordering::SeqCst)
    }
}

impl Drop for MockH2Upstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Clone)]
struct Server {
    acceptor: TlsAcceptor,
    reply: Arc<H2Reply>,
    requests: Arc<Mutex<Vec<RecordedH2Request>>>,
    connections: Arc<AtomicUsize>,
    heads: Arc<AtomicUsize>,
}

type H2Connection = Connection<Recording<TlsStream<TcpStream>>, Bytes>;

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

    /// Records the first request on `stream` and replies; a failed handshake records nothing.
    async fn serve(self, stream: TcpStream) {
        let Ok(tls) = self.acceptor.accept(stream).await else {
            return;
        };
        if let H2Reply::Refuse(refusal) = *self.reply {
            return refuse(tls, refusal, &self.heads).await;
        }
        let session = tls.get_ref().1;
        let server_name = session.server_name().map(str::to_owned);
        let alpn = session.alpn_protocol().map(<[u8]>::to_vec);
        let received = Arc::new(Mutex::new(Vec::new()));
        let recording = Recording {
            inner: tls,
            received: Arc::clone(&received),
        };
        let Ok(mut connection) = h2::server::handshake(recording).await else {
            return;
        };
        let Some(Ok((request, respond))) = connection.accept().await else {
            return;
        };
        // The request's HEADERS frame has been read in full by now, so `received` holds it.
        let fields = first_header_fields(&received.lock().unwrap());
        self.heads.fetch_add(1, Ordering::SeqCst);
        let recorded = record(server_name, alpn, &request, fields);
        self.requests.lock().unwrap().push(recorded);
        reply(&self.reply, connection, respond).await;
    }
}

fn record(
    server_name: Option<String>,
    alpn: Option<Vec<u8>>,
    request: &Request<h2::RecvStream>,
    fields: Option<Vec<Field>>,
) -> RecordedH2Request {
    let uri = request.uri();
    let headers = request
        .headers()
        .iter()
        .map(|(name, value)| (name.as_str().to_owned(), String::from_utf8_lossy(value.as_bytes()).into_owned()))
        .collect();
    RecordedH2Request {
        server_name,
        alpn,
        method: request.method().as_str().to_owned(),
        scheme: uri.scheme_str().map(str::to_owned),
        authority: uri.authority().map(|authority| authority.as_str().to_owned()),
        path: uri.path_and_query().map(|path| path.as_str().to_owned()),
        headers,
        fields,
    }
}

/// Sends `reply` and drives the connection until the client closes it, so every frame is flushed.
async fn reply(reply: &H2Reply, mut connection: H2Connection, mut respond: SendResponse<Bytes>) {
    match reply {
        H2Reply::Respond { status, body } => {
            let response = Response::builder().status(*status).body(()).unwrap();
            let mut stream = respond.send_response(response, false).unwrap();
            stream.send_data(Bytes::from(body.clone()), true).unwrap();
            connection.graceful_shutdown();
        }
        H2Reply::Reset(reason) => respond.send_reset(*reason),
        H2Reply::GoAway(reason) => connection.abrupt_shutdown(*reason),
        H2Reply::Refuse(_) => unreachable!("a refusing server never accepts a stream through h2"),
    }
    while let Some(Ok(_)) = connection.accept().await {}
}

/// A stream that keeps a copy of every byte read through it, so the test upstream can inspect the raw HTTP/2 frames
/// that `h2` decodes.
struct Recording<S> {
    inner: S,
    received: Arc<Mutex<Vec<u8>>>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Recording<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        self.received.lock().unwrap().extend_from_slice(&buf.filled()[before..]);
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Recording<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
