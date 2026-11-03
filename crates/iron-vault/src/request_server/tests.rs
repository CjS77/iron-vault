//! The request server on real sockets, with a stub handler, speaking raw HTTP/1.1 so each limit is hit to the byte.

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use iron_vault_policy::ParsedConfig;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};
use tokio::task::JoinHandle;

use super::*;
use crate::request_listeners::tests::{TestCa, ThreeListeners, name};

const WAIT: Duration = Duration::from_secs(5);
const GET: &[u8] = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";

/// Records every request it sees; answers `200` once it has read the whole body, `500` if reading it failed, never
/// when it stalls, or `504` with a body at the deadline when it waits for it.
#[derive(Default)]
struct Stub {
    stall: bool,
    answer_at_deadline: bool,
    calls: AtomicUsize,
    read_bodies: AtomicUsize,
    tags: Mutex<Vec<ConnectionTags>>,
}

impl RequestHandler for Arc<Stub> {
    fn handle(
        &self,
        request: Request<RequestBody>,
        tags: &ConnectionTags,
        deadline: Instant,
    ) -> impl Future<Output = Response<ResponseBody>> + Send {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.tags.lock().unwrap().push(tags.clone());
        let stub = Arc::clone(self);
        async move {
            if stub.answer_at_deadline {
                tokio::time::sleep_until(deadline).await;
                let mut response = Response::new(
                    Full::new(Bytes::from_static(b"gateway timeout"))
                        .map_err(|never| match never {})
                        .boxed_unsync(),
                );
                *response.status_mut() = StatusCode::GATEWAY_TIMEOUT;
                return response;
            }
            if stub.stall {
                std::future::pending::<()>().await;
            }
            let status = match request.into_body().collect().await {
                Ok(_) => {
                    stub.read_bodies.fetch_add(1, Ordering::SeqCst);
                    StatusCode::OK
                }
                Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
            };
            let mut response = Response::new(Empty::new().map_err(|never| match never {}).boxed_unsync());
            *response.status_mut() = status;
            response
        }
    }
}

/// A request server on three listeners, stopped on drop.
struct Running {
    setup: ThreeListeners,
    ca: TestCa,
    stub: Arc<Stub>,
    task: JoinHandle<()>,
}

impl Running {
    /// Serves with the `[limits]` table `limits` and the stub `stub`.
    fn start(limits: &str, stub: Stub) -> Self {
        let setup = ThreeListeners::new();
        let ca = TestCa::new();
        let listeners = setup.open(&ca, 0o600).unwrap();
        let config = ParsedConfig::from_toml(format!("schema_version = 1\n[limits]\n{limits}").as_bytes()).unwrap();
        let stub = Arc::new(stub);
        let server = RequestServer::new(*config.limits(), Arc::clone(&stub));
        let task = tokio::spawn(async move {
            let _ = server.serve(&listeners).await;
        });
        Self { setup, ca, stub, task }
    }

    async fn unix(&self) -> UnixStream {
        UnixStream::connect(self.setup.unix_path()).await.unwrap()
    }

    /// The status a fresh Unix connection gets for `request`.
    async fn status(&self, request: &[u8]) -> Option<u16> {
        status(&mut self.unix().await, request).await
    }

    fn calls(&self) -> usize {
        self.stub.calls.load(Ordering::SeqCst)
    }

    fn read_bodies(&self) -> usize {
        self.stub.read_bodies.load(Ordering::SeqCst)
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Sends `request` and reads the response head, returning its status; `None` if the connection closed first.
async fn status(stream: &mut (impl AsyncRead + AsyncWrite + Unpin), request: &[u8]) -> Option<u16> {
    stream.write_all(request).await.unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read_u8().await {
            Ok(byte) => head.push(byte),
            Err(_) => break,
        }
    }
    let head = String::from_utf8(head).unwrap();
    head.strip_prefix("HTTP/1.1 ")
        .and_then(|rest| rest.get(..3))
        .map(|code| code.parse().unwrap())
}

/// A `GET` whose request line and headers are exactly `len` bytes.
fn head_of_len(len: usize) -> Vec<u8> {
    let bare = "GET / HTTP/1.1\r\nHost: x\r\nX-Pad: \r\n\r\n".len();
    format!("GET / HTTP/1.1\r\nHost: x\r\nX-Pad: {}\r\n\r\n", "p".repeat(len - bare)).into_bytes()
}

#[tokio::test]
async fn a_head_over_max_header_bytes_gets_431_and_one_at_it_is_served() {
    let running = Running::start("max_header_bytes = 100", Stub::default());
    assert_eq!(running.status(&head_of_len(101)).await, Some(431));
    assert_eq!(running.calls(), 0);
    assert_eq!(running.status(&head_of_len(100)).await, Some(200));
}

#[tokio::test]
async fn more_headers_than_max_header_count_get_431() {
    let running = Running::start("max_header_count = 3", Stub::default());
    assert_eq!(
        running.status(b"GET / HTTP/1.1\r\nHost: x\r\nA: 1\r\nB: 2\r\nC: 3\r\n\r\n").await,
        Some(431)
    );
    assert_eq!(running.calls(), 0);
    assert_eq!(
        running.status(b"GET / HTTP/1.1\r\nHost: x\r\nA: 1\r\nB: 2\r\n\r\n").await,
        Some(200)
    );
}

#[tokio::test]
async fn a_content_length_over_the_body_limit_gets_413_before_the_handler_runs() {
    let running = Running::start("max_request_body_bytes = 10", Stub::default());
    assert_eq!(
        running.status(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n\r\n").await,
        Some(413)
    );
    assert_eq!(running.calls(), 0);
    let at_limit = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n0123456789";
    assert_eq!(running.status(at_limit).await, Some(200));
    assert_eq!(running.read_bodies(), 1);
}

#[tokio::test]
async fn a_chunked_body_is_refused_with_413_once_it_passes_the_limit() {
    let running = Running::start("max_request_body_bytes = 10", Stub::default());
    let over = b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\nworld!\r\n0\r\n\r\n";
    assert_eq!(running.status(over).await, Some(413));
    assert_eq!(running.read_bodies(), 0, "the handler read a body past the limit");
    let at_limit = b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n";
    assert_eq!(running.status(at_limit).await, Some(200));
    assert_eq!(running.read_bodies(), 1);
}

#[tokio::test]
async fn a_connection_past_max_connections_is_closed_while_the_others_are_served() {
    let running = Running::start("max_connections = 2", Stub::default());
    let (mut first, mut second) = (running.unix().await, running.unix().await);
    assert_eq!(status(&mut first, GET).await, Some(200));
    assert_eq!(status(&mut second, GET).await, Some(200));

    let mut third = running.unix().await;
    let read = tokio::time::timeout(WAIT, third.read(&mut [0; 1])).await.unwrap().unwrap();
    assert_eq!(read, 0, "the connection over the limit was not closed");

    assert_eq!(status(&mut first, GET).await, Some(200));
    assert_eq!(running.calls(), 3);
}

#[tokio::test(start_paused = true)]
async fn a_client_that_never_finishes_its_headers_is_dropped_at_the_header_timeout() {
    let running = Running::start("", Stub::default());
    let mut client = running.unix().await;
    let start = Instant::now();
    client.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n").await.unwrap();
    let read = tokio::time::timeout(HEADER_READ_TIMEOUT * 2, client.read(&mut [0; 1]))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read, 0, "the slow client got a response");
    assert!(start.elapsed() >= HEADER_READ_TIMEOUT, "dropped after {:?}", start.elapsed());
    assert_eq!(running.calls(), 0);
}

#[tokio::test(start_paused = true)]
async fn an_idle_connection_that_sends_nothing_is_dropped_at_the_header_timeout() {
    let running = Running::start("", Stub::default());
    let mut client = running.unix().await;
    let start = Instant::now();
    let read = tokio::time::timeout(HEADER_READ_TIMEOUT * 2, client.read(&mut [0; 1]))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read, 0, "the idle client got a response");
    assert!(start.elapsed() >= HEADER_READ_TIMEOUT, "dropped after {:?}", start.elapsed());
    assert_eq!(running.calls(), 0);
}

#[tokio::test(start_paused = true)]
async fn a_request_still_unanswered_at_the_request_timeout_gets_408() {
    let stalled = Stub {
        stall: true,
        ..Stub::default()
    };
    let running = Running::start("request_timeout_secs = 1\nupstream_timeout_secs = 1", stalled);
    let start = Instant::now();
    assert_eq!(running.status(GET).await, Some(408));
    assert!(start.elapsed() >= Duration::from_secs(1), "answered after {:?}", start.elapsed());
}

#[tokio::test(start_paused = true)]
async fn a_handler_answering_at_the_deadline_is_heard_with_its_whole_body() {
    let at_deadline = Stub {
        answer_at_deadline: true,
        ..Stub::default()
    };
    let running = Running::start("request_timeout_secs = 1\nupstream_timeout_secs = 1", at_deadline);
    let (code, text) = response_of(&running, b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await;
    assert_eq!(code, Some(504));
    assert!(text.ends_with("\r\n\r\ngateway timeout"), "{text}");
}

#[tokio::test]
async fn the_handler_sees_the_listener_and_peer_uid_of_each_connection() {
    let running = Running::start("", Stub::default());
    assert_eq!(running.status(GET).await, Some(200));
    assert_eq!(
        status(&mut TcpStream::connect(running.setup.tcp).await.unwrap(), GET).await,
        Some(200)
    );
    let raw = TcpStream::connect(running.setup.tls).await.unwrap();
    let mut tls = running
        .ca
        .client()
        .connect(ServerName::try_from("localhost").unwrap(), raw)
        .await
        .unwrap();
    assert_eq!(status(&mut tls, GET).await, Some(200));

    let seen: Vec<_> = running
        .stub
        .tags
        .lock()
        .unwrap()
        .iter()
        .map(|tags| (tags.listener().clone(), tags.peer_uid()))
        .collect();
    let uid = rustix::process::getuid().as_raw();
    assert_eq!(seen, [(name("a-unix"), Some(uid)), (name("b-tcp"), None), (name("c-tls"), None)]);
}

/// The status and body of the response `request` gets on a fresh Unix connection.
async fn response_of(running: &Running, request: &[u8]) -> (Option<u16>, String) {
    status_and_rest(&mut running.unix().await, request).await
}

async fn status_and_rest(stream: &mut (impl AsyncRead + AsyncWrite + Unpin), request: &[u8]) -> (Option<u16>, String) {
    stream.write_all(request).await.unwrap();
    let mut raw = Vec::new();
    let _ = tokio::time::timeout(WAIT, stream.read_to_end(&mut raw)).await.unwrap();
    let text = String::from_utf8_lossy(&raw).into_owned();
    let code = text
        .strip_prefix("HTTP/1.1 ")
        .and_then(|rest| rest.get(..3))
        .and_then(|code| code.parse().ok());
    (code, text)
}

#[tokio::test]
async fn a_request_outside_origin_form_gets_400_and_never_reaches_the_handler() {
    let running = Running::start("", Stub::default());
    let refused: [&[u8]; 8] = [
        b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
        b"GET https://evil.example/secret?k=SECRET HTTP/1.1\r\nHost: x\r\n\r\n",
        b"GET http://evil.example/ HTTP/1.1\r\nHost: x\r\n\r\n",
        b"OPTIONS * HTTP/1.1\r\nHost: x\r\n\r\n",
        b"GET /?k=SECRET HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
        b"GET /?k=SECRET HTTP/1.1\r\nHost: x\r\nUpgrade: h2c\r\nConnection: Upgrade, HTTP2-Settings\r\n\r\n",
        b"GET /?k=SECRET HTTP/1.1\r\nHost: x\r\nConnection: keep-alive, upgrade\r\n\r\n",
        b"GET /?k=SECRET HTTP/1.1\r\nHost: x\r\nUpgrade: foo\r\n\r\n",
    ];
    for request in refused {
        let (status, text) = response_of(&running, request).await;
        let shown = String::from_utf8_lossy(request);
        assert_eq!(status, Some(400), "{shown}");
        assert!(
            !text.contains("SECRET") && !text.contains("evil"),
            "the 400 repeats the target: {text}"
        );
    }
    assert_eq!(running.calls(), 0);
}

#[tokio::test]
async fn the_400_body_names_the_rule_only() {
    let running = Running::start("", Stub::default());
    let (_, text) = response_of(&running, b"GET https://evil.example/?k=SECRET HTTP/1.1\r\nHost: x\r\n\r\n").await;
    assert!(text.ends_with("the request target must be origin-form"), "{text}");
}

#[tokio::test]
async fn origin_form_requests_pass_through_to_the_handler() {
    let running = Running::start("", Stub::default());
    assert_eq!(running.status(b"GET /fx/latest?x=1 HTTP/1.1\r\nHost: x\r\n\r\n").await, Some(200));
    let post = b"POST /v1/chat HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}";
    assert_eq!(running.status(post).await, Some(200));
    assert_eq!(running.calls(), 2);
}

#[tokio::test]
async fn hyper_refuses_conflicting_content_lengths_before_the_handler_runs() {
    let running = Running::start("", Stub::default());
    let conflicting = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nabc";
    assert_eq!(response_of(&running, conflicting).await.0, Some(400));
    assert_eq!(running.calls(), 0);
}
