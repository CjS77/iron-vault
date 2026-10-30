//! The admin socket end to end, as the unprivileged test user: binding, the peer check, one exchange per connection,
//! the limits and shutdown. The service account is the test's own uid.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::future;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use iron_vault::admin::ADMIN_SOCKET_NAME;
use iron_vault::admin::dispatch::{AdminHandler, HandlerFuture, Handlers};
use iron_vault::admin::principal::{AdminPrincipal, AdminPrincipals};
use iron_vault::admin::protocol::{self, AdminCommand, AdminRequest, AdminResponse, Decoded, ErrorCode, Frame};
use iron_vault::admin::server::{AdminServer, Exchange, Limits};
use iron_vault::admin::socket::{AdminSocket, BindError};
use iron_vault::deployment::DeploymentProfile;
use iron_vault::path_metadata::invoking_user;
use iron_vault::trusted_path::ExpectedOwner;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

static NEXT: AtomicU32 = AtomicU32::new(0);

/// How long a test waits for anything the server should do promptly.
const PATIENCE: Duration = Duration::from_secs(5);

/// A fresh `0700` runtime directory under the system temp directory, removed on drop. Its path stays short, because a
/// socket path is limited to 108 bytes.
struct RuntimeDir(PathBuf);

impl RuntimeDir {
    fn new() -> Self {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("iv-admin-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        Self(dir)
    }

    fn socket(&self) -> PathBuf {
        self.0.join(ADMIN_SOCKET_NAME)
    }
}

impl Drop for RuntimeDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn me() -> ExpectedOwner {
    invoking_user().unwrap()
}

/// A uid that is not the test's and not root, so neither profile admits it.
fn someone_else() -> u32 {
    me().uid.checked_add(1).unwrap()
}

/// A running server, stopped by dropping or sending on `stop`.
struct Running {
    path: PathBuf,
    stop: oneshot::Sender<()>,
    served: JoinHandle<io::Result<()>>,
}

impl Running {
    async fn stop(self) -> io::Result<()> {
        let _ = self.stop.send(());
        tokio::time::timeout(PATIENCE, self.served).await.expect("server stops").unwrap()
    }
}

fn start(dir: &RuntimeDir, limits: Limits) -> Running {
    let socket = AdminSocket::bind(&dir.0, me()).unwrap();
    let principals = AdminPrincipals::new(DeploymentProfile::Protected, me().uid);
    let server = AdminServer::new(principals, Handlers::standard(DeploymentProfile::Protected), limits);
    let (stop, stopped) = oneshot::channel::<()>();
    let served = tokio::spawn(async move {
        server
            .serve(socket, async {
                let _ = stopped.await;
            })
            .await
    });
    Running {
        path: dir.socket(),
        stop,
        served,
    }
}

fn limits(request_deadline: Duration, max_connections: usize) -> Limits {
    Limits {
        request_deadline,
        max_connections,
        shutdown_grace: Duration::from_millis(200),
    }
}

fn frame_bytes(frame: &Frame) -> Vec<u8> {
    let mut out = Vec::new();
    protocol::encode(frame, &mut out).unwrap();
    out
}

fn ping() -> Vec<u8> {
    frame_bytes(&Frame::Request(AdminRequest::Ping))
}

/// A header declaring `len` body bytes, followed by `body`.
fn raw(version: u16, kind: u8, len: u32, body: &[u8]) -> Vec<u8> {
    [&version.to_be_bytes()[..], &[kind], &len.to_be_bytes(), body].concat()
}

/// Reads one response frame. The read stops at the frame, because a peer the server closed on with unread input may
/// see a reset after it.
async fn read_response(stream: &mut UnixStream) -> AdminResponse {
    let read = async {
        let mut bytes = Vec::new();
        loop {
            match protocol::decode(&bytes).unwrap() {
                Decoded::Frame {
                    frame: Frame::Response(response),
                    ..
                } => return response,
                Decoded::Frame { frame, .. } => panic!("expected a response, got {frame:?}"),
                Decoded::NeedMore(n) => {
                    let mut more = vec![0; n];
                    let read = stream.read(&mut more).await.unwrap();
                    assert_ne!(read, 0, "connection closed after {} bytes", bytes.len());
                    bytes.extend_from_slice(more.get(..read).unwrap());
                }
            }
        }
    };
    tokio::time::timeout(PATIENCE, read).await.expect("a response arrives")
}

/// Asserts the server has closed the connection: the next read sees the end of the stream.
async fn assert_closed(stream: &mut UnixStream) {
    let mut rest = Vec::new();
    let read = tokio::time::timeout(PATIENCE, stream.read_to_end(&mut rest))
        .await
        .expect("the server closes");
    assert!(matches!(read, Ok(0)), "expected end of stream, got {read:?} with {rest:?}");
}

async fn exchange(path: &Path, request: &[u8]) -> AdminResponse {
    let mut stream = UnixStream::connect(path).await.unwrap();
    stream.write_all(request).await.unwrap();
    read_response(&mut stream).await
}

fn error_code(response: &AdminResponse) -> ErrorCode {
    match response {
        AdminResponse::Error { code, .. } => *code,
        other => panic!("expected an error response, got {other:?}"),
    }
}

#[tokio::test]
async fn ping_round_trips_and_the_connection_closes() {
    let dir = RuntimeDir::new();
    let server = start(&dir, Limits::default());
    let mut stream = UnixStream::connect(&server.path).await.unwrap();
    stream.write_all(&ping()).await.unwrap();
    assert_eq!(
        read_response(&mut stream).await,
        AdminResponse::Ping {
            profile: DeploymentProfile::Protected
        }
    );
    assert_closed(&mut stream).await;
    server.stop().await.unwrap();
}

#[tokio::test]
async fn a_malformed_frame_is_answered_malformed_frame() {
    let dir = RuntimeDir::new();
    let server = start(&dir, Limits::default());
    let truncated_field = raw(1, 1, 5, &[0, 1, 0, 0, 0]);
    assert_eq!(
        error_code(&exchange(&server.path, &truncated_field).await),
        ErrorCode::MalformedFrame
    );
    server.stop().await.unwrap();
}

#[tokio::test]
async fn an_oversized_length_is_answered_from_the_header_alone() {
    let dir = RuntimeDir::new();
    let server = start(&dir, Limits::default());
    let oversized = u32::try_from(protocol::MAX_BODY_LEN + 1).unwrap();
    let response = exchange(&server.path, &raw(1, 1, oversized, &[])).await;
    assert_eq!(error_code(&response), ErrorCode::MalformedFrame);
    server.stop().await.unwrap();
}

#[tokio::test]
async fn version_and_frame_kind_faults_get_their_own_codes() {
    let dir = RuntimeDir::new();
    let server = start(&dir, Limits::default());
    let newer = raw(2, 1, 0, &[]);
    assert_eq!(error_code(&exchange(&server.path, &newer).await), ErrorCode::UnsupportedVersion);
    let unknown_command = raw(1, 1, 8, &[0, 1, 0, 0, 0, 2, 0, 9]);
    assert_eq!(
        error_code(&exchange(&server.path, &unknown_command).await),
        ErrorCode::UnknownCommand
    );
    let success_first = frame_bytes(&Frame::Response(AdminResponse::Success));
    assert_eq!(
        error_code(&exchange(&server.path, &success_first).await),
        ErrorCode::UnexpectedFrame
    );
    server.stop().await.unwrap();
}

#[tokio::test]
async fn an_idle_connection_is_closed_at_the_deadline() {
    let dir = RuntimeDir::new();
    let server = start(&dir, limits(Duration::from_millis(100), 4));
    let mut idle = UnixStream::connect(&server.path).await.unwrap();
    assert_closed(&mut idle).await;
    let mut partial = UnixStream::connect(&server.path).await.unwrap();
    partial.write_all(&ping()[..3]).await.unwrap();
    assert_closed(&mut partial).await;
    server.stop().await.unwrap();
}

#[tokio::test]
async fn a_connection_over_the_cap_is_answered_busy() {
    let dir = RuntimeDir::new();
    let server = start(&dir, limits(PATIENCE, 2));
    let mut held = [
        UnixStream::connect(&server.path).await.unwrap(),
        UnixStream::connect(&server.path).await.unwrap(),
    ];
    // Let the server accept both before the third connects.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut over = UnixStream::connect(&server.path).await.unwrap();
    assert_eq!(error_code(&read_response(&mut over).await), ErrorCode::Busy);
    let [first, _] = &mut held;
    first.write_all(&ping()).await.unwrap();
    assert!(matches!(read_response(first).await, AdminResponse::Ping { .. }));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(matches!(exchange(&server.path, &ping()).await, AdminResponse::Ping { .. }));
    server.stop().await.unwrap();
}

/// A ping handler that records whether it ran.
struct Recording(Arc<AtomicBool>);

impl AdminHandler for Recording {
    fn handle<'a>(&'a self, _principal: AdminPrincipal, _request: AdminRequest, _exchange: &'a mut Exchange) -> HandlerFuture<'a> {
        self.0.store(true, Ordering::SeqCst);
        Box::pin(future::ready(AdminResponse::Success))
    }
}

#[tokio::test]
async fn a_refused_peer_reaches_no_handler_and_is_told_why() {
    let ran = Arc::new(AtomicBool::new(false));
    let handlers = Handlers::default().with(AdminCommand::Ping, Recording(Arc::clone(&ran)));
    let principals = AdminPrincipals::new(DeploymentProfile::Development, someone_else());
    let server = AdminServer::new(principals, handlers, Limits::default());
    let (ours, mut theirs) = UnixStream::pair().unwrap();
    theirs.write_all(&ping()).await.unwrap();
    tokio::time::timeout(PATIENCE, server.serve_connection(ours)).await.unwrap();
    match read_response(&mut theirs).await {
        AdminResponse::Error { code, message } => {
            assert_eq!(code, ErrorCode::NotAdminPrincipal);
            assert!(message.contains(&me().uid.to_string()), "{message}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert!(!ran.load(Ordering::SeqCst), "the handler ran for a refused peer");
}

#[tokio::test]
async fn an_accepted_peer_reaches_its_handler() {
    let ran = Arc::new(AtomicBool::new(false));
    let handlers = Handlers::default().with(AdminCommand::Ping, Recording(Arc::clone(&ran)));
    let principals = AdminPrincipals::new(DeploymentProfile::Protected, me().uid);
    let server = AdminServer::new(principals, handlers, Limits::default());
    let (ours, mut theirs) = UnixStream::pair().unwrap();
    theirs.write_all(&ping()).await.unwrap();
    tokio::time::timeout(PATIENCE, server.serve_connection(ours)).await.unwrap();
    assert_eq!(read_response(&mut theirs).await, AdminResponse::Success);
    assert!(ran.load(Ordering::SeqCst));
}

#[tokio::test]
async fn a_command_without_a_handler_is_unknown() {
    let principals = AdminPrincipals::new(DeploymentProfile::Protected, me().uid);
    let server = AdminServer::new(principals, Handlers::default(), Limits::default());
    let (ours, mut theirs) = UnixStream::pair().unwrap();
    theirs.write_all(&ping()).await.unwrap();
    tokio::time::timeout(PATIENCE, server.serve_connection(ours)).await.unwrap();
    assert_eq!(error_code(&read_response(&mut theirs).await), ErrorCode::UnknownCommand);
}

#[tokio::test]
async fn shutdown_removes_the_socket_file() {
    let dir = RuntimeDir::new();
    let server = start(&dir, Limits::default());
    assert!(dir.socket().exists());
    server.stop().await.unwrap();
    assert!(!dir.socket().exists());
}

#[tokio::test]
async fn shutdown_abandons_an_exchange_still_open_after_the_grace() {
    let dir = RuntimeDir::new();
    let server = start(&dir, limits(Duration::from_secs(60), 4));
    let _silent = UnixStream::connect(&server.path).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    server.stop().await.unwrap();
    assert!(!dir.socket().exists());
}

#[test]
fn the_bound_socket_is_the_service_accounts_with_mode_0600() {
    let dir = RuntimeDir::new();
    let socket = AdminSocket::bind(&dir.0, me()).unwrap();
    let metadata = fs::symlink_metadata(socket.path()).unwrap();
    assert!(metadata.file_type().is_socket());
    assert_eq!(metadata.uid(), me().uid);
    assert_eq!(metadata.mode() & 0o7777, 0o600);
    std::os::unix::net::UnixStream::connect(socket.path()).unwrap();
}

#[test]
fn a_stale_socket_of_the_service_account_is_replaced() {
    let dir = RuntimeDir::new();
    drop(std::os::unix::net::UnixListener::bind(dir.socket()).unwrap());
    fs::set_permissions(dir.socket(), fs::Permissions::from_mode(0o640)).unwrap();
    let refused = std::os::unix::net::UnixStream::connect(dir.socket()).unwrap_err();
    assert_eq!(
        refused.kind(),
        io::ErrorKind::ConnectionRefused,
        "the stale socket is not listening"
    );
    let socket = AdminSocket::bind(&dir.0, me()).unwrap();
    // The kernel may reuse the stale socket's inode, so a listening socket at mode 0600 is what shows it was replaced.
    assert_eq!(fs::symlink_metadata(socket.path()).unwrap().mode() & 0o7777, 0o600);
    std::os::unix::net::UnixStream::connect(socket.path()).unwrap();
}

fn assert_occupied(dir: &RuntimeDir, owner: ExpectedOwner, found: &str) {
    let refused = AdminSocket::bind(&dir.0, owner).unwrap_err();
    let BindError::Occupied { path, found: what, .. } = &refused else {
        panic!("expected Occupied, got {refused:?}");
    };
    assert_eq!(path, &dir.socket());
    assert!(what.starts_with(found), "{what}");
    assert!(refused.to_string().contains(&dir.socket().display().to_string()), "{refused}");
    assert!(fs::symlink_metadata(dir.socket()).is_ok(), "the refused file was removed");
}

#[test]
fn a_regular_file_at_the_path_is_refused_and_kept() {
    let dir = RuntimeDir::new();
    fs::write(dir.socket(), b"").unwrap();
    assert_occupied(&dir, me(), "a regular file");
}

#[test]
fn a_symlink_at_the_path_is_refused_even_to_an_own_socket() {
    let dir = RuntimeDir::new();
    let real = dir.0.join("real.sock");
    drop(std::os::unix::net::UnixListener::bind(&real).unwrap());
    symlink(&real, dir.socket()).unwrap();
    assert_occupied(&dir, me(), "a symlink");
    assert!(real.exists());
}

#[test]
fn a_socket_another_account_owns_is_refused() {
    let dir = RuntimeDir::new();
    drop(std::os::unix::net::UnixListener::bind(dir.socket()).unwrap());
    // The test cannot chown, so the leftover socket is the test's own and the service account is someone else.
    assert_occupied(&dir, ExpectedOwner { uid: someone_else() }, "a socket");
}

#[test]
fn a_socket_the_service_account_does_not_own_after_binding_never_listens() {
    let dir = RuntimeDir::new();
    let refused = AdminSocket::bind(&dir.0, ExpectedOwner { uid: someone_else() }).unwrap_err();
    assert!(matches!(refused, BindError::Unverified { .. }), "{refused:?}");
    let connect = std::os::unix::net::UnixStream::connect(dir.socket()).unwrap_err();
    assert_eq!(connect.kind(), io::ErrorKind::ConnectionRefused);
}
