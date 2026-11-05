//! `caller-token` over a real admin socket, served by the standard handlers: each call issues a fresh, valid token, and
//! the service's log names the event without the token or its hash (spec §3.4, §3.15).

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use iron_vault::admin::dispatch::Handlers;
use iron_vault::admin::principal::AdminPrincipals;
use iron_vault::admin::protocol::{self, AdminRequest, AdminResponse, Decoded, Frame};
use iron_vault::admin::server::{AdminServer, Limits};
use iron_vault::admin::socket::AdminSocket;
use iron_vault::deployment::DeploymentProfile;
use iron_vault::path_metadata::invoking_user;
use iron_vault_policy::{CallerToken, TokenHash};
use secrecy::ExposeSecret;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::oneshot;
use tracing_subscriber::fmt::MakeWriter;

const PATIENCE: Duration = Duration::from_secs(5);

/// A fresh `0700` runtime directory, removed on drop; short, because a socket path is limited to 108 bytes.
struct RuntimeDir(PathBuf);

impl RuntimeDir {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("iv-ct-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        Self(dir)
    }
}

impl Drop for RuntimeDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Sends `caller-token` and returns the response, read whole before the connection closes.
async fn issue(path: &std::path::Path) -> AdminResponse {
    let mut stream = UnixStream::connect(path).await.unwrap();
    let mut request = Vec::new();
    protocol::encode(&Frame::Request(AdminRequest::CallerToken), &mut request).unwrap();
    stream.write_all(&request).await.unwrap();
    let mut bytes = Vec::new();
    tokio::time::timeout(PATIENCE, stream.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    match protocol::decode(&bytes).unwrap() {
        Decoded::Frame {
            frame: Frame::Response(response),
            ..
        } => response,
        other => panic!("expected a response, got {other:?}"),
    }
}

/// The issued token's text, as the CLI would print it.
fn issued_text(response: AdminResponse) -> String {
    let AdminResponse::CallerToken { token } = response else {
        panic!("expected a caller token, got {response:?}");
    };
    token.expose_once().expose_secret().to_owned()
}

#[tokio::test]
async fn each_call_issues_a_fresh_valid_token_and_the_log_holds_neither_it_nor_its_hash() {
    let logs = captured_logs();
    let dir = RuntimeDir::new();
    let me = invoking_user().unwrap();
    let socket = AdminSocket::bind(&dir.0, me).unwrap();
    let path = dir.0.join(iron_vault::admin::ADMIN_SOCKET_NAME);
    let principals = AdminPrincipals::new(DeploymentProfile::Protected, me.uid);
    let server = AdminServer::new(principals, Handlers::standard(DeploymentProfile::Protected), Limits::default());
    let (stop, stopped) = oneshot::channel::<()>();
    let served = tokio::spawn(async move {
        server
            .serve(socket, async {
                let _ = stopped.await;
            })
            .await
    });

    let first = issued_text(issue(&path).await);
    let second = issued_text(issue(&path).await);
    let _ = stop.send(());
    served.await.unwrap().unwrap();

    assert_ne!(first, second);
    let hashes = [&first, &second].map(|text| TokenHash::of(&CallerToken::parse(text.as_bytes()).unwrap()).to_string());
    let text = logs.text();
    assert_eq!(text.matches("caller.token-issued").count(), 2, "{text}");
    // A hash is checked by its hex digits alone, so it is caught with or without its `blake2b:` prefix.
    let hex = hashes.map(|hash| hash.trim_start_matches("blake2b:").to_owned());
    [&first, &second, &hex[0], &hex[1]]
        .iter()
        .for_each(|secret| assert!(!text.contains(secret.as_str()), "a token or its hash reached the log:\n{text}"));
}

/// Everything this test binary logs at TRACE, from a global subscriber installed on first use.
fn captured_logs() -> Captured {
    static CAPTURED: OnceLock<Captured> = OnceLock::new();
    CAPTURED
        .get_or_init(|| {
            let captured = Captured::default();
            let subscriber = tracing_subscriber::fmt()
                .with_max_level(tracing::Level::TRACE)
                .with_writer(captured.clone())
                .with_ansi(false)
                .finish();
            tracing::subscriber::set_global_default(subscriber).unwrap();
            captured
        })
        .clone()
}

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Captured {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap_or_else(PoisonError::into_inner)).into_owned()
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
