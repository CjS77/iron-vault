//! `caller-token` over a real admin socket, served by the standard handlers: each call issues a fresh, valid token, and
//! the service's log names the event without the token or its hash (spec §7, §18).

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use common::request_log::capture;

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

const PATIENCE: Duration = Duration::from_secs(5);

/// A fresh `0700` runtime directory, removed on drop; short, because a socket path is limited to 108 bytes.
struct RuntimeDir(PathBuf);

impl RuntimeDir {
    fn new() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!("iv-ct-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
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
    let (_guard, logs) = capture();
    let dir = RuntimeDir::new();
    let me = invoking_user().unwrap();
    let socket = AdminSocket::bind(&dir.0, me).unwrap();
    let path = dir.0.join(iron_vault::admin::ADMIN_SOCKET_NAME);
    let principals = AdminPrincipals::new(DeploymentProfile::Development, me.uid);
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
    let issued = logs.audit_events("caller.token-issued");
    assert_eq!(issued.len(), 2, "{text}");
    issued.iter().for_each(|record| assert_eq!(record["level"], "INFO", "{record}"));
    let commands = logs.audit_events("admin.command");
    assert_eq!(commands.len(), 2, "{text}");
    commands.iter().for_each(|record| {
        assert_eq!(
            (record["command"].as_str(), record["principal_uid"].as_u64()),
            (Some("caller_token"), Some(u64::from(me.uid)))
        );
    });
    // A hash is checked by its hex digits alone, so it is caught with or without its `blake2b:` prefix.
    let hex = hashes.map(|hash| hash.trim_start_matches("blake2b:").to_owned());
    [&first, &second, &hex[0], &hex[1]]
        .iter()
        .for_each(|secret| assert!(!text.contains(secret.as_str()), "a token or its hash reached the log:\n{text}"));
}

#[tokio::test]
async fn a_peer_that_is_not_an_admin_principal_is_recorded_without_a_command() {
    let (_guard, logs) = capture();
    let dir = RuntimeDir::new();
    let me = invoking_user().unwrap();
    let socket = AdminSocket::bind(&dir.0, me).unwrap();
    let path = dir.0.join(iron_vault::admin::ADMIN_SOCKET_NAME);
    // The service account is someone else, and this process is not root, so the peer is refused.
    let principals = AdminPrincipals::new(DeploymentProfile::Protected, me.uid + 1);
    let server = AdminServer::new(principals, Handlers::standard(DeploymentProfile::Protected), Limits::default());
    let (stop, stopped) = oneshot::channel::<()>();
    let served = tokio::spawn(async move {
        server
            .serve(socket, async {
                let _ = stopped.await;
            })
            .await
    });

    let mut stream = UnixStream::connect(&path).await.unwrap();
    let mut bytes = Vec::new();
    tokio::time::timeout(PATIENCE, stream.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    let _ = stop.send(());
    served.await.unwrap().unwrap();

    let refused = logs.audit_events("admin.refused");
    assert_eq!(refused.len(), 1, "{}", logs.text());
    let record = &refused[0];
    assert_eq!(
        (record["level"].as_str(), record["refusal"].as_str()),
        (Some("WARN"), Some("not_admin_principal"))
    );
    assert_eq!(record["peer_uid"].as_u64(), Some(u64::from(me.uid)));
    assert!(record["peer_pid"].is_u64(), "{record}");
    assert!(logs.audit_events("admin.command").is_empty());
}

#[tokio::test]
async fn a_malformed_request_from_an_admin_principal_is_refused_with_its_peer() {
    let (_guard, logs) = capture();
    let dir = RuntimeDir::new();
    let me = invoking_user().unwrap();
    let socket = AdminSocket::bind(&dir.0, me).unwrap();
    let path = dir.0.join(iron_vault::admin::ADMIN_SOCKET_NAME);
    let principals = AdminPrincipals::new(DeploymentProfile::Development, me.uid);
    let server = AdminServer::new(principals, Handlers::standard(DeploymentProfile::Protected), Limits::default());
    let (stop, stopped) = oneshot::channel::<()>();
    let served = tokio::spawn(async move {
        server
            .serve(socket, async {
                let _ = stopped.await;
            })
            .await
    });

    // A frame of an unsupported protocol version: header bytes only, never a command.
    let mut stream = UnixStream::connect(&path).await.unwrap();
    stream.write_all(&[0xff; 16]).await.unwrap();
    let mut bytes = Vec::new();
    // The service closes with the rest of the garbage unread, which the peer may see as a reset.
    let _ = tokio::time::timeout(PATIENCE, stream.read_to_end(&mut bytes)).await.unwrap();
    let _ = stop.send(());
    served.await.unwrap().unwrap();

    let refused = logs.audit_events("admin.refused");
    assert_eq!(refused.len(), 1, "{}", logs.text());
    assert_eq!(refused[0]["refusal"], "unsupported_version", "{}", refused[0]);
    assert_eq!(refused[0]["peer_uid"].as_u64(), Some(u64::from(me.uid)));
    assert!(refused[0]["peer_pid"].is_u64(), "{}", refused[0]);
    assert!(logs.audit_events("admin.command").is_empty());
}
