//! The CLI binary end to end against an in-process admin server on a temporary socket, reached with `--admin-socket`:
//! its output, its exit codes and the hints it gives. The service account is the test's own uid.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use iron_vault::admin::ADMIN_SOCKET_NAME;
use iron_vault::admin::dispatch::Handlers;
use iron_vault::admin::principal::AdminPrincipals;
use iron_vault::admin::server::{AdminServer, Limits};
use iron_vault::admin::socket::AdminSocket;
use iron_vault::deployment::DeploymentProfile;
use iron_vault::path_metadata::invoking_user;
use tokio::sync::oneshot;

static NEXT: AtomicU32 = AtomicU32::new(0);

/// A fresh `0700` directory under the system temp directory, removed on drop; short, because a socket path is limited
/// to 108 bytes.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("iv-cli-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        Self(dir)
    }

    fn socket(&self) -> PathBuf {
        self.0.join(ADMIN_SOCKET_NAME)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Runs the binary off the runtime thread, so the in-process server keeps serving while the CLI waits for it.
async fn run_cli(args: Vec<String>) -> Output {
    let run = tokio::task::spawn_blocking(move || Command::new(env!("CARGO_BIN_EXE_iron-vault")).args(args).output());
    tokio::time::timeout(Duration::from_secs(10), run)
        .await
        .expect("the CLI finishes")
        .unwrap()
        .expect("spawn iron-vault")
}

fn ping_args(socket: &Path) -> Vec<String> {
    vec!["ping".into(), "--admin-socket".into(), socket.display().to_string()]
}

/// Serves `ping` on `dir`'s admin socket to the admin principals of a protected install run by `service_uid`, runs
/// `iron-vault ping` against it, then stops the server.
async fn ping_server_as(dir: &TempDir, service_uid: u32) -> Output {
    let me = invoking_user().unwrap();
    let socket = AdminSocket::bind(&dir.0, me).unwrap();
    let principals = AdminPrincipals::new(DeploymentProfile::Protected, service_uid);
    let server = AdminServer::new(principals, Handlers::standard(DeploymentProfile::Protected), Limits::default());
    let (stop, stopped) = oneshot::channel::<()>();
    let served = tokio::spawn(async move {
        server
            .serve(socket, async {
                let _ = stopped.await;
            })
            .await
    });
    let output = run_cli(ping_args(&dir.socket())).await;
    let _ = stop.send(());
    served.await.unwrap().unwrap();
    output
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[tokio::test]
async fn ping_reports_the_services_profile() {
    let dir = TempDir::new();
    let output = ping_server_as(&dir, invoking_user().unwrap().uid).await;
    let (stdout, stderr) = (text(&output.stdout), text(&output.stderr));
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert_eq!(stdout, "the service is running: protected profile, admin protocol version 1\n");
    assert_eq!(stderr, "", "a client command logs nothing");
}

#[tokio::test]
async fn a_refusing_service_gives_the_sudo_hint() {
    let dir = TempDir::new();
    let someone_else = invoking_user().unwrap().uid.checked_add(1).unwrap();
    let output = ping_server_as(&dir, someone_else).await;
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert!(stderr.contains("error 5 (not-admin-principal)"), "{stderr}");
    assert!(stderr.contains("run the command with sudo"), "{stderr}");
}

#[tokio::test]
async fn a_missing_socket_means_the_service_is_not_running() {
    let dir = TempDir::new();
    let output = run_cli(ping_args(&dir.socket())).await;
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(3), "stderr: {stderr}");
    let expected = format!(
        "iron-vault: the Iron Vault service is not running: there is no admin socket at {}\n",
        dir.socket().display()
    );
    assert_eq!(stderr, expected);
}

#[tokio::test]
async fn a_socket_nobody_listens_on_means_the_service_is_not_running() {
    let dir = TempDir::new();
    drop(UnixListener::bind(dir.socket()).unwrap());
    let output = run_cli(ping_args(&dir.socket())).await;
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(3), "stderr: {stderr}");
    assert!(stderr.contains("nothing is listening on the admin socket"), "{stderr}");
}

#[tokio::test]
async fn a_socket_this_account_may_not_open_gives_the_sudo_hint() {
    // Root passes file permission checks, so it cannot see this refusal.
    if invoking_user().unwrap().uid == 0 {
        return;
    }
    let dir = TempDir::new();
    let _listener = UnixListener::bind(dir.socket()).unwrap();
    fs::set_permissions(dir.socket(), fs::Permissions::from_mode(0o000)).unwrap();
    let output = run_cli(ping_args(&dir.socket())).await;
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(3), "stderr: {stderr}");
    assert!(stderr.contains("permission denied"), "{stderr}");
    assert!(stderr.contains("run the command with sudo"), "{stderr}");
}
