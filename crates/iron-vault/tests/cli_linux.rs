//! The CLI binary end to end against an in-process admin server on a temporary socket, reached with `--admin-socket`:
//! its output, its exit codes and the hints it gives. The service account is the test's own uid.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iron_vault::admin::ADMIN_SOCKET_NAME;
use iron_vault::admin::dispatch::{AdminHandler, HandlerFuture, Handlers};
use iron_vault::admin::principal::{AdminPrincipal, AdminPrincipals};
use iron_vault::admin::protocol::{AdminCommand, AdminRequest, AdminResponse, Prompt};
use iron_vault::admin::server::{AdminServer, Exchange, Limits};
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

/// Runs the binary off the runtime thread, so the in-process server keeps serving while the CLI waits for it. Its stdin
/// is empty, so it never touches a terminal.
async fn run_cli(args: Vec<String>) -> Output {
    run_cli_with_input(args, Vec::new()).await
}

/// Runs the binary with `input` piped to its stdin.
async fn run_cli_with_input(args: Vec<String>, input: Vec<u8>) -> Output {
    let run = tokio::task::spawn_blocking(move || {
        let mut child = Command::new(env!("CARGO_BIN_EXE_iron-vault"))
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        // A CLI that stops reading early closes the pipe, so a failed write is not the test's failure.
        let _ = child.stdin.take().map(|mut stdin| stdin.write_all(&input));
        child.wait_with_output()
    });
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
    serve_and_run(dir, service_uid, Handlers::standard(DeploymentProfile::Protected), Vec::new()).await
}

/// Serves `handlers` on `dir`'s admin socket, runs `iron-vault ping` against it with `input` on stdin, then stops the
/// server.
async fn serve_and_run(dir: &TempDir, service_uid: u32, handlers: Handlers, input: Vec<u8>) -> Output {
    let me = invoking_user().unwrap();
    let socket = AdminSocket::bind(&dir.0, me).unwrap();
    let principals = AdminPrincipals::new(DeploymentProfile::Protected, service_uid);
    let server = AdminServer::new(principals, handlers, Limits::default());
    let (stop, stopped) = oneshot::channel::<()>();
    let served = tokio::spawn(async move {
        server
            .serve(socket, async {
                let _ = stopped.await;
            })
            .await
    });
    let output = run_cli_with_input(ping_args(&dir.socket()), input).await;
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

/// A test-only `ping` handler that prompts for a secret and a plain value, records them, and answers as `ping` does.
struct PromptingPing(Arc<Mutex<Vec<Vec<u8>>>>);

impl AdminHandler for PromptingPing {
    fn handle<'a>(&'a self, _principal: AdminPrincipal, _request: AdminRequest, exchange: &'a mut Exchange) -> HandlerFuture<'a> {
        Box::pin(async move {
            for (label, secret) in [("Secret", true), ("Plain", false)] {
                let prompt = Prompt {
                    label: label.to_owned(),
                    secret,
                };
                let input = exchange.prompt(&prompt).await?;
                self.0.lock().unwrap().push(input.expose_secret().to_vec());
            }
            Ok(AdminResponse::Ping {
                profile: DeploymentProfile::Protected,
            })
        })
    }
}

async fn prompted_ping(input: &[u8]) -> (Output, Vec<Vec<u8>>) {
    let dir = TempDir::new();
    let values = Arc::default();
    let handlers = Handlers::default().with(AdminCommand::Ping, PromptingPing(Arc::clone(&values)));
    let output = serve_and_run(&dir, invoking_user().unwrap().uid, handlers, input.to_vec()).await;
    let values = std::mem::take(&mut *values.lock().unwrap());
    (output, values)
}

const MARKER: &str = "MARKER-secret-5d1c9e";

#[tokio::test]
async fn piped_lines_answer_the_services_prompts() {
    let (output, values) = prompted_ping(format!("{MARKER}\r\nplain\n").as_bytes()).await;
    let (stdout, stderr) = (text(&output.stdout), text(&output.stderr));
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert_eq!(values, [MARKER.as_bytes().to_vec(), b"plain".to_vec()]);
    assert_eq!(stdout, "the service is running: protected profile, admin protocol version 1\n");
    assert_eq!(stderr, "", "labels go to stderr only when it is a terminal");
}

#[tokio::test]
async fn piped_input_that_ends_early_cancels_the_command() {
    let (output, values) = prompted_ping(MARKER.as_bytes()).await;
    let (stdout, stderr) = (text(&output.stdout), text(&output.stderr));
    assert_eq!(output.status.code(), Some(3), "stderr: {stderr}");
    assert_eq!(values, [MARKER.as_bytes().to_vec()]);
    assert_eq!(stdout, "");
    assert_eq!(
        stderr,
        "iron-vault: the command was cancelled: the input ended before a value was given\n"
    );
}
