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
use iron_vault::admin::protocol::{
    AdminCommand, AdminRequest, AdminResponse, ErrorCode, MemoryStatus, Prompt, RequestedOrigin, StatusReport, VaultStatus,
};
use iron_vault::admin::server::{AdminServer, Exchange, Limits};
use iron_vault::admin::socket::AdminSocket;
use iron_vault::deployment::DeploymentProfile;
use iron_vault::path_metadata::invoking_user;
use iron_vault::service_state::ServiceState;
use iron_vault_policy::{CredentialKind, Port};
use iron_vault_store::RecordId;
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
    command_args("ping", socket)
}

fn command_args(command: &str, socket: &Path) -> Vec<String> {
    vec![command.into(), "--admin-socket".into(), socket.display().to_string()]
}

/// Serves `ping` on `dir`'s admin socket to the admin principals of a protected install run by `service_uid`, runs
/// `iron-vault ping` against it, then stops the server.
async fn ping_server_as(dir: &TempDir, service_uid: u32) -> Output {
    serve_and_run(
        dir,
        service_uid,
        Handlers::standard(DeploymentProfile::Protected),
        "ping",
        Vec::new(),
    )
    .await
}

/// Serves `handlers` on `dir`'s admin socket, runs `iron-vault <command>` against it with `input` on stdin, then stops
/// the server.
async fn serve_and_run(dir: &TempDir, service_uid: u32, handlers: Handlers, command: &str, input: Vec<u8>) -> Output {
    serve_and_run_args(dir, service_uid, handlers, command_args(command, &dir.socket()), input).await
}

/// Serves `handlers` on `dir`'s admin socket, runs `iron-vault` with `args` and `input` on stdin, then stops the server.
async fn serve_and_run_args(dir: &TempDir, service_uid: u32, handlers: Handlers, args: Vec<String>, input: Vec<u8>) -> Output {
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
    let output = run_cli_with_input(args, input).await;
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
    let output = serve_and_run(&dir, invoking_user().unwrap().uid, handlers, "ping", input.to_vec()).await;
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

/// A test-only `status` handler that answers with a fixed report.
struct FixedStatus(ServiceState);

impl AdminHandler for FixedStatus {
    fn handle<'a>(&'a self, _principal: AdminPrincipal, _request: AdminRequest, _exchange: &'a mut Exchange) -> HandlerFuture<'a> {
        let report = StatusReport {
            state: self.0,
            profile: DeploymentProfile::Protected,
            vault: VaultStatus::Locked,
            memory: MemoryStatus::Unsupported,
        };
        Box::pin(async move { Ok(AdminResponse::Status(Box::new(report))) })
    }
}

async fn status_with(state: ServiceState) -> Output {
    let dir = TempDir::new();
    let handlers = Handlers::default().with(AdminCommand::Status, FixedStatus(state));
    serve_and_run(&dir, invoking_user().unwrap().uid, handlers, "status", Vec::new()).await
}

#[tokio::test]
async fn status_prints_one_field_per_line_and_exits_zero_only_when_ready() {
    let ready = status_with(ServiceState::Ready).await;
    assert_eq!(ready.status.code(), Some(0), "stderr: {}", text(&ready.stderr));
    assert!(
        text(&ready.stdout).starts_with("service: ready\nprofile: protected\nvault: locked\n"),
        "{}",
        text(&ready.stdout)
    );

    let locked = status_with(ServiceState::Locked).await;
    assert_eq!(locked.status.code(), Some(4), "stderr: {}", text(&locked.stderr));
    assert!(text(&locked.stdout).starts_with("service: locked\n"));
    assert_eq!(text(&locked.stderr), "");
}

/// A test-only `unlock` handler: prompts for the vault passphrase as the service does, records the value, and answers
/// with a fixed response, so the CLI's report of each outcome is checked without a vault.
struct ScriptedUnlock {
    response: AdminResponse,
    values: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl AdminHandler for ScriptedUnlock {
    fn handle<'a>(&'a self, _principal: AdminPrincipal, _request: AdminRequest, exchange: &'a mut Exchange) -> HandlerFuture<'a> {
        Box::pin(async move {
            let prompt = Prompt {
                label: "Vault passphrase".to_owned(),
                secret: true,
            };
            let input = exchange.prompt(&prompt).await?;
            self.values.lock().unwrap().push(input.expose_secret().to_vec());
            Ok(self.response.clone())
        })
    }
}

async fn scripted_unlock(response: AdminResponse) -> (Output, Vec<Vec<u8>>) {
    let dir = TempDir::new();
    let values = Arc::default();
    let handler = ScriptedUnlock {
        response,
        values: Arc::clone(&values),
    };
    let handlers = Handlers::default().with(AdminCommand::Unlock, handler);
    let input = format!("{MARKER}\n").into_bytes();
    let output = serve_and_run(&dir, invoking_user().unwrap().uid, handlers, "unlock", input).await;
    let values = std::mem::take(&mut *values.lock().unwrap());
    (output, values)
}

#[tokio::test]
async fn unlock_sends_the_piped_passphrase_and_reports_ready_without_echoing_it() {
    let (output, values) = scripted_unlock(AdminResponse::Success).await;
    let (stdout, stderr) = (text(&output.stdout), text(&output.stderr));
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert_eq!(values, [MARKER.as_bytes().to_vec()]);
    assert_eq!(stdout, "the vault is unlocked: the service is Ready\n");
    assert_eq!(stderr, "");
}

#[tokio::test]
async fn unlock_into_an_unavailable_service_shows_the_redacted_reason() {
    let message = "the vault unlocked, but the config check failed: the service is Unavailable (policy invalid)";
    let response = AdminResponse::Error {
        code: ErrorCode::UnlockedUnavailable,
        message: message.to_owned(),
    };
    let (output, _) = scripted_unlock(response).await;
    let (stdout, stderr) = (text(&output.stdout), text(&output.stderr));
    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert_eq!(stdout, "");
    assert_eq!(
        stderr,
        format!("iron-vault: the service answered error 16 (unlocked-unavailable): {message}\n")
    );
    assert!(!stderr.contains(MARKER), "{stderr}");
}

#[tokio::test]
async fn a_wrong_passphrase_is_reported_without_the_passphrase() {
    let response = AdminResponse::Error {
        code: ErrorCode::UnlockDenied,
        message: "wrong passphrase".to_owned(),
    };
    let (output, _) = scripted_unlock(response).await;
    let (stdout, stderr) = (text(&output.stdout), text(&output.stderr));
    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert_eq!(stdout, "");
    assert_eq!(
        stderr,
        "iron-vault: the service answered error 14 (unlock-denied): wrong passphrase\n"
    );
}

/// A test-only `add` handler: records the request, prompts for the static secret as the service will, records the value,
/// and answers with `RECORD_ID`.
struct StubAdd(Arc<AddLog>);

/// What the stub `add` handler received.
#[derive(Default)]
struct AddLog {
    requests: Mutex<Vec<AdminRequest>>,
    values: Mutex<Vec<Vec<u8>>>,
}

const RECORD_ID: &str = "7c9e6679-7425-40de-944b-e07fc1f90ae7";

impl AdminHandler for StubAdd {
    fn handle<'a>(&'a self, _principal: AdminPrincipal, request: AdminRequest, exchange: &'a mut Exchange) -> HandlerFuture<'a> {
        Box::pin(async move {
            self.0.requests.lock().unwrap().push(request);
            let prompt = Prompt {
                label: "Secret for fx".to_owned(),
                secret: true,
            };
            let input = exchange.prompt(&prompt).await?;
            self.0.values.lock().unwrap().push(input.expose_secret().to_vec());
            Ok(AdminResponse::Add {
                record_id: RECORD_ID.parse::<RecordId>().unwrap(),
            })
        })
    }
}

fn add_args(socket: &Path) -> Vec<String> {
    let args = [
        "add",
        "fx",
        "--origin",
        "API.fx.example",
        "--origin",
        "[::1]:8443",
        "--admin-socket",
    ];
    args.iter()
        .map(|arg| (*arg).to_owned())
        .chain([socket.display().to_string()])
        .collect()
}

#[tokio::test]
async fn add_sends_its_arguments_and_the_piped_secret_and_prints_the_record_id() {
    let dir = TempDir::new();
    let stub = Arc::new(AddLog::default());
    let handlers = Handlers::default().with(AdminCommand::Add, StubAdd(Arc::clone(&stub)));
    let args = add_args(&dir.socket());
    assert!(!args.iter().any(|arg| arg.contains(MARKER)), "the secret is never an argument");
    let input = format!("{MARKER}\n").into_bytes();
    let output = serve_and_run_args(&dir, invoking_user().unwrap().uid, handlers, args, input).await;
    let (stdout, stderr) = (text(&output.stdout), text(&output.stderr));
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert_eq!(stdout, format!("added fx (static) as record {RECORD_ID}\n"));
    assert_eq!(stderr, "");
    assert_eq!(*stub.values.lock().unwrap(), [MARKER.as_bytes().to_vec()]);
    let origin = |host: &str, port: u16| RequestedOrigin {
        host: host.to_owned(),
        port: Port::try_from(port).unwrap(),
    };
    let expected = AdminRequest::Add {
        name: "fx".to_owned(),
        kind: CredentialKind::Static,
        origins: vec![origin("api.fx.example", 443), origin("[::1]", 8443)],
    };
    assert_eq!(*stub.requests.lock().unwrap(), [expected]);
}

#[tokio::test]
async fn add_without_a_service_handler_is_an_unknown_command() {
    let dir = TempDir::new();
    let handlers = Handlers::standard(DeploymentProfile::Protected);
    let input = format!("{MARKER}\n").into_bytes();
    let output = serve_and_run_args(&dir, invoking_user().unwrap().uid, handlers, add_args(&dir.socket()), input).await;
    let (stdout, stderr) = (text(&output.stdout), text(&output.stderr));
    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert_eq!(stdout, "");
    assert!(stderr.contains("error 3 (unknown-command)"), "{stderr}");
    assert!(!stderr.contains("fx") && !stderr.contains(MARKER), "{stderr}");
}

#[tokio::test]
async fn an_add_service_error_goes_to_stderr_without_the_arguments() {
    let dir = TempDir::new();
    let handlers = Handlers::default().with(AdminCommand::Add, FixedError(ErrorCode::NameTaken));
    let output = serve_and_run_args(&dir, invoking_user().unwrap().uid, handlers, add_args(&dir.socket()), Vec::new()).await;
    let (stdout, stderr) = (text(&output.stdout), text(&output.stderr));
    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert_eq!(stdout, "");
    assert_eq!(
        stderr,
        "iron-vault: the service answered error 20 (name-taken): the name is already in the vault\n"
    );
}

/// A test-only handler that answers every request with one error and prompts for nothing.
struct FixedError(ErrorCode);

impl AdminHandler for FixedError {
    fn handle<'a>(&'a self, _principal: AdminPrincipal, _request: AdminRequest, _exchange: &'a mut Exchange) -> HandlerFuture<'a> {
        let response = AdminResponse::Error {
            code: self.0,
            message: "the name is already in the vault".to_owned(),
        };
        Box::pin(async move { Ok(response) })
    }
}

/// `init` shows the recovery key on the controlling terminal only, so without one it stops before connecting and the
/// service never generates a key. `setsid` runs it in a new session, which has no controlling terminal; nothing listens
/// at the socket path, and the CLI never gets as far as saying so.
#[tokio::test]
async fn init_without_a_controlling_terminal_sends_nothing() {
    let dir = TempDir::new();
    let args = command_args("init", &dir.socket());
    let run = tokio::task::spawn_blocking(move || {
        Command::new("setsid")
            .arg("--wait")
            .arg(env!("CARGO_BIN_EXE_iron-vault"))
            .args(args)
            .stdin(Stdio::null())
            .output()
    });
    let output = tokio::time::timeout(Duration::from_secs(10), run)
        .await
        .expect("the CLI finishes")
        .unwrap()
        .expect("spawn setsid");

    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(3), "{stderr}");
    assert!(output.stdout.is_empty());
    assert!(
        stderr.contains("controlling terminal only") && stderr.ends_with("nothing was sent\n") && !stderr.contains("not running"),
        "{stderr}"
    );
}
