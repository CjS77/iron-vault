//! The CLI binary end to end against an in-process admin server on a temporary socket, reached with `--admin-socket`:
//! its output, its exit codes and the hints it gives. The service account is the test's own uid.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iron_vault::admin::dispatch::{AdminHandler, HandlerFuture, Handlers};
use iron_vault::admin::principal::{AdminPrincipal, AdminPrincipals};
use iron_vault::admin::protocol::{
    AdminCommand, AdminRequest, AdminResponse, ErrorCode, MemoryStatus, Prompt, PromptAnswer, RecoveryStatus, RequestedOrigin,
    StatusReport, VaultStatus,
};
use iron_vault::admin::server::{AdminServer, Exchange, Limits};
use iron_vault::admin::socket::AdminSocket;
use iron_vault::admin::{ADMIN_SOCKET_NAME, DEAD_RECOVERY_KEY, UNCONFIRMED_RECOVERY_KEY};
use iron_vault::deployment::DeploymentProfile;
use iron_vault::path_metadata::invoking_user;
use iron_vault::service_state::ServiceState;
use iron_vault::standing::{CredentialStanding, RecordSummary, Standing};
use iron_vault_policy::{CallerToken, CredentialKind, Port, TokenHash};
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
    let principals = AdminPrincipals::new(DeploymentProfile::Development, service_uid);
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
                    switchable: false,
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
            recovery: RecoveryStatus::Unknown {
                detail: "no check record yet".to_owned(),
                due: false,
            },
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
/// with a fixed response, so the CLI's report of each outcome is checked without a vault. The response is taken by the
/// one exchange each test runs.
struct ScriptedUnlock {
    response: Mutex<Option<AdminResponse>>,
    values: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl AdminHandler for ScriptedUnlock {
    fn handle<'a>(&'a self, _principal: AdminPrincipal, _request: AdminRequest, exchange: &'a mut Exchange) -> HandlerFuture<'a> {
        Box::pin(async move {
            let prompt = Prompt {
                label: "Vault passphrase".to_owned(),
                secret: true,
                switchable: false,
            };
            let input = exchange.prompt(&prompt).await?;
            self.values.lock().unwrap().push(input.expose_secret().to_vec());
            Ok(self.response.lock().unwrap().take().expect("one exchange per test"))
        })
    }
}

async fn scripted_unlock(response: AdminResponse) -> (Output, Vec<Vec<u8>>) {
    let dir = TempDir::new();
    let values = Arc::default();
    let handler = ScriptedUnlock {
        response: Mutex::new(Some(response)),
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
async fn an_unlock_refused_for_unlocked_memory_names_the_memory_lock_fix() {
    let message = "memory is not locked against swap (RLIMIT_MEMLOCK soft limit is 65536 bytes, not unlimited), so a protected \
                   install does not open the vault; the service stays Locked";
    let response = AdminResponse::Error {
        code: ErrorCode::MemoryUnprotected,
        message: message.to_owned(),
    };
    let (output, _) = scripted_unlock(response).await;
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert!(
        stderr.starts_with(&format!(
            "iron-vault: the service answered error 27 (memory-unprotected): {message}\n"
        )),
        "{stderr}"
    );
    assert!(
        stderr.contains("LimitMEMLOCK=infinity") && stderr.contains("`ulimits: memlock: -1`"),
        "{stderr}"
    );
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
                switchable: false,
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

/// A test-only `rm` handler: records the request, prompts for the approval passphrase as the service will, records the
/// value, and answers with success.
struct StubRm(Arc<AddLog>);

impl AdminHandler for StubRm {
    fn handle<'a>(&'a self, _principal: AdminPrincipal, request: AdminRequest, exchange: &'a mut Exchange) -> HandlerFuture<'a> {
        Box::pin(async move {
            self.0.requests.lock().unwrap().push(request);
            let prompt = Prompt {
                label: "Approval passphrase for \"approval passphrase\"".to_owned(),
                secret: true,
                switchable: false,
            };
            let input = exchange.prompt(&prompt).await?;
            self.0.values.lock().unwrap().push(input.expose_secret().to_vec());
            Ok(AdminResponse::Success)
        })
    }
}

fn rm_args(socket: &Path) -> Vec<String> {
    ["rm", "old_key", "--admin-socket"]
        .iter()
        .map(|arg| (*arg).to_owned())
        .chain([socket.display().to_string()])
        .collect()
}

#[tokio::test]
async fn rm_sends_its_name_and_the_piped_passphrase_and_prints_removed() {
    let dir = TempDir::new();
    let stub = Arc::new(AddLog::default());
    let handlers = Handlers::default().with(AdminCommand::Rm, StubRm(Arc::clone(&stub)));
    let input = format!("{MARKER}\n").into_bytes();
    let output = serve_and_run_args(&dir, invoking_user().unwrap().uid, handlers, rm_args(&dir.socket()), input).await;
    let (stdout, stderr) = (text(&output.stdout), text(&output.stderr));
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert_eq!(stdout, "removed old_key\n");
    assert_eq!(stderr, "");
    assert_eq!(*stub.values.lock().unwrap(), [MARKER.as_bytes().to_vec()]);
    assert_eq!(
        *stub.requests.lock().unwrap(),
        [AdminRequest::Rm {
            name: "old_key".to_owned()
        }]
    );
}

#[tokio::test]
async fn an_rm_refusal_goes_to_stderr_with_its_code_name() {
    let dir = TempDir::new();
    let handlers = Handlers::default().with(AdminCommand::Rm, FixedError(ErrorCode::CredentialInUse));
    let output = serve_and_run_args(&dir, invoking_user().unwrap().uid, handlers, rm_args(&dir.socket()), Vec::new()).await;
    let (stdout, stderr) = (text(&output.stdout), text(&output.stderr));
    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert_eq!(stdout, "");
    assert!(stderr.contains("error 24 (credential-in-use)"), "{stderr}");
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

/// `caller-token` against the standard handlers: stdout is the token alone, and stderr its hash and how to enroll it.
#[tokio::test]
async fn caller_token_prints_the_token_alone_on_stdout_and_its_hash_on_stderr() {
    let dir = TempDir::new();
    let handlers = Handlers::standard(DeploymentProfile::Protected);
    let output = serve_and_run(&dir, invoking_user().unwrap().uid, handlers, "caller-token", Vec::new()).await;
    let (stdout, stderr) = (text(&output.stdout), text(&output.stderr));
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");

    let line = stdout.strip_suffix('\n').expect("one line");
    assert!(!line.contains('\n'), "{stdout}");
    let token = CallerToken::parse(line.as_bytes()).unwrap();
    let hash_line = format!("token_hash = \"{}\"\n", TokenHash::of(&token));
    assert!(stderr.starts_with(&hash_line), "{stderr}");
    assert!(!stderr.contains(line), "the token reached stderr: {stderr}");
    assert!(
        stderr.contains("shown once and the service keeps no copy") && stderr.contains("iron-vault config approve"),
        "{stderr}"
    );
}

#[tokio::test]
async fn a_failed_random_source_is_a_service_error() {
    let dir = TempDir::new();
    let handlers = Handlers::default().with(AdminCommand::CallerToken, FixedError(ErrorCode::RandomSourceFailed));
    let output = serve_and_run(&dir, invoking_user().unwrap().uid, handlers, "caller-token", Vec::new()).await;
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(text(&output.stdout), "");
    assert!(
        text(&output.stderr).contains("error 25 (random-source-failed)"),
        "{}",
        text(&output.stderr)
    );
}

/// A test-only `list` handler that answers with a fixed list.
struct FixedList(Option<Vec<CredentialStanding>>);

impl AdminHandler for FixedList {
    fn handle<'a>(&'a self, _principal: AdminPrincipal, _request: AdminRequest, _exchange: &'a mut Exchange) -> HandlerFuture<'a> {
        let credentials = self.0.clone();
        Box::pin(async move { Ok(AdminResponse::List { credentials }) })
    }
}

async fn list_with(credentials: Option<Vec<CredentialStanding>>) -> Output {
    let dir = TempDir::new();
    let handlers = Handlers::default().with(AdminCommand::List, FixedList(credentials));
    serve_and_run(&dir, invoking_user().unwrap().uid, handlers, "list", Vec::new()).await
}

fn fx_key() -> CredentialStanding {
    CredentialStanding {
        name: "fx_key".parse().unwrap(),
        standing: Standing::Healthy,
        unavailable_routes: Vec::new(),
        summary: Some(RecordSummary {
            kind: CredentialKind::Static,
            origins: vec![("api.fx.example".parse().unwrap(), Port::try_from(443).unwrap())],
        }),
    }
}

#[tokio::test]
async fn list_prints_one_line_per_credential_identically_on_every_run() {
    let first = list_with(Some(vec![fx_key()])).await;
    let second = list_with(Some(vec![fx_key()])).await;

    assert_eq!(first.status.code(), Some(0), "stderr: {}", text(&first.stderr));
    assert_eq!(text(&first.stdout), "fx_key  static  api.fx.example:443  healthy\n");
    assert_eq!(first.stdout, second.stdout);
    assert_eq!(text(&first.stderr), "");
}

#[tokio::test]
async fn list_with_no_open_vault_says_the_credentials_are_unknown_and_exits_four() {
    let output = list_with(None).await;

    assert_eq!(output.status.code(), Some(4), "stderr: {}", text(&output.stderr));
    assert_eq!(text(&output.stdout), "credentials: unknown while the vault is locked\n");
    assert_eq!(text(&output.stderr), "");
}

/// A recovery key the scripted `init` reveals. It must reach the terminal and never stdout or stderr.
const REVEALED_KEY: &str = "AGE-SECRET-KEY-1TESTONLYREVEALEDRECOVERYKEYQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ";

/// The notice the scripted `init` sends after the reveal: once the CLI has shown it, the CLI has recorded the reveal.
const KEY_SHOWN: &str = "the recovery key is shown";

/// A test-only `init` handler: reveals a key, sends a notice, prompts for `yes` and reports the answer, then holds the
/// exchange open until the test releases it, so the CLI is still waiting for a response when the signal arrives.
struct ScriptedInit {
    answered: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    release: Arc<tokio::sync::Notify>,
}

impl AdminHandler for ScriptedInit {
    fn handle<'a>(&'a self, _principal: AdminPrincipal, _request: AdminRequest, exchange: &'a mut Exchange) -> HandlerFuture<'a> {
        Box::pin(async move {
            exchange.reveal(REVEALED_KEY.as_bytes()).await?;
            exchange.notice(&format!("{KEY_SHOWN}\n")).await?;
            let prompt = Prompt {
                label: "Type yes".to_owned(),
                secret: false,
                switchable: false,
            };
            let input = exchange.prompt(&prompt).await?;
            let _ = self.answered.send(input.expose_secret().to_vec());
            self.release.notified().await;
            Ok(AdminResponse::Success)
        })
    }
}

/// Where the CLI under test reads the owner's answers from.
#[derive(Clone, Copy)]
enum ConsoleMode {
    /// Stdin is a pipe; the pseudo-terminal is only its controlling terminal.
    Piped,
    /// Stdin is the pseudo-terminal.
    Terminal,
}

/// A pseudo-terminal: the master end the test reads and types on, the slave end the CLI gets as its controlling
/// terminal. The test holds the slave open too, so the master never reports a hangup while the CLI starts.
struct Pty {
    master: fs::File,
    slave: fs::File,
    path: String,
}

fn open_pty() -> Pty {
    use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
    let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC).unwrap();
    grantpt(&master).unwrap();
    unlockpt(&master).unwrap();
    let path = ptsname(&master, Vec::new()).unwrap().into_string().unwrap();
    let slave = fs::File::options()
        .read(true)
        .write(true)
        .custom_flags(rustix::fs::OFlags::NOCTTY.bits() as i32)
        .open(&path)
        .unwrap();
    Pty {
        master: fs::File::from(master),
        slave,
        path,
    }
}

/// Copies everything `from` yields into the returned buffer, on a thread of its own.
fn collect(mut from: impl Read + Send + 'static) -> (Arc<Mutex<Vec<u8>>>, std::thread::JoinHandle<()>) {
    let seen = Arc::<Mutex<Vec<u8>>>::default();
    let sink = Arc::clone(&seen);
    let reader = std::thread::spawn(move || {
        let mut chunk = [0; 1024];
        while let Ok(len @ 1..) = from.read(&mut chunk) {
            sink.lock().unwrap().extend_from_slice(&chunk[..len]);
        }
    });
    (seen, reader)
}

async fn wait_for(buffers: &[&Arc<Mutex<Vec<u8>>>], needle: &str) {
    let found = || buffers.iter().any(|buffer| text(&buffer.lock().unwrap()).contains(needle));
    tokio::time::timeout(Duration::from_secs(10), async {
        while !found() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("the CLI never showed {needle:?}"));
}

/// Runs `iron-vault init` in a new session whose controlling terminal is a pseudo-terminal, against the scripted
/// handler; answers `yes` when `confirm` is set; then sends `signal` while the CLI waits. `setsid` execs a shell that
/// opens the terminal as session leader, which makes it the controlling terminal, then execs the CLI in its place, so
/// the child's pid is the CLI's. Returns the exit code, stdout, stderr and what the terminal showed.
async fn interrupt_init(mode: ConsoleMode, confirm: bool, signal: rustix::process::Signal) -> (Option<i32>, String, String, String) {
    let dir = TempDir::new();
    let me = invoking_user().unwrap();
    let socket = AdminSocket::bind(&dir.0, me).unwrap();
    let (answered, mut answers) = tokio::sync::mpsc::unbounded_channel();
    let release = Arc::new(tokio::sync::Notify::new());
    let handler = ScriptedInit {
        answered,
        release: Arc::clone(&release),
    };
    let handlers = Handlers::default().with(AdminCommand::Init, handler);
    let server = AdminServer::new(
        AdminPrincipals::new(DeploymentProfile::Development, me.uid),
        handlers,
        Limits::default(),
    );
    let (stop, stopped) = oneshot::channel::<()>();
    let served = tokio::spawn(async move {
        server
            .serve(socket, async {
                let _ = stopped.await;
            })
            .await
    });

    let pty = open_pty();
    let stdin = match mode {
        ConsoleMode::Piped => Stdio::piped(),
        ConsoleMode::Terminal => Stdio::from(pty.slave.try_clone().unwrap()),
    };
    let mut child = Command::new("setsid")
        .args(["sh", "-c", r#"exec 9<"$IV_PTS" && exec 9<&- && exec "$@""#, "sh"])
        .arg(env!("CARGO_BIN_EXE_iron-vault"))
        .args(command_args("init", &dir.socket()))
        .env("IV_PTS", &pty.path)
        .stdin(stdin)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut piped_stdin = child.stdin.take();
    let (stdout, stdout_reader) = collect(child.stdout.take().unwrap());
    let (stderr, stderr_reader) = collect(child.stderr.take().unwrap());
    let (terminal, _) = collect(pty.master.try_clone().unwrap());

    // A notice goes to stderr when stdin is piped and to the terminal otherwise.
    wait_for(&[&stderr, &terminal], KEY_SHOWN).await;
    if confirm {
        match (mode, piped_stdin.as_mut()) {
            (ConsoleMode::Piped, Some(input)) => input.write_all(b"yes\n").unwrap(),
            _ => (&pty.master).write_all(b"yes\n").unwrap(),
        }
        let answer = tokio::time::timeout(Duration::from_secs(10), answers.recv()).await.unwrap();
        assert_eq!(answer.as_deref(), Some(&b"yes"[..]));
    }
    rustix::process::kill_process(rustix::process::Pid::from_child(&child), signal).unwrap();
    let status = tokio::time::timeout(Duration::from_secs(10), tokio::task::spawn_blocking(move || child.wait()))
        .await
        .expect("the CLI exits on the signal")
        .unwrap()
        .unwrap();
    drop(piped_stdin);

    release.notify_one();
    let _ = stop.send(());
    served.await.unwrap().unwrap();
    stdout_reader.join().unwrap();
    stderr_reader.join().unwrap();
    let read = |buffer: &Arc<Mutex<Vec<u8>>>| text(&buffer.lock().unwrap());
    (status.code(), read(&stdout), read(&stderr), read(&terminal))
}

/// What every interrupted `init` shows: the key on the terminal only, nothing on stdout, and the advice last on stderr.
fn assert_interrupted(outcome: &(Option<i32>, String, String, String), code: i32, advice: &str) {
    let (status, stdout, stderr, terminal) = outcome;
    assert_eq!(*status, Some(code), "stderr: {stderr}");
    assert!(terminal.contains(REVEALED_KEY), "the key is shown on the terminal: {terminal}");
    assert_eq!(stdout, "");
    assert!(!stderr.contains(REVEALED_KEY), "{stderr}");
    assert!(stderr.ends_with(&format!("{advice}\n")), "{stderr}");
}

#[tokio::test]
async fn a_piped_init_interrupted_before_yes_says_the_key_is_dead() {
    let outcome = interrupt_init(ConsoleMode::Piped, false, rustix::process::Signal::INT).await;
    assert_interrupted(&outcome, 130, DEAD_RECOVERY_KEY);
    assert!(outcome.2.contains("before the recovery key was confirmed"), "{}", outcome.2);
}

#[tokio::test]
async fn a_piped_init_terminated_after_yes_says_to_keep_the_key() {
    let outcome = interrupt_init(ConsoleMode::Piped, true, rustix::process::Signal::TERM).await;
    assert_interrupted(&outcome, 143, UNCONFIRMED_RECOVERY_KEY);
}

#[tokio::test]
async fn a_terminal_init_hung_up_after_yes_says_to_keep_the_key() {
    let outcome = interrupt_init(ConsoleMode::Terminal, true, rustix::process::Signal::HUP).await;
    assert_interrupted(&outcome, 129, UNCONFIRMED_RECOVERY_KEY);
}

#[tokio::test]
async fn a_terminal_init_hung_up_before_yes_says_the_key_is_dead() {
    let outcome = interrupt_init(ConsoleMode::Terminal, false, rustix::process::Signal::HUP).await;
    assert_interrupted(&outcome, 129, DEAD_RECOVERY_KEY);
}

/// A `replace` handler that shows a summary, asks for the approval passphrase and then the secret, and keeps what it
/// received.
struct StubReplace(Arc<AddLog>);

impl AdminHandler for StubReplace {
    fn handle<'a>(&'a self, _principal: AdminPrincipal, request: AdminRequest, exchange: &'a mut Exchange) -> HandlerFuture<'a> {
        Box::pin(async move {
            self.0.requests.lock().unwrap().push(request);
            exchange.notice("replace credential fx\n").await?;
            for label in ["Approval passphrase for \"approval passphrase\"", "Secret for fx"] {
                let prompt = Prompt {
                    label: label.to_owned(),
                    secret: true,
                    switchable: false,
                };
                let input = exchange.prompt(&prompt).await?;
                self.0.values.lock().unwrap().push(input.expose_secret().to_vec());
            }
            Ok(AdminResponse::Replace {
                record_id: RECORD_ID.parse::<RecordId>().unwrap(),
            })
        })
    }
}

#[tokio::test]
async fn replace_sends_add_s_arguments_answers_presence_then_the_secret_from_stdin_and_prints_the_new_record_id() {
    let dir = TempDir::new();
    let stub = Arc::new(AddLog::default());
    let handlers = Handlers::default().with(AdminCommand::Replace, StubReplace(Arc::clone(&stub)));
    let mut args = add_args(&dir.socket());
    args[0] = "replace".to_owned();
    let input = format!("approval words\n{MARKER}\n").into_bytes();
    let output = serve_and_run_args(&dir, invoking_user().unwrap().uid, handlers, args, input).await;
    let (stdout, stderr) = (text(&output.stdout), text(&output.stderr));
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert_eq!(stdout, format!("replaced fx (static) as record {RECORD_ID}\n"));
    assert!(stderr.contains("replace credential fx") && !stderr.contains(MARKER), "{stderr}");
    assert_eq!(
        *stub.values.lock().unwrap(),
        [b"approval words".to_vec(), MARKER.as_bytes().to_vec()]
    );
    let requests = stub.requests.lock().unwrap();
    let [AdminRequest::Replace { name, kind, origins }] = &requests[..] else {
        panic!("expected one replace request, got {requests:?}");
    };
    assert_eq!((name.as_str(), *kind, origins.len()), ("fx", CredentialKind::Static, 2));
}

#[test]
fn completions_bash_prints_the_script_with_no_runtime_directory_or_service() {
    let output = Command::new(env!("CARGO_BIN_EXE_iron-vault"))
        .args(["completions", "bash"])
        .env_remove("XDG_RUNTIME_DIR")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "stderr: {}", text(&output.stderr));
    assert!(text(&output.stdout).contains("_iron__vault()"));
    assert!(output.stderr.is_empty(), "stderr: {}", text(&output.stderr));
}

/// The approver prompt the switching handler asks.
const APPROVER_LABEL: &str = "Approval passphrase for \"laptop\"";

/// A test-only `unlock` handler that asks a switchable approver prompt until it gets owner input, reporting each answer
/// (`None` for a switch), then succeeds.
struct SwitchingUnlock(tokio::sync::mpsc::UnboundedSender<Option<Vec<u8>>>);

impl AdminHandler for SwitchingUnlock {
    fn handle<'a>(&'a self, _principal: AdminPrincipal, _request: AdminRequest, exchange: &'a mut Exchange) -> HandlerFuture<'a> {
        Box::pin(async move {
            let prompt = Prompt {
                label: APPROVER_LABEL.to_owned(),
                secret: true,
                switchable: true,
            };
            loop {
                match exchange.prompt_or_switch_unless(&prompt, std::future::pending()).await? {
                    Some(PromptAnswer::Switch) => {
                        let _ = self.0.send(None);
                    }
                    Some(PromptAnswer::OwnerInput(input)) => {
                        let _ = self.0.send(Some(input.expose_secret().to_vec()));
                        return Ok(AdminResponse::Success);
                    }
                    None => return Ok(AdminResponse::Success),
                }
            }
        })
    }
}

/// `iron-vault unlock` running with a pseudo-terminal as its stdin and controlling terminal, against the switching
/// handler.
struct SwitchingRun {
    _dir: TempDir,
    pty: Pty,
    /// The terminal's settings before the CLI started.
    before: rustix::termios::Termios,
    child: std::process::Child,
    answers: tokio::sync::mpsc::UnboundedReceiver<Option<Vec<u8>>>,
    shown: Arc<Mutex<Vec<u8>>>,
    stop: oneshot::Sender<()>,
    served: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl SwitchingRun {
    fn start() -> Self {
        let dir = TempDir::new();
        let me = invoking_user().unwrap();
        let socket = AdminSocket::bind(&dir.0, me).unwrap();
        let (answered, answers) = tokio::sync::mpsc::unbounded_channel();
        let handlers = Handlers::default().with(AdminCommand::Unlock, SwitchingUnlock(answered));
        let server = AdminServer::new(
            AdminPrincipals::new(DeploymentProfile::Development, me.uid),
            handlers,
            Limits::default(),
        );
        let (stop, stopped) = oneshot::channel::<()>();
        let served = tokio::spawn(async move {
            server
                .serve(socket, async {
                    let _ = stopped.await;
                })
                .await
        });
        let pty = open_pty();
        let before = rustix::termios::tcgetattr(&pty.slave).unwrap();
        let child = Command::new("setsid")
            .args(["sh", "-c", r#"exec 9<"$IV_PTS" && exec 9<&- && exec "$@""#, "sh"])
            .arg(env!("CARGO_BIN_EXE_iron-vault"))
            .args(command_args("unlock", &dir.socket()))
            .env("IV_PTS", &pty.path)
            .stdin(Stdio::from(pty.slave.try_clone().unwrap()))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let (shown, _) = collect(pty.master.try_clone().unwrap());
        Self {
            _dir: dir,
            pty,
            before,
            child,
            answers,
            shown,
            stop,
            served,
        }
    }

    /// Waits until the CLI reads a switchable prompt: Ctrl-Y ends a line and echo is off. Typing before then could be
    /// flushed by the CLI's switch to quiet settings.
    async fn wait_for_switchable_read(&self) {
        let ready = || {
            let now = rustix::termios::tcgetattr(&self.pty.slave).unwrap();
            now.special_codes[rustix::termios::SpecialCodeIndex::VEOL] == 0x19
                && !now.local_modes.contains(rustix::termios::LocalModes::ECHO)
        };
        tokio::time::timeout(Duration::from_secs(10), async {
            while !ready() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the CLI never read a switchable prompt");
    }

    fn type_bytes(&self, bytes: &[u8]) {
        (&self.pty.master).write_all(bytes).unwrap();
    }

    async fn answer(&mut self) -> Option<Vec<u8>> {
        tokio::time::timeout(Duration::from_secs(10), self.answers.recv())
            .await
            .unwrap()
            .unwrap()
    }

    /// Waits for the CLI to exit, stops the server and returns the exit code and what the terminal showed.
    async fn finish(mut self) -> (Option<i32>, String) {
        let status = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match self.child.try_wait().unwrap() {
                    Some(status) => break status,
                    None => tokio::time::sleep(Duration::from_millis(10)).await,
                }
            }
        })
        .await
        .expect("the CLI exits");
        self.assert_terminal_restored();
        let _ = self.stop.send(());
        self.served.await.unwrap().unwrap();
        (status.code(), text(&self.shown.lock().unwrap()))
    }

    /// Echo and `VEOL` are as they were before the CLI started.
    fn assert_terminal_restored(&self) {
        let after = rustix::termios::tcgetattr(&self.pty.slave).unwrap();
        let veol = |termios: &rustix::termios::Termios| termios.special_codes[rustix::termios::SpecialCodeIndex::VEOL];
        assert_eq!(veol(&after), veol(&self.before));
        assert_eq!(after.local_modes, self.before.local_modes);
    }
}

#[tokio::test]
async fn ctrl_y_after_typing_sends_a_switch_and_no_typed_byte_then_enter_sends_the_value() {
    let mut run = SwitchingRun::start();
    run.wait_for_switchable_read().await;
    run.type_bytes(b"wrong-approver\x19");
    assert_eq!(run.answer().await, None, "a switch, carrying nothing typed");
    run.wait_for_switchable_read().await;
    run.type_bytes(b"s3cret\n");
    assert_eq!(run.answer().await, Some(b"s3cret".to_vec()));
    let (code, shown) = run.finish().await;
    assert_eq!(code, Some(0), "terminal: {shown}");
    assert_eq!(
        shown.matches(&format!("{APPROVER_LABEL} (Ctrl-Y to try another way): ")).count(),
        2,
        "{shown}"
    );
    assert!(
        !shown.contains("wrong-approver") && !shown.contains("s3cret"),
        "nothing typed is echoed: {shown}"
    );
}

#[tokio::test]
async fn sigint_at_a_switchable_prompt_restores_echo_and_veol() {
    let run = SwitchingRun::start();
    run.wait_for_switchable_read().await;
    run.type_bytes(b"partial");
    rustix::process::kill_process(rustix::process::Pid::from_child(&run.child), rustix::process::Signal::INT).unwrap();
    let (code, shown) = run.finish().await;
    assert_eq!(code, Some(130), "terminal: {shown}");
}
