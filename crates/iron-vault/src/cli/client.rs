//! The admin socket client: one exchange per connection (`design/admin-protocol.md`) over a blocking Unix stream, and
//! the owner-facing report of how it went.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use iron_vault::admin::ADMIN_SOCKET_NAME;
use iron_vault::admin::protocol::{
    self, AdminRequest, AdminResponse, ApprovalResult, Decoded, ErrorCode, Frame, FrameError, HEADER_LEN, MAX_BODY_LEN, MAX_CONFIG_LEN,
    OwnerInput, PROTOCOL_VERSION, PromptAnswer, ProposedConfig, RequestedOrigin, RequestedSignerKind, digest_text,
};
use iron_vault::deployment::{Accounts, DeploymentProfile, ProfileEnv};
use iron_vault::hardening::MEMLOCK_REMEDIATION;
use iron_vault::service_state::ServiceState;
use iron_vault::trusted_path_report::ServicePaths;
use iron_vault_policy::{CredentialKind, Host, Port};
use iron_vault_store::UtcSecond;
use zeroize::Zeroizing;

use super::Exit;
use super::console::{InputError, OwnerConsole, ProcessConsole};

/// How long one read or write on the admin socket may wait, so a wedged service or a stalled forwarded socket ends the
/// command instead of hanging it. It bounds only socket calls: while the owner types, the CLI is not waiting on the
/// socket, so the time spent at a prompt never counts. It is longer than the service's request deadline, which bounds
/// each frame's write once it starts, but not the handler's own work between an owner input and its next frame: that
/// counts here, so a command with a slow step after a prompt (scrypt, a TPM, a touch, OAuth) will need a longer timeout
/// or a progress frame.
const SOCKET_TIMEOUT: Duration = Duration::from_secs(60);

/// In a protected install only root is an admin principal (§5), so the owner reaches the admin socket through `sudo`.
const SUDO_HINT: &str = "In a protected install only root may use the admin socket: run the command with sudo.";

/// Why no admin response came back. Messages name the socket path and protocol numbers, never request arguments.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// Nothing is at the socket path.
    #[error("the Iron Vault service is not running: there is no admin socket at {0}")]
    NoSocket(PathBuf),
    /// A socket is at the path, but no service is listening on it.
    #[error("the Iron Vault service is not running: nothing is listening on the admin socket {0}")]
    NotListening(PathBuf),
    /// The file permissions keep this account off the socket.
    #[error("permission denied connecting to the admin socket {0}. {SUDO_HINT}")]
    PermissionDenied(PathBuf),
    /// Connecting failed for another reason.
    #[error("cannot connect to the admin socket {path}: {source}")]
    Connect {
        /// The admin socket's path.
        path: PathBuf,
        /// What the operating system reported.
        source: io::Error,
    },
    /// The connection failed part-way through the exchange.
    #[error("the connection to the service failed: {0}")]
    Io(io::Error),
    /// The service closed before sending a whole admin response.
    #[error("the service closed the connection without answering")]
    Closed,
    /// The service speaks another protocol version.
    #[error(
        "the CLI and the service versions differ: this CLI speaks admin protocol version {PROTOCOL_VERSION}, the service \
         version {0}; install matching versions"
    )]
    VersionMismatch(u16),
    /// The service sent a frame that does not decode.
    #[error("the service sent a malformed frame: {0}")]
    Malformed(FrameError),
    /// Nothing arrived from the service, or it took nothing, for the socket timeout.
    #[error("the service stopped answering: nothing moved on the admin socket for {} seconds", SOCKET_TIMEOUT.as_secs())]
    TimedOut,
    /// The owner input for a prompt was not collected, so the command was cancelled.
    #[error("the command was cancelled: {0}")]
    Input(InputError),
    /// The service sent a frame only the CLI sends, or a result for another command.
    #[error("the service sent an answer that does not fit the request")]
    Unexpected,
}

impl From<io::Error> for ClientError {
    fn from(error: io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => Self::TimedOut,
            _ => Self::Io(error),
        }
    }
}

impl From<FrameError> for ClientError {
    fn from(error: FrameError) -> Self {
        match error {
            FrameError::UnsupportedVersion(version) => Self::VersionMismatch(version),
            other => Self::Malformed(other),
        }
    }
}

/// Runs `ping` and reports the outcome: the profile on stdout, or what went wrong on stderr.
pub fn ping(socket: Option<&Path>) -> Exit {
    run(socket, AdminRequest::Ping, |response| match response {
        AdminResponse::Ping { profile } => {
            println!(
                "the service is running: {} profile, admin protocol version {PROTOCOL_VERSION}",
                profile_name(profile)
            );
            Exit::Success
        }
        _ => unexpected(),
    })
}

/// Runs `status` and prints the report on stdout. Any answer from the service that is not Ready exits with
/// [`Exit::NotReady`], so a script can wait on readiness.
pub fn status(socket: Option<&Path>) -> Exit {
    run(socket, AdminRequest::Status, |response| match response {
        AdminResponse::Status(report) => {
            print!("{}", super::status::render(&report, invoking_user_name));
            if report.state == ServiceState::Ready {
                Exit::Success
            } else {
                Exit::NotReady
            }
        }
        _ => unexpected(),
    })
}

/// Runs `list` and prints one line per credential on stdout. With no vault open the credentials are unknown and the exit
/// is [`Exit::NotReady`], so a script cannot mistake an empty answer for an empty vault.
pub fn list(socket: Option<&Path>) -> Exit {
    run(socket, AdminRequest::List, |response| match response {
        AdminResponse::List { credentials } => {
            print!("{}", super::list::render(credentials.as_deref()));
            if credentials.is_some() { Exit::Success } else { Exit::NotReady }
        }
        _ => unexpected(),
    })
}

/// Runs `lock` and reports the new state. A drain that expired is a success with a warning on stderr: the service is
/// Locked, but the owner must know that a request may still hold secrets.
pub fn lock(socket: Option<&Path>) -> Exit {
    run(socket, AdminRequest::Lock, |response| match response {
        AdminResponse::Lock { cleared } => {
            println!("locked");
            if !cleared {
                eprintln!("iron-vault: warning: a request still holds secrets in the service's memory; see the service log");
            }
            Exit::Success
        }
        _ => unexpected(),
    })
}

/// One exchange, answering any prompt the service sends from the owner console: `answer` handles a success; an error
/// response and a failed exchange are reported here.
fn run(socket: Option<&Path>, request: AdminRequest, answer: impl FnOnce(AdminResponse) -> Exit) -> Exit {
    run_on(socket, request, &mut ProcessConsole::default(), answer)
}

/// [`run`] with the prompts answered from `console`.
pub(super) fn run_on(
    socket: Option<&Path>,
    request: AdminRequest,
    console: &mut impl OwnerConsole,
    answer: impl FnOnce(AdminResponse) -> Exit,
) -> Exit {
    let path = match socket.map_or_else(installation_socket, |path| Ok(path.to_path_buf())) {
        Ok(path) => path,
        Err(e) => return fail(Exit::Unreachable, &format!("{e:#}")),
    };
    match exchange(&path, request, console) {
        Ok(AdminResponse::Error { code, message }) => fail(Exit::CommandError, &service_error(code, &message)),
        Ok(response) => answer(response),
        Err(e) => fail(Exit::Unreachable, &e.to_string()),
    }
}

/// Runs `unlock`, answering the service's passphrase prompt from the owner console, and reports the state it left the
/// service in: Ready on stdout, or the service's error, which names an Unavailable state's redacted reason, on stderr.
pub fn unlock(socket: Option<&Path>) -> Exit {
    run(socket, AdminRequest::Unlock, |response| match response {
        AdminResponse::Success => {
            println!("the vault is unlocked: the service is Ready");
            Exit::Success
        }
        _ => unexpected(),
    })
}

/// Runs `add`. The service decides what to prompt for, by kind, and each answer comes from the owner console, so the
/// secret never travels as an argument. On success the new record's ID goes to stdout.
pub fn add(socket: Option<&Path>, name: String, kind: CredentialKind, origins: &[(Host, Port)]) -> Exit {
    let request = AdminRequest::Add {
        name: name.clone(),
        kind,
        origins: requested_origins(origins),
    };
    run(socket, request, |response| match response {
        AdminResponse::Add { record_id } => {
            println!("added {name} ({}) as record {record_id}", kind.as_str());
            Exit::Success
        }
        _ => unexpected(),
    })
}

/// Runs `replace`. The service shows its own summary of the change as notices, then prompts for the approval passphrase
/// and the new material; each answer comes from the owner console. On success the new record's ID goes to stdout.
pub fn replace(socket: Option<&Path>, name: String, kind: CredentialKind, origins: &[(Host, Port)]) -> Exit {
    let request = AdminRequest::Replace {
        name: name.clone(),
        kind,
        origins: requested_origins(origins),
    };
    run(socket, request, |response| match response {
        AdminResponse::Replace { record_id } => {
            println!("replaced {name} ({}) as record {record_id}", kind.as_str());
            Exit::Success
        }
        _ => unexpected(),
    })
}

/// Runs `rm`. The service describes the removal in a notice and prompts for the approval passphrase, answered from the
/// owner console. A name a route still uses is refused with the routes to take out of the config first.
pub fn rm(socket: Option<&Path>, name: String) -> Exit {
    let request = AdminRequest::Rm { name: name.clone() };
    run(socket, request, |response| match response {
        AdminResponse::Success => {
            println!("removed {name}");
            Exit::Success
        }
        _ => unexpected(),
    })
}

/// Runs `approver list` and prints one line per approver on stdout.
pub fn approver_list(socket: Option<&Path>) -> Exit {
    run(socket, AdminRequest::ApproverList, |response| match response {
        AdminResponse::ApproverList { entries } => {
            print!("{}", super::approver_list::render(&entries));
            Exit::Success
        }
        _ => unexpected(),
    })
}

/// Runs `recipient list` and prints one line per enrolled recipient on stdout.
pub fn recipient_list(socket: Option<&Path>) -> Exit {
    run(socket, AdminRequest::RecipientList, |response| match response {
        AdminResponse::RecipientList { entries } => {
            print!("{}", super::recipient_list::render(&entries));
            Exit::Success
        }
        _ => unexpected(),
    })
}

/// Runs `recipient add`. The service shows its summary and the completion notice, and prompts for the vault passphrase,
/// answered from the owner console; nothing but those notices is printed on success. `host_unlock` enrols the key with the
/// `host-unlock` role.
pub fn recipient_add(socket: Option<&Path>, recipient: String, label: String, host_unlock: bool) -> Exit {
    let request = if host_unlock {
        AdminRequest::RecipientAddHostUnlock { recipient, label }
    } else {
        AdminRequest::RecipientAdd { recipient, label }
    };
    run(socket, request, |response| match response {
        AdminResponse::RecipientAdd { .. } => Exit::Success,
        _ => unexpected(),
    })
}

/// Runs `recipient remove`. The service describes the removal in a notice and prompts for the approval passphrase, answered
/// from the owner console; its closing notice says what removal does not reach, so success prints nothing to stdout.
pub fn recipient_remove(socket: Option<&Path>, recipient: String) -> Exit {
    run(socket, AdminRequest::RecipientRemove { recipient }, |response| match response {
        AdminResponse::RecipientRemove { .. } => Exit::Success,
        _ => unexpected(),
    })
}

/// Runs `approver add`. The service describes the change in a notice, then prompts for an approver's passphrase and the
/// new one, answered from the owner console. Only the new approver ID goes to stdout, so a script can capture it.
pub fn approver_add(socket: Option<&Path>, kind: RequestedSignerKind, label: String) -> Exit {
    run(socket, AdminRequest::ApproverAdd { kind, label }, |response| match response {
        AdminResponse::ApproverAdd { approver, .. } => {
            println!("{approver}");
            Exit::Success
        }
        _ => unexpected(),
    })
}

/// Runs `approver remove`. The service describes the removal in a notice and prompts for an approver's passphrase, answered
/// from the owner console; its closing notice confirms the removal, so success prints nothing to stdout.
pub fn approver_remove(socket: Option<&Path>, approver: [u8; 16]) -> Exit {
    run(socket, AdminRequest::ApproverRemove { approver }, |response| match response {
        AdminResponse::ApproverRemove { .. } => Exit::Success,
        _ => unexpected(),
    })
}

/// Runs `recovery check`, answering the key prompt from the owner console. A success names the vault the key opened and
/// the check time on stdout; when the check record could not be written, stderr says reminders still count from the last
/// recorded check.
pub fn recovery_check(socket: Option<&Path>) -> Exit {
    run(socket, AdminRequest::RecoveryCheck, |response| match response {
        AdminResponse::RecoveryCheck {
            vault_id,
            checked_at,
            recorded,
        } => {
            println!("the recovery key opens vault {vault_id}: checked {}", check_time(checked_at));
            if !recorded {
                eprintln!(
                    "iron-vault: warning: the check time was not saved, so recovery reminders still count from the last recorded check"
                );
            }
            Exit::Success
        }
        _ => unexpected(),
    })
}

/// The check time as the record writes it, or the raw seconds for a time outside its range.
fn check_time(unix_seconds: u64) -> String {
    UtcSecond::from_unix_seconds(unix_seconds).map_or_else(|_| format!("{unix_seconds} seconds since the epoch"), |t| t.to_string())
}

/// The parsed origins as the request carries them.
fn requested_origins(origins: &[(Host, Port)]) -> Vec<RequestedOrigin> {
    let requested = origins.iter().map(|(host, port)| RequestedOrigin {
        host: host.to_string(),
        port: *port,
    });
    requested.collect()
}

/// Runs `config approve` on the bytes of `file`. The service shows its own summary as notices and prompts for the
/// confirmation and the approval passphrase; the CLI computes no summary or digest of its own. A file longer than
/// [`MAX_CONFIG_LEN`] is refused before anything is sent. No diagnostic quotes the file's bytes.
pub fn config_approve(socket: Option<&Path>, file: &Path) -> Exit {
    let config = match read_config(file) {
        Ok(config) => config,
        Err(message) => return fail(Exit::Usage, &message),
    };
    run(socket, AdminRequest::ConfigApprove(config), |response| match response {
        AdminResponse::ConfigApprove(result) => {
            print!("{}", approved(&result));
            Exit::Success
        }
        _ => unexpected(),
    })
}

/// The proposed config from `file`, read no further than one byte past the limit.
fn read_config(file: &Path) -> Result<ProposedConfig, String> {
    let limit = u64::try_from(MAX_CONFIG_LEN).unwrap_or(u64::MAX).saturating_add(1);
    let mut bytes = Vec::new();
    File::open(file)
        .and_then(|opened| opened.take(limit).read_to_end(&mut bytes))
        .map_err(|e| format!("cannot read the config file {}: {e}", file.display()))?;
    ProposedConfig::new(bytes).ok_or_else(|| format!("the config file {} is longer than {MAX_CONFIG_LEN} bytes", file.display()))
}

/// What a completed approval prints: the committed version with the digest, then the summary headline.
fn approved(result: &ApprovalResult) -> String {
    format!(
        "approved version {} ({})\n{}\n",
        result.version,
        digest_text(&result.digest),
        result.headline
    )
}

pub(super) fn unexpected() -> Exit {
    fail(Exit::Unreachable, &ClientError::Unexpected.to_string())
}

/// The account this CLI runs as, for `status`'s development profile line; its uid when `/etc/passwd` does not name it.
fn invoking_user_name() -> String {
    let accounts = Accounts::read().ok();
    let uid = accounts
        .as_ref()
        .and_then(|accounts| ProfileEnv::from_process(accounts).ok())
        .map(|env| env.invoking_uid);
    match (accounts, uid) {
        (Some(accounts), Some(uid)) => accounts.name(uid).map_or_else(|| format!("uid {uid}"), str::to_owned),
        _ => "this user".to_owned(),
    }
}

/// Sends `request` to the admin socket at `path`, answers the service's prompts from `console`, and returns the
/// service's admin response.
pub fn exchange(path: &Path, request: AdminRequest, console: &mut impl OwnerConsole) -> Result<AdminResponse, ClientError> {
    let mut stream = connect(path)?;
    stream.set_read_timeout(Some(SOCKET_TIMEOUT))?;
    stream.set_write_timeout(Some(SOCKET_TIMEOUT))?;
    converse(&mut stream, request, console)
}

/// The exchange on a connected stream: the request, one owner input for each prompt, then the admin response.
fn converse(stream: &mut UnixStream, request: AdminRequest, console: &mut impl OwnerConsole) -> Result<AdminResponse, ClientError> {
    let mut sent = send_request(stream, request);
    loop {
        // A refusing or busy service writes its answer and closes without reading, and a service whose prompt deadline
        // passed closes while the owner types, so a write may fail with a reset or broken pipe while an answer waits to
        // be read. The write error is reported only when nothing arrives.
        let frame = match (read_frame(stream), sent) {
            (Err(ClientError::Closed | ClientError::Io(_)), Err(e)) => return Err(e.into()),
            (received, _) => received?,
        };
        sent = match frame {
            Frame::Response(response) => return Ok(response),
            Frame::Prompt(prompt) => send_answer(stream, console.answer(&prompt).map_err(ClientError::Input)?),
            // A notice or a reveal comes only after the service has read the request, so the request was sent.
            Frame::Notice(notice) => Ok(console.notice(&notice.text).map_err(ClientError::Input)?),
            Frame::Reveal(secret) => Ok(console.reveal(&secret).map_err(ClientError::Input)?),
            Frame::Request(_) | Frame::OwnerInput(_) | Frame::Switch => return Err(ClientError::Unexpected),
        };
    }
}

/// This installation's admin socket: `admin.sock` in its deployment profile's runtime directory.
fn installation_socket() -> anyhow::Result<PathBuf> {
    let env = ProfileEnv::from_process(&Accounts::read()?)?;
    let paths = ServicePaths::for_profile(DeploymentProfile::current(), &env).context("cannot locate the admin socket")?;
    paths
        .runtime_dir
        .map(|dir| dir.join(ADMIN_SOCKET_NAME))
        .context("this deployment names no runtime directory for the admin socket")
}

fn connect(path: &Path) -> Result<UnixStream, ClientError> {
    UnixStream::connect(path).map_err(|source| match source.kind() {
        io::ErrorKind::NotFound => ClientError::NoSocket(path.to_path_buf()),
        io::ErrorKind::ConnectionRefused => ClientError::NotListening(path.to_path_buf()),
        io::ErrorKind::PermissionDenied => ClientError::PermissionDenied(path.to_path_buf()),
        _ => ClientError::Connect {
            path: path.to_path_buf(),
            source,
        },
    })
}

fn send_request(stream: &mut UnixStream, request: AdminRequest) -> io::Result<()> {
    let mut bytes = Vec::new();
    protocol::encode(&Frame::Request(request), &mut bytes).map_err(io::Error::other)?;
    stream.write_all(&bytes)
}

/// Sends the owner's answer to a prompt: owner input, or a switch frame, which carries nothing typed.
fn send_answer(stream: &mut UnixStream, answer: PromptAnswer) -> io::Result<()> {
    match answer {
        PromptAnswer::OwnerInput(input) => send_input(stream, input),
        PromptAnswer::Switch => {
            let mut bytes = Vec::with_capacity(HEADER_LEN);
            protocol::encode(&Frame::Switch, &mut bytes).map_err(io::Error::other)?;
            stream.write_all(&bytes)
        }
    }
}

/// Sends `input` as one owner-input frame. The frame holds the value, so it is built in a clearing buffer sized for it
/// up front, which never reallocates.
fn send_input(stream: &mut UnixStream, input: OwnerInput) -> io::Result<()> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(HEADER_LEN + input.expose_secret().len()));
    protocol::encode(&Frame::OwnerInput(input), &mut bytes).map_err(io::Error::other)?;
    stream.write_all(&bytes)
}

/// Reads one frame, asking the socket for no more bytes than the decoder needs: a service that closed on unsent
/// input may reset the connection after its last frame. A reveal frame holds a secret, so every frame is read into a
/// clearing buffer sized once for the largest frame, which never reallocates and leaves no copy behind.
fn read_frame(stream: &mut impl Read) -> Result<Frame, ClientError> {
    let mut buffer = Zeroizing::new(vec![0; HEADER_LEN + MAX_BODY_LEN]);
    let mut filled = 0;
    loop {
        let needed = match protocol::decode(buffer.get(..filled).unwrap_or_default())? {
            Decoded::Frame { frame, .. } => return Ok(frame),
            Decoded::NeedMore(needed) => needed,
        };
        // The decoder never asks past the largest frame, which the buffer holds.
        let window = buffer
            .get_mut(filled..filled.saturating_add(needed))
            .ok_or(ClientError::Malformed(FrameError::BodyTooLong))?;
        match stream.read(window) {
            Ok(0) => return Err(ClientError::Closed),
            Ok(read) => filled += read,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
}

/// An error response for the owner: its code, the service's message, and what to do about the codes the owner can
/// act on.
fn service_error(code: ErrorCode, message: &str) -> String {
    let hint = match code {
        ErrorCode::NotAdminPrincipal => Some(SUDO_HINT.to_owned()),
        ErrorCode::UnsupportedVersion => Some("The CLI and the service versions differ; install matching versions.".to_owned()),
        ErrorCode::MemoryUnprotected => Some(format!(
            "A protected install unlocks only once its memory is locked against swap: {MEMLOCK_REMEDIATION}, then restart it."
        )),
        _ => None,
    };
    let line = format!("the service answered error {} ({}): {message}", code as u16, code.name());
    match hint {
        Some(hint) => format!("{line}\n{hint}"),
        None => line,
    }
}

fn profile_name(profile: DeploymentProfile) -> &'static str {
    match profile {
        DeploymentProfile::Protected => "protected",
        DeploymentProfile::Development => "development",
        DeploymentProfile::Container => "container",
    }
}

pub(super) fn fail(exit: Exit, message: &str) -> Exit {
    eprintln!("iron-vault: {message}");
    exit
}

#[cfg(test)]
mod tests;
