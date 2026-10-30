//! The admin socket client: one exchange per connection (`design/admin-protocol.md`) over a blocking Unix stream, and
//! the owner-facing report of how it went.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use iron_vault::admin::ADMIN_SOCKET_NAME;
use iron_vault::admin::protocol::{
    self, AdminRequest, AdminResponse, Decoded, ErrorCode, Frame, FrameError, HEADER_LEN, OwnerInput, PROTOCOL_VERSION,
};
use iron_vault::deployment::{Accounts, DeploymentProfile, ProfileEnv};
use iron_vault::trusted_path_report::ServicePaths;
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

/// In a protected install only root and the service account are admin principals (§3.2), so the owner reaches the
/// admin socket through `sudo`.
const SUDO_HINT: &str = "In a protected install only root and the service account may use the admin socket: run the command with sudo.";

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
    let path = match socket.map_or_else(installation_socket, |path| Ok(path.to_path_buf())) {
        Ok(path) => path,
        Err(e) => return fail(Exit::Unreachable, &format!("{e:#}")),
    };
    match exchange(&path, AdminRequest::Ping, &mut ProcessConsole::default()) {
        Ok(AdminResponse::Ping { profile }) => {
            println!(
                "the service is running: {} profile, admin protocol version {PROTOCOL_VERSION}",
                profile_name(profile)
            );
            Exit::Success
        }
        Ok(AdminResponse::Error { code, message }) => fail(Exit::CommandError, &service_error(code, &message)),
        Ok(AdminResponse::Success) => fail(Exit::Unreachable, &ClientError::Unexpected.to_string()),
        Err(e) => fail(Exit::Unreachable, &e.to_string()),
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
            Frame::Prompt(prompt) => send_input(stream, console.collect(&prompt).map_err(ClientError::Input)?),
            Frame::Request(_) | Frame::OwnerInput(_) => return Err(ClientError::Unexpected),
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

/// Sends `input` as one owner-input frame. The frame holds the value, so it is built in a clearing buffer sized for it
/// up front, which never reallocates.
fn send_input(stream: &mut UnixStream, input: OwnerInput) -> io::Result<()> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(HEADER_LEN + input.expose_secret().len()));
    protocol::encode(&Frame::OwnerInput(input), &mut bytes).map_err(io::Error::other)?;
    stream.write_all(&bytes)
}

/// Reads one frame, asking the socket for no more bytes than the decoder needs: a service that closed on unsent
/// input may reset the connection after its last frame. Frames from the service never hold owner input, so an ordinary
/// buffer is enough.
fn read_frame(stream: &mut impl Read) -> Result<Frame, ClientError> {
    let mut bytes = Vec::new();
    loop {
        let needed = match protocol::decode(&bytes)? {
            Decoded::Frame { frame, .. } => return Ok(frame),
            Decoded::NeedMore(needed) => needed,
        };
        let limit = u64::try_from(needed).unwrap_or(u64::MAX);
        let read = stream.take(limit).read_to_end(&mut bytes)?;
        if read < needed {
            return Err(ClientError::Closed);
        }
    }
}

/// An error response for the owner: its code, the service's message, and what to do about the codes the owner can
/// act on.
fn service_error(code: ErrorCode, message: &str) -> String {
    let hint = match code {
        ErrorCode::NotAdminPrincipal => Some(SUDO_HINT),
        ErrorCode::UnsupportedVersion => Some("The CLI and the service versions differ; install matching versions."),
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
    }
}

fn fail(exit: Exit, message: &str) -> Exit {
    eprintln!("iron-vault: {message}");
    exit
}

#[cfg(test)]
mod tests;
