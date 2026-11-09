//! Binding a request socket (spec §7): a Unix socket on which callers reach the request interface.
//!
//! Any local account may connect, so the socket has mode `0666` and the mode grants nothing: each connection carries
//! the peer identity the kernel recorded, and caller authentication decides from that peer account, or from a caller
//! token, what the connection may use. What stops another account squatting on the path while the service is down
//! (§7) is the directory: it must pass the runtime-directory rule, so only the service account can write it.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixListener as StdUnixListener;
use std::path::{Path, PathBuf};

use crate::deployment::DeploymentProfile;
use crate::socket_file::{self, SocketRole, SocketSpec};
pub use crate::socket_file::{BindError, SocketFile};
use crate::trusted_path::{ExpectedOwner, TrustedPathRule};
use crate::trusted_path_report::{self, PathFailure};

/// The only mode a request socket may have: every account may connect, and caller authentication decides the rest.
const SOCKET_MODE: u32 = 0o666;

/// Why a request socket could not be bound.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RequestBindError {
    /// The path is the admin socket's, which a request socket must never replace.
    #[error("the request socket {path} is the admin socket's path; give the request socket a path of its own")]
    AdminSocketPath {
        /// The request socket's path.
        path: PathBuf,
    },
    /// The path has no directory part, so there is no directory to check.
    #[error("the request socket {path} names no directory; give it an absolute path")]
    NoDirectory {
        /// The request socket's path.
        path: PathBuf,
    },
    /// The directory holding the socket fails the runtime-directory rule, so another account could put its own
    /// socket there while the service is down.
    #[error("refusing to bind the request socket {path}: its directory {dir} is not trusted: {reason}")]
    UntrustedDirectory {
        /// The request socket's path.
        path: PathBuf,
        /// The directory holding it.
        dir: PathBuf,
        /// Why the directory is not trusted.
        reason: PathFailure,
    },
    /// Binding the socket file failed.
    #[error(transparent)]
    Bind(#[from] BindError),
}

/// A request socket, bound at mode `0666` and listening, but not yet accepting.
///
/// It owns its socket file: dropping it removes the file, so no exit after binding leaves one behind.
#[derive(Debug)]
pub struct RequestSocket {
    listener: StdUnixListener,
    file: SocketFile,
}

impl RequestSocket {
    /// Binds a request socket at `path` for the service account `owner`, replacing a stale socket that account owns.
    ///
    /// Refuses `admin_socket_path`, even through a symlinked directory, and a directory that fails the
    /// runtime-directory rule.
    pub fn bind(path: &Path, owner: ExpectedOwner, admin_socket_path: &Path) -> Result<Self, RequestBindError> {
        if is_same_socket_path(path, admin_socket_path) {
            return Err(RequestBindError::AdminSocketPath { path: path.to_path_buf() });
        }
        check_dir(path, owner)?;
        let spec = SocketSpec {
            role: SocketRole::Request,
            path,
            owner,
            mode: SOCKET_MODE,
        };
        let (listener, file) = socket_file::bind(spec)?;
        Ok(Self { listener, file })
    }

    /// The socket file's path.
    pub fn path(&self) -> &Path {
        self.file.path()
    }

    /// The listening socket and the socket file it owns, for a caller that registers the socket itself.
    pub(crate) fn into_parts(self) -> (StdUnixListener, SocketFile) {
        (self.listener, self.file)
    }
}

/// Why the directory holding a request socket is not trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DirFault {
    /// The path has no directory part.
    NoDirectory,
    /// The directory fails the runtime-directory rule.
    Untrusted {
        /// The directory holding the socket.
        dir: PathBuf,
        /// Why it is not trusted.
        reason: PathFailure,
    },
}

/// Refuses `path` unless the directory holding it passes the runtime-directory rule.
fn check_dir(path: &Path, owner: ExpectedOwner) -> Result<(), RequestBindError> {
    check_socket_dir(path, owner).map_err(|fault| match fault {
        DirFault::NoDirectory => RequestBindError::NoDirectory { path: path.to_path_buf() },
        DirFault::Untrusted { dir, reason } => RequestBindError::UntrustedDirectory {
            path: path.to_path_buf(),
            dir,
            reason,
        },
    })
}

/// Checks the directory holding the request socket `path` against the runtime-directory rule, whether the service
/// binds the socket or systemd passed it.
pub(crate) fn check_socket_dir(path: &Path, owner: ExpectedOwner) -> Result<(), DirFault> {
    let dir = path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .ok_or(DirFault::NoDirectory)?;
    // The runtime-directory rule is the same in both profiles; the profile only decides who may own the binary.
    trusted_path_report::check_path(TrustedPathRule::RuntimeDir, DeploymentProfile::Protected, owner, dir)
        .map(|_| ())
        .map_err(|reason| DirFault::Untrusted {
            dir: dir.to_path_buf(),
            reason,
        })
}

/// Whether `path` names `admin`: the same path, or the same file name in the same directory reached another way.
/// Binding there would remove the live admin socket as stale.
fn is_same_socket_path(path: &Path, admin: &Path) -> bool {
    let dir_id = |p: &Path| {
        p.parent()
            .and_then(|dir| fs::metadata(dir).ok())
            .map(|metadata| (metadata.dev(), metadata.ino()))
    };
    path == admin || (path.file_name() == admin.file_name() && dir_id(path).is_some_and(|id| Some(id) == dir_id(admin)))
}
