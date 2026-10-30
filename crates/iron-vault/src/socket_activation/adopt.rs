//! Taking the sockets systemd passed and checking each against its listener before anything uses it.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::io;
use std::net::{SocketAddr, TcpListener};
use std::os::fd::{AsFd, BorrowedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

use iron_vault_policy::{Endpoint, ListenerConfig, ListenerName};
use listenfd::ListenFd;
use rustix::io::FdFlags;
use rustix::net::{AddressFamily, SocketAddrAny, SocketAddrUnix, SocketType, sockopt};

use super::{ActivationError, FIRST_FD};
use crate::request_socket::{self, DirFault};
use crate::socket_file;
use crate::trusted_path::ExpectedOwner;
use crate::trusted_path_report::PathFailure;

/// A listening socket systemd passed, checked against its listener's endpoint.
#[derive(Debug)]
pub enum AdoptedSocket {
    /// A TCP listener.
    Tcp(TcpListener),
    /// A Unix stream listener. Its socket file belongs to systemd, which removes it; the service never does.
    Unix(UnixListener),
}

impl AsFd for AdoptedSocket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        match self {
            Self::Tcp(listener) => listener.as_fd(),
            Self::Unix(listener) => listener.as_fd(),
        }
    }
}

/// Why a passed socket cannot serve its listener.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AdoptError {
    /// The activation variables did not match the config.
    #[error(transparent)]
    Activation(#[from] ActivationError),
    /// `listenfd` found no socket where the activation variables said one was.
    #[error("no socket was passed as fd {fd} for listener {listener}")]
    Missing {
        /// The listener.
        listener: ListenerName,
        /// Where its socket should be.
        fd: RawFd,
    },
    /// The socket is not a stream socket.
    #[error("the socket passed for listener {listener} is not a stream socket; use ListenStream= in its .socket unit")]
    NotStream {
        /// The listener.
        listener: ListenerName,
    },
    /// The socket is not listening, so it can accept no connection.
    #[error("the socket passed for listener {listener} is not listening")]
    NotListening {
        /// The listener.
        listener: ListenerName,
    },
    /// The socket's local address is not the one the config, and its TLS rule, assumed.
    #[error(
        "the socket passed for listener {listener} is bound to {actual}, but the config says {configured}; make the \
         .socket unit listen on exactly the configured address"
    )]
    AddressMismatch {
        /// The listener.
        listener: ListenerName,
        /// The configured endpoint.
        configured: String,
        /// Where the socket is bound.
        actual: String,
    },
    /// The configured Unix socket path names no directory.
    #[error("the socket passed for listener {listener} at {path} names no directory")]
    NoDirectory {
        /// The listener.
        listener: ListenerName,
        /// The socket's path.
        path: PathBuf,
    },
    /// The directory holding the Unix socket fails the runtime-directory rule, so another account could replace it.
    #[error("the socket passed for listener {listener} at {path} is in an untrusted directory {dir}: {reason}")]
    UntrustedDirectory {
        /// The listener.
        listener: ListenerName,
        /// The socket's path.
        path: PathBuf,
        /// The directory holding it.
        dir: PathBuf,
        /// Why the directory is not trusted, boxed because it is far larger than every other variant.
        reason: Box<PathFailure>,
    },
    /// The Unix socket file is not a socket owned by root or the service account.
    #[error("the socket file {path} for listener {listener} is {found}, not a socket owned by root or uid {owner}")]
    SocketFile {
        /// The listener.
        listener: ListenerName,
        /// The socket's path.
        path: PathBuf,
        /// What stands there.
        found: String,
        /// The service account's uid.
        owner: u32,
    },
    /// A system call on the socket failed.
    #[error("cannot {step} the socket passed for listener {listener}: {kind}")]
    Io {
        /// The listener.
        listener: ListenerName,
        /// What the service was doing.
        step: &'static str,
        /// The underlying error kind.
        kind: io::ErrorKind,
    },
}

/// Takes the sockets systemd passed, in fd order as `inherited` names them, and checks each against its listener.
///
/// Every adopted fd is close-on-exec. Call it at most once, before the service starts any thread: `listenfd` removes
/// `LISTEN_PID` and `LISTEN_FDS` from the environment as it takes the fds.
pub fn adopt(
    inherited: &[ListenerName],
    listeners: &BTreeMap<ListenerName, ListenerConfig>,
    owner: ExpectedOwner,
) -> Result<BTreeMap<ListenerName, AdoptedSocket>, AdoptError> {
    let mut fds = ListenFd::from_env();
    inherited
        .iter()
        .zip(FIRST_FD..)
        .enumerate()
        .map(|(index, (name, fd))| {
            let endpoint = listeners
                .get(name)
                .map(ListenerConfig::endpoint)
                .ok_or_else(|| ActivationError::UnknownName {
                    fd,
                    name: format!("\"{name}\""),
                })?;
            let socket = take(&mut fds, index, name, fd)?;
            set_cloexec(name, socket.as_fd())?;
            verify(name, socket.as_fd(), endpoint, owner)?;
            Ok((name.clone(), socket))
        })
        .collect()
}

/// Checks that `fd` is a listening stream socket bound exactly where `endpoint` says, and for a Unix socket that its
/// file is in a trusted directory and owned by root or `owner`.
pub fn verify(listener: &ListenerName, fd: BorrowedFd<'_>, endpoint: &Endpoint, owner: ExpectedOwner) -> Result<(), AdoptError> {
    check_stream(listener, fd)?;
    check_listening(listener, fd)?;
    let configured = LocalAddress::configured(endpoint);
    let actual = local_address(listener, fd)?;
    if actual != configured {
        return Err(AdoptError::AddressMismatch {
            listener: listener.clone(),
            configured: configured.to_string(),
            actual: actual.to_string(),
        });
    }
    match endpoint {
        Endpoint::UnixSocket(path) => check_socket_file(listener, path.as_path(), owner),
        Endpoint::Tcp { .. } => Ok(()),
    }
}

/// The socket at `index` as whichever stream listener it is; anything else stays with `listenfd` and is refused.
fn take(fds: &mut ListenFd, index: usize, listener: &ListenerName, fd: RawFd) -> Result<AdoptedSocket, AdoptError> {
    let missing = || AdoptError::Missing {
        listener: listener.clone(),
        fd,
    };
    let not_stream = |_| AdoptError::NotStream {
        listener: listener.clone(),
    };
    match fds.take_tcp_listener(index) {
        Ok(tcp) => tcp.map(AdoptedSocket::Tcp).ok_or_else(missing),
        Err(_) => fds
            .take_unix_listener(index)
            .map_err(not_stream)?
            .map(AdoptedSocket::Unix)
            .ok_or_else(missing),
    }
}

/// Marks `fd` close-on-exec. `listenfd` already does, but the guarantee should not rest on a dependency's internals.
fn set_cloexec(listener: &ListenerName, fd: BorrowedFd<'_>) -> Result<(), AdoptError> {
    rustix::io::fcntl_setfd(fd, FdFlags::CLOEXEC).map_err(failed(listener, "set close-on-exec on"))
}

fn check_stream(listener: &ListenerName, fd: BorrowedFd<'_>) -> Result<(), AdoptError> {
    match sockopt::socket_type(fd).map_err(failed(listener, "read the type of"))? {
        SocketType::STREAM => Ok(()),
        _ => Err(AdoptError::NotStream {
            listener: listener.clone(),
        }),
    }
}

fn check_listening(listener: &ListenerName, fd: BorrowedFd<'_>) -> Result<(), AdoptError> {
    match sockopt::socket_acceptconn(fd).map_err(failed(listener, "check"))? {
        true => Ok(()),
        false => Err(AdoptError::NotListening {
            listener: listener.clone(),
        }),
    }
}

/// Refuses a socket file that is not a socket owned by root or the service account. Its directory passing the
/// runtime-directory rule means no other account can have replaced it since.
fn check_socket_file(listener: &ListenerName, path: &Path, owner: ExpectedOwner) -> Result<(), AdoptError> {
    request_socket::check_socket_dir(path, owner).map_err(|fault| match fault {
        DirFault::NoDirectory => AdoptError::NoDirectory {
            listener: listener.clone(),
            path: path.to_path_buf(),
        },
        DirFault::Untrusted { dir, reason } => AdoptError::UntrustedDirectory {
            listener: listener.clone(),
            path: path.to_path_buf(),
            dir,
            reason: Box::new(reason),
        },
    })?;
    let metadata = fs::symlink_metadata(path).map_err(failed(listener, "inspect the file of"))?;
    match metadata.file_type().is_socket() && [0, owner.uid].contains(&metadata.uid()) {
        true => Ok(()),
        false => Err(AdoptError::SocketFile {
            listener: listener.clone(),
            path: path.to_path_buf(),
            found: socket_file::describe(&metadata),
            owner: owner.uid,
        }),
    }
}

/// Where a socket is bound, in a form a configured endpoint can be compared with exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
enum LocalAddress {
    /// An IPv4 or IPv6 address and port.
    Inet(SocketAddr),
    /// A Unix socket bound to a path.
    UnixPath(PathBuf),
    /// A Unix socket in the abstract namespace, or not bound at all.
    UnixOther,
    /// A socket of another address family.
    Other(AddressFamily),
}

impl LocalAddress {
    fn configured(endpoint: &Endpoint) -> Self {
        match endpoint {
            Endpoint::Tcp { address, .. } => Self::Inet(*address),
            Endpoint::UnixSocket(path) => Self::UnixPath(path.as_path().to_path_buf()),
        }
    }

    fn of(address: SocketAddrAny) -> Self {
        let family = address.address_family();
        match family {
            AddressFamily::INET | AddressFamily::INET6 => SocketAddr::try_from(address).map_or(Self::Other(family), Self::Inet),
            AddressFamily::UNIX => SocketAddrUnix::try_from(address).ok().map_or(Self::UnixOther, |unix| {
                unix.path_bytes()
                    .map_or(Self::UnixOther, |bytes| Self::UnixPath(PathBuf::from(OsStr::from_bytes(bytes))))
            }),
            family => Self::Other(family),
        }
    }
}

impl fmt::Display for LocalAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inet(address) => write!(f, "TCP {address}"),
            Self::UnixPath(path) => write!(f, "Unix socket {}", path.display()),
            Self::UnixOther => write!(f, "an abstract or unnamed Unix socket"),
            Self::Other(family) => write!(f, "a socket of address family {}", family.as_raw()),
        }
    }
}

fn local_address(listener: &ListenerName, fd: BorrowedFd<'_>) -> Result<LocalAddress, AdoptError> {
    rustix::net::getsockname(fd)
        .map(LocalAddress::of)
        .map_err(failed(listener, "read the local address of"))
}

/// Maps a failed system call at `step` to an [`AdoptError`] naming the listener.
fn failed<'a, E: Into<io::Error>>(listener: &'a ListenerName, step: &'static str) -> impl FnOnce(E) -> AdoptError + 'a {
    move |error| AdoptError::Io {
        listener: listener.clone(),
        step,
        kind: error.into().kind(),
    }
}
