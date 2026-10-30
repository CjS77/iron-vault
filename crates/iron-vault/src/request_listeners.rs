//! The request listeners (spec §3.4, §3.5): every configured listener open at once, each accepted connection tagged
//! by the transport with the listener it arrived on and, on a Unix socket, the peer identity the kernel reports.
//!
//! Caller identification takes the listener name and the peer uid from here and never from the request, so an
//! [`IncomingConnection`]'s tags are its only inputs besides the request headers.
//!
//! `serve` does not open these yet: it has no active policy to serve until the request pipeline (EP-18) and policy
//! activation at startup (EP-22) land. EP-18 calls [`RequestListeners::open`] and runs the accept loop on
//! [`RequestListeners::accept`].
//!
//! Startup order matters. [`adopt`](crate::socket_activation::adopt) runs first, before the async runtime or any
//! other thread exists, because `listenfd` edits the environment as it takes the fds. [`RequestListeners::open`] runs
//! afterwards inside the runtime, because it registers each socket with the runtime's reactor.

use std::collections::BTreeMap;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use iron_vault_policy::{Endpoint, ListenerConfig, ListenerName};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use zeroize::Zeroizing;

use crate::admin::ADMIN_SOCKET_NAME;
use crate::admin_file::{self, AdminFile, AdminFileError};
use crate::listener_tls::{DEFAULT_HANDSHAKE_TIMEOUT, ListenerTls, ListenerTlsError};
use crate::peer::peer_identity;
use crate::request_socket::{RequestBindError, RequestSocket, SocketFile};
use crate::socket_activation::{AdoptedSocket, NotActivated, check_origin};
use crate::trusted_path_report::ServicePaths;

mod stream;
pub use stream::{IncomingConnection, RequestStream};

/// How long accepting pauses after an error such as running out of file descriptors: long enough not to spin on an
/// error that persists, short enough that service resumes soon after connections close.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// Every configured request listener, open and accepting.
///
/// Dropping it closes every listener and removes the socket files the service bound itself. Sockets systemd passed
/// keep their files, which belong to systemd.
#[derive(Debug)]
pub struct RequestListeners {
    open: Vec<OpenListener>,
    /// Where the next accept starts looking, so a busy listener cannot starve the ones after it.
    next: AtomicUsize,
}

/// One open listener. Its socket is declared before its socket file, so dropping it stops listening before the file
/// is removed.
#[derive(Debug)]
struct OpenListener {
    name: ListenerName,
    socket: Socket,
    tls: Option<Arc<ListenerTls>>,
    /// The socket file the service bound, held to be removed on drop; `None` for a TCP listener or one systemd passed.
    _file: Option<SocketFile>,
}

#[derive(Debug)]
enum Socket {
    Unix(UnixListener),
    Tcp(TcpListener),
}

/// A stream just accepted, before it is tagged.
enum Accepted {
    Unix(UnixStream),
    Tcp(TcpStream),
}

/// Why the request listeners did not open. Nothing stays open after one fails.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum OpenError {
    /// `open` was called outside an async runtime, so no socket could be registered.
    #[error("the request listeners must be opened inside the async runtime")]
    NoRuntime,
    /// The deployment names no runtime directory, so the admin socket's path, which no request socket may take, is
    /// unknown.
    #[error("this deployment names no runtime directory, so the request sockets cannot be checked against the admin socket")]
    NoRuntimeDir,
    /// A Unix listener's socket could not be bound.
    #[error("listener {listener}: {source}")]
    Unix {
        /// The listener.
        listener: ListenerName,
        /// Why binding failed, boxed because it is far larger than every other variant.
        source: Box<RequestBindError>,
    },
    /// A TCP listener in a protected install was not passed by systemd.
    #[error(transparent)]
    NotActivated(#[from] NotActivated),
    /// A TCP listener's address could not be bound.
    #[error("cannot bind listener {listener} on {address}: {kind}")]
    Tcp {
        /// The listener.
        listener: ListenerName,
        /// Its address.
        address: SocketAddr,
        /// The underlying error kind.
        kind: io::ErrorKind,
    },
    /// A TLS listener's certificate and key did not load; the error names the listener.
    #[error(transparent)]
    Tls(#[from] ListenerTlsError),
    /// The runtime would not take the socket.
    #[error("cannot register listener {listener} with the async runtime: {kind}")]
    Register {
        /// The listener.
        listener: ListenerName,
        /// The underlying error kind.
        kind: io::ErrorKind,
    },
}

impl RequestListeners {
    /// Opens every listener in `listeners`, in name order: the socket systemd passed for it in `activated` if there
    /// is one, otherwise one the service binds, which in a protected install only a Unix listener may be. A listener
    /// with TLS files loads them first.
    ///
    /// All or nothing: when one listener fails, those already open are closed and their socket files removed before
    /// the error returns. A socket in `activated` that no listener names is closed.
    ///
    /// Call it inside the async runtime, after [`adopt`](crate::socket_activation::adopt) has run outside it.
    pub fn open(
        listeners: &BTreeMap<ListenerName, ListenerConfig>,
        paths: &ServicePaths,
        activated: BTreeMap<ListenerName, AdoptedSocket>,
    ) -> Result<Self, OpenError> {
        Self::open_with(listeners, paths, activated, |file, path| {
            admin_file::read(file, paths.profile, paths.owner, path)
        })
    }

    /// [`open`](Self::open) with the TLS file reader passed in, so tests can supply certificates without trusted
    /// paths on disk.
    pub(crate) fn open_with(
        listeners: &BTreeMap<ListenerName, ListenerConfig>,
        paths: &ServicePaths,
        mut activated: BTreeMap<ListenerName, AdoptedSocket>,
        read: impl Fn(AdminFile, &Path) -> Result<Zeroizing<Vec<u8>>, AdminFileError>,
    ) -> Result<Self, OpenError> {
        tokio::runtime::Handle::try_current().map_err(|_| OpenError::NoRuntime)?;
        let admin_socket = admin_socket_path(paths)?;
        let open = listeners
            .iter()
            .map(|(name, config)| {
                let tls = load_tls(name, config.endpoint(), &read)?;
                let (socket, file) = match activated.remove(name) {
                    Some(adopted) => (register(name, adopted)?, None),
                    None => bind(name, config.endpoint(), paths, &admin_socket)?,
                };
                Ok(OpenListener {
                    name: name.clone(),
                    socket,
                    tls,
                    _file: file,
                })
            })
            .collect::<Result<_, OpenError>>()?;
        Ok(Self {
            open,
            next: AtomicUsize::new(0),
        })
    }

    /// The next connection on any listener, tagged with its listener and, on a Unix socket, its peer identity. Its TLS
    /// handshake has not run: [`IncomingConnection::establish`] runs it in the connection's own task, so a slow client
    /// cannot hold up accepting.
    ///
    /// Accept errors are logged and never returned. Running out of file descriptors pauses accepting briefly; a
    /// connection the peer abandoned before it was accepted is skipped at once, so a client cannot slow accepting by
    /// abandoning connections. A Unix connection whose peer credentials cannot be read is closed and logged: without
    /// them it cannot be told apart from any other account's. With no listeners this never completes.
    pub async fn accept(&self) -> IncomingConnection {
        loop {
            let (listener, accepted) = std::future::poll_fn(|cx| self.poll_any(cx)).await;
            match accepted {
                Ok(accepted) => {
                    if let Some(connection) = listener.tag(accepted) {
                        return connection;
                    }
                }
                Err(e) => pause(&listener.name, &e).await,
            }
        }
    }

    /// The first listener with a connection, looking from a different one each time.
    fn poll_any(&self, cx: &mut Context<'_>) -> Poll<(&OpenListener, io::Result<Accepted>)> {
        let count = self.open.len();
        let start = self.next.fetch_add(1, Ordering::Relaxed).checked_rem(count).unwrap_or(0);
        self.open
            .iter()
            .cycle()
            .skip(start)
            .take(count)
            .find_map(|listener| match listener.socket.poll_accept(cx) {
                Poll::Ready(accepted) => Some((listener, accepted)),
                Poll::Pending => None,
            })
            .map_or(Poll::Pending, Poll::Ready)
    }
}

impl OpenListener {
    /// Tags an accepted stream with this listener and its peer, or closes it when its peer credentials are unreadable.
    fn tag(&self, accepted: Accepted) -> Option<IncomingConnection> {
        match accepted {
            Accepted::Unix(stream) => match peer_identity(&stream) {
                Ok(peer) => Some(IncomingConnection::unix(self.name.clone(), peer, stream)),
                Err(e) => {
                    tracing::warn!("listener {}: connection closed: cannot read its peer credentials: {e}", self.name);
                    None
                }
            },
            Accepted::Tcp(stream) => Some(IncomingConnection::tcp(self.name.clone(), stream, self.tls.clone())),
        }
    }
}

impl Socket {
    fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<io::Result<Accepted>> {
        match self {
            Self::Unix(listener) => listener.poll_accept(cx).map_ok(|(stream, _)| Accepted::Unix(stream)),
            Self::Tcp(listener) => listener.poll_accept(cx).map_ok(|(stream, _)| Accepted::Tcp(stream)),
        }
    }
}

/// Logs a failed accept, then pauses unless only that one connection was lost.
async fn pause(listener: &ListenerName, error: &io::Error) {
    match error.kind() {
        io::ErrorKind::ConnectionAborted | io::ErrorKind::ConnectionReset => {
            tracing::debug!("listener {listener}: a connection was abandoned before it was accepted: {error}");
        }
        _ => {
            tracing::warn!("listener {listener}: accept failed, pausing {ACCEPT_BACKOFF:?}: {error}");
            tokio::time::sleep(ACCEPT_BACKOFF).await;
        }
    }
}

/// The admin socket's path, which a request socket must never take.
fn admin_socket_path(paths: &ServicePaths) -> Result<PathBuf, OpenError> {
    paths
        .runtime_dir
        .as_deref()
        .map(|dir| dir.join(ADMIN_SOCKET_NAME))
        .ok_or(OpenError::NoRuntimeDir)
}

/// The listener's TLS acceptor, when its endpoint has TLS files.
fn load_tls(
    name: &ListenerName,
    endpoint: &Endpoint,
    read: impl Fn(AdminFile, &Path) -> Result<Zeroizing<Vec<u8>>, AdminFileError>,
) -> Result<Option<Arc<ListenerTls>>, OpenError> {
    match endpoint {
        Endpoint::Tcp { tls: Some(files), .. } => Ok(Some(Arc::new(ListenerTls::open_with(
            name,
            files,
            DEFAULT_HANDSHAKE_TIMEOUT,
            read,
        )?))),
        Endpoint::Tcp { tls: None, .. } | Endpoint::UnixSocket(_) => Ok(None),
    }
}

/// Registers a socket systemd passed with the runtime. Its file, for a Unix socket, stays systemd's.
fn register(name: &ListenerName, adopted: AdoptedSocket) -> Result<Socket, OpenError> {
    match adopted {
        AdoptedSocket::Tcp(listener) => listener
            .set_nonblocking(true)
            .and_then(|()| TcpListener::from_std(listener))
            .map(Socket::Tcp),
        AdoptedSocket::Unix(listener) => listener
            .set_nonblocking(true)
            .and_then(|()| UnixListener::from_std(listener))
            .map(Socket::Unix),
    }
    .map_err(registering(name))
}

/// Binds the listener's endpoint, where the deployment profile lets the service bind it.
fn bind(
    name: &ListenerName,
    endpoint: &Endpoint,
    paths: &ServicePaths,
    admin_socket: &Path,
) -> Result<(Socket, Option<SocketFile>), OpenError> {
    check_origin(paths.profile, name, endpoint, false)?;
    match endpoint {
        Endpoint::UnixSocket(path) => {
            let bound = RequestSocket::bind(path.as_path(), paths.owner, admin_socket).map_err(|source| OpenError::Unix {
                listener: name.clone(),
                source: Box::new(source),
            })?;
            let (listener, file) = bound.into_parts();
            let listener = UnixListener::from_std(listener).map_err(registering(name))?;
            Ok((Socket::Unix(listener), Some(file)))
        }
        Endpoint::Tcp { address, .. } => Ok((Socket::Tcp(bind_tcp(name, *address)?), None)),
    }
}

fn bind_tcp(name: &ListenerName, address: SocketAddr) -> Result<TcpListener, OpenError> {
    let listener = std::net::TcpListener::bind(address)
        .and_then(|listener| listener.set_nonblocking(true).map(|()| listener))
        .map_err(|e| OpenError::Tcp {
            listener: name.clone(),
            address,
            kind: e.kind(),
        })?;
    TcpListener::from_std(listener).map_err(registering(name))
}

fn registering(name: &ListenerName) -> impl FnOnce(io::Error) -> OpenError + '_ {
    move |e| OpenError::Register {
        listener: name.clone(),
        kind: e.kind(),
    }
}

#[cfg(test)]
mod tests;
