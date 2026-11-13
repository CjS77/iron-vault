// SPDX-License-Identifier: MPL-2.0
//! The request listeners ([spec §7][s7], [§8][s8]): every configured listener open at once, each accepted connection tagged
//! by the transport with the listener it arrived on and, on a Unix socket, the peer identity the kernel reports.
//!
//! Caller identification takes the listener name and the peer uid from here and never from the request, so an
//! [`IncomingConnection`]'s tags are its only inputs besides the request headers.
//!
//! The listeners go through four steps, in this order:
//!
//! ```text
//! when                               call                          what it does
//! ---------------------------------  ----------------------------  ---------------------------------------------------------
//! startup, before any thread         PassedSockets::take           takes the fds systemd passed; listenfd edits the environment
//! startup, inside the runtime        RequestListeners::open_each   the provisional set, from the unverified config
//! entry to Ready                     RequestListeners::rebuild     the verified set: unchanged listeners kept, the rest reopened
//! every connection                   RequestListeners::accept      tags the stream with its listener and peer
//! ```
//!
//! [`PassedSockets::take`] runs before the async runtime exists because `listenfd` edits the environment as it takes
//! the fds. [`RequestListeners::open_each`] and [`RequestListeners::rebuild`] run inside the runtime, because they
//! register each socket with the runtime's reactor. [`RequestServer::serve`](crate::request_server::RequestServer::serve)
//! runs the accept loop on [`RequestListeners::accept`].
//!
//! [s7]: ../../../design/iron-vault-specification.md#7-caller-authentication-and-listeners
//! [s8]: ../../../design/iron-vault-specification.md#8-request-flow

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsFd, BorrowedFd};
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
use crate::library_error::LibraryError;
use crate::listener_tls::{DEFAULT_HANDSHAKE_TIMEOUT, ListenerTls, ListenerTlsError};
use crate::peer::peer_identity;
use crate::request_socket::{RequestBindError, RequestSocket, SocketFile};
use crate::socket_activation::{AdoptError, AdoptedSocket, NotActivated, PassedSockets, check_origin, verify};
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
    /// The configuration it was opened for, which a rebuild compares with the verified one.
    config: ListenerConfig,
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

/// What a listener rebuild left open.
#[derive(Debug)]
pub struct Rebuilt {
    /// The rebuilt set.
    pub listeners: RequestListeners,
    /// The listeners kept open through the rebuild, whose connections may stay open with them.
    pub kept: BTreeSet<ListenerName>,
    /// The verified listeners that could not be opened.
    pub failures: Vec<OpenError>,
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
    /// A plain-HTTP TCP listener is off loopback, so caller tokens would cross the network in clear text. A verified
    /// config never has one; an unverified published config can.
    #[error("listener {listener} on {address} is plain HTTP off loopback and was not opened")]
    PlainOffLoopback {
        /// The listener.
        listener: ListenerName,
        /// Its address.
        address: SocketAddr,
    },
    /// A TLS listener's certificate and key did not load; the error names the listener.
    #[error(transparent)]
    Tls(#[from] ListenerTlsError),
    /// A socket systemd passed, or one kept through a rebuild, does not pass the checks an adopted socket must.
    #[error(transparent)]
    Adopt(#[from] AdoptError),
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
    /// Opens every listener in `listeners`, in name order: the socket systemd passed for it in `passed` if there is
    /// one, adopted once it passes its checks, otherwise one the service binds, which in a protected install only a
    /// Unix listener may be. A listener with TLS files loads them first.
    ///
    /// All or nothing: when one listener fails, those already open are closed and their socket files removed before
    /// the error returns. A socket in `passed` that no listener adopts is closed.
    ///
    /// Call it inside the async runtime, after [`PassedSockets::take`] has run outside it.
    pub fn open(
        listeners: &BTreeMap<ListenerName, ListenerConfig>,
        paths: &ServicePaths,
        passed: PassedSockets,
    ) -> Result<Self, OpenError> {
        Self::open_with(listeners, paths, passed, |file, path| {
            admin_file::read(file, paths.profile, paths.owner, path)
        })
    }

    /// Opens the listeners as [`open`](Self::open) does, with the TLS file reader passed in, so tests can supply
    /// certificates without trusted paths on disk.
    pub(crate) fn open_with(
        listeners: &BTreeMap<ListenerName, ListenerConfig>,
        paths: &ServicePaths,
        mut passed: PassedSockets,
        read: impl Fn(AdminFile, &Path) -> Result<Zeroizing<Vec<u8>>, AdminFileError>,
    ) -> Result<Self, OpenError> {
        let admin_socket = prerequisites(paths)?;
        let open = listeners
            .iter()
            .map(|(name, config)| open_one(name, config, paths, &admin_socket, &mut passed, &read))
            .collect::<Result<_, OpenError>>()?;
        Ok(Self::of(open))
    }

    /// Opens each listener in `listeners` on its own, as [`open`](Self::open) does: one that fails is left out and its
    /// error returned, and the others open. For the provisional set, where a listener the unverified config names
    /// wrongly must not keep the rest from answering `503`. The sockets in `passed` that no listener adopts stay there.
    pub fn open_each(
        listeners: &BTreeMap<ListenerName, ListenerConfig>,
        paths: &ServicePaths,
        passed: &mut PassedSockets,
    ) -> (Self, Vec<OpenError>) {
        let read = |file, path: &Path| admin_file::read(file, paths.profile, paths.owner, path);
        let results = match prerequisites(paths) {
            Ok(admin_socket) => listeners
                .iter()
                .map(|(name, config)| open_one(name, config, paths, &admin_socket, passed, read))
                .collect(),
            Err(error) => vec![Err(error)],
        };
        Self::partition(results)
    }

    /// Rebuilds the set as the verified `listeners` name it (the listener rebuild on entry to Ready).
    ///
    /// An open listener is kept only when `listeners` names it with exactly the configuration it was opened for: the
    /// same endpoint, TLS files and token header. Its socket is then checked again as an adopted socket is, and its TLS
    /// files read again through their trusted-path rules, so it holds no certificate or key the unverified config
    /// chose. Every other open listener is closed, its socket file removed, before anything is bound, so a changed
    /// listener can take its old path. Each verified listener not kept is then adopted from `passed`, or else bound.
    /// One that fails is left out and its error returned.
    pub fn rebuild(self, listeners: &BTreeMap<ListenerName, ListenerConfig>, paths: &ServicePaths, passed: &mut PassedSockets) -> Rebuilt {
        let read = |file, path: &Path| admin_file::read(file, paths.profile, paths.owner, path);
        let (kept, closed): (Vec<_>, Vec<_>) = self
            .open
            .into_iter()
            .partition(|open| listeners.get(&open.name) == Some(&open.config));
        drop(closed);
        let mut kept: BTreeMap<_, _> = kept.into_iter().map(|open| (open.name.clone(), open)).collect();
        let results: Vec<_> = match prerequisites(paths) {
            Ok(admin_socket) => listeners
                .iter()
                .map(|(name, config)| match kept.remove(name) {
                    Some(open) => (true, open.recheck(paths, read)),
                    None => (false, open_one(name, config, paths, &admin_socket, passed, read)),
                })
                .collect(),
            Err(error) => vec![(false, Err(error))],
        };
        let kept = results
            .iter()
            .filter_map(|(kept, result)| result.as_ref().ok().filter(|_| *kept))
            .map(|open| open.name.clone())
            .collect();
        let (listeners, failures) = Self::partition(results.into_iter().map(|(_, result)| result).collect());
        Rebuilt { listeners, kept, failures }
    }

    /// Returns a set with no listeners, which never accepts.
    pub fn empty() -> Self {
        Self::of(Vec::new())
    }

    /// The name of each open listener, in name order.
    pub fn names(&self) -> impl Iterator<Item = &ListenerName> {
        self.open.iter().map(|open| &open.name)
    }

    fn of(open: Vec<OpenListener>) -> Self {
        Self {
            open,
            next: AtomicUsize::new(0),
        }
    }

    fn partition(results: Vec<Result<OpenListener, OpenError>>) -> (Self, Vec<OpenError>) {
        let (open, failed): (Vec<_>, Vec<_>) = results.into_iter().partition(Result::is_ok);
        (
            Self::of(open.into_iter().flatten().collect()),
            failed.into_iter().filter_map(Result::err).collect(),
        )
    }

    /// Waits for the next connection on any listener and returns it tagged with its listener and, on a Unix socket, its
    /// peer identity. Its TLS handshake has not run: [`IncomingConnection::establish`] runs it in the connection's own
    /// task, so a slow client cannot hold up accepting.
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

    /// Polls for the first listener with a connection, starting from a different one each time.
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
    /// Checks this listener's socket and TLS files again, for a listener kept through a rebuild.
    fn recheck(
        mut self,
        paths: &ServicePaths,
        read: impl Fn(AdminFile, &Path) -> Result<Zeroizing<Vec<u8>>, AdminFileError>,
    ) -> Result<Self, OpenError> {
        verify(&self.name, self.socket.as_fd(), self.config.endpoint(), paths.owner)?;
        self.tls = load_tls(&self.name, self.config.endpoint(), read)?;
        Ok(self)
    }

    /// Tags an accepted stream with this listener and its peer, or closes it when its peer credentials are unreadable.
    fn tag(&self, accepted: Accepted) -> Option<IncomingConnection> {
        match accepted {
            Accepted::Unix(stream) => match peer_identity(&stream) {
                Ok(peer) => Some(IncomingConnection::unix(self.name.clone(), peer, stream)),
                Err(e) => {
                    let listener = &self.name;
                    tracing::warn!(
                        error_kind = %e.kind_label(),
                        "listener {listener}: connection closed: cannot read its peer credentials"
                    );
                    None
                }
            },
            Accepted::Tcp(stream) => Some(IncomingConnection::tcp(self.name.clone(), stream, self.tls.clone())),
        }
    }
}

impl AsFd for Socket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        match self {
            Self::Unix(listener) => listener.as_fd(),
            Self::Tcp(listener) => listener.as_fd(),
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
            tracing::debug!(error_kind = %error.kind_label(), "listener {listener}: a connection was abandoned before it was accepted");
        }
        _ => {
            tracing::warn!(error_kind = %error.kind_label(), "listener {listener}: accept failed, pausing {ACCEPT_BACKOFF:?}");
            tokio::time::sleep(ACCEPT_BACKOFF).await;
        }
    }
}

/// Opens one listener: the socket systemd passed for it in `passed` if there is one and it passes its checks, otherwise
/// one the service binds. Every listener is opened here, so the plain-HTTP-off-loopback rule is enforced here for the
/// unverified provisional set as well as for verified configs. Its TLS files load first.
fn open_one(
    name: &ListenerName,
    config: &ListenerConfig,
    paths: &ServicePaths,
    admin_socket: &Path,
    passed: &mut PassedSockets,
    read: impl Fn(AdminFile, &Path) -> Result<Zeroizing<Vec<u8>>, AdminFileError>,
) -> Result<OpenListener, OpenError> {
    if let Some(address) = config.plain_off_loopback() {
        return Err(OpenError::PlainOffLoopback {
            listener: name.clone(),
            address,
        });
    }
    let tls = load_tls(name, config.endpoint(), read)?;
    let (socket, file) = match passed.adopt(name, config.endpoint(), paths.owner) {
        Some(adopted) => (register(name, adopted?)?, None),
        None => bind(name, config.endpoint(), paths, admin_socket)?,
    };
    Ok(OpenListener {
        name: name.clone(),
        config: config.clone(),
        socket,
        tls,
        _file: file,
    })
}

/// What opening any listener needs: a runtime to register with, and the admin socket's path.
fn prerequisites(paths: &ServicePaths) -> Result<PathBuf, OpenError> {
    tokio::runtime::Handle::try_current().map_err(|_| OpenError::NoRuntime)?;
    admin_socket_path(paths)
}

/// The admin socket's path, which a request socket must never take.
fn admin_socket_path(paths: &ServicePaths) -> Result<PathBuf, OpenError> {
    paths
        .runtime_dir
        .as_deref()
        .map(|dir| dir.join(ADMIN_SOCKET_NAME))
        .ok_or(OpenError::NoRuntimeDir)
}

/// Loads the listener's TLS acceptor, or returns `None` when its endpoint has no TLS files.
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

// The request server's tests reuse its listener setup.
#[cfg(test)]
pub(crate) mod tests;
