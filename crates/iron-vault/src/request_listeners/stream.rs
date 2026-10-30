//! An accepted connection and the stream it becomes once its TLS handshake, if any, has run.

use std::fmt;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use iron_vault_policy::ListenerName;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, UnixStream};
use tokio_rustls::server::TlsStream;

use crate::listener_tls::{HandshakeError, ListenerTls};
use crate::peer::PeerIdentity;

/// A connection accepted on a request listener, tagged by the transport with its listener name and, on a Unix socket,
/// the peer identity. These tags are the only inputs to caller identification besides the request headers; nothing
/// the client sends can set them.
#[derive(Debug)]
pub struct IncomingConnection {
    listener: ListenerName,
    peer: Option<PeerIdentity>,
    pending: Pending,
}

/// The accepted stream, before any TLS handshake.
#[derive(Debug)]
enum Pending {
    Unix(UnixStream),
    Tcp(TcpStream),
    Tls(TcpStream, Arc<ListenerTls>),
}

/// A request connection ready to carry HTTP: a Unix or plain TCP stream, or a TLS stream whose handshake completed.
pub enum RequestStream {
    /// A connection on a Unix request socket.
    Unix(UnixStream),
    /// A connection on a loopback TCP listener without TLS.
    Tcp(TcpStream),
    /// A connection on a TLS listener, boxed because the TLS state is far larger than a socket.
    Tls(Box<TlsStream<TcpStream>>),
}

impl IncomingConnection {
    /// A connection on a Unix listener, with the peer identity the kernel reported.
    pub(super) fn unix(listener: ListenerName, peer: PeerIdentity, stream: UnixStream) -> Self {
        Self {
            listener,
            peer: Some(peer),
            pending: Pending::Unix(stream),
        }
    }

    /// A connection on a TCP listener, which reports no peer, with the listener's TLS acceptor if it has one.
    pub(super) fn tcp(listener: ListenerName, stream: TcpStream, tls: Option<Arc<ListenerTls>>) -> Self {
        let pending = match tls {
            Some(tls) => Pending::Tls(stream, tls),
            None => Pending::Tcp(stream),
        };
        Self {
            listener,
            peer: None,
            pending,
        }
    }

    /// The listener the connection arrived on.
    pub fn listener(&self) -> &ListenerName {
        &self.listener
    }

    /// The peer identity the kernel reported for a Unix connection; `None` on TCP, which reports no account.
    pub fn peer(&self) -> Option<PeerIdentity> {
        self.peer
    }

    /// Runs the TLS handshake on a TLS listener's connection, within its handshake timeout; other connections are
    /// ready as they are. Await it in the connection's own task, never in the accept loop.
    pub async fn establish(self) -> Result<RequestStream, HandshakeError> {
        match self.pending {
            Pending::Unix(stream) => Ok(RequestStream::Unix(stream)),
            Pending::Tcp(stream) => Ok(RequestStream::Tcp(stream)),
            Pending::Tls(stream, tls) => tls.accept(stream).await.map(|stream| RequestStream::Tls(Box::new(stream))),
        }
    }
}

/// The byte stream under any request connection.
trait Io: AsyncRead + AsyncWrite + Unpin {}

impl<T: AsyncRead + AsyncWrite + Unpin> Io for T {}

impl RequestStream {
    fn io(self: Pin<&mut Self>) -> Pin<&mut dyn Io> {
        match self.get_mut() {
            Self::Unix(stream) => Pin::new(stream),
            Self::Tcp(stream) => Pin::new(stream),
            Self::Tls(stream) => Pin::new(stream.as_mut()),
        }
    }
}

impl AsyncRead for RequestStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.io().poll_read(cx, buf)
    }
}

impl AsyncWrite for RequestStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.io().poll_write(cx, buf)
    }

    fn poll_write_vectored(self: Pin<&mut Self>, cx: &mut Context<'_>, bufs: &[IoSlice<'_>]) -> Poll<io::Result<usize>> {
        self.io().poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Unix(stream) => stream.is_write_vectored(),
            Self::Tcp(stream) => stream.is_write_vectored(),
            Self::Tls(stream) => stream.is_write_vectored(),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.io().poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.io().poll_shutdown(cx)
    }
}

// The TLS session holds traffic keys, so only the transport is shown.
impl fmt::Debug for RequestStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let transport = match self {
            Self::Unix(_) => "Unix",
            Self::Tcp(_) => "Tcp",
            Self::Tls(_) => "Tls",
        };
        f.debug_tuple("RequestStream").field(&transport).finish()
    }
}
