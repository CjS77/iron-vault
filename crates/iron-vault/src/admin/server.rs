//! The admin server (`design/admin-protocol.md`, "Admin socket"): one exchange per connection, and nothing reaches a
//! handler unless the kernel reports the peer as an admin principal.
//!
//! Each connection is checked before a byte is read from it. Only [`peer_identity`]'s answer for the accepted stream is
//! ever judged, so no value the peer sends takes part in deciding who it is.

use std::future::Future;
use std::io;
use std::path::Path;
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinSet;
use zeroize::{Zeroize, Zeroizing};

use super::dispatch::Handlers;
use super::principal::{AdminPrincipal, AdminPrincipals, peer_identity};
use super::protocol::{self, AdminRequest, AdminResponse, Decoded, ErrorCode, Frame, FrameError, HEADER_LEN, MAX_BODY_LEN};
use super::socket::AdminSocket;

/// How long the server pauses after a failed accept, such as running out of file descriptors, so the loop cannot spin.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// The server's bounds on time and connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// How long a peer has to send its whole admin request, and the server to write its response.
    pub request_deadline: Duration,
    /// How many exchanges may be open at once; one more is answered `busy`.
    pub max_connections: usize,
    /// How long open exchanges may run on after shutdown begins before they are abandoned.
    pub shutdown_grace: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            request_deadline: Duration::from_secs(30),
            max_connections: 4,
            shutdown_grace: Duration::from_secs(5),
        }
    }
}

/// Serves the admin protocol to admin principals.
#[derive(Clone)]
pub struct AdminServer {
    principals: AdminPrincipals,
    handlers: Arc<Handlers>,
    limits: Limits,
}

impl AdminServer {
    /// A server admitting `principals` and dispatching to `handlers`.
    pub fn new(principals: AdminPrincipals, handlers: Handlers, limits: Limits) -> Self {
        Self {
            principals,
            handlers: Arc::new(handlers),
            limits,
        }
    }

    /// Serves `socket` until `shutdown` completes. Then it stops accepting, gives open exchanges the shutdown grace to
    /// finish, abandons the rest and removes the socket file.
    pub async fn serve(&self, socket: AdminSocket, shutdown: impl Future<Output = ()>) -> io::Result<()> {
        let (listener, path) = socket.into_parts();
        let listener = UnixListener::from_std(listener)?;
        let mut open = JoinSet::new();
        let mut shutdown = pin!(shutdown);
        loop {
            tokio::select! {
                () = &mut shutdown => break,
                accepted = listener.accept() => match accepted {
                    Ok((stream, _)) => self.admit(stream, &mut open),
                    Err(e) => {
                        tracing::warn!("admin socket accept failed: {e}");
                        tokio::time::sleep(ACCEPT_BACKOFF).await;
                    }
                },
            }
        }
        drop(listener);
        self.drain(open).await;
        remove_socket_file(&path)
    }

    /// Serves one connection: the peer check, then one request, its handler and the response.
    pub async fn serve_connection(&self, stream: UnixStream) {
        let Some(principal) = self.check_peer(&stream).await else {
            return;
        };
        let mut exchange = Exchange::new(stream, self.limits.request_deadline);
        let response = match exchange.read_request().await {
            Ok(request) => {
                let (uid, command) = (principal.peer().uid(), request.command().name());
                tracing::info!("admin command `{command}` from uid {uid}");
                self.handlers.dispatch(principal, request, &mut exchange).await
            }
            Err(NoRequest::Unanswered) => return,
            Err(NoRequest::Answer(response)) => response,
        };
        exchange.respond(&response).await;
    }

    /// Starts serving `stream`, or answers `busy` when the connection cap is reached.
    fn admit(&self, stream: UnixStream, open: &mut JoinSet<()>) {
        while open.try_join_next().is_some() {}
        if open.len() >= self.limits.max_connections {
            tracing::warn!("admin connection refused: {} exchanges are already open", open.len());
            let busy = error(ErrorCode::Busy, "the service is busy with other admin commands; try again");
            // A short frame fits the empty send buffer of a new connection, so it is written without waiting.
            let _ = stream.try_write(&encoded(&busy));
            return;
        }
        let server = self.clone();
        open.spawn(async move { server.serve_connection(stream).await });
    }

    /// Accepts the peer when the kernel reports an admin principal; otherwise answers `not-admin-principal`.
    async fn check_peer(&self, stream: &UnixStream) -> Option<AdminPrincipal> {
        let peer = match peer_identity(stream) {
            Ok(peer) => peer,
            Err(e) => {
                tracing::warn!("admin connection closed: cannot read its peer credentials: {e}");
                return None;
            }
        };
        match self.principals.accepts(peer) {
            Ok(principal) => Some(principal),
            Err(refused) => {
                tracing::warn!(
                    "admin connection refused: uid {} (pid {}) is not an admin principal",
                    peer.uid(),
                    peer.pid()
                );
                let response = error(ErrorCode::NotAdminPrincipal, &refused.to_string());
                let _ = tokio::time::timeout(self.limits.request_deadline, write_and_close(stream, &response)).await;
                None
            }
        }
    }

    async fn drain(&self, mut open: JoinSet<()>) {
        let finished = tokio::time::timeout(self.limits.shutdown_grace, async { while open.join_next().await.is_some() {} }).await;
        if finished.is_err() {
            tracing::warn!("abandoning {} admin exchanges still open at shutdown", open.len());
            open.abort_all();
        }
    }
}

/// One open exchange on the admin socket. Handlers receive it so they can prompt the owner.
pub struct Exchange {
    stream: UnixStream,
    /// Frames are read here before decoding, so it holds owner input: it is sized once for the largest frame, never
    /// reallocated, cleared after each frame and on drop.
    buffer: Zeroizing<Vec<u8>>,
    deadline: Duration,
}

/// Why no admin request was read.
enum NoRequest {
    /// The peer closed, timed out or failed; nothing is sent back.
    Unanswered,
    /// The peer sent something other than a valid admin request, answered with this error.
    Answer(AdminResponse),
}

/// Why a frame was not read.
enum ReadError {
    Closed,
    Io(io::Error),
    Frame(FrameError),
}

impl Exchange {
    fn new(stream: UnixStream, deadline: Duration) -> Self {
        Self {
            stream,
            buffer: Zeroizing::new(vec![0; HEADER_LEN + MAX_BODY_LEN]),
            deadline,
        }
    }

    /// The exchange's first frame, which must be an admin request, read within the request deadline.
    async fn read_request(&mut self) -> Result<AdminRequest, NoRequest> {
        let read = tokio::time::timeout(self.deadline, self.read_frame()).await;
        let unanswered = |reason: &str| {
            tracing::warn!("admin connection closed without a response: {reason}");
            NoRequest::Unanswered
        };
        match read {
            Ok(Ok(Frame::Request(request))) => Ok(request),
            Ok(Ok(_)) => Err(NoRequest::Answer(error(
                ErrorCode::UnexpectedFrame,
                "an exchange must start with an admin request",
            ))),
            Ok(Err(ReadError::Frame(e))) => {
                tracing::warn!("admin request refused: {e}");
                Err(NoRequest::Answer(error(ErrorCode::for_frame_error(e), &e.to_string())))
            }
            Ok(Err(ReadError::Closed)) => Err(unanswered("the peer closed before sending a whole request")),
            Ok(Err(ReadError::Io(e))) => Err(unanswered(&format!("reading the request failed: {e}"))),
            Err(_) => Err(unanswered("no whole request arrived before the deadline")),
        }
    }

    /// Reads exactly one frame, asking the socket for no more bytes than the decoder needs, so nothing past the frame
    /// is consumed. The bytes read are cleared before returning.
    async fn read_frame(&mut self) -> Result<Frame, ReadError> {
        let mut filled = 0;
        let result = loop {
            let decoded = self.buffer.get(..filled).map(protocol::decode);
            let needed = match decoded {
                Some(Ok(Decoded::Frame { frame, .. })) => break Ok(frame),
                Some(Ok(Decoded::NeedMore(needed))) => needed,
                Some(Err(e)) => break Err(ReadError::Frame(e)),
                // Unreachable: `filled` never passes the buffer, which holds the largest frame.
                None => break Err(ReadError::Frame(FrameError::BodyTooLong)),
            };
            match self.read_into(filled, needed).await {
                Ok(0) => break Err(ReadError::Closed),
                Ok(read) => filled += read,
                Err(e) => break Err(ReadError::Io(e)),
            }
        };
        if let Some(read) = self.buffer.get_mut(..filled) {
            read.zeroize();
        }
        result
    }

    /// Reads up to `needed` bytes into the buffer at `filled`.
    async fn read_into(&mut self, filled: usize, needed: usize) -> io::Result<usize> {
        let window = filled
            .checked_add(needed)
            .and_then(|end| self.buffer.get_mut(filled..end))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "admin frame larger than the read buffer"))?;
        self.stream.read(window).await
    }

    /// Sends the exchange's admin response within the request deadline and closes; a peer that has gone is not an
    /// error.
    async fn respond(&self, response: &AdminResponse) {
        let sent = tokio::time::timeout(self.deadline, write_and_close(&self.stream, response)).await;
        if !matches!(sent, Ok(Ok(()))) {
            tracing::warn!("the admin response could not be delivered");
        }
    }
}

/// Writes `response` and shuts down the writing half, so the peer reads the end of the exchange.
async fn write_and_close(stream: &UnixStream, response: &AdminResponse) -> io::Result<()> {
    let bytes = encoded(response);
    let mut written = 0;
    while let Some(rest) = bytes.get(written..).filter(|rest| !rest.is_empty()) {
        stream.writable().await?;
        match stream.try_write(rest) {
            Ok(n) => written += n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }
    }
    rustix::net::shutdown(stream, rustix::net::Shutdown::Write).map_err(io::Error::from)
}

/// A response frame's bytes. Responses never hold owner input, so an ordinary buffer is enough.
fn encoded(response: &AdminResponse) -> Vec<u8> {
    let mut out = Vec::new();
    let frame = Frame::Response(response.clone());
    if let Err(e) = protocol::encode(&frame, &mut out) {
        // Only an oversized message fails, and the service writes every message itself, so this is a bug; the peer
        // then sees the connection close.
        tracing::error!("cannot encode an admin response: {e}");
        out.clear();
    }
    out
}

fn error(code: ErrorCode, message: &str) -> AdminResponse {
    AdminResponse::Error {
        code,
        message: message.to_owned(),
    }
}

/// Removes the socket file, so no client finds a dead socket at the path.
fn remove_socket_file(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}
