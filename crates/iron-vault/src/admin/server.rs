//! The admin server (`design/admin-protocol.md`, "Admin socket"): one exchange per connection, and nothing reaches a
//! handler unless the kernel reports the peer as an admin principal.
//!
//! Each connection is checked before a byte is read from it. Only [`peer_identity`]'s answer for the accepted stream is
//! ever judged, so no value the peer sends takes part in deciding who it is.

use std::future::Future;
use std::io;
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinSet;
use tokio::time::Instant;
use zeroize::{Zeroize, Zeroizing};

use super::dispatch::Handlers;
use super::principal::{AdminPrincipal, AdminPrincipals, peer_identity};
use super::protocol::{
    self, AdminRequest, AdminResponse, BundleChunk, Decoded, ErrorCode, Frame, FrameError, HEADER_LEN, MAX_BODY_LEN, Notice, OwnerInput,
    Prompt, PromptAnswer,
};
use super::socket::AdminSocket;
use crate::audit::AuditEvent;
use crate::audit::admin::{AdminCommandRead, AdminRefusal, AdminRefused};
use crate::library_error::{ErrorKindLabel, LibraryError};
use crate::logging::LogFailure;

/// How long the server pauses after a failed accept, such as running out of file descriptors, so the loop cannot spin.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// The server's bounds on time and connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// How long a peer has to send its whole admin request, and the server to write a prompt or its response. It is also
    /// how long each bundle data frame may take to be written or read.
    pub request_deadline: Duration,
    /// How long a whole migration bundle may take to cross the socket, in either direction: the
    /// [bundle transfer deadline](Exchange::send_bundle_chunk), which starts at the exchange's first bundle data frame.
    pub transfer_deadline: Duration,
    /// How long the server waits for owner input after sending a prompt: a person is typing, so it is longer than the
    /// request deadline.
    pub prompt_deadline: Duration,
    /// How many exchanges may be open at once; one more is answered `busy`.
    pub max_connections: usize,
    /// How long open exchanges may run on after shutdown begins before they are abandoned.
    pub shutdown_grace: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            request_deadline: Duration::from_secs(30),
            transfer_deadline: Duration::from_secs(10 * 60),
            prompt_deadline: Duration::from_secs(5 * 60),
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
    log_failure: LogFailure,
}

impl AdminServer {
    /// A server admitting `principals` and dispatching to `handlers`.
    pub fn new(principals: AdminPrincipals, handlers: Handlers, limits: Limits) -> Self {
        Self {
            principals,
            handlers: Arc::new(handlers),
            limits,
            log_failure: LogFailure::default(),
        }
    }

    /// Answers every command `wrong-state` once `log_failure` has tripped: the service never accepts a change it cannot
    /// record, and it is stopping.
    #[must_use]
    pub fn with_log_failure(mut self, log_failure: LogFailure) -> Self {
        self.log_failure = log_failure;
        self
    }

    /// Serves `socket` until `shutdown` completes. Then it stops accepting, gives open exchanges the shutdown grace to
    /// finish, abandons the rest and removes the socket file. The socket file is removed on an early error too.
    pub async fn serve(&self, socket: AdminSocket, shutdown: impl Future<Output = ()>) -> io::Result<()> {
        let (listener, file) = socket.into_parts();
        let listener = UnixListener::from_std(listener)?;
        let mut open = JoinSet::new();
        let mut shutdown = pin!(shutdown);
        loop {
            tokio::select! {
                () = &mut shutdown => break,
                accepted = listener.accept() => match accepted {
                    Ok((stream, _)) => self.admit(stream, &mut open),
                    Err(e) => {
                        tracing::warn!(error_kind = %e.kind_label(), "admin socket accept failed");
                        tokio::time::sleep(ACCEPT_BACKOFF).await;
                    }
                },
            }
        }
        drop(listener);
        self.drain(open).await;
        file.remove()
    }

    /// Serves one connection: the peer check, then one request, its handler and the response.
    pub async fn serve_connection(&self, mut stream: UnixStream) {
        let Some(principal) = self.check_peer(&mut stream).await else {
            return;
        };
        let mut exchange = Exchange::new(stream, self.limits);
        let response = match exchange.read_request().await {
            Ok(_) if self.log_failure.is_tripped() => {
                tracing::warn!("admin command refused: a log write failed");
                error(ErrorCode::WrongState, "the service is stopping because a log write failed")
            }
            Ok(request) => {
                let command = request.command().name();
                AdminCommandRead {
                    command: request.command(),
                    principal: principal.peer(),
                }
                .emit();
                match self.handlers.dispatch(principal, request, &mut exchange).await {
                    Ok(response) => response,
                    Err(cancelled) => {
                        tracing::warn!("admin command `{command}` cancelled: {cancelled}");
                        let Some(response) = cancelled.response() else {
                            return;
                        };
                        response
                    }
                }
            }
            Err(NoRequest::Unanswered) => return,
            Err(NoRequest::Answer { refusal, response }) => {
                AdminRefused {
                    refusal,
                    peer: Some(principal.peer()),
                }
                .emit();
                response
            }
        };
        exchange.respond(response).await;
    }

    /// Starts serving `stream`, or answers `busy` when the connection cap is reached.
    fn admit(&self, stream: UnixStream, open: &mut JoinSet<()>) {
        while open.try_join_next().is_some() {}
        if open.len() >= self.limits.max_connections {
            AdminRefused {
                refusal: AdminRefusal::Busy,
                peer: None,
            }
            .emit();
            let busy = error(ErrorCode::Busy, "the service is busy with other admin commands; try again");
            // A short frame fits the empty send buffer of a new connection, so it is written without waiting.
            let _ = stream.try_write(&encoded(&Frame::Response(busy)));
            return;
        }
        let server = self.clone();
        open.spawn(async move { server.serve_connection(stream).await });
    }

    /// Accepts the peer when the kernel reports an admin principal; otherwise answers `not-admin-principal`.
    async fn check_peer(&self, stream: &mut UnixStream) -> Option<AdminPrincipal> {
        let peer = match peer_identity(&*stream) {
            Ok(peer) => peer,
            Err(_) => {
                AdminRefused {
                    refusal: AdminRefusal::PeerUnreadable,
                    peer: None,
                }
                .emit();
                return None;
            }
        };
        match self.principals.accepts(peer) {
            Ok(principal) => Some(principal),
            Err(refused) => {
                AdminRefused {
                    refusal: AdminRefusal::NotAdminPrincipal,
                    peer: Some(peer),
                }
                .emit();
                let response = error(ErrorCode::NotAdminPrincipal, &refused.to_string());
                let _ = tokio::time::timeout(self.limits.request_deadline, write_and_close(stream, response)).await;
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
    limits: Limits,
    /// When the approver prompt under way times out: set by its first switchable prompt and kept across switches, so
    /// switching never stretches the approver prompt past one prompt deadline (`design/approval-signers.md`,
    /// "Switching"). Owner input ends the approver prompt and clears it.
    approver_deadline: Option<Instant>,
    /// When the bundle transfer times out: set by the exchange's first bundle data frame, sent or received, and kept for
    /// the rest of the exchange.
    transfer_deadline: Option<Instant>,
    /// Whether a frame write was cut off or failed part-way, so the peer may hold the front of a frame. Any later write
    /// would be read as the rest of that frame's body, so [`respond`](Self::respond) writes nothing and the connection
    /// just closes.
    frame_cut: bool,
}

/// Why a prompt got no owner input. The exchange is over: the handler returns the error, which cancels its command
/// before it changes anything. The messages never hold frame bodies, so none can carry owner input.
#[derive(Debug, thiserror::Error)]
pub enum ExchangeError {
    /// The CLI closed the connection instead of answering, or before the end of the bundle.
    #[error("the CLI closed the connection before sending what the exchange waited for")]
    Closed,
    /// No owner input arrived within the prompt deadline, or a prompt or bundle data frame could not be written or read
    /// within the request deadline.
    #[error("a frame did not move before its deadline")]
    TimedOut,
    /// The whole bundle was not written or read within the transfer deadline, though each frame so far met its own.
    #[error("the bundle transfer did not finish before the transfer deadline")]
    TransferTimedOut,
    /// The connection failed.
    #[error("the admin connection failed: {}", ErrorKindLabel::from(*.0))]
    Io(io::ErrorKind),
    /// The CLI answered with a frame that does not decode.
    #[error("the CLI sent a malformed frame: {0}")]
    Malformed(FrameError),
    /// The CLI answered with a well-formed frame other than the one the exchange waited for: owner input (a switch frame
    /// only when the prompt was switchable), or a bundle data frame.
    #[error("the CLI sent a frame other than the one the exchange waited for")]
    Unexpected,
    /// The handler asked to send a frame the codec refuses, such as an empty reveal: a bug in the handler. Nothing was
    /// sent.
    #[error("the service could not encode an admin frame: {0}")]
    Unencodable(FrameError),
    /// An earlier frame write was cut off part-way, so nothing more is written: the CLI would read it as the rest of that
    /// frame.
    #[error("an earlier frame write was cut off, so the exchange writes nothing more")]
    Cut,
}

impl ExchangeError {
    /// The error response a cancelled exchange ends with, or `None` when the CLI has gone or stopped answering and the
    /// connection is closed without one, as when no admin request arrives.
    fn response(&self) -> Option<AdminResponse> {
        match self {
            Self::Closed | Self::TimedOut | Self::TransferTimedOut | Self::Io(_) | Self::Unencodable(_) | Self::Cut => None,
            Self::Malformed(e) => Some(error(ErrorCode::for_frame_error(*e), &e.to_string())),
            Self::Unexpected => Some(error(ErrorCode::UnexpectedFrame, "the frame is out of turn in this exchange")),
        }
    }
}

/// Why no admin request was read.
enum NoRequest {
    /// The peer closed, timed out or failed; nothing is sent back.
    Unanswered,
    /// The peer sent something other than a valid admin request: refused for `refusal`, answered with `response`.
    Answer { refusal: AdminRefusal, response: AdminResponse },
}

/// Why a frame was not read.
enum ReadError {
    Closed,
    Io(io::Error),
    Frame(FrameError),
}

impl Exchange {
    pub(super) fn new(stream: UnixStream, limits: Limits) -> Self {
        Self {
            stream,
            buffer: Zeroizing::new(vec![0; HEADER_LEN + MAX_BODY_LEN]),
            limits,
            approver_deadline: None,
            transfer_deadline: None,
            frame_cut: false,
        }
    }

    /// Asks the owner for one value: sends `prompt` within the request deadline, then waits for the CLI's owner input
    /// within the prompt deadline. On an error the handler returns it, so its command is cancelled. The prompt is not
    /// switchable: a switch frame answering it is unexpected; a switchable prompt goes through
    /// [`prompt_or_switch_unless`](Self::prompt_or_switch_unless).
    pub async fn prompt(&mut self, prompt: &Prompt) -> Result<OwnerInput, ExchangeError> {
        self.send(&Frame::Prompt(prompt.clone())).await?;
        only_input(self.answer(false).await?)
    }

    /// [`prompt`](Self::prompt), unless `cancel` completes while the owner's input is awaited: then `None`. The prompt
    /// frame is always written whole and nothing more is read, so the exchange can still end with a response.
    pub async fn prompt_unless(&mut self, prompt: &Prompt, cancel: impl Future<Output = ()>) -> Result<Option<OwnerInput>, ExchangeError> {
        self.send(&Frame::Prompt(prompt.clone())).await?;
        self.answer_unless(false, cancel).await?.map(only_input).transpose()
    }

    /// Sends `prompt` and returns the CLI's answer: owner input, or, when `prompt` is switchable, a switch frame asking
    /// for the next approver (`design/approval-signers.md`, "Switching"). `None` when `cancel` completes first, as for
    /// [`prompt_unless`](Self::prompt_unless). One prompt deadline covers the whole approver prompt: it starts at the
    /// first switchable prompt, and a switch does not restart it, so a handler may loop on switches without bounding them.
    pub async fn prompt_or_switch_unless(
        &mut self,
        prompt: &Prompt,
        cancel: impl Future<Output = ()>,
    ) -> Result<Option<PromptAnswer>, ExchangeError> {
        self.send(&Frame::Prompt(prompt.clone())).await?;
        self.answer_unless(prompt.switchable, cancel).await
    }

    /// [`answer`](Self::answer), unless `cancel` completes first: then `None`, with the read buffer cleared.
    async fn answer_unless(&mut self, switchable: bool, cancel: impl Future<Output = ()>) -> Result<Option<PromptAnswer>, ExchangeError> {
        let answered = tokio::select! {
            biased;
            () = cancel => None,
            answer = self.answer(switchable) => Some(answer),
        };
        match answered {
            Some(answer) => answer.map(Some),
            None => {
                // The read it cut off may have left part of the owner's input in the buffer.
                self.buffer.as_mut_slice().zeroize();
                Ok(None)
            }
        }
    }

    /// The CLI's answer to the prompt just sent, within the prompt deadline: for a switchable prompt, the approver
    /// prompt's deadline. A switch frame is an answer only when the prompt was `switchable`.
    async fn answer(&mut self, switchable: bool) -> Result<PromptAnswer, ExchangeError> {
        let deadline = self.answer_deadline(switchable);
        match tokio::time::timeout_at(deadline, self.read_frame()).await {
            Ok(Ok(Frame::OwnerInput(input))) => {
                self.approver_deadline = None;
                Ok(PromptAnswer::OwnerInput(input))
            }
            Ok(Ok(Frame::Switch)) if switchable => Ok(PromptAnswer::Switch),
            Ok(Ok(_)) => Err(ExchangeError::Unexpected),
            Ok(Err(ReadError::Closed)) => Err(ExchangeError::Closed),
            Ok(Err(ReadError::Io(e))) => Err(ExchangeError::Io(e.kind())),
            Ok(Err(ReadError::Frame(e))) => Err(ExchangeError::Malformed(e)),
            Err(_) => Err(ExchangeError::TimedOut),
        }
    }

    /// When the answer to the prompt just sent times out: one prompt deadline from now, or for a switchable prompt the
    /// approver prompt's deadline, started now if this is its first prompt.
    fn answer_deadline(&mut self, switchable: bool) -> Instant {
        let fresh = Instant::now() + self.limits.prompt_deadline;
        if switchable {
            *self.approver_deadline.get_or_insert(fresh)
        } else {
            fresh
        }
    }

    /// Shows `text` to the owner, as many notices as it takes, each written within the request deadline. The text is
    /// never truncated. A failed write cancels the command, as a failed prompt does.
    pub async fn notice(&mut self, text: &str) -> Result<(), ExchangeError> {
        for notice in Notice::split(text) {
            self.send(&Frame::Notice(notice)).await?;
        }
        Ok(())
    }

    /// Shows `value`, a secret the service generated, to the owner once, in one reveal frame written within the request
    /// deadline. The frame is built in a clearing buffer sized for it up front, straight from `value`, and dropped as soon
    /// as it is written. A failed write cancels the command, as a failed prompt does.
    pub async fn reveal(&mut self, value: &[u8]) -> Result<(), ExchangeError> {
        let mut frame = Zeroizing::new(Vec::with_capacity(HEADER_LEN + value.len()));
        protocol::encode_reveal(value, &mut frame).map_err(ExchangeError::Unencodable)?;
        self.write(&frame).await
    }

    /// Sends one bundle data frame of up to [`MAX_BODY_LEN`] bytes of `bytes`; the empty slice ends the bundle. The write
    /// must finish within the request deadline and the bundle within the transfer deadline, which starts with the exchange's
    /// first bundle data frame, so a CLI that stalls or trickles cannot hold the service-wide lock past them. The error
    /// says which deadline passed.
    ///
    /// A deadline that has already passed when the frame is about to move gives [`ExchangeError::TransferTimedOut`] with
    /// nothing written, so the CLI holds only whole frames and the handler may still answer `export-failed`. A deadline that
    /// passes mid-write leaves part of a frame on the socket: the exchange then writes nothing more, its response included,
    /// and the connection closes, because the CLI would read a response as the rest of the frame.
    pub async fn send_bundle_chunk(&mut self, bytes: &[u8]) -> Result<(), ExchangeError> {
        let mut frame = Vec::with_capacity(HEADER_LEN + bytes.len());
        protocol::encode_bundle_data(bytes, &mut frame).map_err(ExchangeError::Unencodable)?;
        let (deadline, expired) = self.bundle_frame_deadline()?;
        self.write_until(&frame, deadline, expired).await
    }

    /// Reads the next bundle data frame, within the same two deadlines as [`send_bundle_chunk`](Self::send_bundle_chunk).
    /// The empty chunk ends the bundle. Any other kind of frame is [`Unexpected`](ExchangeError::Unexpected).
    pub async fn receive_bundle_chunk(&mut self) -> Result<BundleChunk, ExchangeError> {
        let (deadline, expired) = self.bundle_frame_deadline()?;
        match tokio::time::timeout_at(deadline, self.read_frame()).await {
            Ok(Ok(Frame::BundleData(chunk))) => Ok(chunk),
            Ok(Ok(_)) => Err(ExchangeError::Unexpected),
            Ok(Err(ReadError::Closed)) => Err(ExchangeError::Closed),
            Ok(Err(ReadError::Io(e))) => Err(ExchangeError::Io(e.kind())),
            Ok(Err(ReadError::Frame(e))) => Err(ExchangeError::Malformed(e)),
            Err(_) => Err(expired),
        }
    }

    /// When the bundle data frame about to move times out, and the error that expiry is: one request deadline from now, or
    /// the transfer deadline, started now if this is the exchange's first bundle frame, whichever comes first. A transfer
    /// deadline that has passed is an error here, before any byte moves: a timeout polls its future first, so a frame that
    /// could move at once would otherwise still succeed.
    fn bundle_frame_deadline(&mut self) -> Result<(Instant, ExchangeError), ExchangeError> {
        let now = Instant::now();
        let transfer = *self.transfer_deadline.get_or_insert(now + self.limits.transfer_deadline);
        if now >= transfer {
            return Err(ExchangeError::TransferTimedOut);
        }
        let frame = now + self.limits.request_deadline;
        Ok(if transfer <= frame {
            (transfer, ExchangeError::TransferTimedOut)
        } else {
            (frame, ExchangeError::TimedOut)
        })
    }

    /// Writes one frame the service sends within the request deadline.
    async fn send(&mut self, frame: &Frame) -> Result<(), ExchangeError> {
        self.write(&encoded(frame)).await
    }

    /// Writes an encoded frame within the request deadline.
    async fn write(&mut self, bytes: &[u8]) -> Result<(), ExchangeError> {
        let deadline = Instant::now() + self.limits.request_deadline;
        self.write_until(bytes, deadline, ExchangeError::TimedOut).await
    }

    /// Writes an encoded frame by `deadline`, which is `expired` if it passes. `frame_cut` is set before the write and
    /// cleared only once the whole frame is written, so a write that fails, is cut off, or whose future is dropped
    /// part-way leaves it set, and no later write follows it.
    async fn write_until(&mut self, bytes: &[u8], deadline: Instant, expired: ExchangeError) -> Result<(), ExchangeError> {
        if self.frame_cut {
            return Err(ExchangeError::Cut);
        }
        self.frame_cut = true;
        let written = tokio::time::timeout_at(deadline, self.stream.write_all(bytes)).await;
        match written {
            Ok(Ok(())) => {
                self.frame_cut = false;
                Ok(())
            }
            Ok(Err(e)) => Err(ExchangeError::Io(e.kind())),
            Err(_) => Err(expired),
        }
    }

    /// The exchange's first frame, which must be an admin request, read within the request deadline.
    async fn read_request(&mut self) -> Result<AdminRequest, NoRequest> {
        let read = tokio::time::timeout(self.limits.request_deadline, self.read_frame()).await;
        let unanswered = |reason: &str| {
            tracing::warn!("admin connection closed without a response: {reason}");
            NoRequest::Unanswered
        };
        match read {
            Ok(Ok(Frame::Request(request))) => Ok(request),
            Ok(Ok(_)) => Err(NoRequest::Answer {
                refusal: AdminRefusal::UnexpectedFrame,
                response: error(ErrorCode::UnexpectedFrame, "an exchange must start with an admin request"),
            }),
            Ok(Err(ReadError::Frame(e))) => Err(NoRequest::Answer {
                refusal: AdminRefusal::of_frame(e),
                response: error(ErrorCode::for_frame_error(e), &e.to_string()),
            }),
            Ok(Err(ReadError::Closed)) => Err(unanswered("the peer closed before sending a whole request")),
            Ok(Err(ReadError::Io(e))) => Err(unanswered(&format!("reading the request failed: {}", e.kind_label()))),
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
    /// error. After a frame write that was cut off it writes nothing and just closes, since the peer would read the
    /// response as the rest of that frame.
    async fn respond(&mut self, response: AdminResponse) {
        if self.frame_cut {
            tracing::warn!("the admin response was not sent: an earlier frame write was cut off, so the connection is closed");
            return;
        }
        let sent = tokio::time::timeout(self.limits.request_deadline, write_and_close(&mut self.stream, response)).await;
        if !matches!(sent, Ok(Ok(()))) {
            tracing::warn!("the admin response could not be delivered");
        }
    }
}

/// The owner input of an answer to a prompt that was not switchable, where a switch frame is out of turn.
fn only_input(answer: PromptAnswer) -> Result<OwnerInput, ExchangeError> {
    match answer {
        PromptAnswer::OwnerInput(input) => Ok(input),
        PromptAnswer::Switch => Err(ExchangeError::Unexpected),
    }
}

/// Writes `response` and shuts down the writing half, so the peer reads the end of the exchange.
async fn write_and_close(stream: &mut UnixStream, response: AdminResponse) -> io::Result<()> {
    stream.write_all(&encoded(&Frame::Response(response))).await?;
    stream.shutdown().await
}

/// The bytes of a frame the service sends: a prompt, a notice or a response. `caller-token`'s response holds the token,
/// so every frame is encoded into a clearing buffer; `encode` sizes it once, so no partial copy is left behind.
fn encoded(frame: &Frame) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::new());
    if let Err(e) = protocol::encode(frame, &mut out) {
        // Only an oversized label or message fails, and the service writes every one itself, so this is a bug; the
        // peer then sees the connection close.
        tracing::error!("cannot encode an admin frame: {e}");
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
