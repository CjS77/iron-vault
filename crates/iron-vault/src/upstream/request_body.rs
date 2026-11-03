//! The body of an upstream request: the caller's bytes, forwarded as they arrive (specification §3.5 step 9, §3.6, §9).
//!
//! The body is not part of a [`CheckedRequest`](iron_vault_policy::CheckedRequest). The final check never inspects it,
//! because no credential goes into a caller's body, and keeping it apart makes that visible.

use std::fmt;
use std::pin::Pin;

use bytes::Bytes;
use futures_core::Stream;

/// A request body stream failed before its end, for example because the caller disconnected or passed the body size
/// limit. It carries nothing, so it cannot show what the stream held.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the request body stream failed")]
pub struct BodyStreamError;

/// The chunks of a streamed body, which the client polls from whichever task drives the request.
type Chunks = Pin<Box<dyn Stream<Item = Result<Bytes, BodyStreamError>> + Send>>;

/// What [`UpstreamClient::send`](super::client::UpstreamClient::send) forwards as the request's body.
#[must_use]
pub struct RequestBody {
    pub(super) kind: Kind,
}

/// The two shapes a body takes.
pub(super) enum Kind {
    Empty,
    Stream { length: Option<u64>, chunks: Chunks },
}

impl RequestBody {
    /// No body: the request has no `Content-Length` or `Transfer-Encoding` unless the method makes reqwest add
    /// `Content-Length: 0`.
    pub fn empty() -> Self {
        Self { kind: Kind::Empty }
    }

    /// A body read from `chunks` as the upstream accepts it.
    ///
    /// `length` is the `Content-Length` the caller declared, if any. It is sent as `Content-Length` and the body is
    /// not chunked; with `None` the transport frames the body as chunked (HTTP/1.1) or by stream end (HTTP/2). The
    /// declared length is not checked here: a stream that ends short, or that yields an error, aborts the upstream
    /// request, so the upstream never sees a complete request with a short body.
    pub fn stream(length: Option<u64>, chunks: impl Stream<Item = Result<Bytes, BodyStreamError>> + Send + 'static) -> Self {
        Self {
            kind: Kind::Stream {
                length,
                chunks: Box::pin(chunks),
            },
        }
    }
}

impl fmt::Debug for RequestBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            Kind::Empty => f.write_str("RequestBody::Empty"),
            Kind::Stream { length, .. } => f
                .debug_struct("RequestBody::Stream")
                .field("length", length)
                .finish_non_exhaustive(),
        }
    }
}
