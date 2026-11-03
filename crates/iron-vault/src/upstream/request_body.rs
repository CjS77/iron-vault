//! The body of an upstream request: the caller's bytes, forwarded as they arrive (specification §3.5 step 9, §3.6, §9).
//!
//! The body is not part of a [`CheckedRequest`](iron_vault_policy::CheckedRequest). The final check never inspects it,
//! because no credential goes into a caller's body, and keeping it apart makes that visible.

use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_core::Stream;

/// An upstream body stream failed before its end, for example because the caller disconnected or passed the body size
/// limit. It carries nothing, so it cannot show what the stream held.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the upstream body stream failed")]
pub struct UpstreamBodyError;

/// The chunks of a streamed body, which the client polls from whichever task drives the request.
type Chunks = Pin<Box<dyn Stream<Item = Result<Bytes, UpstreamBodyError>> + Send>>;

/// What [`UpstreamClient::send`](super::client::UpstreamClient::send) forwards as the request's body.
#[must_use]
pub struct UpstreamBody {
    pub(super) kind: Kind,
}

/// The two shapes a body takes.
pub(super) enum Kind {
    Empty,
    Stream { length: Option<u64>, chunks: Chunks },
}

impl UpstreamBody {
    /// No body: the request carries no body framing of its own, neither a `Content-Length` nor a `Transfer-Encoding`.
    pub fn empty() -> Self {
        Self { kind: Kind::Empty }
    }

    /// A body read from `chunks` as the upstream accepts it.
    ///
    /// `length` is the `Content-Length` the caller declared, if any. It is sent as `Content-Length` and the body is
    /// not chunked; with `None` the transport frames the body as chunked (HTTP/1.1) or by stream end (HTTP/2).
    ///
    /// A declared length is enforced here: a stream that ends short of it, or whose chunk would take the total past it,
    /// yields [`UpstreamBodyError`] and aborts the upstream request. The transport cannot be left to do this: hyper's
    /// HTTP/1.1 encoder silently cuts a longer stream off at `Content-Length`, which would give the upstream a complete
    /// request with a truncated body, and its HTTP/2 client never compares the count with the declaration. A stream
    /// that yields an error aborts the request too, so the upstream never sees a complete request with a wrong body.
    pub fn stream(length: Option<u64>, chunks: impl Stream<Item = Result<Bytes, UpstreamBodyError>> + Send + 'static) -> Self {
        let chunks: Chunks = match length {
            Some(declared) => Box::pin(Counted::new(Box::pin(chunks), declared)),
            None => Box::pin(chunks),
        };
        Self {
            kind: Kind::Stream { length, chunks },
        }
    }
}

/// Passes chunks through while counting them against the declared length, so a body of any other length fails instead of
/// reaching the transport.
struct Counted {
    inner: Chunks,
    declared: u64,
    seen: u64,
    finished: bool,
}

impl Counted {
    fn new(inner: Chunks, declared: u64) -> Self {
        Self {
            inner,
            declared,
            seen: 0,
            finished: false,
        }
    }

    /// Ends the stream with an error: nothing is polled after one, so a transport that retries cannot see more chunks.
    fn fail(&mut self) -> Poll<Option<Result<Bytes, UpstreamBodyError>>> {
        self.finished = true;
        Poll::Ready(Some(Err(UpstreamBodyError)))
    }
}

impl Stream for Counted {
    type Item = Result<Bytes, UpstreamBodyError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.finished {
            return Poll::Ready(None);
        }
        match self.inner.as_mut().poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Ok(chunk))) => {
                self.seen = self.seen.saturating_add(chunk.len() as u64);
                if self.seen > self.declared {
                    self.fail()
                } else {
                    Poll::Ready(Some(Ok(chunk)))
                }
            }
            Poll::Ready(Some(Err(error))) => {
                self.finished = true;
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) if self.seen < self.declared => self.fail(),
            Poll::Ready(None) => {
                self.finished = true;
                Poll::Ready(None)
            }
        }
    }
}

impl fmt::Debug for UpstreamBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            Kind::Empty => f.write_str("UpstreamBody::Empty"),
            Kind::Stream { length, .. } => f
                .debug_struct("UpstreamBody::Stream")
                .field("length", length)
                .finish_non_exhaustive(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::future::poll_fn;

    use super::*;

    struct Items(VecDeque<Result<Bytes, UpstreamBodyError>>);

    impl Stream for Items {
        type Item = Result<Bytes, UpstreamBodyError>;

        fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Ready(self.0.pop_front())
        }
    }

    /// Every item `Counted` yields over `chunks` with `declared`, polling past the end to see that it stays ended.
    async fn drain(declared: u64, chunks: &[&'static str]) -> Vec<Result<Bytes, UpstreamBodyError>> {
        let items = chunks.iter().map(|chunk| Ok(Bytes::from_static(chunk.as_bytes()))).collect();
        let mut counted = Box::pin(Counted::new(Box::pin(Items(items)), declared));
        let mut out = Vec::new();
        while let Some(item) = poll_fn(|cx| counted.as_mut().poll_next(cx)).await {
            out.push(item);
        }
        assert!(poll_fn(|cx| counted.as_mut().poll_next(cx)).await.is_none());
        out
    }

    #[tokio::test]
    async fn a_stream_of_exactly_the_declared_length_passes_unchanged() {
        let out = drain(5, &["ab", "cde"]).await;
        assert_eq!(out, vec![Ok(Bytes::from_static(b"ab")), Ok(Bytes::from_static(b"cde"))]);
    }

    #[tokio::test]
    async fn a_stream_that_ends_short_fails_at_its_end() {
        let out = drain(5, &["ab"]).await;
        assert_eq!(out, vec![Ok(Bytes::from_static(b"ab")), Err(UpstreamBodyError)]);
    }

    #[tokio::test]
    async fn a_chunk_past_the_declared_length_fails_and_is_not_passed_on() {
        let out = drain(5, &["abc", "def", "g"]).await;
        assert_eq!(out, vec![Ok(Bytes::from_static(b"abc")), Err(UpstreamBodyError)]);
    }

    #[tokio::test]
    async fn an_empty_stream_of_declared_length_zero_passes() {
        assert!(drain(0, &[]).await.is_empty());
    }
}
