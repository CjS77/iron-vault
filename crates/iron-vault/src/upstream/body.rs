//! The body of an upstream request: the caller's bytes, forwarded as they arrive ([spec §8][s8] step 9, [§9][s9],
//! [implementation spec §3][i3]).
//!
//! The body is not part of a [`CheckedRequest`](iron_vault_policy::CheckedRequest). The final check never inspects it,
//! because no credential goes into a caller's body, and keeping it apart makes that visible.
//!
//! [s8]: ../../../../design/iron-vault-specification.md#8-request-flow
//! [s9]: ../../../../design/iron-vault-specification.md#9-url-header-and-slot-rules
//! [i3]: ../../../../design/implementation-specification.md#3-implementation-gates-and-unresolved-details

use std::cmp::Ordering;
use std::fmt;
use std::future::poll_fn;
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
    /// Creates an absent body: the request carries no body framing of its own, neither a `Content-Length` nor a
    /// `Transfer-Encoding`.
    pub fn empty() -> Self {
        Self { kind: Kind::Empty }
    }

    /// Creates a body read from `chunks` as the upstream accepts it.
    ///
    /// `length` is the `Content-Length` the caller declared, if any. It is sent as `Content-Length` and the body is
    /// not chunked; with `None` the transport frames the body as chunked (HTTP/1.1) or by stream end (HTTP/2).
    ///
    /// A declared length is enforced here, because the transport cannot be left to do it. hyper's HTTP/1.1 client stops
    /// polling a body once it has written `Content-Length` bytes (and never polls it for length 0), so a longer stream
    /// would reach the upstream as a complete request with a truncated body; its HTTP/2 client never compares the
    /// count with the declaration. The stream therefore holds back the chunk that brings the total to the declared
    /// length until the source has proved it ends there: the transport gets the last byte only after that, and a source
    /// that goes on, or fails, yields [`UpstreamBodyError`] with that chunk never sent. A stream that ends short fails
    /// the same way. A zero length has no chunk to hold, so [`UpstreamClient::send`](super::client::UpstreamClient::send)
    /// settles it by draining the stream before sending anything. A stream that yields an error aborts the request too,
    /// so the upstream never sees a complete request with a wrong body.
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
/// reaching the transport. The chunk that completes the count is held until the source ends; only one is ever held.
struct Counted {
    inner: Chunks,
    declared: u64,
    seen: u64,
    held: Option<Bytes>,
    finished: bool,
}

impl Counted {
    fn new(inner: Chunks, declared: u64) -> Self {
        Self {
            inner,
            declared,
            seen: 0,
            held: None,
            finished: false,
        }
    }

    /// Ends the stream with `error`, dropping any held chunk: nothing is polled after one, so a transport that polls
    /// again cannot see more chunks.
    fn fail(&mut self, error: UpstreamBodyError) -> Poll<Option<Result<Bytes, UpstreamBodyError>>> {
        self.held = None;
        self.finished = true;
        Poll::Ready(Some(Err(error)))
    }

    /// Counts a non-empty `chunk`: it is passed on while the total stays short of the declared length, held when it
    /// reaches it, and a failure when it passes it. `None` means keep polling.
    fn count(&mut self, chunk: Bytes) -> Option<Poll<Option<Result<Bytes, UpstreamBodyError>>>> {
        self.seen = self.seen.saturating_add(chunk.len() as u64);
        match self.seen.cmp(&self.declared) {
            Ordering::Less => Some(Poll::Ready(Some(Ok(chunk)))),
            Ordering::Equal => {
                self.held = Some(chunk);
                None
            }
            Ordering::Greater => Some(self.fail(UpstreamBodyError)),
        }
    }

    /// Handles the end of the source: a short count fails; otherwise the held chunk, if any, is released and the stream
    /// then ends.
    fn end(&mut self) -> Poll<Option<Result<Bytes, UpstreamBodyError>>> {
        if self.seen < self.declared {
            return self.fail(UpstreamBodyError);
        }
        self.finished = true;
        Poll::Ready(self.held.take().map(Ok))
    }
}

impl Stream for Counted {
    type Item = Result<Bytes, UpstreamBodyError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            if self.finished {
                return Poll::Ready(None);
            }
            match self.inner.as_mut().poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(chunk))) if chunk.is_empty() => {}
                Poll::Ready(Some(Ok(chunk))) => {
                    if let Some(ready) = self.count(chunk) {
                        return ready;
                    }
                }
                Poll::Ready(Some(Err(error))) => return self.fail(error),
                Poll::Ready(None) => return self.end(),
            }
        }
    }
}

/// Reads a zero-length body to its end, which only empty chunks may precede. hyper's HTTP/1.1 client never polls a body
/// whose `Content-Length` is 0, so this is the only place a source that goes on or fails is caught.
pub(super) async fn settle_empty(mut chunks: Chunks) -> Result<(), UpstreamBodyError> {
    loop {
        match poll_fn(|cx| chunks.as_mut().poll_next(cx)).await {
            None => return Ok(()),
            Some(Ok(chunk)) if chunk.is_empty() => {}
            Some(Ok(_)) => return Err(UpstreamBodyError),
            Some(Err(error)) => return Err(error),
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
    use super::*;
    use std::collections::VecDeque;

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
    async fn the_chunk_that_completes_the_length_is_not_passed_on_when_the_source_goes_on() {
        let out = drain(5, &["abcde", "fg"]).await;
        assert_eq!(out, vec![Err(UpstreamBodyError)]);
    }

    #[tokio::test]
    async fn the_chunk_that_completes_the_length_is_released_when_only_empty_chunks_follow() {
        let out = drain(5, &["abcde", ""]).await;
        assert_eq!(out, vec![Ok(Bytes::from_static(b"abcde"))]);
    }

    #[tokio::test]
    async fn a_failing_source_drops_the_held_chunk() {
        let items = VecDeque::from([Ok(Bytes::from_static(b"abcde")), Err(UpstreamBodyError)]);
        let mut counted = Box::pin(Counted::new(Box::pin(Items(items)), 5));
        assert_eq!(poll_fn(|cx| counted.as_mut().poll_next(cx)).await, Some(Err(UpstreamBodyError)));
        assert!(poll_fn(|cx| counted.as_mut().poll_next(cx)).await.is_none());
    }

    #[tokio::test]
    async fn any_data_in_a_stream_of_declared_length_zero_fails() {
        let out = drain(0, &["x"]).await;
        assert_eq!(out, vec![Err(UpstreamBodyError)]);
    }

    #[tokio::test]
    async fn an_empty_stream_of_declared_length_zero_passes() {
        assert!(drain(0, &[]).await.is_empty());
    }
}
