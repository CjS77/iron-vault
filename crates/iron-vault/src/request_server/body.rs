//! The request body counted against the body limit, and the response body cut off at the request deadline.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use hyper::body::{Body, Frame, Incoming, SizeHint};
use tokio::sync::Notify;
use tokio::time::{Instant, Sleep};

use super::{BoxError, ResponseBody};

/// Why reading a request body failed.
#[derive(Debug, thiserror::Error)]
pub enum RequestBodyError {
    /// The body passed `max_request_body_bytes`; the server answers `413` if no response has started.
    #[error("the request body is larger than {limit} bytes")]
    TooLarge {
        /// The body limit, in bytes.
        limit: u64,
    },
    /// The connection failed while the body was being read.
    #[error("cannot read the request body: {0}")]
    Read(#[from] hyper::Error),
}

/// Whether a request's body has passed the body limit, set by its [`RequestBody`] and awaited by the server.
#[derive(Debug, Default)]
pub(super) struct Overflow {
    tripped: AtomicBool,
    notify: Notify,
}

impl Overflow {
    fn trip(&self) {
        self.tripped.store(true, Ordering::Release);
        self.notify.notify_one();
    }

    pub(super) fn is_tripped(&self) -> bool {
        self.tripped.load(Ordering::Acquire)
    }

    /// Completes once the body passes the limit. `notify_one` keeps its permit for a waiter that has not polled yet.
    pub(super) async fn tripped(&self) {
        self.notify.notified().await;
    }
}

/// A request body that fails as soon as it passes the body limit, counting the bytes of a chunked body as they
/// stream in.
#[derive(Debug)]
pub struct RequestBody {
    incoming: Incoming,
    limit: u64,
    remaining: u64,
    overflow: Arc<Overflow>,
}

impl RequestBody {
    pub(super) fn new(incoming: Incoming, limit: u64, overflow: Arc<Overflow>) -> Self {
        Self {
            incoming,
            limit,
            remaining: limit,
            overflow,
        }
    }

    /// Charges a data frame against the remaining allowance; trailers cost nothing, since the header limit bounds them.
    fn count(&mut self, frame: Frame<Bytes>) -> Result<Frame<Bytes>, RequestBodyError> {
        let len = frame.data_ref().map_or(0, |data| u64::try_from(data.len()).unwrap_or(u64::MAX));
        match self.remaining.checked_sub(len) {
            Some(remaining) => {
                self.remaining = remaining;
                Ok(frame)
            }
            None => {
                self.overflow.trip();
                Err(self.too_large())
            }
        }
    }

    fn too_large(&self) -> RequestBodyError {
        RequestBodyError::TooLarge { limit: self.limit }
    }
}

impl Body for RequestBody {
    type Data = Bytes;
    type Error = RequestBodyError;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, RequestBodyError>>> {
        let this = self.get_mut();
        if this.overflow.is_tripped() {
            return Poll::Ready(Some(Err(this.too_large())));
        }
        let frame = ready!(Pin::new(&mut this.incoming).poll_frame(cx));
        Poll::Ready(frame.map(|frame| frame.map_err(RequestBodyError::from).and_then(|frame| this.count(frame))))
    }

    fn is_end_stream(&self) -> bool {
        self.incoming.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.incoming.size_hint()
    }
}

/// The request deadline passed while the response was still streaming.
#[derive(Debug, thiserror::Error)]
#[error("the request deadline passed while the response was streaming")]
struct DeadlinePassed;

/// A response body that fails at the request deadline, so a response cannot stream past the whole-request timeout.
pub(super) struct Deadline {
    body: ResponseBody,
    sleep: Pin<Box<Sleep>>,
}

impl Deadline {
    pub(super) fn new(body: ResponseBody, deadline: Instant) -> Self {
        Self {
            body,
            sleep: Box::pin(tokio::time::sleep_until(deadline)),
        }
    }
}

impl Body for Deadline {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = self.get_mut();
        if this.sleep.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Some(Err(Box::new(DeadlinePassed))));
        }
        Pin::new(&mut this.body).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}
