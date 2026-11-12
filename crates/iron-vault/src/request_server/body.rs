//! The request body counted against the body limit, the response body cut off at the request deadline, and the
//! outermost response body that carries the request's record.

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
use crate::audit::{Ending, ReasonCode, RequestFacts, RequestRecord, count_of};

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

/// A flag, set by a request's [`RequestBody`] once the body passes the body limit, that the server awaits.
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
    facts: RequestFacts,
}

impl RequestBody {
    pub(super) fn new(incoming: Incoming, limit: u64, overflow: Arc<Overflow>, facts: RequestFacts) -> Self {
        Self {
            incoming,
            limit,
            remaining: limit,
            overflow,
            facts,
        }
    }

    /// Charges a data frame against the remaining allowance; trailers cost nothing, since the header limit bounds them.
    fn count(&mut self, frame: Frame<Bytes>) -> Result<Frame<Bytes>, RequestBodyError> {
        let len = frame.data_ref().map_or(0, |data| count_of(data.len()));
        match self.remaining.checked_sub(len) {
            Some(remaining) => {
                self.remaining = remaining;
                self.facts.add_request_bytes(len);
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
///
/// A body whose rest is already in hand at the deadline still finishes: a handler may answer at the deadline itself
/// with a fixed body, and failing that body would drop the connection without its status. Only a body still waiting
/// on more fails.
pub(super) struct Deadline {
    body: ResponseBody,
    sleep: Pin<Box<Sleep>>,
    facts: RequestFacts,
}

impl Deadline {
    pub(super) fn new(body: ResponseBody, deadline: Instant, facts: RequestFacts) -> Self {
        Self {
            body,
            sleep: Box::pin(tokio::time::sleep_until(deadline)),
            facts,
        }
    }
}

impl Body for Deadline {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = self.get_mut();
        let frame = Pin::new(&mut this.body).poll_frame(cx);
        if this.sleep.as_mut().poll(cx).is_pending() {
            return frame;
        }
        match frame {
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Ok(frame))) if this.body.is_end_stream() => Poll::Ready(Some(Ok(frame))),
            _ => {
                this.facts.refuse(ReasonCode::Deadline);
                Poll::Ready(Some(Err(Box::new(DeadlinePassed))))
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

/// The outermost response body: it counts the bytes handed to hyper and ends the request's record when the body ends,
/// fails or is dropped.
///
/// It forwards `is_end_stream` and `size_hint`, so hyper sees the body it would have seen unwrapped and skips polling an
/// empty one. A drop before the end is a clean end when hyper had nothing to poll: the response cannot carry a body, or
/// the inner body says it is empty or finished.
pub(super) struct Recorded {
    body: ResponseBody,
    record: RequestRecord,
    can_have_body: bool,
}

impl Recorded {
    pub(super) fn new(body: ResponseBody, record: RequestRecord, can_have_body: bool) -> Self {
        Self {
            body,
            record,
            can_have_body,
        }
    }
}

impl Body for Recorded {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = self.get_mut();
        let frame = ready!(Pin::new(&mut this.body).poll_frame(cx));
        match &frame {
            Some(Ok(frame)) => this.record.sent(frame.data_ref().map_or(0, |data| count_of(data.len()))),
            Some(Err(_)) => this.record.end(Ending::Cut),
            None => this.record.end(Ending::Clean),
        }
        Poll::Ready(frame)
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

impl Drop for Recorded {
    /// Ends the record before the inner body drops; every fact the inner layers know is already in the record's facts.
    fn drop(&mut self) {
        let unpolled = !self.can_have_body || self.body.is_end_stream() || self.body.size_hint().exact() == Some(0);
        self.record.end(if unpolled { Ending::Clean } else { Ending::Cut });
    }
}
