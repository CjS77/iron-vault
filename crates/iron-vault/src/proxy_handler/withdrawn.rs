//! A response body that fails once the serving snapshot it is served from is withdrawn.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use hyper::body::{Body, Frame, SizeHint};
use tokio_util::sync::WaitForCancellationFutureOwned;

use crate::audit::{ReasonCode, RequestFacts};
use crate::request_server::{BoxError, ResponseBody};
use crate::serving_snapshot::ServingSnapshot;

/// The error a body fails with when its snapshot is withdrawn. The request server's HTTP stack aborts the connection on
/// any body error, so the caller never sees the cut-off body end cleanly.
#[derive(Debug, thiserror::Error)]
#[error("the serving snapshot was withdrawn")]
struct Withdrawn;

/// `inner` until `withdrawn` completes, then an error, recorded as the request's `withdrawn` reason. The withdrawal is
/// checked before the inner body on every poll, so a withdrawn snapshot releases no further bytes.
///
/// It holds the snapshot for as long as it lives, because `inner` owns the request's secret patterns (the scrubber's)
/// and a lock waits for the snapshot to drop before it reports the secrets cleared. `snapshot` is declared after
/// `inner` so the patterns are dropped first, and the snapshot, with its vault, only after them.
pub(super) struct UntilWithdrawn {
    inner: ResponseBody,
    withdrawn: Pin<Box<WaitForCancellationFutureOwned>>,
    facts: RequestFacts,
    /// Never read: held so the snapshot outlives the body.
    _snapshot: Arc<ServingSnapshot>,
}

impl UntilWithdrawn {
    pub(super) fn new(inner: ResponseBody, snapshot: Arc<ServingSnapshot>, facts: RequestFacts) -> Self {
        Self {
            inner,
            withdrawn: Box::pin(snapshot.withdrawn()),
            facts,
            _snapshot: snapshot,
        }
    }
}

impl Body for UntilWithdrawn {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        match self.withdrawn.as_mut().poll(cx) {
            Poll::Ready(()) => {
                self.facts.refuse(ReasonCode::Withdrawn);
                Poll::Ready(Some(Err(Box::new(Withdrawn))))
            }
            Poll::Pending => Pin::new(&mut self.inner).poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
