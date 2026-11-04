//! A response body that fails once the serving snapshot it is served from is withdrawn.

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use hyper::body::{Body, Frame, SizeHint};
use tokio_util::sync::WaitForCancellationFutureOwned;

use crate::request_server::{BoxError, ResponseBody};

/// The error a body fails with when its snapshot is withdrawn. The request server's HTTP stack aborts the connection on
/// any body error, so the caller never sees the cut-off body end cleanly.
#[derive(Debug, thiserror::Error)]
#[error("the serving snapshot was withdrawn")]
struct Withdrawn;

/// `inner` until `withdrawn` completes, then an error. The withdrawal is checked before the inner body on every poll,
/// so a withdrawn snapshot releases no further bytes.
pub(super) struct UntilWithdrawn {
    inner: ResponseBody,
    withdrawn: Pin<Box<WaitForCancellationFutureOwned>>,
}

impl UntilWithdrawn {
    pub(super) fn new(inner: ResponseBody, withdrawn: WaitForCancellationFutureOwned) -> Self {
        Self {
            inner,
            withdrawn: Box::pin(withdrawn),
        }
    }
}

impl Body for UntilWithdrawn {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        match self.withdrawn.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(Some(Err(Box::new(Withdrawn)))),
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
