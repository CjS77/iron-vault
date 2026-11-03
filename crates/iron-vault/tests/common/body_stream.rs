//! Request bodies for the upstream client's tests, and a wait for a test upstream to finish recording.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use futures_core::Stream;
use iron_vault::upstream::request_body::{BodyStreamError, RequestBody};

/// How long a failing stream waits before its error, so the client has sent the chunks before it as well as the head.
const PAUSE_BEFORE_ERROR: Duration = Duration::from_millis(100);

/// A stream that yields its items in order, each ready at once except that an error waits for `pause` first, then ends.
struct Items {
    items: VecDeque<Result<Bytes, BodyStreamError>>,
    pause: Pin<Box<tokio::time::Sleep>>,
}

impl Stream for Items {
    type Item = Result<Bytes, BodyStreamError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.items.front().is_some_and(Result::is_err) && self.pause.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
        }
        Poll::Ready(self.items.pop_front())
    }
}

/// A body of `chunks` in order, declaring `length` when given.
pub fn body(length: Option<u64>, chunks: &[&str]) -> RequestBody {
    stream(length, chunks.iter().map(|chunk| Ok(Bytes::copy_from_slice(chunk.as_bytes()))))
}

/// A body that yields `chunks`, then fails with [`BodyStreamError`].
pub fn failing_body(length: Option<u64>, chunks: &[&str]) -> RequestBody {
    let items = chunks.iter().map(|chunk| Ok(Bytes::copy_from_slice(chunk.as_bytes())));
    stream(length, items.chain([Err(BodyStreamError)]))
}

fn stream(length: Option<u64>, items: impl Iterator<Item = Result<Bytes, BodyStreamError>>) -> RequestBody {
    let items = Items {
        items: items.collect(),
        pause: Box::pin(tokio::time::sleep(PAUSE_BEFORE_ERROR)),
    };
    RequestBody::stream(length, items)
}

/// Polls `probe` until it returns a value. A test upstream records an aborted request after the client has already
/// reported the failure, so a test waits for the recording instead of assuming it is there.
pub async fn eventually<T>(mut probe: impl FnMut() -> Option<T>) -> T {
    for _ in 0..200 {
        if let Some(found) = probe() {
            return found;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the test upstream recorded nothing within two seconds");
}
