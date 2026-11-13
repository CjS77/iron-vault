// SPDX-License-Identifier: MPL-2.0
//! Request bodies for the upstream client's tests, and a wait for a test upstream to finish recording.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use futures_core::Stream;
use iron_vault::upstream::body::{UpstreamBody, UpstreamBodyError};

use super::WAIT;

/// How long a failing stream waits before its error, so the client has sent the chunks before it as well as the head.
const PAUSE_BEFORE_ERROR: Duration = Duration::from_millis(100);

/// A stream that yields its items in order, each ready at once except that an error waits for `pause` first, then ends.
struct Items {
    items: VecDeque<Result<Bytes, UpstreamBodyError>>,
    pause: Pin<Box<tokio::time::Sleep>>,
}

impl Stream for Items {
    type Item = Result<Bytes, UpstreamBodyError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.items.front().is_some_and(Result::is_err) && self.pause.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
        }
        Poll::Ready(self.items.pop_front())
    }
}

/// A body of `chunks` in order, declaring `length` when given.
pub fn body(length: Option<u64>, chunks: &[&str]) -> UpstreamBody {
    stream(length, chunks.iter().map(|chunk| Ok(Bytes::copy_from_slice(chunk.as_bytes()))))
}

/// A body that yields `chunks`, then fails with [`UpstreamBodyError`].
pub fn failing_body(length: Option<u64>, chunks: &[&str]) -> UpstreamBody {
    let items = chunks.iter().map(|chunk| Ok(Bytes::copy_from_slice(chunk.as_bytes())));
    stream(length, items.chain([Err(UpstreamBodyError)]))
}

fn stream(length: Option<u64>, items: impl Iterator<Item = Result<Bytes, UpstreamBodyError>>) -> UpstreamBody {
    let items = Items {
        items: items.collect(),
        pause: Box::pin(tokio::time::sleep(PAUSE_BEFORE_ERROR)),
    };
    UpstreamBody::stream(length, items)
}

/// Polls `probe` until it returns a value, for up to [`WAIT`]. A test upstream records an aborted request, or a closed
/// connection, after the client has already moved on, so a test waits for the recording instead of assuming it is there.
pub async fn eventually<T>(mut probe: impl FnMut() -> Option<T>) -> T {
    let deadline = tokio::time::Instant::now() + WAIT;
    while tokio::time::Instant::now() < deadline {
        if let Some(found) = probe() {
            return found;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the test upstream did not reach the awaited state within {WAIT:?}");
}
