// SPDX-License-Identifier: MPL-2.0
//! What the log file and stdout writers share: the latch a failed write trips, and the `Write` adapter that trips it
//! ([audit logging: failure behaviour](../../../../design/audit-logging.md#failure-behaviour)).
//!
//! `tracing-subscriber`'s `fmt::Layer` discards a writer's error, so the writer is the one place that sees a failed write
//! and can act on it. The service never runs without its audit log, so the first failed write trips [`LogFailure`] and
//! the `serve` loop stops.

// Only the Linux log file and stdout writers append records; the latch is shared on every platform.
#[cfg(target_os = "linux")]
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::Notify;

/// A latch, shared by the log writer and the `serve` loop, that the first failed log write trips. Once tripped it stays
/// tripped: the service stops, and the next start decides afresh whether the destination is usable.
#[derive(Debug, Clone, Default)]
pub struct LogFailure(Arc<Latch>);

#[derive(Debug, Default)]
struct Latch {
    tripped: AtomicBool,
    wake: Notify,
}

impl LogFailure {
    /// Records that a log write failed and wakes everything waiting in [`Self::tripped`].
    pub fn trip(&self) {
        self.0.tripped.store(true, Ordering::SeqCst);
        self.0.wake.notify_waiters();
    }

    /// Returns `true` if and only if a log write has failed.
    pub fn is_tripped(&self) -> bool {
        self.0.tripped.load(Ordering::SeqCst)
    }

    /// Completes once a log write has failed. The `Notified` future is made before the flag is read, so a trip between
    /// the read and the wait is not missed.
    pub async fn tripped(&self) {
        loop {
            let notified = self.0.wake.notified();
            if self.is_tripped() {
                return;
            }
            notified.await;
        }
    }
}

/// A destination that takes one whole record at a time and trips its latch when it cannot.
#[cfg(target_os = "linux")]
pub trait Append {
    /// Writes `record` whole, or fails; writers on different threads never interleave their records.
    fn append(&self, record: &[u8]) -> io::Result<()>;

    /// The latch a failed [`Self::append`] trips.
    fn failure(&self) -> &LogFailure;
}

/// The `Write` the formatter gets for one record: `fmt::Layer` writes the formatted record with a single `write_all`, so
/// each [`Write::write`](std::io::Write::write) here carries a whole record.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct RecordWriter<'a, A>(pub(super) &'a A);

#[cfg(target_os = "linux")]
impl<A: Append> io::Write for RecordWriter<'_, A> {
    fn write(&mut self, record: &[u8]) -> io::Result<usize> {
        self.0
            .append(record)
            .inspect_err(|_| self.0.failure().trip())
            .map(|()| record.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn a_new_latch_is_untripped_and_a_trip_is_seen_by_every_clone() {
        let failure = LogFailure::default();
        let clone = failure.clone();
        assert!(!failure.is_tripped());
        clone.trip();
        assert!(failure.is_tripped());
    }

    #[tokio::test]
    async fn tripped_completes_when_the_latch_trips_after_the_wait_began() {
        let failure = LogFailure::default();
        let waiting = tokio::spawn({
            let failure = failure.clone();
            async move { failure.tripped().await }
        });
        tokio::task::yield_now().await;
        failure.trip();
        assert!(tokio::time::timeout(Duration::from_secs(5), waiting).await.is_ok());
    }

    #[tokio::test]
    async fn tripped_completes_at_once_for_a_latch_already_tripped() {
        let failure = LogFailure::default();
        failure.trip();
        assert!(tokio::time::timeout(Duration::from_secs(5), failure.tripped()).await.is_ok());
    }
}
