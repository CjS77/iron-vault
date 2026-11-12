//! The wall clock ([glossary: *Wall clock*](../../../design/glossary.md#terms)): the one place the service reads the
//! current UTC time, so the recovery schedule is tested by setting the time instead of waiting for it.

use std::fmt::Debug;
use std::time::SystemTime;

use iron_vault_store::{UtcSecond, UtcSecondError};

/// A source of the current UTC time.
pub trait WallClock: Debug + Send + Sync {
    /// Returns the current time to whole seconds, or an error when the clock reads outside 1970 to 9999.
    fn now(&self) -> Result<UtcSecond, UtcSecondError>;
}

/// The operating system's clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl WallClock for SystemClock {
    fn now(&self) -> Result<UtcSecond, UtcSecondError> {
        UtcSecond::from_system_time(SystemTime::now())
    }
}

/// A clock that reads the time it was last set to, for tests.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug)]
pub struct TestClock(std::sync::atomic::AtomicU64);

#[cfg(any(test, feature = "test-support"))]
impl TestClock {
    /// Creates a clock reading `unix_seconds`.
    pub fn at(unix_seconds: u64) -> Self {
        Self(std::sync::atomic::AtomicU64::new(unix_seconds))
    }

    /// Moves the clock forward by `days` whole days.
    pub fn advance_days(&self, days: u64) {
        self.0.fetch_add(days * 86_400, std::sync::atomic::Ordering::SeqCst);
    }

    /// Sets the clock to `unix_seconds`, which may be earlier than it read before.
    pub fn set(&self, unix_seconds: u64) {
        self.0.store(unix_seconds, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(any(test, feature = "test-support"))]
impl WallClock for TestClock {
    fn now(&self) -> Result<UtcSecond, UtcSecondError> {
        UtcSecond::from_unix_seconds(self.0.load(std::sync::atomic::Ordering::SeqCst))
    }
}
