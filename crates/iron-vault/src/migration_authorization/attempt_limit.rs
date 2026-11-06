//! The passphrase attempt limit (design/migration-authorization.md, "Passphrase attempt limit"): a count of
//! consecutive owner failures that refuses further attempts for a cooldown which doubles with each failure.
//!
//! Pure: the clock is an argument, so the policy is deterministic under a paused tokio clock. Which outcomes count is
//! the caller's decision, and it is fixed by the design: only `wrong_passphrase` and `not_this_vault` call
//! [`AttemptLimiter::record_failure`]. An `unavailable` check, a `cancelled` prompt, a `lock`, a `rate_limited`
//! refusal and a failure after a proof (`expired`, `not_pending`, `binding_mismatch`) record nothing.

use std::time::Duration;

use thiserror::Error;
use tokio::time::Instant;

/// Consecutive failures after which attempts are refused.
pub const FAILURE_THRESHOLD: u32 = 5;
/// The cooldown after the threshold-th failure; each further failure doubles it.
pub const BASE_COOLDOWN: Duration = Duration::from_secs(30);
/// The longest cooldown.
pub const MAX_COOLDOWN: Duration = Duration::from_secs(15 * 60);

/// An attempt was refused because the limiter is in a cooldown. The exchange ends with `migration-rate-limited`
/// before any prompt, so the owner is not asked to type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("too many wrong vault passphrases; try again in {retry_after} seconds")]
pub struct RateLimited {
    /// Whole seconds until an attempt is allowed again, rounded up so waiting this long is always enough.
    pub retry_after: u64,
}

/// The count of consecutive owner failures and when the last one happened.
///
/// It lives in the service context beside, not inside, the pending migration slot, so `lock` (which retires the
/// slot) does not clear it: a guesser could otherwise lock after every fourth failure. A restart does clear it.
#[derive(Debug, Default)]
pub struct AttemptLimiter {
    failures: u32,
    last_failure: Option<Instant>,
}

impl AttemptLimiter {
    /// A limiter with no failures.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether an attempt may start at `now`. Call it before any prompt.
    pub fn check(&self, now: Instant) -> Result<(), RateLimited> {
        let Some(last) = self.last_failure else { return Ok(()) };
        let remaining = self.cooldown().saturating_sub(now.saturating_duration_since(last));
        match remaining.is_zero() {
            true => Ok(()),
            false => Err(RateLimited {
                retry_after: remaining.as_secs() + u64::from(remaining.subsec_nanos() > 0),
            }),
        }
    }

    /// Counts an owner failure at `now`.
    pub fn record_failure(&mut self, now: Instant) {
        self.failures = self.failures.saturating_add(1);
        self.last_failure = Some(now);
    }

    /// Clears the count after the owner proved the passphrase.
    pub fn record_success(&mut self) {
        *self = Self::default();
    }

    /// The cooldown the current count carries: none below the threshold, then the base doubled per further failure.
    fn cooldown(&self) -> Duration {
        let Some(doublings) = self.failures.checked_sub(FAILURE_THRESHOLD) else {
            return Duration::ZERO;
        };
        BASE_COOLDOWN
            .saturating_mul(1u32.checked_shl(doublings).unwrap_or(u32::MAX))
            .min(MAX_COOLDOWN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fail_times(limiter: &mut AttemptLimiter, times: u32) {
        (0..times).for_each(|_| limiter.record_failure(Instant::now()));
    }

    fn limited_for(limiter: &AttemptLimiter) -> u64 {
        limiter.check(Instant::now()).unwrap_err().retry_after
    }

    #[tokio::test(start_paused = true)]
    async fn failures_below_the_threshold_never_limit() {
        let mut limiter = AttemptLimiter::new();
        assert_eq!(limiter.check(Instant::now()), Ok(()));
        (1..FAILURE_THRESHOLD).for_each(|_| {
            limiter.record_failure(Instant::now());
            assert_eq!(limiter.check(Instant::now()), Ok(()));
        });
    }

    #[tokio::test(start_paused = true)]
    async fn the_threshold_refuses_until_the_base_cooldown_passes() {
        let mut limiter = AttemptLimiter::new();
        fail_times(&mut limiter, FAILURE_THRESHOLD);
        assert_eq!(limited_for(&limiter), 30);
        tokio::time::advance(Duration::from_millis(29_500)).await;
        assert_eq!(limited_for(&limiter), 1, "half a second left rounds up to a whole second");
        tokio::time::advance(Duration::from_millis(500)).await;
        assert_eq!(limiter.check(Instant::now()), Ok(()));
    }

    #[tokio::test(start_paused = true)]
    async fn the_cooldown_doubles_with_each_further_failure_up_to_the_cap() {
        let mut limiter = AttemptLimiter::new();
        fail_times(&mut limiter, FAILURE_THRESHOLD);
        let seen = (0..7)
            .map(|_| {
                let retry_after = limited_for(&limiter);
                limiter.record_failure(Instant::now());
                retry_after
            })
            .collect::<Vec<_>>();
        assert_eq!(seen, [30, 60, 120, 240, 480, 900, 900]);
    }

    #[tokio::test(start_paused = true)]
    async fn an_enormous_count_stays_at_the_cap() {
        let mut limiter = AttemptLimiter::new();
        fail_times(&mut limiter, 200);
        assert_eq!(limited_for(&limiter), MAX_COOLDOWN.as_secs());
    }

    #[tokio::test(start_paused = true)]
    async fn a_success_resets_the_count() {
        let mut limiter = AttemptLimiter::new();
        fail_times(&mut limiter, FAILURE_THRESHOLD);
        limiter.record_success();
        assert_eq!(limiter.check(Instant::now()), Ok(()));
        fail_times(&mut limiter, FAILURE_THRESHOLD - 1);
        assert_eq!(limiter.check(Instant::now()), Ok(()), "the count restarted from zero");
    }

    #[tokio::test(start_paused = true)]
    async fn an_attempt_after_the_cooldown_that_fails_again_waits_longer() {
        let mut limiter = AttemptLimiter::new();
        fail_times(&mut limiter, FAILURE_THRESHOLD);
        tokio::time::advance(BASE_COOLDOWN).await;
        limiter.record_failure(Instant::now());
        assert_eq!(limited_for(&limiter), 60);
    }
}
