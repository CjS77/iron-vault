//! The token bucket that enforces a route's [`RateLimit`] (spec §3.5, §3.12, R-1).
//!
//! The arithmetic is exact integer arithmetic so rounding can never grant an extra request. The level is counted in
//! *units*, where one token is `per_seconds × 10⁹` units: one nanosecond then refills exactly `requests` units, so
//! no fraction of a token is ever lost or invented. Time is passed in, which keeps the bucket pure and lets tests
//! step a clock instead of sleeping.

use std::time::{Duration, Instant};

use thiserror::Error;

use crate::RateLimit;

const NANOS_PER_SEC: u128 = 1_000_000_000;

/// A rate-limit counter for one route (or one caller/route pair).
///
/// It starts **empty** and refills at `requests / per_seconds` up to `burst` tokens, so restarting the service can
/// never hand out a fresh burst. A clock reading earlier than the last update counts as no time passing.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    /// Units refilled per elapsed nanosecond.
    requests: u128,
    /// Units in one token: `per_seconds × 10⁹`.
    token_units: u128,
    /// The most units the bucket holds: `burst` tokens.
    capacity: u128,
    /// Units currently held.
    level: u128,
    /// The latest instant the level accounts for; it never moves backwards.
    updated: Instant,
}

impl TokenBucket {
    /// Creates an empty bucket for `limit`, accounting for time from `now`.
    ///
    /// Starting empty is deliberate (spec §3.5): a bucket that started full would let every restart replenish a
    /// whole burst instantly.
    pub fn new(limit: RateLimit, now: Instant) -> Self {
        // Each factor is below 2³², so these products stay far below u128::MAX.
        let token_units = u128::from(limit.per_seconds().get()).saturating_mul(NANOS_PER_SEC);
        Self {
            requests: u128::from(limit.requests().get()),
            token_units,
            capacity: u128::from(limit.burst().get()).saturating_mul(token_units),
            level: 0,
            updated: now,
        }
    }

    /// Refills for the time elapsed up to `now`, then spends one token.
    ///
    /// When no whole token is available the bucket is left refilled but unspent, and the error says how long until
    /// one will be.
    pub fn try_take(&mut self, now: Instant) -> Result<(), RetryAfter> {
        self.refill(now);
        match self.level.checked_sub(self.token_units) {
            Some(rest) => {
                self.level = rest;
                Ok(())
            }
            None => Err(RetryAfter::for_deficit(self.token_units.saturating_sub(self.level), self.requests)),
        }
    }

    /// Whole tokens available at `now`, rounded down, without changing the bucket.
    ///
    /// Intended for tests and the `status` report; enforcement goes through [`TokenBucket::try_take`].
    pub fn level_at(&self, now: Instant) -> u64 {
        u64::try_from(self.level_after(now) / self.token_units).unwrap_or(u64::MAX)
    }

    /// Brings the level up to date with `now` and advances the update instant, so no elapsed time is counted twice.
    fn refill(&mut self, now: Instant) {
        self.level = self.level_after(now);
        self.updated = self.updated.max(now);
    }

    /// The level the bucket would hold at `now`; time before the last update counts as zero.
    fn level_after(&self, now: Instant) -> u128 {
        let elapsed = now.saturating_duration_since(self.updated).as_nanos();
        self.level.saturating_add(elapsed.saturating_mul(self.requests)).min(self.capacity)
    }
}

/// How long a refused caller should wait before a token is available, in whole seconds.
///
/// Rounded **up** and never below one second, so a client honouring it is never refused again for retrying too early
/// and the value can go straight into a `Retry-After` header (spec §3.12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("rate limit exhausted; retry after {secs} s")]
pub struct RetryAfter {
    secs: u64,
}

impl RetryAfter {
    /// The wait for `deficit` units to refill at `requests` units per nanosecond.
    fn for_deficit(deficit: u128, requests: u128) -> Self {
        let nanos = deficit.div_ceil(requests.max(1));
        let secs = nanos.div_ceil(NANOS_PER_SEC).max(1);
        Self { secs: u64::try_from(secs).unwrap_or(u64::MAX) }
    }

    /// The wait in whole seconds; always at least 1.
    pub fn as_secs(&self) -> u64 {
        self.secs
    }

    /// The wait as a [`Duration`] of whole seconds.
    pub fn as_duration(&self) -> Duration {
        Duration::from_secs(self.secs)
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use super::*;

    fn limit(requests: u32, per_seconds: u32, burst: u32) -> RateLimit {
        let nz = |n| NonZeroU32::new(n).unwrap();
        RateLimit::new(nz(requests), nz(per_seconds), nz(burst))
    }

    /// Takes tokens at `now` until refused; returns how many passed.
    fn drain(bucket: &mut TokenBucket, now: Instant) -> u64 {
        std::iter::from_fn(|| bucket.try_take(now).ok()).count() as u64
    }

    #[test]
    fn new_bucket_is_empty_and_refuses_with_one_second() {
        let t0 = Instant::now();
        let mut bucket = TokenBucket::new(limit(60, 60, 10), t0);
        assert_eq!(bucket.level_at(t0), 0);
        assert_eq!(bucket.try_take(t0).unwrap_err().as_secs(), 1);
    }

    #[test]
    fn one_second_grants_exactly_one() {
        let t0 = Instant::now();
        let mut bucket = TokenBucket::new(limit(60, 60, 10), t0);
        assert_eq!(drain(&mut bucket, t0 + Duration::from_secs(1)), 1);
    }

    #[test]
    fn burst_caps_the_level() {
        let t0 = Instant::now();
        let mut bucket = TokenBucket::new(limit(60, 60, 10), t0);
        let t60 = t0 + Duration::from_secs(60);
        assert_eq!(bucket.level_at(t60), 10);
        assert_eq!(drain(&mut bucket, t60), 10);
        assert_eq!(bucket.try_take(t60).unwrap_err().as_secs(), 1);
    }

    #[test]
    fn slow_refill_refuses_early_and_grants_on_time() {
        let t0 = Instant::now();
        let mut bucket = TokenBucket::new(limit(1, 3, 5), t0);
        let err = bucket.try_take(t0 + Duration::from_millis(2900)).unwrap_err();
        assert_eq!(err.as_secs(), 1);
        assert_eq!(err.as_duration(), Duration::from_secs(1));
        assert!(bucket.try_take(t0 + Duration::from_secs(3)).is_ok());
    }

    #[test]
    fn retry_after_rounds_up_to_whole_seconds() {
        let t0 = Instant::now();
        let mut bucket = TokenBucket::new(limit(1, 3, 5), t0);
        assert_eq!(bucket.try_take(t0).unwrap_err().as_secs(), 3);
        assert_eq!(bucket.try_take(t0 + Duration::from_millis(1)).unwrap_err().as_secs(), 3);
        assert_eq!(bucket.try_take(t0 + Duration::from_millis(1001)).unwrap_err().as_secs(), 2);
    }

    #[test]
    fn fractional_rate_does_not_drift() {
        let t0 = Instant::now();
        let mut bucket = TokenBucket::new(limit(7, 3, 1000), t0);
        // Step a clock that does not divide the refill period evenly, draining at every step.
        let granted: u64 = (1..=300_000u64).map(|ms| drain(&mut bucket, t0 + Duration::from_millis(ms))).sum();
        assert_eq!(granted, 700);
    }

    #[test]
    fn clock_going_backwards_grants_nothing() {
        let t0 = Instant::now();
        let t10 = t0 + Duration::from_secs(10);
        let mut bucket = TokenBucket::new(limit(60, 60, 10), t10);
        assert!(bucket.try_take(t0).is_err());
        assert_eq!(bucket.level_at(t0), 0);
        assert_eq!(drain(&mut bucket, t10 + Duration::from_secs(1)), 1);
        // A step back after a refill must not let the same elapsed time be counted again.
        assert!(bucket.try_take(t10).is_err());
        assert!(bucket.try_take(t10 + Duration::from_secs(1)).is_err());
    }

    #[test]
    fn extreme_values_neither_overflow_nor_panic() {
        let t0 = Instant::now();
        let century_secs = 100 * 366 * 24 * 3600;
        let century = t0.checked_add(Duration::from_secs(century_secs)).unwrap();
        let max = u32::MAX;
        let mut bucket = TokenBucket::new(limit(max, max, max), t0);
        assert_eq!(bucket.try_take(t0).unwrap_err().as_secs(), 1);
        // One token per second, and a century is fewer than u32::MAX seconds, so the cap does not bite.
        assert_eq!(bucket.level_at(century), century_secs);
        assert!(bucket.try_take(century).is_ok());

        let mut slow = TokenBucket::new(limit(1, max, max), t0);
        assert_eq!(slow.try_take(t0).unwrap_err().as_secs(), u64::from(max));
        assert!(slow.try_take(century).is_err());
        assert_eq!(slow.level_at(century), 0);
    }
}
