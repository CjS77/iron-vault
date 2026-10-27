//! A route's request-rate allowance (spec §3.3, §3.5).
//!
//! The service enforces it as a token bucket that refills at `requests / per_seconds` and holds at most `burst`
//! tokens. This type only carries the validated numbers; [`TokenBucket`](crate::TokenBucket) does the counting.

use std::num::NonZeroU32;

use serde::Deserialize;

/// A token-bucket rate limit: `requests` per `per_seconds`, with up to `burst` requests available at once.
///
/// Every field is non-zero, so a limit can never silently block a route forever or divide by zero. TOML form:
/// `rate_limit = { requests = 60, per_seconds = 60, burst = 10 }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimit {
    requests: NonZeroU32,
    per_seconds: NonZeroU32,
    burst: NonZeroU32,
}

impl RateLimit {
    /// Builds a rate limit; the non-zero types make every combination valid.
    pub fn new(requests: NonZeroU32, per_seconds: NonZeroU32, burst: NonZeroU32) -> Self {
        Self { requests, per_seconds, burst }
    }

    /// Tokens added per refill period.
    pub fn requests(&self) -> NonZeroU32 {
        self.requests
    }

    /// Length of the refill period in seconds.
    pub fn per_seconds(&self) -> NonZeroU32 {
        self.per_seconds
    }

    /// Bucket capacity: the most requests that may pass back to back.
    pub fn burst(&self) -> NonZeroU32 {
        self.burst
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct Route {
        rate_limit: RateLimit,
    }

    fn parse(s: &str) -> Result<RateLimit, toml::de::Error> {
        toml::from_str::<Route>(s).map(|r| r.rate_limit)
    }

    #[test]
    fn spec_examples_parse() {
        let fx = parse("rate_limit = { requests = 60, per_seconds = 60, burst = 10 }").unwrap();
        assert_eq!((fx.requests().get(), fx.per_seconds().get(), fx.burst().get()), (60, 60, 10));
        let venice = parse("rate_limit = { requests = 120, per_seconds = 60, burst = 20 }").unwrap();
        assert_eq!((venice.requests().get(), venice.per_seconds().get(), venice.burst().get()), (120, 60, 20));
    }

    #[test]
    fn zero_values_are_rejected() {
        [
            "rate_limit = { requests = 0, per_seconds = 60, burst = 10 }",
            "rate_limit = { requests = 60, per_seconds = 0, burst = 10 }",
            "rate_limit = { requests = 60, per_seconds = 60, burst = 0 }",
        ]
        .iter()
        .for_each(|s| assert!(parse(s).is_err(), "{s}"));
    }

    #[test]
    fn missing_and_unknown_fields_are_rejected() {
        assert!(parse("rate_limit = { requests = 60, per_seconds = 60 }").is_err());
        assert!(parse("rate_limit = { requests = 60, per_seconds = 60, burst = 10, jitter = 1 }").is_err());
        assert!(parse("rate_limit = { requests = -1, per_seconds = 60, burst = 10 }").is_err());
    }
}
