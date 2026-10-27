//! Operational limits on request size, response size, time and concurrency (spec §9).
//!
//! Every limit has a conservative default so an installation without a `[limits]` table is still bounded. A
//! `[limits]` table overrides individual fields; each override must be non-zero and below a sanity ceiling, because
//! an unbounded value would reopen the resource-exhaustion paths these limits exist to close.

use serde::Deserialize;
use thiserror::Error;

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;
const GIB: u64 = 1024 * MIB;

/// Why a `[limits]` override was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LimitsError {
    /// The field was set to zero, which would refuse every request.
    #[error("limits.{field} must not be zero")]
    Zero {
        /// The `[limits]` key that was zero.
        field: &'static str,
    },
    /// The field exceeded its sanity ceiling.
    #[error("limits.{field} is {value}; the maximum is {max}")]
    TooLarge {
        /// The `[limits]` key that was too large.
        field: &'static str,
        /// The rejected value.
        value: u64,
        /// The largest accepted value.
        max: u64,
    },
    /// The upstream header wait outlasts the whole-request timeout, so it could never take effect.
    #[error("limits.upstream_timeout_secs ({upstream}) must not exceed limits.request_timeout_secs ({request})")]
    UpstreamExceedsRequest {
        /// The configured upstream timeout, in seconds.
        upstream: u64,
        /// The configured whole-request timeout, in seconds.
        request: u64,
    },
}

/// Validated operational limits.
///
/// Defaults and why each was chosen:
///
/// | Field | Default | Ceiling | Reason |
/// |---|---|---|---|
/// | `max_header_bytes` | 64 KiB | 1 MiB | Request line plus headers; fits large bearer/cookie headers, caps per-connection memory. |
/// | `max_header_count` | 100 | 1 000 | Matches common HTTP server defaults; real API clients send far fewer. |
/// | `max_request_body_bytes` | 10 MiB | 1 GiB | Covers JSON API payloads and small uploads; larger uploads are an explicit choice. |
/// | `max_decompressed_response_bytes` | 64 MiB | 4 GiB | Scrubbing decompresses responses, so this bounds decompression bombs. |
/// | `request_timeout_secs` | 300 | 3 600 | Whole-request ceiling long enough for streamed model responses. |
/// | `upstream_timeout_secs` | 300 | 600 | Wait for upstream response headers; non-streaming LLM replies send them after generation. |
/// | `max_connections` | 256 | 65 536 | Concurrent caller connections; well above local use, low enough to bound file descriptors. |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "RawLimits")]
pub struct Limits {
    max_header_bytes: u64,
    max_header_count: u64,
    max_request_body_bytes: u64,
    max_decompressed_response_bytes: u64,
    request_timeout_secs: u64,
    upstream_timeout_secs: u64,
    max_connections: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_header_bytes: 64 * KIB,
            max_header_count: 100,
            max_request_body_bytes: 10 * MIB,
            max_decompressed_response_bytes: 64 * MIB,
            request_timeout_secs: 300,
            upstream_timeout_secs: 300,
            max_connections: 256,
        }
    }
}

impl Limits {
    /// Largest accepted request line plus headers, in bytes.
    pub fn max_header_bytes(&self) -> u64 {
        self.max_header_bytes
    }

    /// Largest accepted number of request headers.
    pub fn max_header_count(&self) -> u64 {
        self.max_header_count
    }

    /// Largest accepted request body, in bytes.
    pub fn max_request_body_bytes(&self) -> u64 {
        self.max_request_body_bytes
    }

    /// Largest response body, in bytes after decompression, that the service will process.
    pub fn max_decompressed_response_bytes(&self) -> u64 {
        self.max_decompressed_response_bytes
    }

    /// Time allowed for a whole request, in seconds.
    pub fn request_timeout_secs(&self) -> u64 {
        self.request_timeout_secs
    }

    /// Time allowed for the upstream to return response headers, in seconds.
    pub fn upstream_timeout_secs(&self) -> u64 {
        self.upstream_timeout_secs
    }

    /// Largest number of concurrent caller connections.
    pub fn max_connections(&self) -> u64 {
        self.max_connections
    }
}

/// The `[limits]` table as written; every field is optional so an override can be partial.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLimits {
    max_header_bytes: Option<u64>,
    max_header_count: Option<u64>,
    max_request_body_bytes: Option<u64>,
    max_decompressed_response_bytes: Option<u64>,
    request_timeout_secs: Option<u64>,
    upstream_timeout_secs: Option<u64>,
    max_connections: Option<u64>,
}

/// Returns the override if present and in `1..=max`, otherwise the default.
fn pick(field: &'static str, value: Option<u64>, default: u64, max: u64) -> Result<u64, LimitsError> {
    match value {
        None => Ok(default),
        Some(0) => Err(LimitsError::Zero { field }),
        Some(value) if value > max => Err(LimitsError::TooLarge { field, value, max }),
        Some(value) => Ok(value),
    }
}

impl TryFrom<RawLimits> for Limits {
    type Error = LimitsError;

    fn try_from(raw: RawLimits) -> Result<Self, Self::Error> {
        let d = Limits::default();
        let limits = Self {
            max_header_bytes: pick("max_header_bytes", raw.max_header_bytes, d.max_header_bytes, MIB)?,
            max_header_count: pick("max_header_count", raw.max_header_count, d.max_header_count, 1_000)?,
            max_request_body_bytes: pick("max_request_body_bytes", raw.max_request_body_bytes, d.max_request_body_bytes, GIB)?,
            max_decompressed_response_bytes: pick(
                "max_decompressed_response_bytes",
                raw.max_decompressed_response_bytes,
                d.max_decompressed_response_bytes,
                4 * GIB,
            )?,
            request_timeout_secs: pick("request_timeout_secs", raw.request_timeout_secs, d.request_timeout_secs, 3_600)?,
            upstream_timeout_secs: pick("upstream_timeout_secs", raw.upstream_timeout_secs, d.upstream_timeout_secs, 600)?,
            max_connections: pick("max_connections", raw.max_connections, d.max_connections, 65_536)?,
        };
        check_timeouts(limits)
    }
}

/// Rejects an upstream timeout longer than the whole-request timeout; equal values are valid.
fn check_timeouts(limits: Limits) -> Result<Limits, LimitsError> {
    match (limits.upstream_timeout_secs, limits.request_timeout_secs) {
        (upstream, request) if upstream > request => Err(LimitsError::UpstreamExceedsRequest { upstream, request }),
        _ => Ok(limits),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct Config {
        #[serde(default)]
        limits: Limits,
    }

    fn parse(s: &str) -> Result<Limits, toml::de::Error> {
        toml::from_str::<Config>(s).map(|c| c.limits)
    }

    #[test]
    fn defaults_are_deliberate() {
        let d = Limits::default();
        assert_eq!(d.max_header_bytes(), 65_536);
        assert_eq!(d.max_header_count(), 100);
        assert_eq!(d.max_request_body_bytes(), 10_485_760);
        assert_eq!(d.max_decompressed_response_bytes(), 67_108_864);
        assert_eq!(d.request_timeout_secs(), 300);
        assert_eq!(d.upstream_timeout_secs(), 300);
        assert_eq!(d.max_connections(), 256);
    }

    #[test]
    fn omitted_and_empty_tables_use_defaults() {
        assert_eq!(parse("").unwrap(), Limits::default());
        assert_eq!(parse("[limits]").unwrap(), Limits::default());
    }

    #[test]
    fn partial_override_keeps_other_defaults() {
        let l = parse("[limits]\nmax_connections = 32\nrequest_timeout_secs = 3600").unwrap();
        assert_eq!(l.max_connections(), 32);
        assert_eq!(l.request_timeout_secs(), 3_600);
        assert_eq!(l.max_header_count(), Limits::default().max_header_count());
    }

    #[test]
    fn zero_is_rejected_naming_the_field() {
        assert_eq!(pick("max_header_count", Some(0), 100, 1_000), Err(LimitsError::Zero { field: "max_header_count" }));
        let err = parse("[limits]\nmax_header_count = 0").unwrap_err();
        assert!(err.to_string().contains("limits.max_header_count must not be zero"), "{err}");
    }

    #[test]
    fn ceiling_is_inclusive_and_enforced() {
        let l = parse("[limits]\nupstream_timeout_secs = 600\nrequest_timeout_secs = 600").unwrap();
        assert_eq!(l.upstream_timeout_secs(), 600);
        let err = parse("[limits]\nupstream_timeout_secs = 601").unwrap_err();
        assert!(err.to_string().contains("limits.upstream_timeout_secs is 601; the maximum is 600"), "{err}");
    }

    #[test]
    fn upstream_timeout_may_equal_but_not_exceed_request_timeout() {
        let d = Limits::default();
        assert_eq!(d.upstream_timeout_secs(), d.request_timeout_secs());
        let err = parse("[limits]\nrequest_timeout_secs = 120").unwrap_err();
        assert!(err.to_string().contains("limits.upstream_timeout_secs (300) must not exceed limits.request_timeout_secs (120)"), "{err}");
    }

    #[test]
    fn unknown_and_negative_fields_are_rejected() {
        assert!(parse("[limits]\nmax_body = 1").is_err());
        assert!(parse("[limits]\nmax_connections = -1").is_err());
    }
}
