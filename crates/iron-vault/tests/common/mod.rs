//! Shared helpers for the upstream client's integration tests: a recording TLS test upstream, in HTTP/1.1 and HTTP/2
//! modes, and checked requests built through the public policy API.

// Each test binary compiles its own copy of this module and uses a different part of it.
#![allow(dead_code)]
// Workspace lints deny these outside tests, and clippy treats only `#[test]` functions as tests; these helpers run only
// under the test harness, where a panic is a test failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod admin_response;
#[cfg(target_os = "linux")]
pub mod approval_harness;
pub mod body_stream;
pub mod checked;
pub mod gated_fs;
pub mod h2_refusal;
pub mod hpack_fields;
pub mod mock_upstream;
pub mod mock_upstream_h2;
#[cfg(target_os = "linux")]
pub mod proxy_harness;
#[cfg(target_os = "linux")]
pub mod scrub_stream;

/// How long a test waits for one response, or for a test upstream to record something, before failing.
pub const WAIT: std::time::Duration = std::time::Duration::from_secs(10);
