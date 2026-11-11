//! The outbound HTTPS client: construction, h1 and h2 behaviour, hostile environments and retry control.

// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::panic)]

#[path = "../common/mod.rs"]
mod common;

mod reqwest_retry_control;
mod upstream_client;
mod upstream_client_h2;
mod upstream_construction;
mod upstream_hostile_env;
