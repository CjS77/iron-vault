//! The proxy's request path: coding, scrubbing, location, serving gate, egress and the request events.

// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../common/mod.rs"]
mod common;

mod pipeline_egress;
mod proxy_coding;
mod proxy_coding_stream;
mod proxy_handler;
mod proxy_location;
mod proxy_scrub;
mod proxy_scrub_stream;
mod proxy_serving_gate;
mod refusal_events;
mod request_events;
mod request_events_relayed;
mod request_socket;
