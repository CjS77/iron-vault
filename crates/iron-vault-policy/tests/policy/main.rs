//! The policy crate's examples, reference configuration and destination checks.

// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used)]

#[path = "../common/mod.rs"]
mod common;

mod compose_example;
mod config_man_page;
mod destination;
mod hostile_paths;
mod reference_example;
