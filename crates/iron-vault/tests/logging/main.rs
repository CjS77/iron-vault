// SPDX-License-Identifier: MPL-2.0
//! Log redaction and startup logging checks that install no process-wide subscriber.

// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../common/mod.rs"]
mod common;

mod library_error_redaction;
mod log_destination_reserved;
mod log_error_redaction;
mod startup_logging;
