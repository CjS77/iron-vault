//! Credential commands, caller tokens and config approval.

// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../common/mod.rs"]
mod common;

mod add;
mod approval_release;
mod caller_token;
mod config_approve;
mod credential_commands;
mod replace;
mod rm;
