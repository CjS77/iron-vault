//! The vault's life: init, reset, migration, bundle transfer, export and the admin socket.

// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../common/mod.rs"]
mod common;

mod admin_socket;
mod bundle_transfer;
mod export;
mod init;
mod migration;
mod migration_authorization;
mod migration_prompt;
mod migration_rejection;
mod migration_tpm_pin;
mod reset;
