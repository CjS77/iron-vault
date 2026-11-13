// SPDX-License-Identifier: MPL-2.0
//! The service as deployed: serve refusals, socket activation, packaging, hardening and the CLI.

// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../common/mod.rs"]
mod common;

mod acceptance_index;
mod cli;
mod deployment_profile;
mod hardening;
mod package_account_check;
mod package_units;
mod reference_docs;
mod serve_refusal;
mod socket_activation;
mod socket_activation_e2e;
mod trusted_path;
