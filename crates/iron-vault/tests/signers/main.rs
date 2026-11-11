//! Approvers and recipients: who may approve a config and who can open the vault.

// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../common/mod.rs"]
mod common;

mod approver_add;
mod approver_list;
mod approver_order;
mod approver_remove;
mod approvers;
mod recipient_add;
mod recipient_list;
mod recipient_remove;
mod recipients;
mod recovery_check;
mod recovery_reminder;
mod recovery_status;
