// SPDX-License-Identifier: MPL-2.0
use iron_vault_store::{ApproverId, ApproverLabel, SignerKind, UtcSecond};

use super::*;

fn entry(id: &str, active: bool, label: &str, seconds: u64) -> ApproverEntry {
    ApproverEntry {
        id: ApproverId::from_bytes(*uuid::Uuid::parse_str(id).unwrap().as_bytes()).unwrap(),
        kind: SignerKind::Software,
        active,
        label: ApproverLabel::new(label).unwrap(),
        enrolled_at: UtcSecond::from_unix_seconds(seconds).unwrap(),
    }
}

fn entries() -> [ApproverEntry; 2] {
    [
        entry("4b0e3d2c-1a9f-4e8d-8c7b-6a5f4e3d2c1b", true, "backup passphrase", 1_794_132_764),
        entry("8d1c6f0e-2b7a-4c59-9e3d-5a4b3c2d1e0f", false, "approval passphrase", 1_793_958_553),
    ]
}

/// The example in `design/approval-signers.md`, "`approver list`", byte for byte.
#[test]
fn the_output_matches_the_design_example() {
    assert_eq!(
        render(&entries()),
        "\
4b0e3d2c-1a9f-4e8d-8c7b-6a5f4e3d2c1b  software  2026-11-08T10:12:44Z  active  backup passphrase
8d1c6f0e-2b7a-4c59-9e3d-5a4b3c2d1e0f  software  2026-11-06T09:49:13Z  -       approval passphrase
"
    );
}

#[test]
fn the_output_is_identical_across_runs() {
    assert_eq!(render(&entries()), render(&entries()));
}

#[test]
fn no_entries_print_nothing() {
    assert_eq!(render(&[]), "");
}
