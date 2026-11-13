// SPDX-License-Identifier: MPL-2.0
use iron_vault_store::{RecipientLabel, RecipientRole, UtcSecond};

use super::*;

fn entry(key: &str, role: RecipientRole, label: &str, seconds: u64) -> RecipientEntry {
    RecipientEntry::new(
        key.parse().unwrap(),
        role,
        RecipientLabel::new(label).unwrap(),
        UtcSecond::from_unix_seconds(seconds).unwrap(),
    )
}

/// The example in `design/recipients.md`, "`recipient list`", byte for byte.
#[test]
fn the_output_matches_the_design_example() {
    let entries = [
        entry(
            "age1csc5wgcsw68jdz8uxh9sramjkys02nk8qf740lpywzvlzm9pjf7qxffk4e",
            RecipientRole::Recovery,
            "recovery key",
            1_793_958_553,
        ),
        entry(
            "age1jy4a0t77ngkqdm42qqd3xuja9zrjsy6f62u49qw06tza9z9rxpxqwf95ly",
            RecipientRole::Operational,
            "vault passphrase",
            1_793_958_553,
        ),
        entry(
            "age1v4q6gqhc84l6yrmyeqcske956a65frdww5rc4jnrdfhkpsdglqksx4muhw",
            RecipientRole::Added,
            "bob's new laptop",
            1_794_060_171,
        ),
    ];

    assert_eq!(
        render(&entries),
        "\
age1csc5wgcsw68jdz8uxh9sramjkys02nk8qf740lpywzvlzm9pjf7qxffk4e  recovery     2026-11-06T09:49:13Z  recovery key
age1jy4a0t77ngkqdm42qqd3xuja9zrjsy6f62u49qw06tza9z9rxpxqwf95ly  operational  2026-11-06T09:49:13Z  vault passphrase
age1v4q6gqhc84l6yrmyeqcske956a65frdww5rc4jnrdfhkpsdglqksx4muhw  added        2026-11-07T14:02:51Z  bob's new laptop
"
    );
}

#[test]
fn no_entries_print_nothing() {
    assert_eq!(render(&[]), "");
}
