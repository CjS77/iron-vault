use iron_vault_store::UtcSecond;

use super::*;

const KEY: &str = "age1csc5wgcsw68jdz8uxh9sramjkys02nk8qf740lpywzvlzm9pjf7qxffk4e";

fn checked(days: u64, due: bool) -> RecoveryStatus {
    RecoveryStatus::Checked {
        last_checked: UtcSecond::from_unix_seconds(1_800_000_000).unwrap(),
        days,
        due,
    }
}

#[test]
fn a_healthy_vault_prints_the_checks_then_the_guidance_and_no_warning() {
    let recovery = checked(37, false);
    let out = render(KEY, None, &recovery);
    assert!(out.starts_with(&format!("{KEY} is not a recipient of this vault.")));
    assert!(out.contains("\nindependence rule: holds\nrecovery last checked: 2027-01-15 (37 days ago)\n\n"));
    assert!(out.ends_with(GUIDANCE));
    assert!(warnings(None, &recovery).is_empty());
}

#[test]
fn the_guidance_names_the_host_unlock_steps_and_the_lost_machine_case() {
    [
        "systemd-cryptenroll",
        "LoadCredentialEncrypted|SetCredentialEncrypted|ImportCredential",
        "/run/credstore.encrypted",
        "/usr/local/lib/credstore.encrypted",
        "tpm2_getcap handles-persistent",
        "tpm2_getcap handles-nv-index",
        "/etc/iron-vault-host/host-unlock.cred",
        "tpm2_clear",
        "iron-vault replace NAME --origin ORIGIN",
        "On the vault that stays",
    ]
    .iter()
    .for_each(|needle| assert!(GUIDANCE.contains(needle), "guidance lacks {needle}"));
}

#[test]
fn an_overdue_recovery_check_is_a_warning_and_the_guidance_still_prints() {
    let recovery = checked(97, true);
    let warned = warnings(None, &recovery);
    assert_eq!(warned.len(), 1);
    assert!(warned[0].contains("overdue") && warned[0].contains("recovery check"));
    assert!(render(KEY, None, &recovery).contains("97 days ago, overdue"));
    assert!(render(KEY, None, &recovery).ends_with(GUIDANCE));
}

#[test]
fn a_never_checked_or_unknown_recovery_record_is_a_warning_even_when_no_reminder_is_due() {
    let never = RecoveryStatus::NeverChecked {
        since: UtcSecond::from_unix_seconds(1_800_000_000).unwrap(),
        days: 3,
        due: false,
    };
    let unknown = RecoveryStatus::Unknown {
        detail: "no check record yet".to_owned(),
        due: false,
    };
    [(never, "has never run"), (unknown, "is not on record")]
        .iter()
        .for_each(|(recovery, state)| {
            let warned = warnings(None, recovery);
            assert_eq!(warned.len(), 1, "{recovery:?}");
            assert!(
                warned[0].contains(state) && warned[0].contains("iron-vault recovery check"),
                "{warned:?}"
            );
        });
}

#[test]
fn a_broken_independence_rule_is_a_warning_that_names_the_part() {
    let recovery = checked(1, false);
    let part = "the vault would be left with no recovery recipient";
    assert!(render(KEY, Some(part), &recovery).contains(&format!("independence rule: BROKEN ({part})")));
    assert_eq!(warnings(Some(part), &recovery).len(), 1);
}

#[test]
fn the_output_is_the_same_every_time() {
    let recovery = checked(5, false);
    assert_eq!(render(KEY, None, &recovery), render(KEY, None, &recovery));
}

#[test]
fn no_line_of_the_guidance_is_over_the_width_limit() {
    GUIDANCE.lines().for_each(|line| assert!(line.chars().count() <= 140, "{line}"));
}
