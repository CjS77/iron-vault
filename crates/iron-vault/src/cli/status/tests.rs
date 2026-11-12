use iron_vault::hardening::MemoryProtection;
use iron_vault::service_context::HostUnlockOutcome;
use iron_vault::standing::RouteFaultKind;
use iron_vault_store::{RecordDamage, UtcSecond, VaultId};

use super::*;

fn alice() -> String {
    "alice".to_owned()
}

fn credential(name: &str, standing: Standing, routes: &[&str]) -> CredentialStanding {
    CredentialStanding {
        name: name.parse().unwrap(),
        standing,
        unavailable_routes: routes.iter().map(|route| route.parse().unwrap()).collect(),
        summary: None,
    }
}

fn ready(credentials: Vec<CredentialStanding>) -> StatusReport {
    StatusReport {
        state: ServiceState::Ready,
        profile: DeploymentProfile::Protected,
        vault: VaultStatus::Unlocked(UnlockedVault {
            id: VaultId::from_bytes(*b"\x11\x11\x11\x11\x11\x11\x41\x11\x91\x11\x11\x11\x11\x11\x11\x11").unwrap(),
            committed: Some(3),
            highest_reserved: 4,
            credentials,
            route_faults: Vec::new(),
        }),
        memory: MemoryStatus::Locked,
        host_unlock_outcome: None,
        listener_failures: Vec::new(),
        recovery: RecoveryStatus::Unknown {
            detail: "no check record yet".to_owned(),
            due: false,
        },
    }
}

fn locked(state: ServiceState) -> StatusReport {
    StatusReport {
        state,
        vault: VaultStatus::Locked,
        ..ready(Vec::new())
    }
}

#[test]
fn a_locked_service_shows_what_is_sealed_as_unknown() {
    let text = render(&locked(ServiceState::Locked), alice);
    let lines = text.lines().collect::<Vec<_>>();
    assert_eq!(lines[0], "service: locked");
    assert_eq!(lines[1], "profile: protected");
    assert_eq!(lines[2..4], ["vault: locked", "vault id: unknown"]);
    assert!(lines[4].ends_with("unknown while the vault is locked"), "{text}");
    assert!(lines[5].ends_with("unknown while the vault is locked"), "{text}");
    assert_eq!(lines[7], "recovery last checked: unknown (no check record yet)");
    assert_eq!(lines[8], "credentials: unknown while the vault is locked");
}

#[test]
fn an_unavailable_service_names_its_redacted_reason() {
    [
        (FailureReason::PolicyInvalid, "policy invalid"),
        (FailureReason::RecoveryNeeded, "recovery needed"),
    ]
    .into_iter()
    .for_each(|(failure, reason)| {
        let text = render(&locked(ServiceState::Unavailable(failure)), alice);
        assert_eq!(
            text.lines().take(2).collect::<Vec<_>>(),
            ["service: unavailable", &format!("reason: {reason}")]
        );
    });
}

#[test]
fn a_ready_service_lists_each_credential_in_the_order_given() {
    let credentials = vec![
        credential("brave", Standing::Damaged(RecordDamage::Missing), &["brave", "brave-alt"]),
        credential("fx", Standing::Healthy, &[]),
        credential("venice", Standing::Damaged(RecordDamage::Unreadable), &[]),
    ];
    let text = render(&ready(credentials), alice);
    assert_eq!(
        text,
        "service: ready\n\
         profile: protected\n\
         vault: unlocked\n\
         vault id: 11111111-1111-4111-9111-111111111111\n\
         approval committed: 3\n\
         approval highest reserved: 4\n\
         memory protection: locked against swap\n\
         recovery last checked: unknown (no check record yet)\n\
         credential brave: damaged (missing); unavailable routes: brave, brave-alt\n\
         credential fx: healthy\n\
         credential venice: damaged (unreadable); unavailable routes: none\n"
    );
}

#[test]
fn no_credentials_and_no_approval_are_shown_as_none() {
    let mut report = ready(Vec::new());
    if let VaultStatus::Unlocked(vault) = &mut report.vault {
        vault.committed = None;
    }
    let text = render(&report, alice);
    assert!(text.contains("approval committed: none\n"), "{text}");
    assert!(text.ends_with("credentials: none\n"), "{text}");
}

#[test]
fn the_development_profile_line_is_exact() {
    let report = StatusReport {
        profile: DeploymentProfile::Development,
        ..ready(Vec::new())
    };
    let text = render(&report, alice);
    assert_eq!(
        text.lines().nth(1),
        Some("profile: development — no isolation from malware running as alice")
    );
}

#[test]
fn only_locked_memory_claims_swap_protection() {
    let reports = [
        MemoryStatus::from(&MemoryProtection::Locked),
        MemoryStatus::Unavailable("mlockall failed: Cannot allocate memory".to_owned()),
        MemoryStatus::Unsupported,
    ]
    .map(|memory| StatusReport {
        memory,
        ..ready(Vec::new())
    });
    let lines = reports.map(|report| render(&report, alice).lines().nth(6).unwrap_or_default().to_owned());
    assert_eq!(lines[0], "memory protection: locked against swap");
    lines[1..].iter().for_each(|line| {
        assert!(line.starts_with("memory protection: NOT protected"), "{line}");
        assert!(!line.contains("locked"), "{line}");
    });
}

#[test]
fn rendering_twice_gives_the_same_bytes() {
    let report = ready(vec![credential("fx", Standing::Damaged(RecordDamage::Substituted), &["fx"])]);
    assert_eq!(render(&report, alice), render(&report, alice));
}

#[test]
fn the_protected_profile_never_asks_for_the_user_name() {
    let text = render(&ready(Vec::new()), || panic!("the protected profile names no user"));
    assert_eq!(text.lines().nth(1), Some("profile: protected"));
}

#[test]
fn each_route_fault_follows_the_credentials() {
    let mut report = ready(vec![credential("fx", Standing::Healthy, &[])]);
    if let VaultStatus::Unlocked(vault) = &mut report.vault {
        vault.route_faults = ["internal", "lab"]
            .iter()
            .map(|route| RouteFault {
                name: route.parse().unwrap(),
                kind: RouteFaultKind::PinnedCaUnavailable,
            })
            .collect();
    }
    let text = render(&report, alice);
    assert!(
        text.ends_with(
            "credential fx: healthy\n\
             route internal: unavailable (pinned CA unavailable)\n\
             route lab: unavailable (pinned CA unavailable)\n"
        ),
        "{text}"
    );
}

#[test]
fn an_uninitialized_or_unfinished_vault_says_what_to_run() {
    [
        (VaultStatus::NotInitialized, "vault: not initialized (run iron-vault init)"),
        (
            VaultStatus::InitializationUnfinished,
            "vault: initialization unfinished (run iron-vault init again)",
        ),
        (
            VaultStatus::ImportUnfinished,
            "vault: import unfinished (run iron-vault import again)",
        ),
    ]
    .into_iter()
    .for_each(|(vault, line)| {
        let report = StatusReport {
            vault,
            ..locked(ServiceState::Locked)
        };
        let text = render(&report, alice);
        assert_eq!(text.lines().nth(2), Some(line), "{text}");
        assert_eq!(render(&report, alice), text);
    });
}

fn recovery_line_of(recovery: RecoveryStatus) -> String {
    let report = StatusReport {
        recovery,
        ..ready(Vec::new())
    };
    let text = render(&report, alice);
    text.lines().nth(7).unwrap_or_default().to_owned()
}

fn at(date_seconds: u64) -> UtcSecond {
    UtcSecond::from_unix_seconds(date_seconds).unwrap()
}

/// 2027-02-01T00:00:00Z.
const FEBRUARY_FIRST: u64 = 1_801_440_000;

#[test]
fn every_recovery_form_and_due_state_gives_its_exact_line() {
    let checked = |days, due| RecoveryStatus::Checked {
        last_checked: at(FEBRUARY_FIRST + 3_600),
        days,
        due,
    };
    let never = |due| RecoveryStatus::NeverChecked {
        since: at(1_793_000_000),
        days: 12,
        due,
    };
    let unknown = |detail: &str, due| RecoveryStatus::Unknown {
        detail: detail.to_owned(),
        due,
    };
    [
        (checked(37, false), "recovery last checked: 2027-02-01 (37 days ago)"),
        (checked(97, true), "recovery last checked: 2027-02-01 (97 days ago, overdue)"),
        (checked(0, false), "recovery last checked: 2027-02-01 (today)"),
        (checked(1, false), "recovery last checked: 2027-02-01 (1 day ago)"),
        (never(false), "recovery last checked: never (reminders counting since 2026-10-26)"),
        (
            never(true),
            "recovery last checked: never (reminders counting since 2026-10-26, overdue)",
        ),
        (
            unknown("the vault is not initialized", false),
            "recovery last checked: unknown (the vault is not initialized)",
        ),
        (
            unknown("the check record is unusable (not_toml)", true),
            "recovery last checked: unknown (the check record is unusable (not_toml), overdue)",
        ),
    ]
    .into_iter()
    .for_each(|(recovery, line)| assert_eq!(recovery_line_of(recovery), line));
}

#[test]
fn the_host_unlock_outcome_follows_memory_protection_and_only_when_there_is_one() {
    let line = |outcome| {
        let report = StatusReport {
            host_unlock_outcome: outcome,
            ..locked(ServiceState::Locked)
        };
        let text = render(&report, alice);
        (text.lines().nth(6).map(str::to_owned), text.lines().nth(7).map(str::to_owned))
    };
    let (memory, host) = line(Some(HostUnlockOutcome::UnsealFailed));
    assert_eq!(memory.as_deref(), Some("memory protection: locked against swap"));
    assert_eq!(host.as_deref(), Some("host unlock: unseal_failed"));
    assert_eq!(line(Some(HostUnlockOutcome::Unlocked)).1.as_deref(), Some("host unlock: unlocked"));
    assert_eq!(
        line(Some(HostUnlockOutcome::OwnerLocked)).1.as_deref(),
        Some("host unlock: owner_locked")
    );
    assert!(!line(None).1.unwrap_or_default().starts_with("host unlock"));
}

#[test]
fn listeners_not_open_print_one_line_each_and_nothing_when_all_are_open() {
    use iron_vault::listener_failure::ListenerFailureReason;

    assert!(!render(&ready(Vec::new()), alice).contains("Listeners not open"));
    let report = StatusReport {
        listener_failures: vec![ListenerFailure {
            name: "wide".parse().unwrap(),
            reason: ListenerFailureReason::TlsKeyMismatch,
        }],
        ..ready(Vec::new())
    };
    let text = render(&report, alice);
    let lines = text.lines().skip_while(|line| *line != "Listeners not open:").collect::<Vec<_>>();
    assert_eq!(
        lines,
        [
            "Listeners not open:",
            "  wide: the TLS key does not match the certificate (tls-key-mismatch)"
        ]
    );
}
