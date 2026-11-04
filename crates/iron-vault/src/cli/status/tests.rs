use iron_vault::hardening::MemoryProtection;
use iron_vault_store::{RecordDamage, VaultId};

use super::*;

const FX_SECRET: &str = "fx-secret-4b1d";

fn credential(name: &str, standing: Standing, routes: &[&str]) -> CredentialStatus {
    CredentialStatus {
        name: name.parse().unwrap(),
        standing,
        unavailable_routes: routes.iter().map(|route| route.parse().unwrap()).collect(),
    }
}

fn ready(credentials: Vec<CredentialStatus>) -> StatusReport {
    StatusReport {
        state: ServiceState::Ready,
        profile: DeploymentProfile::Protected,
        vault: VaultStatus::Unlocked(UnlockedVault {
            id: VaultId::from_bytes(*b"\x11\x11\x11\x11\x11\x11\x41\x11\x91\x11\x11\x11\x11\x11\x11\x11").unwrap(),
            committed: Some(3),
            highest_reserved: 4,
            credentials,
        }),
        memory: MemoryStatus::Locked,
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
    let text = render(&locked(ServiceState::Locked), "alice");
    let lines = text.lines().collect::<Vec<_>>();
    assert_eq!(lines[0], "service: locked");
    assert_eq!(lines[1], "profile: protected");
    assert_eq!(lines[2..4], ["vault: locked", "vault id: unknown"]);
    assert!(lines[4].ends_with("unknown while the vault is locked"), "{text}");
    assert!(lines[5].ends_with("unknown while the vault is locked"), "{text}");
    assert_eq!(lines[7], "credentials: unknown while the vault is locked");
}

#[test]
fn an_unavailable_service_names_its_redacted_reason() {
    [
        (FailureReason::PolicyInvalid, "policy invalid"),
        (FailureReason::RecoveryNeeded, "recovery needed"),
    ]
    .into_iter()
    .for_each(|(failure, reason)| {
        let text = render(&locked(ServiceState::Unavailable(failure)), "alice");
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
    let text = render(&ready(credentials), "alice");
    assert_eq!(
        text,
        "service: ready\n\
         profile: protected\n\
         vault: unlocked\n\
         vault id: 11111111-1111-4111-9111-111111111111\n\
         approval committed: 3\n\
         approval highest reserved: 4\n\
         memory protection: locked against swap\n\
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
    let text = render(&report, "alice");
    assert!(text.contains("approval committed: none\n"), "{text}");
    assert!(text.ends_with("credentials: none\n"), "{text}");
}

#[test]
fn the_development_profile_line_is_exact() {
    let report = StatusReport {
        profile: DeploymentProfile::Development,
        ..ready(Vec::new())
    };
    let text = render(&report, "alice");
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
    let lines = reports.map(|report| render(&report, "alice").lines().nth(6).unwrap_or_default().to_owned());
    assert_eq!(lines[0], "memory protection: locked against swap");
    lines[1..].iter().for_each(|line| {
        assert!(line.starts_with("memory protection: NOT protected"), "{line}");
        assert!(!line.contains("locked"), "{line}");
    });
}

#[test]
fn rendering_twice_gives_the_same_bytes_and_never_a_secret() {
    let report = ready(vec![credential("fx", Standing::Damaged(RecordDamage::Substituted), &["fx"])]);
    let first = render(&report, "alice");
    assert_eq!(first, render(&report, "alice"));
    assert!(!first.contains(FX_SECRET));
}
