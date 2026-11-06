//! `iron-vault status` output: one field per line, in a fixed order, from the service's status report. Pure, so the same
//! report always prints the same bytes.

use iron_vault::admin::protocol::{MemoryStatus, RecoveryStatus, StatusReport, UnlockedVault, VaultStatus};
use iron_vault::deployment::{DeploymentProfile, no_isolation_warning};
use iron_vault::service_state::{FailureReason, ServiceState, UnavailableReason};
use iron_vault::standing::{CredentialStanding, RouteFault, Standing};
use iron_vault_store::UtcSecond;

/// What a value sealed behind the vault identity shows while the vault is locked.
const UNKNOWN: &str = "unknown while the vault is locked";

/// The report as the lines `status` prints, each ending in a newline. `user` names the account the CLI runs as, which in
/// the development profile is the service account too; it is called only for that profile's line.
pub fn render(report: &StatusReport, user: impl FnOnce() -> String) -> String {
    let mut lines = service_lines(report.state);
    lines.push(profile_line(report.profile, user));
    lines.extend(vault_lines(&report.vault));
    lines.push(memory_line(&report.memory));
    lines.push(recovery_line(&report.recovery));
    lines.extend(credential_lines(&report.vault));
    lines.extend(route_fault_lines(&report.vault));
    lines.iter().map(|line| format!("{line}\n")).collect()
}

fn service_lines(state: ServiceState) -> Vec<String> {
    match state {
        ServiceState::Starting => vec!["service: starting".to_owned()],
        ServiceState::Locked => vec!["service: locked".to_owned()],
        ServiceState::Checking => vec!["service: checking".to_owned()],
        ServiceState::Ready => vec!["service: ready".to_owned()],
        ServiceState::Stopped => vec!["service: stopped".to_owned()],
        ServiceState::Unavailable(reason) => vec!["service: unavailable".to_owned(), format!("reason: {}", reason_text(reason))],
    }
}

fn reason_text(reason: FailureReason) -> &'static str {
    UnavailableReason::from_failure(reason).as_str()
}

fn profile_line(profile: DeploymentProfile, user: impl FnOnce() -> String) -> String {
    match profile {
        DeploymentProfile::Protected => "profile: protected".to_owned(),
        DeploymentProfile::Container => "profile: container".to_owned(),
        DeploymentProfile::Development => format!("profile: development — {}", no_isolation_warning(&user())),
    }
}

fn vault_lines(vault: &VaultStatus) -> [String; 4] {
    match vault {
        VaultStatus::Locked => [
            "vault: locked".to_owned(),
            "vault id: unknown".to_owned(),
            format!("approval committed: {UNKNOWN}"),
            format!("approval highest reserved: {UNKNOWN}"),
        ],
        VaultStatus::NotInitialized => closed_vault("not initialized (run iron-vault init)"),
        VaultStatus::InitializationUnfinished => closed_vault("initialization unfinished (run iron-vault init again)"),
        VaultStatus::Unlocked(UnlockedVault {
            id,
            committed,
            highest_reserved,
            ..
        }) => [
            "vault: unlocked".to_owned(),
            format!("vault id: {id}"),
            format!(
                "approval committed: {}",
                committed.map_or_else(|| "none".to_owned(), |version| version.to_string())
            ),
            format!("approval highest reserved: {highest_reserved}"),
        ],
    }
}

/// The lines for a vault that is not open and is not merely locked: its sealed values are unknown as for a locked one.
fn closed_vault(what: &str) -> [String; 4] {
    [
        format!("vault: {what}"),
        "vault id: unknown".to_owned(),
        format!("approval committed: {UNKNOWN}"),
        format!("approval highest reserved: {UNKNOWN}"),
    ]
}

/// Only `Locked` claims swap protection.
fn memory_line(memory: &MemoryStatus) -> String {
    match memory {
        MemoryStatus::Locked => "memory protection: locked against swap".to_owned(),
        MemoryStatus::Unavailable(why) => format!("memory protection: NOT protected, swap protection unavailable ({why})"),
        MemoryStatus::Unsupported => "memory protection: NOT protected, unsupported on this platform".to_owned(),
    }
}

/// The recovery check line. The service counted the days and decided the due flag, so this reads no clock.
fn recovery_line(recovery: &RecoveryStatus) -> String {
    let overdue = |due: bool| if due { ", overdue" } else { "" };
    let text = match recovery {
        RecoveryStatus::Unknown { detail, due } => format!("unknown ({detail}{})", overdue(*due)),
        RecoveryStatus::NeverChecked { since, due, .. } => {
            format!("never (reminders counting since {}{})", date(*since), overdue(*due))
        }
        RecoveryStatus::Checked { last_checked, days, due } => {
            format!("{} ({}{})", date(*last_checked), days_ago(*days), overdue(*due))
        }
    };
    format!("recovery last checked: {text}")
}

/// The UTC date of a time: the first ten characters of its RFC 3339 form.
fn date(time: UtcSecond) -> String {
    time.to_string().chars().take(10).collect()
}

fn days_ago(days: u64) -> String {
    match days {
        0 => "today".to_owned(),
        1 => "1 day ago".to_owned(),
        n => format!("{n} days ago"),
    }
}

fn credential_lines(vault: &VaultStatus) -> Vec<String> {
    match vault {
        VaultStatus::Locked | VaultStatus::NotInitialized | VaultStatus::InitializationUnfinished => {
            vec![format!("credentials: {UNKNOWN}")]
        }
        VaultStatus::Unlocked(unlocked) if unlocked.credentials.is_empty() => vec!["credentials: none".to_owned()],
        VaultStatus::Unlocked(unlocked) => unlocked.credentials.iter().map(credential_line).collect(),
    }
}

/// One line per route fault; nothing while the vault is locked or no route has one.
fn route_fault_lines(vault: &VaultStatus) -> Vec<String> {
    match vault {
        VaultStatus::Locked | VaultStatus::NotInitialized | VaultStatus::InitializationUnfinished => Vec::new(),
        VaultStatus::Unlocked(unlocked) => unlocked.route_faults.iter().map(route_fault_line).collect(),
    }
}

fn route_fault_line(route: &RouteFault) -> String {
    format!("route {}: unavailable ({})", route.name, route.kind)
}

fn credential_line(credential: &CredentialStanding) -> String {
    let name = &credential.name;
    match credential.standing {
        Standing::Healthy => format!("credential {name}: healthy"),
        Standing::Damaged(damage) => {
            let routes = credential
                .unavailable_routes
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            let routes = if routes.is_empty() { "none".to_owned() } else { routes };
            format!("credential {name}: damaged ({damage}); unavailable routes: {routes}")
        }
    }
}

#[cfg(test)]
mod tests;
