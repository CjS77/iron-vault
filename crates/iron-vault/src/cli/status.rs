//! `iron-vault status` output: one field per line, in a fixed order, from the service's status report. Pure, so the same
//! report always prints the same bytes.

use iron_vault::admin::protocol::{CredentialStatus, MemoryStatus, Standing, StatusReport, UnlockedVault, VaultStatus};
use iron_vault::deployment::{DeploymentProfile, no_isolation_warning};
use iron_vault::service_state::{FailureReason, ServiceState, UnavailableReason};

/// What a value sealed behind the vault identity shows while the vault is locked.
const UNKNOWN: &str = "unknown while the vault is locked";

/// The report as the lines `status` prints, each ending in a newline. `user` is the account the CLI runs as, which in the
/// development profile is the service account too.
pub fn render(report: &StatusReport, user: &str) -> String {
    let mut lines = service_lines(report.state);
    lines.push(profile_line(report.profile, user));
    lines.extend(vault_lines(&report.vault));
    lines.push(memory_line(&report.memory));
    lines.extend(credential_lines(&report.vault));
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

fn profile_line(profile: DeploymentProfile, user: &str) -> String {
    match profile {
        DeploymentProfile::Protected => "profile: protected".to_owned(),
        DeploymentProfile::Development => format!("profile: development — {}", no_isolation_warning(user)),
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

/// Only `Locked` claims swap protection.
fn memory_line(memory: &MemoryStatus) -> String {
    match memory {
        MemoryStatus::Locked => "memory protection: locked against swap".to_owned(),
        MemoryStatus::Unavailable(why) => format!("memory protection: NOT protected, swap protection unavailable ({why})"),
        MemoryStatus::Unsupported => "memory protection: NOT protected, unsupported on this platform".to_owned(),
    }
}

fn credential_lines(vault: &VaultStatus) -> Vec<String> {
    match vault {
        VaultStatus::Locked => vec![format!("credentials: {UNKNOWN}")],
        VaultStatus::Unlocked(unlocked) if unlocked.credentials.is_empty() => vec!["credentials: none".to_owned()],
        VaultStatus::Unlocked(unlocked) => unlocked.credentials.iter().map(credential_line).collect(),
    }
}

fn credential_line(credential: &CredentialStatus) -> String {
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
