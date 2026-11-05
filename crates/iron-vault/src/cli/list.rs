//! `iron-vault list` output: one line per credential, from the service's list. Pure, so the same list always prints the
//! same bytes. It holds names, kinds, hosts and standing only, so it cannot print a secret.

use iron_vault::standing::{CredentialStanding, RecordSummary, Standing};

/// What `list` prints while no vault is open.
const LOCKED: &str = "credentials: unknown while the vault is locked";

/// The list as the lines `list` prints, each ending in a newline: `<name>  <kind>  <host:port,...>  <standing>`. A
/// damaged record has no known kind or hosts, so those print as `unknown`. `None` is no open vault.
pub fn render(credentials: Option<&[CredentialStanding]>) -> String {
    match credentials {
        None => format!("{LOCKED}\n"),
        Some(credentials) => credentials.iter().map(|credential| format!("{}\n", line(credential))).collect(),
    }
}

fn line(credential: &CredentialStanding) -> String {
    let (kind, hosts) = credential.summary.as_ref().map_or_else(
        || ("unknown".to_owned(), "unknown".to_owned()),
        |summary| (summary.kind.as_str().to_owned(), hosts(summary)),
    );
    format!("{}  {kind}  {hosts}  {}", credential.name, standing_text(credential.standing))
}

fn hosts(summary: &RecordSummary) -> String {
    let origins = summary.origins.iter().map(|(host, port)| format!("{host}:{}", port.get()));
    origins.collect::<Vec<_>>().join(",")
}

fn standing_text(standing: Standing) -> String {
    match standing {
        Standing::Healthy => "healthy".to_owned(),
        Standing::Damaged(damage) => format!("damaged ({damage})"),
    }
}

#[cfg(test)]
mod tests;
