//! `iron-vault approver list` output: one line per approver, from the service's list. Pure, so the same list always prints
//! the same bytes. It holds approver IDs, kinds, times and owner labels only, so it cannot print a secret.

use iron_vault::admin::protocol::ApproverEntry;

/// The width the kind is padded to: the longest kind name, `hardware`.
const KIND_WIDTH: usize = 8;
/// The width the active marker is padded to: `active`.
const ACTIVE_WIDTH: usize = 6;

/// The entries as the lines `approver list` prints, each ending in a newline:
/// `<id>  <kind padded to 8>  <YYYY-MM-DDTHH:MM:SSZ>  <active|- padded to 6>  <label>`. A label is valid on construction, but
/// the service's text is shown to a terminal, so control characters are dropped here too.
pub fn render(entries: &[ApproverEntry]) -> String {
    entries.iter().map(|entry| format!("{}\n", line(entry))).collect()
}

fn line(entry: &ApproverEntry) -> String {
    let label: String = entry.label.as_str().chars().filter(|c| !c.is_control()).collect();
    format!(
        "{}  {:<KIND_WIDTH$}  {}  {:<ACTIVE_WIDTH$}  {label}",
        entry.id,
        entry.kind.name(),
        entry.enrolled_at,
        if entry.active { "active" } else { "-" },
    )
}

#[cfg(test)]
mod tests;
