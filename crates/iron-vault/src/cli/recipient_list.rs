// SPDX-License-Identifier: MPL-2.0
//! `iron-vault recipient list` output: one line per recipient, from the service's list. Pure, so the same inventory always
//! prints the same bytes. It holds public keys, roles, times and owner labels only, so it cannot print a secret.

use iron_vault_store::RecipientEntry;

/// The width the role is padded to: the longest role name, `operational`.
const ROLE_WIDTH: usize = 11;

/// The entries as the lines `recipient list` prints, each ending in a newline:
/// `<age1... key>  <role padded to 11>  <YYYY-MM-DDTHH:MM:SSZ>  <label>`. A label is valid on construction, but the
/// service's text is shown to a terminal, so control characters are dropped here too.
pub fn render(entries: &[RecipientEntry]) -> String {
    entries.iter().map(|entry| format!("{}\n", line(entry))).collect()
}

/// One recipient's line, without its newline.
fn line(entry: &RecipientEntry) -> String {
    let label: String = entry.label().as_str().chars().filter(|c| !c.is_control()).collect();
    format!(
        "{}  {:<ROLE_WIDTH$}  {}  {label}",
        entry.key(),
        entry.role().name(),
        entry.enrolled_at()
    )
}

#[cfg(test)]
mod tests;
