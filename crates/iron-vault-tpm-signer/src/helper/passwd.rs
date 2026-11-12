//! Looks up the uid of the one account the helper answers, by default the service account `iron-vault`.
//!
//! The helper reads `/etc/passwd` directly, where the package's `sysusers.d` file puts the service account, rather
//! than going through NSS.

use anyhow::Context;

/// Returns the uid of account `name` in `/etc/passwd`.
pub fn uid_of(name: &str) -> anyhow::Result<u32> {
    let passwd = std::fs::read_to_string("/etc/passwd").context("reading /etc/passwd")?;
    passwd
        .lines()
        .find_map(|line| uid_in_line(line, name))
        .with_context(|| format!("no account {name:?} in /etc/passwd"))
}

/// Returns the uid on a `name:password:uid:…` line, or `None` when the line is for another account or its uid is not a number.
fn uid_in_line(line: &str, name: &str) -> Option<u32> {
    let mut fields = line.split(':');
    match fields.next() == Some(name) {
        true => fields.nth(1)?.parse().ok(),
        false => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_uid_is_the_third_field_of_the_named_line() {
        assert_eq!(uid_in_line("iron-vault:x:996:996::/:/usr/sbin/nologin", "iron-vault"), Some(996));
        assert_eq!(uid_in_line("iron-vault-tpm:x:995:995::/:/usr/sbin/nologin", "iron-vault"), None);
        assert_eq!(uid_in_line("iron-vault:x:abc:996::/:", "iron-vault"), None);
    }
}
