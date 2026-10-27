//! A route's owner-confirmation policy (spec §2, §3.3, §5.1).

use serde::Deserialize;

/// Whether a request on a route needs fresh owner confirmation before its credential is used.
///
/// TOML form: `confirm = "touch"`. Omitting `confirm` means [`Confirmation::None`]; `confirm = "none"` is also
/// accepted so a configuration can state it explicitly. Parsing `touch` always succeeds: v0 has no touch provider,
/// and route activation, not parsing, refuses it so the error names the route (spec §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confirmation {
    /// No confirmation; the route's other restrictions still apply.
    #[default]
    None,
    /// A fresh hardware-key touch for each request (spec §5.1).
    Touch,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct Route {
        #[serde(default)]
        confirm: Confirmation,
    }

    fn parse(s: &str) -> Result<Confirmation, toml::de::Error> {
        toml::from_str::<Route>(s).map(|r| r.confirm)
    }

    #[test]
    fn omitted_means_none() {
        assert_eq!(parse("").unwrap(), Confirmation::None);
    }

    #[test]
    fn explicit_values_parse() {
        assert_eq!(parse(r#"confirm = "none""#).unwrap(), Confirmation::None);
        assert_eq!(parse(r#"confirm = "touch""#).unwrap(), Confirmation::Touch);
    }

    #[test]
    fn unknown_values_are_rejected() {
        ["\"Touch\"", "\"pin\"", "\"\"", "true"].iter().for_each(|v| assert!(parse(&format!("confirm = {v}")).is_err(), "{v}"));
    }
}
