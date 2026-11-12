//! A route's owner-confirmation policy (spec §6, future spec §2.1).

use serde::Deserialize;
use serde::de::{Deserializer, Error as _};

/// The refusal for `confirm = "touch"`, which v0 names but cannot honour (spec §6).
const TOUCH_NOT_YET_AVAILABLE: &str = r#"confirm = "touch" is not yet available: v0 has no touch confirmation provider"#;

/// Whether a request on a route needs fresh owner confirmation before its credential is used.
///
/// TOML form: `confirm = "none"`, which is also the value when `confirm` is omitted. `touch` is named but refused when
/// the config is read: a later phase adds per-request touch on a hardware key (`book/src/cookbook/roadmap/yubikey.md`),
/// and until a confirmation provider exists a touch route could never serve, so it is a mistake caught before any
/// approval prompt rather than a route left unavailable (spec §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Confirmation {
    /// No confirmation; the route's other restrictions still apply.
    #[default]
    None,
}

/// The values `confirm` accepts, as serde's unknown-variant refusal lists them.
const ACCEPTED: &[&str] = &["none"];

impl<'de> Deserialize<'de> for Confirmation {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        match value.as_str() {
            "none" => Ok(Self::None),
            "touch" => Err(D::Error::custom(TOUCH_NOT_YET_AVAILABLE)),
            other => Err(D::Error::unknown_variant(other, ACCEPTED)),
        }
    }
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
    fn explicit_none_parses() {
        assert_eq!(parse(r#"confirm = "none""#).unwrap(), Confirmation::None);
    }

    #[test]
    fn touch_is_refused_as_not_yet_available() {
        let err = parse(r#"confirm = "touch""#).unwrap_err();
        assert_eq!(err.message(), TOUCH_NOT_YET_AVAILABLE);
    }

    #[test]
    fn other_values_get_the_unknown_variant_refusal() {
        let err = parse(r#"confirm = "always""#).unwrap_err();
        assert_eq!(err.message(), "unknown variant `always`, expected `none`");
    }

    #[test]
    fn unknown_values_are_rejected() {
        ["\"Touch\"", "\"pin\"", "\"\"", "true"]
            .iter()
            .for_each(|v| assert!(parse(&format!("confirm = {v}")).is_err(), "{v}"));
    }
}
