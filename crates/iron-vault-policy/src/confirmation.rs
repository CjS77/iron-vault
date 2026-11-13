// SPDX-License-Identifier: MPL-2.0
//! A route's owner-confirmation policy: whether each request needs fresh owner confirmation
//! ([spec §6](../../../design/iron-vault-specification.md#6-credential-records-and-configuration)).
//!
//! v0 has no confirmation provider, so reading a config refuses `confirm = "touch"`.

use serde::Deserialize;
use serde::de::{Deserializer, Error as _};

/// The refusal for `confirm = "touch"`, which v0 names but cannot honour
/// ([spec §6](../../../design/iron-vault-specification.md#6-credential-records-and-configuration)).
const TOUCH_NOT_YET_AVAILABLE: &str = r#"confirm = "touch" is not yet available: v0 has no touch confirmation provider"#;

/// Says if a request on a route needs fresh owner confirmation before its credential is used.
///
/// TOML form: `confirm = "none"`, which is also the value when `confirm` is omitted. Reading the config refuses
/// `confirm = "touch"`: per-request touch on a hardware key arrives in a later phase
/// ([future spec §2.1](../../../design/future-specifications.md#21-hardware-key-recipients-signers-and-touch-confirmation),
/// [roadmap](../../../book/src/cookbook/roadmap/yubikey.md)). Until a confirmation provider exists a touch route
/// could never serve, so the refusal comes before any approval prompt
/// ([spec §6](../../../design/iron-vault-specification.md#6-credential-records-and-configuration)).
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
