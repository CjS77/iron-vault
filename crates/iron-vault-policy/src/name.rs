//! Validated configuration names for callers, routes, listeners, and credentials.
//!
//! Names reach logs and audit events, so every name type shares one strict rule that leaves no room for log
//! injection: 1 to [`MAX_NAME_LEN`] bytes of ASCII `[a-z0-9_-]`, starting with a lowercase letter (spec §3.15).

use std::fmt;
use std::str::FromStr;

use serde::Deserialize;
use thiserror::Error;

/// The longest name, in bytes, that any name type accepts.
pub const MAX_NAME_LEN: usize = 64;

/// The rule a rejected name broke.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NameRule {
    /// The name was empty.
    #[error("must not be empty")]
    Empty,
    /// The name was longer than [`MAX_NAME_LEN`] bytes.
    #[error("is {len} bytes long; the limit is {MAX_NAME_LEN}")]
    TooLong {
        /// Length of the rejected name in bytes.
        len: usize,
    },
    /// The first character was not a lowercase ASCII letter.
    #[error("must start with a lowercase ASCII letter, found {found}")]
    BadStart {
        /// The offending character, escaped so control characters never reach a log raw.
        found: String,
    },
    /// A character outside `[a-z0-9_-]` appeared after the first.
    #[error("may contain only a-z, 0-9, '_' and '-', found {found} at byte {position}")]
    BadChar {
        /// The offending character, escaped so control characters never reach a log raw.
        found: String,
        /// Byte offset of the offending character.
        position: usize,
    },
}

/// A name that failed validation, with the kind of name it was meant to be.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid {kind} name: {rule}")]
pub struct NameError {
    kind: &'static str,
    rule: NameRule,
}

impl NameError {
    /// The kind of name being built, such as `"caller"`.
    pub fn kind(&self) -> &'static str {
        self.kind
    }

    /// The rule the name broke.
    pub fn rule(&self) -> &NameRule {
        &self.rule
    }
}

/// Quotes a character with Rust escapes so control and non-ASCII characters print as visible text.
fn escaped(c: char) -> String {
    format!("'{}'", c.escape_default())
}

fn is_name_char(c: char) -> bool {
    matches!(c, 'a'..='z' | '0'..='9' | '_' | '-')
}

/// Applies the shared name rule, returning the first rule broken.
fn check_name(s: &str) -> Result<(), NameRule> {
    let first = s.chars().next().ok_or(NameRule::Empty)?;
    if s.len() > MAX_NAME_LEN {
        return Err(NameRule::TooLong { len: s.len() });
    }
    if !first.is_ascii_lowercase() {
        return Err(NameRule::BadStart { found: escaped(first) });
    }
    s.char_indices().find(|&(_, c)| !is_name_char(c)).map_or(Ok(()), |(position, c)| {
        Err(NameRule::BadChar {
            found: escaped(c),
            position,
        })
    })
}

/// Defines a distinct name newtype so one kind of name cannot be passed where another is expected.
macro_rules! name_type {
    ($(#[$doc:meta])* $name:ident, $kind:literal) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
        #[serde(try_from = "String")]
        pub struct $name(String);

        impl $name {
            /// The validated name.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<&str> for $name {
            type Error = NameError;

            fn try_from(s: &str) -> Result<Self, Self::Error> {
                check_name(s).map(|()| Self(s.to_owned())).map_err(|rule| NameError { kind: $kind, rule })
            }
        }

        impl TryFrom<String> for $name {
            type Error = NameError;

            fn try_from(s: String) -> Result<Self, Self::Error> {
                check_name(&s).map(|()| Self(s)).map_err(|rule| NameError { kind: $kind, rule })
            }
        }

        impl FromStr for $name {
            type Err = NameError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::try_from(s)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

name_type!(
    /// The configured name of a caller, the authenticated program identity granted named routes (spec §3.3, §3.4).
    CallerName,
    "caller"
);

name_type!(
    /// The configured name of a route, which a caller is granted by name (spec §3.3).
    RouteName,
    "route"
);

name_type!(
    /// The configured name of a listener, the endpoint a caller connects through (spec §3.3, §3.4).
    ListenerName,
    "listener"
);

name_type!(
    /// The unique name of a credential, which routes reference to select it (spec §3.3).
    CredentialName,
    "credential"
);

#[cfg(test)]
mod tests {
    use serde::de::IntoDeserializer;
    use serde::de::value::{Error as DeError, StringDeserializer};

    use super::*;

    fn rule_of(s: &str) -> NameRule {
        CallerName::try_from(s).unwrap_err().rule().clone()
    }

    #[test]
    fn spec_examples_parse() {
        ["fx-mcp", "naomi-backoffice"]
            .iter()
            .for_each(|s| assert_eq!(CallerName::try_from(*s).unwrap().as_str(), *s));
        ["fx", "venice", "brave"]
            .iter()
            .for_each(|s| assert_eq!(s.parse::<RouteName>().unwrap().as_str(), *s));
        ["local", "naomi-backoffice"]
            .iter()
            .for_each(|s| assert_eq!(ListenerName::try_from(*s).unwrap().as_str(), *s));
        ["fx_key", "venice", "brave"]
            .iter()
            .for_each(|s| assert_eq!(CredentialName::try_from(*s).unwrap().as_str(), *s));
    }

    #[test]
    fn empty_is_rejected() {
        assert_eq!(rule_of(""), NameRule::Empty);
    }

    #[test]
    fn length_limit_is_inclusive() {
        let max = format!("a{}", "b".repeat(MAX_NAME_LEN - 1));
        assert!(CallerName::try_from(max.as_str()).is_ok());
        assert_eq!(rule_of(&format!("{max}c")), NameRule::TooLong { len: MAX_NAME_LEN + 1 });
    }

    #[test]
    fn leading_non_letter_is_rejected() {
        ["1fx", "-fx", "_fx", "Fx"]
            .iter()
            .for_each(|s| assert!(matches!(rule_of(s), NameRule::BadStart { .. }), "{s}"));
    }

    #[test]
    fn uppercase_is_rejected() {
        assert_eq!(
            rule_of("fxKey"),
            NameRule::BadChar {
                found: "'K'".into(),
                position: 2
            }
        );
    }

    #[test]
    fn whitespace_is_rejected() {
        ["fx key", "fx\tkey", "fx\n", " fx"]
            .iter()
            .for_each(|s| assert!(CallerName::try_from(*s).is_err(), "{s:?}"));
    }

    #[test]
    fn control_characters_are_rejected_and_escaped() {
        let err = CallerName::try_from("fx\u{1b}[31m").unwrap_err();
        assert_eq!(
            err.rule(),
            &NameRule::BadChar {
                found: "'\\u{1b}'".into(),
                position: 2
            }
        );
        assert!(!err.to_string().chars().any(char::is_control));
        assert!(!CallerName::try_from("fx\nkey").unwrap_err().to_string().contains('\n'));
    }

    #[test]
    fn non_ascii_is_rejected() {
        assert_eq!(
            rule_of("fxé"),
            NameRule::BadChar {
                found: "'\\u{e9}'".into(),
                position: 2
            }
        );
        assert!(matches!(rule_of("éfx"), NameRule::BadStart { .. }));
    }

    #[test]
    fn error_names_the_kind() {
        let err = RouteName::try_from("").unwrap_err();
        assert_eq!(err.kind(), "route");
        assert_eq!(err.to_string(), "invalid route name: must not be empty");
    }

    #[test]
    fn deserialize_validates() {
        let ok: Result<CredentialName, DeError> = CredentialName::deserialize("fx_key".to_owned().into_deserializer());
        assert_eq!(ok.unwrap().as_str(), "fx_key");
        let bad: StringDeserializer<DeError> = "Fx".to_owned().into_deserializer();
        assert!(CredentialName::deserialize(bad).is_err());
    }

    #[test]
    fn names_order_lexically() {
        let mut names: Vec<RouteName> = ["venice", "brave", "fx"].iter().map(|s| RouteName::try_from(*s).unwrap()).collect();
        names.sort();
        assert_eq!(names.iter().map(RouteName::as_str).collect::<Vec<_>>(), ["brave", "fx", "venice"]);
    }
}
