//! The OS account a `peer` caller must connect as (spec §7).

use std::fmt;
use std::str::FromStr;

use serde::Deserialize;
use thiserror::Error;

use crate::display::quoted;

/// The longest account name, in bytes, that [`AccountName`] accepts; Linux `useradd` refuses longer ones.
pub const MAX_ACCOUNT_NAME_LEN: usize = 32;

/// A POSIX user name, as written in a caller's `user` key: 1 to [`MAX_ACCOUNT_NAME_LEN`] bytes matching
/// `[a-z_][a-z0-9_-]*`, optionally ending in `$`.
///
/// This is `useradd`'s default `NAME_REGEX`, so every account the package or the owner creates with it parses, and the
/// name can never carry a control character into a log. Whether the account exists is a fact about the host, checked
/// when policy activates, not here.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct AccountName(String);

/// Why a string is not an [`AccountName`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AccountNameError {
    /// The name was empty.
    #[error("account name must not be empty")]
    Empty,
    /// The name was longer than [`MAX_ACCOUNT_NAME_LEN`] bytes.
    #[error("account name is {len} bytes long; the limit is {MAX_ACCOUNT_NAME_LEN}")]
    TooLong {
        /// Length of the rejected name in bytes.
        len: usize,
    },
    /// The name does not match `[a-z_][a-z0-9_-]*[$]?`.
    #[error("invalid account name {0}: must be a-z or '_', then a-z, 0-9, '_' or '-', with an optional trailing '$'")]
    BadForm(
        /// The rejected name, quoted and escaped so control characters never reach a log raw.
        String,
    ),
}

impl AccountName {
    /// The validated account name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Applies `useradd`'s default name rule.
fn check_account_name(s: &str) -> Result<(), AccountNameError> {
    if s.is_empty() {
        return Err(AccountNameError::Empty);
    }
    if s.len() > MAX_ACCOUNT_NAME_LEN {
        return Err(AccountNameError::TooLong { len: s.len() });
    }
    let body = s.strip_suffix('$').unwrap_or(s);
    let mut chars = body.chars();
    let well_formed =
        chars.next().is_some_and(|c| matches!(c, 'a'..='z' | '_')) && chars.all(|c| matches!(c, 'a'..='z' | '0'..='9' | '_' | '-'));
    well_formed.then_some(()).ok_or_else(|| AccountNameError::BadForm(quoted(s)))
}

impl TryFrom<String> for AccountName {
    type Error = AccountNameError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        check_account_name(&s).map(|()| Self(s))
    }
}

impl TryFrom<&str> for AccountName {
    type Error = AccountNameError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        check_account_name(s).map(|()| Self(s.to_owned()))
    }
}

impl FromStr for AccountName {
    type Err = AccountNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

impl fmt::Display for AccountName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn useradd_names_parse() {
        ["code", "trading", "_svc", "build-01", "machine$", "a"]
            .iter()
            .for_each(|s| assert_eq!(AccountName::try_from(*s).unwrap().as_str(), *s));
    }

    #[test]
    fn length_limit_is_inclusive() {
        let max = "a".repeat(MAX_ACCOUNT_NAME_LEN);
        assert!(AccountName::try_from(max.as_str()).is_ok());
        assert!(AccountName::try_from(format!("{}$", "a".repeat(MAX_ACCOUNT_NAME_LEN - 1))).is_ok());
        assert_eq!(
            AccountName::try_from(format!("{max}a")),
            Err(AccountNameError::TooLong {
                len: MAX_ACCOUNT_NAME_LEN + 1
            })
        );
    }

    #[test]
    fn empty_is_refused() {
        assert_eq!(AccountName::try_from(""), Err(AccountNameError::Empty));
    }

    #[test]
    fn names_outside_the_rule_are_refused() {
        ["Code", "1code", "-code", "a b", "a$b", "$", "code$$", "cöde", "\u{1b}", "code\n"]
            .iter()
            .for_each(|s| assert!(matches!(AccountName::try_from(*s), Err(AccountNameError::BadForm(_))), "{s:?}"));
    }

    #[test]
    fn errors_never_carry_a_raw_control_character() {
        ["\u{1b}[31m", "a\nb", "a\u{202e}b"].iter().for_each(|s| {
            let err = AccountName::try_from(*s).unwrap_err().to_string();
            assert!(!err.chars().any(|c| c.is_control() || !c.is_ascii()), "{err}");
        });
        assert_eq!(
            AccountName::try_from("\u{1b}").unwrap_err(),
            AccountNameError::BadForm("\"\\u{1b}\"".into())
        );
    }

    #[test]
    fn deserialize_validates() {
        #[derive(Debug, Deserialize)]
        struct Doc {
            user: AccountName,
        }
        assert_eq!(toml::from_str::<Doc>("user = \"code\"").unwrap().user.as_str(), "code");
        let err = toml::from_str::<Doc>("user = \"Code\"").unwrap_err().to_string();
        assert!(err.contains("invalid account name \"Code\""), "{err}");
    }
}
