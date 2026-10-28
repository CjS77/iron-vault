//! HTTP header field names as configuration values.

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

use serde::Deserialize;
use thiserror::Error;

use crate::display::quoted;

/// An HTTP field name: a non-empty RFC 9110 `token`.
///
/// Field names are case-insensitive (RFC 9110 §5.1), so equality, hashing and ordering use the lowercase form. The
/// configured spelling is kept for display, because operators recognise `X-Subscription-Token` faster than its
/// lowercase form.
#[derive(Debug, Clone, Deserialize)]
#[serde(try_from = "String")]
pub struct HeaderName {
    spelling: String,
    lowercase: String,
}

/// A string that is not a valid HTTP field name.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HeaderNameError {
    /// The name is the empty string.
    #[error("header name is empty")]
    Empty,
    /// The name contains a character outside the RFC 9110 `tchar` set.
    #[error("header name {name} contains {found:?}, which is not allowed in an HTTP token")]
    InvalidChar {
        /// The rejected name, escaped so control characters never reach a log raw.
        name: String,
        /// The first offending character.
        found: char,
    },
}

impl HeaderName {
    /// The name as configured.
    pub fn as_str(&self) -> &str {
        &self.spelling
    }

    /// The lowercase form used for every comparison.
    pub fn lowercase(&self) -> &str {
        &self.lowercase
    }

    /// `Authorization`, the header a Basic slot writes; built directly because a constant cannot fail to parse.
    pub(crate) fn authorization() -> Self {
        Self { spelling: "Authorization".to_owned(), lowercase: "authorization".to_owned() }
    }
}

/// RFC 9110 §5.6.2 `tchar`.
fn is_tchar(c: char) -> bool {
    c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c)
}

impl TryFrom<&str> for HeaderName {
    type Error = HeaderNameError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        if s.is_empty() {
            return Err(HeaderNameError::Empty);
        }
        match s.chars().find(|c| !is_tchar(*c)) {
            Some(found) => Err(HeaderNameError::InvalidChar { name: quoted(s), found }),
            None => Ok(Self { spelling: s.to_owned(), lowercase: s.to_ascii_lowercase() }),
        }
    }
}

impl TryFrom<String> for HeaderName {
    type Error = HeaderNameError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::try_from(s.as_str())
    }
}

impl FromStr for HeaderName {
    type Err = HeaderNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

impl PartialEq for HeaderName {
    fn eq(&self, other: &Self) -> bool {
        self.lowercase == other.lowercase
    }
}

impl Eq for HeaderName {}

impl Hash for HeaderName {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.lowercase.hash(state);
    }
}

impl PartialOrd for HeaderName {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HeaderName {
    fn cmp(&self, other: &Self) -> Ordering {
        self.lowercase.cmp(&other.lowercase)
    }
}

impl fmt::Display for HeaderName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.spelling)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn name(s: &str) -> HeaderName {
        s.parse().unwrap()
    }

    #[test]
    fn accepts_tokens_and_keeps_spelling() {
        let n = name("X-Subscription-Token");
        assert_eq!(n.as_str(), "X-Subscription-Token");
        assert_eq!(n.lowercase(), "x-subscription-token");
        assert_eq!(n.to_string(), "X-Subscription-Token");
        assert!("a!#$%&'*+-.^_`|~9".parse::<HeaderName>().is_ok());
    }

    #[test]
    fn compares_case_insensitively() {
        assert_eq!(name("Authorization"), name("AUTHORIZATION"));
        assert_eq!(name("a").cmp(&name("B")), Ordering::Less);
        let set: BTreeSet<_> = [name("Host"), name("host"), name("HOST")].into_iter().collect();
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn authorization_matches_its_parsed_form() {
        let parsed = name("Authorization");
        assert_eq!((HeaderName::authorization().as_str(), HeaderName::authorization().lowercase()), (parsed.as_str(), parsed.lowercase()));
    }

    #[test]
    fn rejects_empty() {
        assert_eq!(HeaderName::try_from(""), Err(HeaderNameError::Empty));
    }

    #[test]
    fn rejects_non_token_characters() {
        ["X Token", "X:Token", ":authority", "X\r\nY", "X\0", "Tök", "(x)", "a/b", "a\"b"]
            .iter()
            .for_each(|s| assert!(matches!(HeaderName::try_from(*s), Err(HeaderNameError::InvalidChar { .. })), "{s:?}"));
    }

    #[test]
    fn error_escapes_control_characters() {
        let message = HeaderName::try_from("X\r\nY").unwrap_err().to_string();
        assert!(!message.contains('\r') && !message.contains('\n'), "{message}");
    }
}
