//! The fixed text around a credential written into a header slot.

use std::fmt;
use std::str::FromStr;

use serde::Deserialize;
use thiserror::Error;

/// The placeholder a slot format replaces with the credential.
const PLACEHOLDER: &str = "{}";

/// A header-value template with exactly one `{}` substitution point, such as `Bearer {}` (spec §3.6).
///
/// The fixed text is printable ASCII without braces, so the template cannot split a header with CR or LF, cannot
/// carry a second substitution point, and renders to the same bytes on every HTTP stack. The default is `{}`: the
/// credential alone.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct SlotFormat {
    prefix: String,
    suffix: String,
}

/// A string that is not a valid slot format.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SlotFormatError {
    /// The format has no `{}` substitution point.
    #[error("slot format {0} has no {{}} substitution point")]
    MissingPlaceholder(
        /// The rejected format, escaped.
        String,
    ),
    /// The format has a second `{}`, or a lone `{` or `}`.
    #[error("slot format {0} must contain exactly one {{}} and no other braces")]
    ExtraBrace(
        /// The rejected format, escaped.
        String,
    ),
    /// The format contains a control character or a character outside printable ASCII.
    #[error("slot format {format} contains {found:?}; only printable ASCII is allowed")]
    InvalidChar {
        /// The rejected format, escaped so control characters never reach a log raw.
        format: String,
        /// The first offending character.
        found: char,
    },
}

impl SlotFormat {
    /// The header value carrying `credential` in place of `{}`.
    pub fn render(&self, credential: &str) -> String {
        format!("{}{credential}{}", self.prefix, self.suffix)
    }
}

fn escaped(s: &str) -> String {
    format!("\"{}\"", s.escape_default())
}

impl TryFrom<&str> for SlotFormat {
    type Error = SlotFormatError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        if let Some(found) = s.chars().find(|c| !(' '..='~').contains(c)) {
            return Err(SlotFormatError::InvalidChar { format: escaped(s), found });
        }
        let (prefix, suffix) = s.split_once(PLACEHOLDER).ok_or_else(|| SlotFormatError::MissingPlaceholder(escaped(s)))?;
        if prefix.contains(['{', '}']) || suffix.contains(['{', '}']) {
            return Err(SlotFormatError::ExtraBrace(escaped(s)));
        }
        Ok(Self { prefix: prefix.to_owned(), suffix: suffix.to_owned() })
    }
}

impl TryFrom<String> for SlotFormat {
    type Error = SlotFormatError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::try_from(s.as_str())
    }
}

impl FromStr for SlotFormat {
    type Err = SlotFormatError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

impl fmt::Display for SlotFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{PLACEHOLDER}{}", self.prefix, self.suffix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_the_bare_credential() {
        assert_eq!(SlotFormat::default().render("k3y"), "k3y");
        assert_eq!(SlotFormat::default(), "{}".parse().unwrap());
        assert_eq!(SlotFormat::default().to_string(), "{}");
    }

    #[test]
    fn renders_prefix_and_suffix() {
        let format: SlotFormat = "Bearer {}".parse().unwrap();
        assert_eq!(format.render("k3y"), "Bearer k3y");
        assert_eq!(format.to_string(), "Bearer {}");
        assert_eq!("token={}; v=1".parse::<SlotFormat>().unwrap().render("k"), "token=k; v=1");
    }

    #[test]
    fn rejects_missing_placeholder() {
        ["", "Bearer", "Bearer { }"]
            .iter()
            .for_each(|s| assert!(matches!(SlotFormat::try_from(*s), Err(SlotFormatError::MissingPlaceholder(_))), "{s:?}"));
    }

    #[test]
    fn rejects_second_placeholder_and_stray_braces() {
        ["Bearer {} {}", "{}{}", "{{}}", "{} }", "{ {}", "{0}{}", "{}{x}"]
            .iter()
            .for_each(|s| assert!(matches!(SlotFormat::try_from(*s), Err(SlotFormatError::ExtraBrace(_))), "{s:?}"));
    }

    #[test]
    fn rejects_control_and_non_ascii_characters() {
        ["x\r\ny: {}", "Bearer {}\n", "Bearer\t{}", "Bearer {}\0", "{}\u{7f}", "{}\u{85}", "Bé {}"]
            .iter()
            .for_each(|s| assert!(matches!(SlotFormat::try_from(*s), Err(SlotFormatError::InvalidChar { .. })), "{s:?}"));
    }

    #[test]
    fn error_escapes_control_characters() {
        let message = SlotFormat::try_from("x\r\ny: {}").unwrap_err().to_string();
        assert!(!message.contains('\r') && !message.contains('\n'), "{message}");
    }
}
