//! Rendering rejected configuration text and caller names inside error messages.

use crate::name::CallerName;

/// `s` in double quotes with control and non-ASCII characters escaped, so a rejected value never reaches a log raw.
pub(crate) fn quoted(s: &str) -> String {
    format!("\"{}\"", s.escape_default())
}

/// `s` with control and non-ASCII characters escaped, unquoted, for text such as a parser message that may echo input.
///
/// Non-ASCII is escaped as well as control characters so that format characters such as U+202E (right-to-left
/// override) cannot reorder what a log reader sees.
pub(crate) fn escaped(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control() || !c.is_ascii() {
                c.escape_default().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// Names separated by ", ", for error messages.
pub(crate) fn joined(names: &[CallerName]) -> String {
    names.iter().map(CallerName::as_str).collect::<Vec<_>>().join(", ")
}
