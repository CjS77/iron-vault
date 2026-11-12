//! Renders rejected configuration text and caller names inside error messages.
//!
//! Error messages reach logs and the owner's terminal, so any text that came from a config or a caller is escaped
//! first. For example, the name `a`, a line feed, then `b` appears as `"a\nb"`, on one line.

use crate::name::CallerName;

/// Wraps `s` in double quotes and escapes control and non-ASCII characters, so a rejected value never reaches a log
/// raw.
pub(crate) fn quoted(s: &str) -> String {
    format!("\"{}\"", s.escape_default())
}

/// Escapes control and non-ASCII characters in `s`, without quotes, for text such as a parser message that may echo
/// input.
///
/// Non-ASCII is escaped as well as control characters so that format characters such as U+202E (right-to-left
/// override) cannot reorder what a log reader sees.
pub fn escaped(s: &str) -> String {
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

/// Joins caller names with `, ` for an error message.
pub(crate) fn joined(names: &[CallerName]) -> String {
    names.iter().map(CallerName::as_str).collect::<Vec<_>>().join(", ")
}
