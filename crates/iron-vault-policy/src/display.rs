//! Rendering rejected configuration text inside error messages.

/// `s` in double quotes with control and non-ASCII characters escaped, so a rejected value never reaches a log raw.
pub(crate) fn quoted(s: &str) -> String {
    format!("\"{}\"", s.escape_default())
}
