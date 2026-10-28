//! The one encoding a credential gets in a query slot, and the decoding used to compare caller parameters with it
//! (spec §3.6).
//!
//! `url::form_urlencoded::byte_serialize` is not used for the value: it writes a space as `+` and leaves `*` bare,
//! which an upstream that decodes with RFC 3986 rules rather than form rules would read differently. Encoding every
//! byte outside the RFC 3986 unreserved set reads back the same under both rules.

use std::borrow::Cow;

use url::form_urlencoded;

use crate::escape::{is_unreserved, push_uppercase_escape};

/// `value` with every byte outside the RFC 3986 unreserved set (`A-Z a-z 0-9 - . _ ~`) written as `%XX` in uppercase.
///
/// This is the only encoding a credential gets in a query slot, so response scrubbing computes its URL-encoded
/// pattern by calling this same function: the pattern then matches exactly the bytes that were sent.
///
/// The result is allocated at its largest possible size up front, so writing a secret never reallocates and leaves
/// no stale partial copy behind.
pub fn encode_query_value(value: &str) -> String {
    value.bytes().fold(String::with_capacity(value.len() * 3), |mut out, byte| {
        push_encoded(&mut out, byte);
        out
    })
}

fn push_encoded(out: &mut String, byte: u8) {
    if is_unreserved(char::from(byte)) {
        out.push(char::from(byte));
    } else {
        push_uppercase_escape(out, byte);
    }
}

/// One `name=value` query parameter, percent-decoded with `+` read as a space, as upstream form parsers read it.
///
/// Comparing decoded names is what stops `access%5Fkey` from surviving beside `access_key` when both decode to the
/// slot name. `None` for an empty parameter, as between `&&`. Invalid UTF-8 decodes to U+FFFD, which no slot name
/// contains, so a lossy decode can never make a name match.
pub(crate) fn decode_param(param: &str) -> Option<(Cow<'_, str>, Cow<'_, str>)> {
    form_urlencoded::parse(param.as_bytes()).next()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decoded(param: &str) -> Option<(String, String)> {
        decode_param(param).map(|(n, v)| (n.into_owned(), v.into_owned()))
    }

    #[test]
    fn unreserved_characters_are_kept() {
        let unreserved = "ABCXYZabcxyz0189-._~";
        assert_eq!(encode_query_value(unreserved), unreserved);
    }

    #[test]
    fn everything_else_is_percent_encoded_in_uppercase() {
        assert_eq!(encode_query_value("a&b=c+d%e f"), "a%26b%3Dc%2Bd%25e%20f");
        assert_eq!(encode_query_value("*'!/?#[]@"), "%2A%27%21%2F%3F%23%5B%5D%40");
        assert_eq!(encode_query_value("\u{e9}\u{2028}"), "%C3%A9%E2%80%A8");
    }

    #[test]
    fn every_byte_round_trips_through_the_form_decoder() {
        let all: String = (0x20u8..=0x7e).map(char::from).chain(['\u{e9}', '\u{2028}', '\u{1f511}']).collect();
        let param = format!("k={}", encode_query_value(&all));
        assert_eq!(decoded(&param), Some(("k".to_owned(), all)));
    }

    #[test]
    fn decode_reads_escapes_and_plus() {
        assert_eq!(decoded("access%5Fkey=a+b%2B"), Some(("access_key".to_owned(), "a b+".to_owned())));
        assert_eq!(decoded("flag"), Some(("flag".to_owned(), String::new())));
        assert_eq!(decoded(""), None);
    }
}
