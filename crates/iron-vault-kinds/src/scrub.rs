//! The byte forms of an injected secret that response scrubbing watches for (spec §3.8).

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use iron_vault_policy::encode_query_value;
use secrecy::zeroize::Zeroizing;

/// A deterministic, ordered set of secret byte strings, each wiped on drop.
///
/// The order is bytewise, so the scrubber sees the same patterns in the same order on every run. Patterns are never
/// case-folded: a provider key is case-sensitive, and folding it would scrub unrelated text. `Debug` shows the count
/// only.
#[derive(Default)]
pub struct ScrubPatterns(BTreeSet<ScrubPattern>);

/// One pattern; a newtype because [`Zeroizing`] does not implement `Ord`.
#[derive(PartialEq, Eq)]
struct ScrubPattern(Zeroizing<Vec<u8>>);

impl Ord for ScrubPattern {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.as_slice().cmp(other.0.as_slice())
    }
}

impl PartialOrd for ScrubPattern {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl ScrubPatterns {
    /// The patterns in bytewise order.
    pub fn iter(&self) -> impl Iterator<Item = &[u8]> {
        self.0.iter().map(|pattern| pattern.0.as_slice())
    }

    /// How many distinct patterns there are.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there are no patterns.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Adds `pattern`; an empty one is dropped, since it would match everywhere.
    pub(crate) fn insert(&mut self, pattern: Zeroizing<Vec<u8>>) {
        if !pattern.is_empty() {
            self.0.insert(ScrubPattern(pattern));
        }
    }

    /// Adds `secret` as sent, URL-encoded in both hex cases, and in standard and URL-safe base64 with and without
    /// padding. Kinds that inject a secret verbatim share this list.
    pub(crate) fn insert_encodings(&mut self, secret: &str) {
        let encoded = Zeroizing::new(encode_query_value(secret));
        self.insert(copy(secret.as_bytes()));
        self.insert(lowercase_escapes(encoded.as_bytes()));
        self.insert(copy(encoded.as_bytes()));
        [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
            .iter()
            .for_each(|engine| self.insert(Zeroizing::new(engine.encode(secret).into_bytes())));
    }
}

impl fmt::Debug for ScrubPatterns {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ScrubPatterns({} patterns)", self.len())
    }
}

/// `bytes` in a buffer sized exactly, so the copy never reallocates and leaves no stale partial copy.
///
/// Base64 needs no such care: the engine allocates its output at the exact encoded length.
fn copy(bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
    out.extend_from_slice(bytes);
    out
}

/// `encoded` with the two hex digits after each `%` in lowercase and every other byte unchanged.
///
/// Only the escapes are lowered: the unescaped characters are part of a case-sensitive key.
fn lowercase_escapes(encoded: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(encoded.len()));
    out.extend(encoded.iter().enumerate().map(|(i, byte)| lowered_if_escape(encoded, i, *byte)));
    out
}

fn lowered_if_escape(encoded: &[u8], i: usize, byte: u8) -> u8 {
    let after_percent = (1..=2).any(|back| i.checked_sub(back).and_then(|j| encoded.get(j)) == Some(&b'%'));
    if after_percent { byte.to_ascii_lowercase() } else { byte }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn patterns(secret: &str) -> Vec<String> {
        let mut set = ScrubPatterns::default();
        set.insert_encodings(secret);
        set.iter().map(|p| String::from_utf8(p.to_vec()).unwrap()).collect()
    }

    #[test]
    fn key_with_reserved_characters_gets_every_form() {
        let found = patterns("a/b+c=d");
        ["a/b+c=d", "a%2Fb%2Bc%3Dd", "a%2fb%2bc%3dd", "YS9iK2M9ZA==", "YS9iK2M9ZA"]
            .iter()
            .for_each(|expected| assert!(found.iter().any(|f| f == expected), "{expected} missing from {found:?}"));
    }

    #[test]
    fn url_safe_base64_differs_where_the_alphabet_does() {
        let found = patterns("??>");
        ["Pz8+", "Pz8-"].iter().for_each(|expected| assert!(found.contains(&(*expected).to_owned()), "{found:?}"));
    }

    #[test]
    fn unescaped_letters_keep_their_case() {
        let found = patterns("AbC/");
        assert!(found.contains(&"AbC%2f".to_owned()) && found.contains(&"AbC%2F".to_owned()), "{found:?}");
        assert!(!found.iter().any(|f| f.starts_with("abc") || f.starts_with("ABC")), "{found:?}");
    }

    #[test]
    fn duplicate_forms_collapse_and_order_is_bytewise() {
        let found = patterns("abc");
        assert_eq!(found, ["YWJj", "abc"]);
        let mut sorted = found.clone();
        sorted.sort();
        assert_eq!(found, sorted);
    }

    #[test]
    fn empty_pattern_is_dropped() {
        let mut set = ScrubPatterns::default();
        set.insert(Zeroizing::new(Vec::new()));
        assert!(set.is_empty());
    }

    #[test]
    fn debug_shows_count_only() {
        let mut set = ScrubPatterns::default();
        set.insert_encodings("QQQQ");
        let debug = format!("{set:?}");
        assert_eq!(debug, format!("ScrubPatterns({} patterns)", set.len()));
        assert!(!debug.contains('Q'));
    }
}
