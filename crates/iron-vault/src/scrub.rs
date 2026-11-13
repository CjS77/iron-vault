// SPDX-License-Identifier: MPL-2.0
//! The scrubber: replaces every occurrence of a request's scrub patterns in a streamed response body and in the
//! response headers ([spec §11][s11]). It is the response stage's backstop: if an upstream echoes the injected
//! credential in any of the forms its credential kind lists as scrub patterns, the caller sees [`SCRUB_REPLACEMENT`]
//! instead.
//!
//! The body arrives in chunks, so a secret can straddle two of them. The scrubber holds back only the bytes that could
//! still begin a match. For example, with the one pattern `sk-123`:
//!
//! ```text
//! push("data: sk-1")   returns "data: "                       holds "sk-1", which "23" could complete
//! push("23 done\n")    returns "[iron-vault:scrubbed] done\n"   holds nothing
//! finish()             returns "" and 1 match
//! ```
//!
//! Matching is a hand-written scan, not `aho-corasick`: a request has 10-20 short patterns, `aho-corasick`'s streaming
//! search does not support leftmost-longest matching, and its automaton would hold copies of the secrets that are never
//! wiped. The scrubber borrows or takes the patterns and copies none of them.
//!
//! [s11]: ../../../design/iron-vault-specification.md#11-responses-redirects-and-scrubbing

use std::fmt;

use bytes::Bytes;
use iron_vault_kinds::ScrubPatterns;
use reqwest::header::{HeaderMap, HeaderValue};
use zeroize::{Zeroize, Zeroizing};

#[cfg(test)]
mod tests;

/// The scrub replacement, written in place of every match of any length, so the output shows neither the length nor
/// the position of the secret it replaced.
pub const SCRUB_REPLACEMENT: &[u8] = REPLACEMENT_TEXT.as_bytes();

/// [`SCRUB_REPLACEMENT`] as text, so the header fallback can be a `&'static str` without repeating the literal.
const REPLACEMENT_TEXT: &str = "[iron-vault:scrubbed]";

/// The per-response streaming matcher for one request's scrub patterns.
///
/// Matching is leftmost-longest and byte-exact: where several patterns match at one position, the longest wins, so
/// `Basic <token>` is replaced whole instead of leaving `Basic ` before a replaced token. Between chunks it holds back
/// only the bytes from the first position where a match could still begin or grow; everything before that is released
/// at once, so an SSE event is never delayed until the next one. The held bytes are at most one less than the longest
/// pattern ([§11](../../../design/iron-vault-specification.md#11-responses-redirects-and-scrubbing)) and are wiped when
/// the scrubber is dropped.
///
/// Call [`finish`](Self::finish) at the end of the body. It consumes the scrubber, so no chunk can be pushed after the
/// held bytes are released, and it returns the body's total match count. Dropping the scrubber without it releases
/// nothing further, which is the path for a body that fails partway: the held bytes may be a secret prefix and are never
/// sent.
pub struct Scrubber<'p> {
    patterns: Patterns<'p>,
    held: Zeroizing<Vec<u8>>,
    matches: u64,
}

/// The patterns a scrubber watches for. A header scrub borrows them for one value; a response body's scrubber owns
/// them, because the body outlives the request handler that resolved them, and dropping the scrubber wipes them.
enum Patterns<'p> {
    Borrowed(Vec<&'p [u8]>),
    Owned(ScrubPatterns),
}

impl Patterns<'_> {
    /// Returns `true` if and only if some pattern satisfies `test`.
    fn any(&self, test: impl Fn(&[u8]) -> bool) -> bool {
        match self {
            Self::Borrowed(patterns) => patterns.iter().any(|pattern| test(pattern)),
            Self::Owned(patterns) => patterns.iter().any(test),
        }
    }

    /// Returns the length of the longest pattern that satisfies `test`, or `None` if none does.
    fn longest(&self, test: impl Fn(&[u8]) -> bool) -> Option<usize> {
        match self {
            Self::Borrowed(patterns) => longest_of(patterns.iter().copied(), test),
            Self::Owned(patterns) => longest_of(patterns.iter(), test),
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Borrowed(patterns) => patterns.len(),
            Self::Owned(patterns) => patterns.len(),
        }
    }
}

fn longest_of<'a>(patterns: impl Iterator<Item = &'a [u8]>, test: impl Fn(&[u8]) -> bool) -> Option<usize> {
    patterns.filter(|pattern| test(pattern)).map(<[u8]>::len).max()
}

/// The end of a scrubbed body, from [`Scrubber::finish`].
#[derive(Debug)]
pub struct Finished {
    /// The held bytes, scrubbed: the last of the body's output.
    pub tail: Bytes,
    /// How many matches were replaced in the whole body, including any the tail completed.
    pub matches: u64,
}

/// What the scan does at one position of the pending bytes.
enum Step {
    /// A pattern could still match here once more bytes arrive.
    Hold,
    /// The longest pattern matching here has this length.
    Replace(usize),
    /// No pattern matches here.
    Release,
}

impl Scrubber<'static> {
    /// Creates a scrubber that takes `patterns`, for a response body that outlives the request that resolved them. They are
    /// wiped when the scrubber is dropped, by [`finish`](Scrubber::finish) or with a body that fails.
    pub fn owning(patterns: ScrubPatterns) -> Self {
        Self::over(Patterns::Owned(patterns))
    }
}

impl<'p> Scrubber<'p> {
    /// Creates a scrubber for one response that borrows `patterns`.
    pub fn new(patterns: &'p ScrubPatterns) -> Self {
        Self::over(Patterns::Borrowed(patterns.iter().collect()))
    }

    /// Creates a scrubber over arbitrary patterns, for tests; an empty pattern is dropped, since it would match everywhere.
    #[cfg(test)]
    pub(crate) fn with_patterns(patterns: impl IntoIterator<Item = &'p [u8]>) -> Self {
        let patterns: Vec<&[u8]> = patterns.into_iter().filter(|pattern| !pattern.is_empty()).collect();
        Self::over(Patterns::Borrowed(patterns))
    }

    fn over(patterns: Patterns<'p>) -> Self {
        let longest = patterns.longest(|_| true).unwrap_or(0);
        // Held bytes never reach the longest pattern's length, so this buffer never reallocates and leaves no copy.
        let held = Zeroizing::new(Vec::with_capacity(longest.saturating_sub(1)));
        Self {
            patterns,
            held,
            matches: 0,
        }
    }

    /// Scrubs the next chunk of the body and returns the bytes safe to release now.
    pub fn push(&mut self, chunk: &[u8]) -> Bytes {
        let pending = self.pending(chunk);
        self.scan(&pending, false)
    }

    /// Ends the body and returns the held bytes, scrubbed, since no further byte can complete a match, with the total
    /// match count.
    pub fn finish(mut self) -> Finished {
        let pending = self.pending(&[]);
        let tail = self.scan(&pending, true);
        Finished {
            tail,
            matches: self.matches,
        }
    }

    /// How many matches have been replaced so far; a match the held bytes complete at the end of the body is counted only
    /// in the total from [`finish`](Self::finish).
    pub fn matches(&self) -> u64 {
        self.matches
    }

    /// Joins the held bytes and `chunk` in a buffer sized for both, so it never reallocates.
    fn pending(&self, chunk: &[u8]) -> Zeroizing<Vec<u8>> {
        let mut pending = Zeroizing::new(Vec::with_capacity(self.held.len() + chunk.len()));
        pending.extend_from_slice(&self.held);
        pending.extend_from_slice(chunk);
        pending
    }

    /// Scrubs `pending` up to the first position that must be held, keeps the rest in `held`, and returns the output.
    fn scan(&mut self, pending: &[u8], at_end: bool) -> Bytes {
        let mut out = Vec::with_capacity(pending.len());
        let mut at = 0;
        while let Some(rest) = pending.get(at..).filter(|rest| !rest.is_empty()) {
            match self.step(rest, at_end) {
                Step::Hold => break,
                Step::Replace(len) => {
                    out.extend_from_slice(SCRUB_REPLACEMENT);
                    self.matches += 1;
                    at += len;
                }
                Step::Release => {
                    out.extend(rest.first());
                    at += 1;
                }
            }
        }
        self.held.zeroize();
        self.held.extend_from_slice(pending.get(at..).unwrap_or_default());
        Bytes::from(out)
    }

    /// Decides what to do at the start of `rest`. Holding comes first: a longer pattern that `rest` begins would win
    /// over any shorter match here, and a match here would win over any later one.
    fn step(&self, rest: &[u8], at_end: bool) -> Step {
        if !at_end && self.could_grow(rest) {
            return Step::Hold;
        }
        self.patterns
            .longest(|pattern| rest.starts_with(pattern))
            .map_or(Step::Release, Step::Replace)
    }

    /// Returns `true` if and only if some pattern is longer than `rest` and begins with it, so the next chunk could
    /// complete it.
    fn could_grow(&self, rest: &[u8]) -> bool {
        self.patterns.any(|pattern| pattern.len() > rest.len() && pattern.starts_with(rest))
    }
}

impl fmt::Debug for Scrubber<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Scrubber")
            .field("patterns", &self.patterns.len())
            .field("held", &self.held.len())
            .field("matches", &self.matches)
            .finish()
    }
}

/// Scrubs every response header value in place and returns how many matches were replaced across all values
/// ([spec §11](../../../design/iron-vault-specification.md#11-responses-redirects-and-scrubbing)).
///
/// Each value is scrubbed whole and one-shot through the same [`Scrubber`] as the body, so headers and body share one
/// matching rule. Header names are not scrubbed: a secret in a name is implausible, and rewriting names would change
/// semantics. A value that is not UTF-8 is scrubbed as bytes. `Location` is scrubbed like any other header.
///
/// The relay rewrites `Location` before this call, so the scrub is the last transform on every emitted byte.
pub fn scrub_headers(headers: &mut HeaderMap, patterns: &ScrubPatterns) -> u64 {
    scrub_header_values(headers, || Scrubber::new(patterns))
}

/// Scrubs every header value as [`scrub_headers`] does, with a fresh scrubber from `scrubber` for each value.
pub(crate) fn scrub_header_values<'p>(headers: &mut HeaderMap, scrubber: impl Fn() -> Scrubber<'p>) -> u64 {
    headers
        .values_mut()
        .map(|value| match scrub_value(scrubber(), value.as_bytes()) {
            Some((scrubbed, matches)) => {
                let sensitive = value.is_sensitive();
                *value = scrubbed;
                value.set_sensitive(sensitive);
                matches
            }
            None => 0,
        })
        .sum()
}

/// Returns the scrubbed value and its match count if `value` held a match. Returns `None` otherwise, so an unmatched
/// value stays byte-identical.
fn scrub_value(mut scrubber: Scrubber<'_>, value: &[u8]) -> Option<(HeaderValue, u64)> {
    let mut out = Zeroizing::new(scrubber.push(value).to_vec());
    let finished = scrubber.finish();
    out.extend_from_slice(&finished.tail);
    (finished.matches > 0).then(|| (header_value(&out), finished.matches))
}

/// Builds a header value from scrubbed bytes. The replacement is ASCII and the rest came from a valid header value, so
/// this cannot fail; if it did, the whole value becomes the replacement, so the secret is never left in place.
fn header_value(bytes: &[u8]) -> HeaderValue {
    HeaderValue::from_bytes(bytes).unwrap_or_else(|_| {
        debug_assert!(false, "scrubbed header value is not a valid header value");
        HeaderValue::from_static(REPLACEMENT_TEXT)
    })
}
