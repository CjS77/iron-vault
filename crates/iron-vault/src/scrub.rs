//! The scrubber: replaces every occurrence of a request's scrub patterns in a streamed response body (spec §3.8, R-12).
//!
//! Matching is a hand-rolled scan rather than `aho-corasick`: a request has 10-20 short patterns, `aho-corasick`'s
//! streaming search does not support leftmost-longest matching, and its automaton would hold copies of the secrets that
//! are never wiped. The scrubber borrows the patterns and copies none of them.

use std::fmt;

use bytes::Bytes;
use iron_vault_kinds::ScrubPatterns;
use zeroize::{Zeroize, Zeroizing};

#[cfg(test)]
mod tests;

/// The scrub replacement, written in place of every match whatever its length, so the output shows neither the length
/// nor the position of the secret it replaced.
pub const SCRUB_REPLACEMENT: &[u8] = b"[iron-vault:scrubbed]";

/// The per-response streaming matcher for one request's scrub patterns.
///
/// Matching is leftmost-longest and byte-exact: where several patterns match at one position, the longest wins, so
/// `Basic <token>` is replaced whole rather than leaving `Basic ` before a replaced token. Between chunks it holds back
/// only the bytes from the first position where a match could still begin or grow; everything before that is released
/// at once, so an SSE event is never delayed until the next one. The held bytes are at most one less than the longest
/// pattern (§3.8) and are wiped when the scrubber is dropped.
///
/// Call [`finish`](Self::finish) at the end of the body. It consumes the scrubber, so no chunk can be pushed after the
/// held bytes are released, and it returns the body's total match count. Dropping the scrubber without it releases
/// nothing further, which is the path for a body that fails partway: the held bytes may be a secret prefix and are never
/// sent.
pub struct Scrubber<'p> {
    patterns: Vec<&'p [u8]>,
    held: Zeroizing<Vec<u8>>,
    matches: u64,
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

impl<'p> Scrubber<'p> {
    /// A scrubber for one response, watching for `patterns`.
    pub fn new(patterns: &'p ScrubPatterns) -> Self {
        Self::with_patterns(patterns.iter())
    }

    /// A scrubber over arbitrary patterns; an empty pattern is dropped, since it would match everywhere.
    pub(crate) fn with_patterns(patterns: impl IntoIterator<Item = &'p [u8]>) -> Self {
        let patterns: Vec<&[u8]> = patterns.into_iter().filter(|pattern| !pattern.is_empty()).collect();
        let longest = patterns.iter().map(|pattern| pattern.len()).max().unwrap_or(0);
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

    /// The held bytes followed by `chunk`, in a buffer sized for both so it never reallocates.
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
            .iter()
            .filter(|pattern| rest.starts_with(pattern))
            .map(|pattern| pattern.len())
            .max()
            .map_or(Step::Release, Step::Replace)
    }

    /// Whether some pattern is longer than `rest` and begins with it, so the next chunk could complete it.
    fn could_grow(&self, rest: &[u8]) -> bool {
        self.patterns
            .iter()
            .any(|pattern| pattern.len() > rest.len() && pattern.starts_with(rest))
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
