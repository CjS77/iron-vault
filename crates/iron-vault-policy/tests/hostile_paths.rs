//! Property tests over hostile caller request paths (specification §3.6, §8; threat R-7).
//!
//! Example tests cover the attacks someone thought of. These generate targets that mix ordinary segments with raw,
//! mixed-case encoded and double- or triple-encoded hostile fragments under the prefixes of a fixed config, then check
//! invariants that must hold for every target [`RequestTarget::parse`] accepts and every request [`authorize`] accepts.

// Workspace lints deny `unwrap` outside tests, and clippy treats only `#[test]` functions as tests here; these helpers
// run only under the test harness, where a panic is a test failure.
#![allow(clippy::unwrap_used)]

mod common;

use std::collections::BTreeSet;

use common::{FOLDS, POLICY, config, encoded, hostile_target, sample};
use iron_vault_policy::{AuthorizedRequest, AuthzError, Method, NormalizedPath, RequestTarget, authorize};
use proptest::collection::vec;
use proptest::prelude::*;
use proptest::sample::select;
use proptest::test_runner::TestCaseError;

/// Cases for each property over generated hostile targets: enough to reach every fragment kind in many combinations,
/// small enough that the whole file runs in a few seconds.
const CASES: u32 = 4096;

/// Cases for the panic-freedom properties, whose inputs are cheap to parse and mostly rejected at the first character.
const PANIC_CASES: u32 = 8192;

/// Rounds of decoding and folding that [`readings`] follows; the segments of an accepted path settle after one, and
/// anything still changing after this many has already shown every reading a test needs.
const MAX_PASSES: usize = 8;

/// Paths dense with escapes of any byte, encoded one to three times in mixed case, between dots, separators, `;` and
/// stray `%`, so the invariants also meet escapes that the fixed lists in [`fragment`] do not name.
fn escape_soup() -> impl Strategy<Value = String> {
    let byte = prop_oneof![3 => 0u8..0x80, 1 => any::<u8>()];
    let layers = prop_oneof![3 => Just(1usize), 1 => 2..=3usize];
    let any_escape = (byte, layers, any::<u8>()).prop_map(|(byte, layers, case)| encoded(byte, layers, case));
    let filler = select(&[".", "/", ";", "a", "-", "%", "\\"][..]).prop_map(String::from);
    vec(prop_oneof![2 => any_escape, 1 => filler], 0..8).prop_map(|tokens| format!("/{}", tokens.concat()))
}

// Readings: what a decoder downstream might make of a segment.

fn hex_value(byte: u8) -> Option<u8> {
    char::from(byte).to_digit(16).and_then(|d| u8::try_from(d).ok())
}

/// One lenient percent-decoding pass: every well-formed escape is decoded, everything else is kept.
fn decode_once(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut rest = input;
    while let Some((&first, tail)) = rest.split_first() {
        match (first, tail) {
            (b'%', [high, low, after @ ..]) if hex_value(*high).is_some() && hex_value(*low).is_some() => {
                out.extend(hex_value(*high).zip(hex_value(*low)).map(|(h, l)| h << 4 | l));
                rest = after;
            }
            _ => {
                out.push(first);
                rest = tail;
            }
        }
    }
    out
}

/// Replaces each look-alike with the ASCII it folds to; bytes that are not UTF-8 are left alone.
fn fold(input: &[u8]) -> Vec<u8> {
    match std::str::from_utf8(input) {
        Ok(text) => text.chars().map(fold_char).collect::<String>().into(),
        Err(_) => input.to_vec(),
    }
}

fn fold_char(c: char) -> String {
    FOLDS.iter().find(|(look_alike, _)| *look_alike == c).map_or_else(|| c.to_string(), |(_, ascii)| (*ascii).to_owned())
}

/// The segment as written plus every text reachable from it by percent-decoding and Unicode folding, in any order.
fn readings(segment: &str) -> BTreeSet<Vec<u8>> {
    let start = BTreeSet::from([segment.as_bytes().to_vec()]);
    let levels = std::iter::successors(Some(start), |level| {
        let next: BTreeSet<_> = level.iter().flat_map(|r| [decode_once(r), fold(r)]).collect();
        (next != *level).then_some(next)
    });
    levels.take(MAX_PASSES).flatten().collect()
}

/// Whether a reading is a plain segment: not `.` or `..`, no `/`, `\` or NUL, and not empty or a dot segment before a
/// `;` path parameter, which servers such as Tomcat strip before resolving dot segments.
fn is_inert(reading: &[u8]) -> bool {
    let before_parameter = reading.split(|&b| b == b';').next().unwrap_or_default();
    let separator = reading.iter().any(|b| matches!(b, b'/' | b'\\' | 0));
    !separator && !matches!(before_parameter, b"" | b"." | b"..")
}

// Invariant checks, shared by the properties and the regression examples.

/// Invariant 1: no segment of an accepted path reads as traversal or a separator under any further decoding.
fn check_segments_inert(raw: &str) -> Result<(), TestCaseError> {
    let Ok(target) = RequestTarget::parse(raw) else { return Ok(()) };
    target.path().segments().iter().try_for_each(|segment| {
        let bad = readings(segment).into_iter().find(|r| !is_inert(r)).map(|r| String::from_utf8_lossy(&r).into_owned());
        prop_assert!(bad.is_none(), "{raw:?} kept segment {segment:?}, which reads as {bad:?}");
        Ok(())
    })
}

/// Invariant 2: an accepted target's rendering parses back to the same target, and renders identically.
fn check_idempotent(raw: &str) -> Result<(), TestCaseError> {
    let Ok(target) = RequestTarget::parse(raw) else { return Ok(()) };
    let rendered = target.to_string();
    let reparsed = RequestTarget::parse(&rendered);
    prop_assert_eq!(reparsed.as_ref(), Ok(&target), "{:?} rendered as {:?}", raw, rendered);
    prop_assert_eq!(reparsed.map(|t| t.to_string()), Ok(rendered));
    Ok(())
}

fn request(path: &NormalizedPath) -> Result<AuthorizedRequest, AuthzError> {
    authorize(&POLICY, &"agent".parse().unwrap(), &Method::Get, path, None)
}

/// Invariant 3: an authorized upstream path is the route's base segments followed by the request segments after a
/// whole-segment prefix, and nothing after the base can climb out of it.
fn check_stays_under_base(raw: &str) -> Result<(), TestCaseError> {
    let Ok(target) = RequestTarget::parse(raw) else { return Ok(()) };
    let path = target.path();
    let Ok(authorized) = request(path) else { return Ok(()) };
    let route = POLICY.route(authorized.route()).unwrap();
    let (prefix, base) = (route.prefix().segments(), route.upstream().base_segments());
    prop_assert!(path.segments().starts_with(prefix), "{raw:?} selected {} without its whole-segment prefix", authorized.route());
    let upstream = authorized.upstream_segments();
    prop_assert!(upstream.starts_with(base), "{raw:?} left the base path of {}: {upstream:?}", authorized.route());
    let remainder = &upstream[base.len()..];
    prop_assert_eq!(remainder, &path.segments()[prefix.len()..]);
    prop_assert!(remainder.iter().flat_map(|s| readings(s)).all(|r| is_inert(&r)), "{raw:?} forwards {remainder:?}");
    prop_assert_eq!(authorized.has_trailing_slash(), path.has_trailing_slash() && !upstream.is_empty());
    Ok(())
}

/// A request selects a route exactly when that route's prefix is a whole-segment prefix of the path.
fn check_route_selection(raw: &str) -> Result<(), TestCaseError> {
    let Ok(target) = RequestTarget::parse(raw) else { return Ok(()) };
    let path = target.path();
    let matching: Vec<_> = POLICY.config().routes().iter().filter(|(_, r)| path.segments().starts_with(r.prefix().segments())).collect();
    let selected = match request(path) {
        Ok(authorized) => Some(authorized.route().clone()),
        Err(AuthzError::Forbidden { route, .. } | AuthzError::Unavailable { route }) => Some(route),
        Err(AuthzError::NotFound) => None,
    };
    prop_assert_eq!(selected.as_ref(), matching.first().map(|(name, _)| *name), "{:?}", raw);
    prop_assert!(matching.len() <= 1, "{raw:?} matches several prefixes");
    Ok(())
}

proptest! {
    #![proptest_config(config(CASES))]

    #[test]
    fn accepted_segments_never_read_as_traversal(raw in hostile_target()) {
        check_segments_inert(&raw)?;
    }

    #[test]
    fn accepted_escape_soup_never_reads_as_traversal(raw in escape_soup()) {
        check_segments_inert(&raw)?;
    }

    #[test]
    fn normalization_is_idempotent(raw in hostile_target()) {
        check_idempotent(&raw)?;
    }

    #[test]
    fn escape_soup_normalization_is_idempotent(raw in escape_soup()) {
        check_idempotent(&raw)?;
    }

    #[test]
    fn authorized_paths_stay_under_the_upstream_base(raw in hostile_target()) {
        check_stays_under_base(&raw)?;
    }

    #[test]
    fn routes_are_selected_by_whole_segment_prefix(raw in hostile_target()) {
        check_route_selection(&raw)?;
    }
}

proptest! {
    #![proptest_config(config(PANIC_CASES))]

    #[test]
    fn parse_never_panics_on_arbitrary_strings(slash in any::<bool>(), text in any::<String>()) {
        let raw = if slash { format!("/{text}") } else { text };
        let _ = RequestTarget::parse(&raw);
    }

    #[test]
    fn parse_never_panics_on_arbitrary_bytes(slash in any::<bool>(), bytes in vec(any::<u8>(), 0..64)) {
        let text = String::from_utf8_lossy(&bytes);
        let raw = if slash { format!("/{text}") } else { text.into_owned() };
        let _ = RequestTarget::parse(&raw);
    }

    #[test]
    fn parse_never_panics_on_arbitrary_ascii(raw in "/[\\x00-\\x7f]{0,48}") {
        let _ = RequestTarget::parse(&raw);
    }
}

/// The properties above are vacuous if a generator never produces an accepted or authorized target; this keeps the
/// generators honest as the parser's rules change.
#[test]
fn hostile_targets_reach_acceptance_and_authorization() {
    let samples = sample(hostile_target(), 2000);
    let accepted: Vec<RequestTarget> = samples.iter().filter_map(|raw| RequestTarget::parse(raw).ok()).collect();
    let authorized = accepted.iter().filter(|target| request(target.path()).is_ok()).count();
    assert!(accepted.len() >= 400, "only {} of 2000 accepted", accepted.len());
    assert!(authorized >= 200, "only {authorized} of 2000 authorized");
}

#[test]
fn escape_soup_reaches_accepted_escapes() {
    let samples = sample(escape_soup(), 2000);
    let accepted = samples.iter().filter(|raw| raw.contains('%') && RequestTarget::parse(raw).is_ok()).count();
    assert!(accepted >= 100, "only {accepted} of 2000 accepted with an escape");
}

/// Minimal counterexamples the properties shrank to when one rejection rule was deliberately weakened: an escaped `%`
/// (double encoding), an escaped `/`, a literal `..`, an escaped fullwidth full stop, a prefix matched on characters
/// rather than segments, and a segment empty before its `;` parameter. Each must keep every invariant.
#[test]
fn shrunk_counterexamples_keep_every_invariant() {
    ["/fx/%252e", "/a/b/%252e/~", "/%2f", "/fx/..", "/fx/%ef%bc%8e", "/fx.evil.example", "/fx/;", "/%20/;"].into_iter().for_each(|raw| {
        [check_segments_inert, check_idempotent, check_stays_under_base, check_route_selection]
            .into_iter()
            .for_each(|check| check(raw).unwrap_or_else(|e| panic!("{raw:?}: {e}")));
    });
}
