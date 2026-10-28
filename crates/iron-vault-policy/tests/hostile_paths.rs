//! Property tests over hostile caller request paths (specification §3.6, §8; threat R-7).
//!
//! Example tests cover the attacks someone thought of. These generate targets that mix ordinary segments with raw,
//! mixed-case encoded and double- or triple-encoded hostile fragments under the prefixes of a fixed config, then check
//! invariants that must hold for every target [`RequestTarget::parse`] accepts and every request [`authorize`] accepts.

// Workspace lints deny `unwrap` outside tests, and clippy treats only `#[test]` functions as tests here; these helpers
// run only under the test harness, where a panic is a test failure.
#![allow(clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::sync::LazyLock;

use iron_vault_policy::{
    ActivePolicy, AuthorizedRequest, AuthzError, Capabilities, CatalogEntry, CredentialCatalog, CredentialName, Host, Method,
    NormalizedPath, ParsedConfig, Port, RequestTarget, ValidatedConfig, activate, authorize,
};
use proptest::collection::vec;
use proptest::prelude::*;
use proptest::sample::select;
use proptest::strategy::ValueTree;
use proptest::test_runner::{Config, TestCaseError, TestRunner};

/// Cases for each property over generated hostile targets: enough to reach every fragment kind in many combinations,
/// small enough that the whole file runs in a few seconds.
const CASES: u32 = 4096;

/// Cases for the panic-freedom properties, whose inputs are cheap to parse and mostly rejected at the first character.
const PANIC_CASES: u32 = 8192;

/// One caller granted every route. The routes have one- and two-segment prefixes, `/fxa` shares its first characters
/// with `/fx` so only whole-segment matching tells them apart, and the upstream base paths are zero, one and two
/// segments deep.
const CONFIG: &str = r#"schema_version = 1

[listeners.local]
unix_socket = "/run/iron-vault/proxy.sock"

[callers.agent]
listener = "local"
token_hash = "blake2b:0123456789abcdef00112233445566778899aabbccddeeff0f1e2d3c4b5a6978"
routes = ["fx", "fxa", "venice", "deep"]

[routes.fx]
prefix = "/fx"
upstream = "https://api.fx.example"
credential = "fx_key"
slot = { query = "access_key" }
methods = ["GET"]
paths = ["/**"]
rate_limit = { requests = 60, per_seconds = 60, burst = 10 }

[routes.fxa]
prefix = "/fxa"
upstream = "https://api.fxa.example/x"
credential = "fxa_key"
slot = { header = "X-Api-Key" }
methods = ["GET"]
paths = ["/x/**"]
rate_limit = { requests = 60, per_seconds = 60, burst = 10 }

[routes.venice]
prefix = "/venice"
upstream = "https://api.venice.ai/api/v1"
credential = "venice"
slot = { header = "Authorization", format = "Bearer {}" }
methods = ["GET"]
paths = ["/api/v1/chat/*", "/api/v1/models"]
rate_limit = { requests = 60, per_seconds = 60, burst = 10 }

[routes.deep]
prefix = "/a/b"
upstream = "https://api.deep.example/v2/base"
credential = "deep"
slot = { header = "X-Api-Key" }
methods = ["GET"]
paths = ["/v2/base/**"]
rate_limit = { requests = 60, per_seconds = 60, burst = 10 }
"#;

/// The config's route prefixes, and spellings of them with unreserved characters escaped, which select the same route.
const ROUTE_PREFIXES: &[&str] = &["fx", "fxa", "venice", "a/b", "f%78", "%66%78", "venic%65", "a/%62"];

/// Look-alikes of the route prefixes that must not select a route, or must select a different one.
const DECOY_PREFIXES: &[&str] =
    &["fx.evil.example", "fx@evil.example", "FX", "fX", "%66%58", "fx;x", "fx%2e", "f", "a", "b", "b/a", "nothing"];

/// Queries, which must never influence the path.
const QUERIES: &[&str] = &["", "?", "?a=1", "?x=%2e%2E&y=/?%25"];

/// Bytes whose escapes are traversal, a separator, a cut-short path, or a second decoding pass in waiting.
const HOSTILE_BYTES: &[u8] = &[b'.', b'/', b'\\', 0, b'%', b'?', b'#', b';', b'\n', 0x7f];

/// Bytes whose escapes are harmless: unreserved characters, sub-delimiters, and characters that stay encoded.
const BENIGN_BYTES: &[u8] = b"Az0~-_ :@!=\"";

/// Raw text that is invalid, or valid only in some positions, in a path.
const RAW_SPECIALS: &[&str] =
    &["\\", "\0", "\t", "\x7f", " ", ";", ";x=1", "%", "%2", "%zz", "%+f", "?", "#", "//", "\u{e9}", "\u{FF0E}", "%c3%a9", "%C0%AE"];

/// Unicode look-alikes and the ASCII text an upstream that folds Unicode (NFKC or a best-fit code page) turns them into.
const FOLDS: &[(char, &str)] = &[
    ('\u{FF0E}', "."),
    ('\u{2024}', "."),
    ('\u{2025}', ".."),
    ('\u{FE52}', "."),
    ('\u{FF0F}', "/"),
    ('\u{2215}', "/"),
    ('\u{2044}', "/"),
    ('\u{FF3C}', "\\"),
    ('\u{FE68}', "\\"),
    ('\u{00A5}', "\\"),
    ('\u{FF05}', "%"),
    ('\u{FE6A}', "%"),
    ('\u{FF1B}', ";"),
    ('\u{FE54}', ";"),
];

/// Rounds of decoding and folding that [`readings`] follows; the segments of an accepted path settle after one, and
/// anything still changing after this many has already shown every reading a test needs.
const MAX_PASSES: usize = 8;

static POLICY: LazyLock<ActivePolicy> = LazyLock::new(|| {
    let config = ValidatedConfig::try_from(ParsedConfig::from_toml(CONFIG.as_bytes()).unwrap()).unwrap();
    let origins = config.routes().values().map(|route| (route.upstream().host().clone(), route.upstream().port())).collect();
    activate(&config, &Capabilities::default(), &Catalog(origins)).unwrap()
});

/// Permits every credential on every route's upstream, so each route is available.
struct Catalog(BTreeSet<(Host, Port)>);

impl CredentialCatalog for Catalog {
    fn entry(&self, _: &CredentialName) -> CatalogEntry {
        CatalogEntry::Usable { origins: self.0.clone() }
    }
}

fn config(cases: u32) -> Config {
    Config { cases, failure_persistence: None, ..Config::default() }
}

// Generators.

/// The hex digits of `byte`, each letter in the case the matching low bit of `case` picks.
fn hex(byte: u8, case: u8) -> String {
    let digits = format!("{byte:02x}");
    digits.chars().enumerate().map(|(i, c)| if case >> i & 1 == 1 { c.to_ascii_uppercase() } else { c }).collect()
}

/// `byte` percent-encoded `layers` times: `%2e`, `%252e`, `%25252e`.
fn encoded(byte: u8, layers: usize, case: u8) -> String {
    format!("%{}{}", "25".repeat(layers.saturating_sub(1)), hex(byte, case))
}

fn ordinary() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9_~-]{1,6}"
}

fn dots() -> impl Strategy<Value = String> {
    select(&[".", "..", "...", ".x", "x."][..]).prop_map(String::from)
}

fn hostile_escape() -> impl Strategy<Value = String> {
    (select(HOSTILE_BYTES), 1..=3usize, any::<u8>()).prop_map(|(byte, layers, case)| encoded(byte, layers, case))
}

fn benign_escape() -> impl Strategy<Value = String> {
    (select(BENIGN_BYTES), any::<u8>()).prop_map(|(byte, case)| encoded(byte, 1, case))
}

/// A look-alike's UTF-8 bytes, each escaped with its own mix of hex case.
fn look_alike() -> impl Strategy<Value = String> {
    let chars: Vec<char> = FOLDS.iter().map(|(c, _)| *c).collect();
    (select(chars), any::<u32>()).prop_map(|(c, case)| {
        c.to_string().bytes().enumerate().map(|(i, byte)| encoded(byte, 1, (case >> (2 * i)) as u8)).collect()
    })
}

fn fragment() -> impl Strategy<Value = String> {
    prop_oneof![
        6 => ordinary(),
        2 => dots(),
        3 => hostile_escape(),
        1 => look_alike(),
        2 => benign_escape(),
        1 => select(RAW_SPECIALS).prop_map(String::from),
        1 => Just(String::new()),
    ]
}

/// One to three fragments run together, so `.` and `%2E` can meet to spell `..` and empty fragments can leave `//`.
fn segment() -> impl Strategy<Value = String> {
    vec(fragment(), 1..4).prop_map(|fragments| fragments.concat())
}

/// A route prefix most of the time, so that enough targets reach authorization; otherwise a decoy or none.
fn prefix() -> impl Strategy<Value = Option<&'static str>> {
    prop_oneof![4 => select(ROUTE_PREFIXES).prop_map(Some), 2 => select(DECOY_PREFIXES).prop_map(Some), 1 => Just(None)]
}

/// An origin-form target: an optional prefix, up to four segments, an optional trailing slash and a query.
fn hostile_target() -> impl Strategy<Value = String> {
    (prefix(), vec(segment(), 0..5), any::<bool>(), select(QUERIES)).prop_map(|(prefix, segments, slash, query)| {
        let path = prefix.map(String::from).into_iter().chain(segments).collect::<Vec<_>>().join("/");
        let trailing = if slash { "/" } else { "" };
        format!("/{path}{trailing}{query}")
    })
}

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

/// Draws `count` values from `strategy` with a fixed seed.
fn sample(strategy: impl Strategy<Value = String>, count: usize) -> Vec<String> {
    let mut runner = TestRunner::deterministic();
    (0..count).map(|_| strategy.new_tree(&mut runner).unwrap().current()).collect()
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
