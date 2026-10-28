//! The fixed config and the hostile request-path generators that the property-test files share (specification §3.6,
//! §8; threat R-7).

// Each test binary compiles its own copy of this module and uses a different part of it, so the rest is dead code in
// that binary.
#![allow(dead_code)]
// Workspace lints deny `unwrap` outside tests, and clippy treats only `#[test]` functions as tests here; these helpers
// run only under the test harness, where a panic is a test failure.
#![allow(clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::sync::LazyLock;

use iron_vault_policy::{
    ActivePolicy, Capabilities, CatalogEntry, CredentialCatalog, CredentialKind, CredentialName, Host, ParsedConfig, Port, ValidatedConfig,
    activate,
};
use proptest::collection::vec;
use proptest::prelude::*;
use proptest::sample::select;
use proptest::strategy::ValueTree;
use proptest::test_runner::{Config, TestRunner};

/// One caller granted every route. The routes have one- and two-segment prefixes, `/fxa` shares its first characters
/// with `/fx` so only whole-segment matching tells them apart, and the upstream base paths are zero, one and two
/// segments deep. `fx` and `fxa` differ only in host, and `basic` shares `fx`'s host on another port, written with a
/// trailing dot that the one host conversion removes. Every slot shape appears: query, header with and without a
/// format, and Basic.
pub const CONFIG: &str = r#"schema_version = 1

[listeners.local]
unix_socket = "/run/iron-vault/proxy.sock"

[callers.agent]
listener = "local"
token_hash = "blake2b:0123456789abcdef00112233445566778899aabbccddeeff0f1e2d3c4b5a6978"
routes = ["fx", "fxa", "venice", "deep", "basic"]

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

[routes.basic]
prefix = "/basic"
upstream = "https://api.fx.example.:8443/b"
credential = "basic_login"
slot = "basic"
methods = ["GET"]
paths = ["/b/**"]
rate_limit = { requests = 60, per_seconds = 60, burst = 10 }
"#;

/// The config's route prefixes, and spellings of them with unreserved characters escaped, which select the same route.
pub const ROUTE_PREFIXES: &[&str] = &[
    "fx", "fxa", "venice", "a/b", "basic", "f%78", "%66%78", "venic%65", "a/%62", "b%61sic",
];

/// Look-alikes of the route prefixes that must not select a route, or must select a different one.
pub const DECOY_PREFIXES: &[&str] = &[
    "fx.evil.example",
    "fx@evil.example",
    "FX",
    "fX",
    "%66%58",
    "fx;x",
    "fx%2e",
    "f",
    "a",
    "b",
    "b/a",
    "nothing",
    "basic.",
    "BASIC",
];

/// Queries, which must never influence the path.
pub const QUERIES: &[&str] = &["", "?", "?a=1", "?x=%2e%2E&y=/?%25"];

/// Bytes whose escapes are traversal, a separator, a cut-short path, or a second decoding pass in waiting.
pub const HOSTILE_BYTES: &[u8] = &[b'.', b'/', b'\\', 0, b'%', b'?', b'#', b';', b'\n', 0x7f];

/// Bytes whose escapes are harmless: unreserved characters, sub-delimiters, and characters that stay encoded.
pub const BENIGN_BYTES: &[u8] = b"Az0~-_ :@!=\"";

/// Raw text that is invalid, or valid only in some positions, in a path.
pub const RAW_SPECIALS: &[&str] = &[
    "\\", "\0", "\t", "\x7f", " ", ";", ";x=1", "%", "%2", "%zz", "%+f", "?", "#", "//", "\u{e9}", "\u{FF0E}", "%c3%a9", "%C0%AE",
];

/// Unicode look-alikes and the ASCII text an upstream that folds Unicode (NFKC or a best-fit code page) turns them into.
pub const FOLDS: &[(char, &str)] = &[
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

/// [`CONFIG`] activated with every credential permitted on every route's upstream, so each route is available.
pub static POLICY: LazyLock<ActivePolicy> = LazyLock::new(|| {
    let config = ValidatedConfig::try_from(ParsedConfig::from_toml(CONFIG.as_bytes()).unwrap()).unwrap();
    activate(&config, &Capabilities::default(), &Catalog(route_origins(&config))).unwrap()
});

/// Every route upstream's host and port pair.
pub fn route_origins(config: &ValidatedConfig) -> BTreeSet<(Host, Port)> {
    config
        .routes()
        .values()
        .map(|route| (route.upstream().host().clone(), route.upstream().port()))
        .collect()
}

/// The one credential of the Basic kind, used by the `basic` route's Basic slot.
const BASIC_CREDENTIAL: &str = "basic_login";

/// Permits every credential on the same origins, each of the kind its route's slot needs.
struct Catalog(BTreeSet<(Host, Port)>);

impl CredentialCatalog for Catalog {
    fn entry(&self, name: &CredentialName) -> CatalogEntry {
        let kind = if name.as_str() == BASIC_CREDENTIAL {
            CredentialKind::Basic
        } else {
            CredentialKind::Static
        };
        CatalogEntry::Usable {
            kind,
            origins: self.0.clone(),
        }
    }
}

/// A runner config with `cases` cases and no failure files, so CI runs are reproducible from the seed alone.
pub fn config(cases: u32) -> Config {
    Config {
        cases,
        failure_persistence: None,
        ..Config::default()
    }
}

/// Draws `count` values from `strategy` with a fixed seed.
pub fn sample<T>(strategy: impl Strategy<Value = T>, count: usize) -> Vec<T> {
    let mut runner = TestRunner::deterministic();
    (0..count).map(|_| strategy.new_tree(&mut runner).unwrap().current()).collect()
}

/// The hex digits of `byte`, each letter in the case the matching low bit of `case` picks.
pub fn hex(byte: u8, case: u8) -> String {
    let digits = format!("{byte:02x}");
    digits
        .chars()
        .enumerate()
        .map(|(i, c)| if case >> i & 1 == 1 { c.to_ascii_uppercase() } else { c })
        .collect()
}

/// `byte` percent-encoded `layers` times: `%2e`, `%252e`, `%25252e`.
pub fn encoded(byte: u8, layers: usize, case: u8) -> String {
    format!("%{}{}", "25".repeat(layers.saturating_sub(1)), hex(byte, case))
}

pub fn ordinary() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9_~-]{1,6}"
}

pub fn dots() -> impl Strategy<Value = String> {
    select(&[".", "..", "...", ".x", "x."][..]).prop_map(String::from)
}

pub fn hostile_escape() -> impl Strategy<Value = String> {
    (select(HOSTILE_BYTES), 1..=3usize, any::<u8>()).prop_map(|(byte, layers, case)| encoded(byte, layers, case))
}

pub fn benign_escape() -> impl Strategy<Value = String> {
    (select(BENIGN_BYTES), any::<u8>()).prop_map(|(byte, case)| encoded(byte, 1, case))
}

/// A look-alike's UTF-8 bytes, each escaped with its own mix of hex case.
pub fn look_alike() -> impl Strategy<Value = String> {
    let chars: Vec<char> = FOLDS.iter().map(|(c, _)| *c).collect();
    (select(chars), any::<u32>()).prop_map(|(c, case)| {
        c.to_string()
            .bytes()
            .enumerate()
            .map(|(i, byte)| encoded(byte, 1, (case >> (2 * i)) as u8))
            .collect()
    })
}

/// One piece of a hostile path segment: ordinary text, dots, an escape, a look-alike, raw specials, or nothing.
pub fn fragment() -> impl Strategy<Value = String> {
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
pub fn segment() -> impl Strategy<Value = String> {
    vec(fragment(), 1..4).prop_map(|fragments| fragments.concat())
}

/// A route prefix most of the time, so that enough targets reach authorization; otherwise a decoy or none.
pub fn prefix() -> impl Strategy<Value = Option<&'static str>> {
    prop_oneof![4 => select(ROUTE_PREFIXES).prop_map(Some), 2 => select(DECOY_PREFIXES).prop_map(Some), 1 => Just(None)]
}

/// `/`, the prefix and segments joined by `/`, and an optional trailing slash.
pub fn join_path(prefix: Option<&str>, segments: Vec<String>, trailing_slash: bool) -> String {
    let path = prefix.map(String::from).into_iter().chain(segments).collect::<Vec<_>>().join("/");
    let trailing = if trailing_slash { "/" } else { "" };
    format!("/{path}{trailing}")
}

/// An origin-form target: an optional prefix, up to four segments, an optional trailing slash and a query.
pub fn hostile_target() -> impl Strategy<Value = String> {
    (prefix(), vec(segment(), 0..5), any::<bool>(), select(QUERIES))
        .prop_map(|(prefix, segments, slash, query)| format!("{}{query}", join_path(prefix, segments, slash)))
}
