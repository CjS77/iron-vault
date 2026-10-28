//! The configuration document: listeners, callers, routes and limits parsed from TOML bytes (spec §3.3).
//!
//! Parsing takes bytes the caller already holds, so this crate stays free of I/O and approval can hash exactly the
//! bytes that were parsed (spec §3.9). Only section-local rules are checked here; references between sections are
//! resolved by [`ValidatedConfig`](crate::ValidatedConfig).

use std::collections::BTreeMap;
use std::fmt;
use std::ops::Range;

use serde::Deserialize;
use serde::de::IgnoredAny;
use thiserror::Error;

use crate::caller::CallerConfig;
use crate::display::escaped;
use crate::limits::Limits;
use crate::listener::ListenerConfig;
use crate::name::{CallerName, ListenerName, RouteName};
use crate::route::RouteConfig;

/// The only configuration schema version this release understands.
pub const SCHEMA_VERSION: i64 = 1;

/// A configuration document whose every section passed its own validation.
///
/// Sections are held in [`BTreeMap`]s so iteration, and anything derived from it, follows name order rather than
/// file or hash order (spec §7). An omitted `[listeners]`, `[callers]` or `[routes]` table is empty; an omitted
/// `[limits]` table means the default limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedConfig {
    listeners: BTreeMap<ListenerName, ListenerConfig>,
    callers: BTreeMap<CallerName, CallerConfig>,
    routes: BTreeMap<RouteName, RouteConfig>,
    limits: Limits,
}

/// Where in the input an error was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Location {
    span: Range<usize>,
    line: usize,
    column: usize,
}

/// Why a configuration document was rejected.
///
/// Messages name the offending key or value and its position but never quote whole input lines.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConfigError {
    /// The input is not UTF-8; the location is the first invalid byte.
    #[error("configuration is not valid UTF-8 at {location}")]
    NotUtf8 {
        /// The first invalid byte.
        location: Location,
    },
    /// The document has no top-level `schema_version`.
    #[error("configuration has no schema_version at {location}; expected schema_version = {SCHEMA_VERSION}")]
    MissingSchemaVersion {
        /// The start of the document, since a missing key has no position of its own.
        location: Location,
    },
    /// `schema_version` names a schema this release does not understand.
    #[error("unsupported schema version {version} at {location}; this release reads schema_version = {SCHEMA_VERSION}")]
    UnsupportedSchemaVersion {
        /// The configured version.
        version: i64,
        /// The version's value in the input.
        location: Location,
    },
    /// The document is not valid TOML or a section breaks its rules.
    #[error("{message}{}", at(.location.as_ref()))]
    Invalid {
        /// The parser's description, with control and non-ASCII characters escaped.
        message: String,
        /// The offending key or value, when the parser could place it.
        location: Option<Location>,
    },
}

impl ParsedConfig {
    /// Parses and validates a configuration document.
    ///
    /// `schema_version` is checked before anything else, so a document written for a newer schema reports that
    /// rather than an unknown-field error from a key that schema added.
    pub fn from_toml(bytes: &[u8]) -> Result<Self, ConfigError> {
        let text = std::str::from_utf8(bytes).map_err(|e| not_utf8(bytes, e.valid_up_to()))?;
        check_schema_version(text)?;
        let raw: RawConfig = toml::from_str(text).map_err(|e| invalid(text, &e))?;
        Ok(Self {
            listeners: raw.listeners,
            callers: raw.callers,
            routes: raw.routes,
            limits: raw.limits,
        })
    }

    /// The schema version the document declared, which is always [`SCHEMA_VERSION`].
    pub fn schema_version(&self) -> i64 {
        SCHEMA_VERSION
    }

    /// Listeners by name.
    pub fn listeners(&self) -> &BTreeMap<ListenerName, ListenerConfig> {
        &self.listeners
    }

    /// Callers by name.
    pub fn callers(&self) -> &BTreeMap<CallerName, CallerConfig> {
        &self.callers
    }

    /// Routes by name.
    pub fn routes(&self) -> &BTreeMap<RouteName, RouteConfig> {
        &self.routes
    }

    /// Operational limits: the `[limits]` overrides, or the defaults when the table is absent.
    pub fn limits(&self) -> &Limits {
        &self.limits
    }
}

impl Location {
    /// The byte range of the offending text.
    pub fn span(&self) -> Range<usize> {
        self.span.clone()
    }

    /// The 1-based line of the span's start.
    pub fn line(&self) -> usize {
        self.line
    }

    /// The 1-based column, in characters, of the span's start.
    pub fn column(&self) -> usize {
        self.column
    }

    /// Locates `span` within `text`.
    fn new(text: &str, span: Range<usize>) -> Self {
        let before = text.get(..span.start).unwrap_or(text);
        let line = before.matches('\n').count() + 1;
        let column = before.rsplit('\n').next().map_or(0, |tail| tail.chars().count()) + 1;
        Self { span, line, column }
    }
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}, column {}", self.line, self.column)
    }
}

/// The top-level table as written; every section rejects keys it does not define.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    /// Already checked by [`check_schema_version`]; named here only so it is not an unknown field.
    #[serde(rename = "schema_version")]
    _schema_version: IgnoredAny,
    #[serde(default)]
    listeners: BTreeMap<ListenerName, ListenerConfig>,
    #[serde(default)]
    callers: BTreeMap<CallerName, CallerConfig>,
    #[serde(default)]
    routes: BTreeMap<RouteName, RouteConfig>,
    #[serde(default)]
    limits: Limits,
}

/// Just the version key, read before the rest of the document is interpreted.
#[derive(Deserialize)]
struct SchemaProbe {
    schema_version: Option<toml::Spanned<i64>>,
}

/// Rejects a document whose `schema_version` is missing or not [`SCHEMA_VERSION`].
fn check_schema_version(text: &str) -> Result<(), ConfigError> {
    let probe: SchemaProbe = toml::from_str(text).map_err(|e| invalid(text, &e))?;
    match probe.schema_version {
        None => Err(ConfigError::MissingSchemaVersion {
            location: Location::new(text, 0..0),
        }),
        Some(version) if *version.get_ref() == SCHEMA_VERSION => Ok(()),
        Some(version) => Err(ConfigError::UnsupportedSchemaVersion {
            version: *version.get_ref(),
            location: Location::new(text, version.span()),
        }),
    }
}

fn not_utf8(bytes: &[u8], valid_up_to: usize) -> ConfigError {
    let valid = bytes.get(..valid_up_to).map(String::from_utf8_lossy).unwrap_or_default();
    ConfigError::NotUtf8 {
        location: Location::new(&valid, valid.len()..valid.len() + 1),
    }
}

/// Keeps the parser's message and position but not its rendering of the input line.
fn invalid(text: &str, err: &toml::de::Error) -> ConfigError {
    ConfigError::Invalid {
        message: escaped(err.message().trim_end()),
        location: err.span().map(|span| Location::new(text, span)),
    }
}

/// " at <location>", or nothing when the parser gave no position.
fn at(location: Option<&Location>) -> String {
    location.map(|l| format!(" at {l}")).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec_example::SPEC_EXAMPLE;

    fn parse(s: &str) -> Result<ParsedConfig, ConfigError> {
        ParsedConfig::from_toml(s.as_bytes())
    }

    fn names<K: ToString, V>(map: &BTreeMap<K, V>) -> Vec<String> {
        map.keys().map(ToString::to_string).collect()
    }

    /// The error for `s`, which must carry a position on `line`.
    fn located(s: &str, line: usize) -> ConfigError {
        let err = parse(s).unwrap_err();
        let location = match &err {
            ConfigError::NotUtf8 { location }
            | ConfigError::MissingSchemaVersion { location }
            | ConfigError::UnsupportedSchemaVersion { location, .. } => location.clone(),
            ConfigError::Invalid { location, .. } => location.clone().unwrap_or_else(|| panic!("{err} has no location")),
        };
        assert_eq!(location.line(), line, "{err}");
        err
    }

    /// The 1-based line of the first occurrence of `needle` in `doc`.
    fn line_of(doc: &str, needle: &str) -> usize {
        doc[..doc.find(needle).unwrap()].matches('\n').count() + 1
    }

    /// Asserts that `doc` is rejected as invalid on the line holding `needle`, with a message containing `expected`.
    fn invalid(doc: &str, needle: &str, expected: &str) {
        let err = located(doc, line_of(doc, needle));
        assert!(
            matches!(err, ConfigError::Invalid { .. }) && err.to_string().contains(expected),
            "{err}"
        );
    }

    /// The spec example with the `key = ...` line removed from the `[routes.fx]` table only.
    fn fx_without(key: &str) -> String {
        let fx = SPEC_EXAMPLE.find("[routes.fx]").unwrap();
        let start = fx + SPEC_EXAMPLE[fx..].find(&format!("\n{key} =")).unwrap();
        let end = start + 1 + SPEC_EXAMPLE[start + 1..].find('\n').unwrap();
        format!("{}{}", &SPEC_EXAMPLE[..start], &SPEC_EXAMPLE[end..])
    }

    #[test]
    fn spec_example_parses() {
        let config = parse(SPEC_EXAMPLE).unwrap();
        assert_eq!(config.schema_version(), 1);
        assert_eq!(names(config.listeners()), ["local", "naomi-backoffice"]);
        assert_eq!(names(config.callers()), ["fx-mcp", "naomi-backoffice"]);
        assert_eq!(names(config.routes()), ["brave", "fx", "venice"]);
        assert_eq!(config.limits(), &Limits::default());
        let venice = config.routes().values().find(|r| r.prefix().as_str() == "/venice").unwrap();
        assert_eq!(venice.credential().as_str(), "venice");
    }

    #[test]
    fn same_bytes_give_equal_configs() {
        assert_eq!(parse(SPEC_EXAMPLE).unwrap(), parse(SPEC_EXAMPLE).unwrap());
    }

    #[test]
    fn sections_may_be_omitted() {
        let config = parse("schema_version = 1").unwrap();
        assert!(config.listeners().is_empty() && config.callers().is_empty() && config.routes().is_empty());
        assert_eq!(config.limits(), &Limits::default());
    }

    #[test]
    fn limits_table_overrides_defaults() {
        let config = parse(&format!("{SPEC_EXAMPLE}\n[limits]\nmax_connections = 16\n")).unwrap();
        assert_eq!(config.limits().max_connections(), 16);
        assert_eq!(config.limits().max_header_count(), Limits::default().max_header_count());
    }

    #[test]
    fn missing_schema_version_is_rejected() {
        let err = located(SPEC_EXAMPLE.trim_start_matches("schema_version = 1\n"), 1);
        assert!(matches!(err, ConfigError::MissingSchemaVersion { .. }), "{err}");
    }

    #[test]
    fn other_schema_versions_are_rejected_before_other_checks() {
        let v2 = format!(
            "{}\nfuture_section = true\n",
            SPEC_EXAMPLE.replace("schema_version = 1", "schema_version = 2")
        );
        let err = located(&v2, 1);
        assert!(matches!(err, ConfigError::UnsupportedSchemaVersion { version: 2, .. }), "{err}");
        assert_eq!(
            err.to_string(),
            "unsupported schema version 2 at line 1, column 18; this release reads schema_version = 1"
        );
        ["0", "-1"].iter().for_each(|v| {
            assert!(
                matches!(
                    parse(&format!("schema_version = {v}")),
                    Err(ConfigError::UnsupportedSchemaVersion { .. })
                ),
                "{v}"
            );
        });
        invalid("schema_version = \"1\"", "schema_version", "invalid type");
    }

    #[test]
    fn unknown_keys_are_rejected_at_every_level() {
        let cases = [
            ("schema_version = 1\n", "schema_version = 1\nextra = 1\n", "extra = 1"),
            ("schema_version = 1\n", "schema_version = 1\n[extra]\n", "[extra]"),
            ("[listeners.local]\n", "[listeners.local]\nbacklog = 5\n", "backlog"),
            ("routes = [\"fx\"]", "routes = [\"fx\"]\nrole = \"admin\"", "role"),
            ("prefix = \"/fx\"", "prefix = \"/fx\"\nhosts = []", "hosts"),
            (
                "slot = { query = \"access_key\" }",
                "slot = { query = \"access_key\", x = 1 }",
                "x = 1",
            ),
            ("burst = 10 }\n\n[routes.venice]", "burst = 10, y = 1 }\n\n[routes.venice]", "y = 1"),
        ];
        cases.iter().for_each(|(from, to, needle)| {
            let doc = SPEC_EXAMPLE.replacen(from, to, 1);
            let key = needle.trim_start_matches('[').split([' ', ']']).next().unwrap();
            invalid(&doc, needle, &format!("unknown field `{key}`"));
        });
        let limits = format!("{SPEC_EXAMPLE}\n[limits]\nmax_sockets = 1\n");
        invalid(&limits, "max_sockets", "unknown field `max_sockets`");
    }

    #[test]
    fn route_restrictions_are_required() {
        ["methods", "paths", "rate_limit"]
            .iter()
            .for_each(|key| invalid(&fx_without(key), "[routes.fx]", &format!("missing field `{key}`")));
    }

    #[test]
    fn bad_prefixes_are_located() {
        [("/", "must not be \"/\""), ("/fx/", "trailing slash"), ("/fx/*", "wildcard")]
            .iter()
            .for_each(|(prefix, expected)| {
                let line = format!("prefix = \"{prefix}\"");
                invalid(&SPEC_EXAMPLE.replace("prefix = \"/fx\"", &line), &line, expected);
            });
    }

    #[test]
    fn syntax_errors_are_located_without_echoing_input() {
        let err = located("schema_version = 1\n[routes.fx\nsecret = \"abc\"\n", 2);
        assert!(!err.to_string().contains('\n'), "{err}");
        assert!(!err.to_string().contains("secret"), "{err}");
    }

    #[test]
    fn control_characters_are_escaped() {
        let err = parse("schema_version = 1\n[routes.fx]\nprefix = \"/a\\u001b[31m\"\n")
            .unwrap_err()
            .to_string();
        assert!(!err.chars().any(char::is_control), "{err}");
    }

    #[test]
    fn bidi_controls_are_escaped() {
        let err = parse("schema_version = 1\n\"a\u{202e}b\" = 1\n").unwrap_err().to_string();
        assert!(err.contains("a\\u{202e}b"), "{err}");
        assert!(err.is_ascii(), "{err}");
    }

    #[test]
    fn non_utf8_input_is_located() {
        let err = ParsedConfig::from_toml(b"schema_version = 1\n# caf\xe9\n").unwrap_err();
        match err {
            ConfigError::NotUtf8 { location } => assert_eq!((location.line(), location.column(), location.span()), (2, 6, 24..25)),
            other => panic!("{other}"),
        }
    }
}
