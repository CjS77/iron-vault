//! The one place a route may write its credential (spec §1.3, §3.6).
//!
//! Configuration spells a slot in one of four TOML shapes (spec §3.3):
//!
//! ```toml
//! slot = { header = "X-Subscription-Token" }
//! slot = { header = "Authorization", format = "Bearer {}" }
//! slot = { query = "access_key" }
//! slot = "basic"
//! ```
//!
//! The Basic slot is the bare string `"basic"` because it takes no parameters: the username and password come from the
//! credential record, and the slot always writes `Authorization`.

use std::fmt;
use std::str::FromStr;

use serde::de::value::MapAccessDeserializer;
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use thiserror::Error;

use crate::display::quoted;
use crate::header_name::HeaderName;
use crate::reserved_headers;
use crate::slot_format::SlotFormat;

/// The keyword that selects the Basic slot.
const BASIC: &str = "basic";

/// The header a Basic slot writes, in lowercase.
const AUTHORIZATION: &str = "authorization";

/// Where a route writes its credential.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Slot {
    /// One header, holding the credential rendered through a format.
    Header(HeaderSlot),
    /// One query parameter, holding the credential.
    Query(QueryParamName),
    /// `Authorization: Basic …`, built from the credential's username and password.
    Basic,
}

impl Slot {
    /// The lowercase name of the header this slot writes, or `None` for a query slot.
    ///
    /// Every check that asks "does this route write header X" goes through here, so the Basic slot's implicit
    /// `Authorization` cannot be forgotten by one of them.
    pub fn header_written(&self) -> Option<&str> {
        match self {
            Self::Header(slot) => Some(slot.name().lowercase()),
            Self::Basic => Some(AUTHORIZATION),
            Self::Query(_) => None,
        }
    }
}

/// A header slot: a non-reserved header name and the format of its value.
///
/// The fields are private so that every header slot has passed the reserved-header check.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HeaderSlot {
    name: HeaderName,
    format: SlotFormat,
}

/// A query parameter name: non-empty, with no `&`, `=`, `#`, `%`, `+`, whitespace or control characters.
///
/// Those characters would end the name, start the value or fragment, or read differently after decoding (`%` starts an
/// escape, `+` decodes to a space), so the parameter the policy removes could differ from the one the upstream reads.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct QueryParamName(String);

/// A slot that cannot be accepted.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SlotError {
    /// The header slot names a caller-authentication or transport-control header.
    #[error("header {0} is reserved for caller authentication or transport control and cannot be a slot")]
    ReservedHeader(HeaderName),
    /// The query parameter name is empty.
    #[error("query parameter name is empty")]
    EmptyQueryName,
    /// The query parameter name contains a delimiter, decoding character, whitespace or control character.
    #[error("query parameter name {name} contains {found:?}")]
    InvalidQueryChar {
        /// The rejected name, escaped so control characters never reach a log raw.
        name: String,
        /// The first offending character.
        found: char,
    },
    /// A slot table names both `header` and `query`, or neither.
    #[error("a slot table must name exactly one of `header` or `query`")]
    Ambiguous,
    /// A query slot carries a `format`, which only header slots use.
    #[error("`format` applies only to header slots")]
    FormatWithoutHeader,
}

impl HeaderSlot {
    /// A header slot, refused when `name` is a reserved header (spec §3.6).
    pub fn new(name: HeaderName, format: SlotFormat) -> Result<Self, SlotError> {
        if reserved_headers::is_reserved(&name) {
            return Err(SlotError::ReservedHeader(name));
        }
        Ok(Self { name, format })
    }

    /// The header the credential is written to.
    pub fn name(&self) -> &HeaderName {
        &self.name
    }

    /// The format of the header's value.
    pub fn format(&self) -> &SlotFormat {
        &self.format
    }

    /// The header slot a Basic slot amounts to: `Authorization` with the format `Basic {}`.
    pub(crate) fn basic() -> Self {
        Self { name: HeaderName::authorization(), format: SlotFormat::basic() }
    }
}

impl QueryParamName {
    /// The name as configured.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn is_forbidden_query_char(c: char) -> bool {
    matches!(c, '&' | '=' | '#' | '%' | '+') || c.is_whitespace() || c.is_control()
}

impl TryFrom<&str> for QueryParamName {
    type Error = SlotError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        if s.is_empty() {
            return Err(SlotError::EmptyQueryName);
        }
        match s.chars().find(|c| is_forbidden_query_char(*c)) {
            Some(found) => Err(SlotError::InvalidQueryChar { name: quoted(s), found }),
            None => Ok(Self(s.to_owned())),
        }
    }
}

impl TryFrom<String> for QueryParamName {
    type Error = SlotError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::try_from(s.as_str())
    }
}

impl FromStr for QueryParamName {
    type Err = SlotError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

impl fmt::Display for QueryParamName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The inline-table spelling of a header or query slot, before the combination of keys is checked.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SlotTable {
    header: Option<HeaderName>,
    format: Option<SlotFormat>,
    query: Option<QueryParamName>,
}

impl TryFrom<SlotTable> for Slot {
    type Error = SlotError;

    fn try_from(table: SlotTable) -> Result<Self, Self::Error> {
        match (table.header, table.query, table.format) {
            (Some(name), None, format) => Ok(Self::Header(HeaderSlot::new(name, format.unwrap_or_default())?)),
            (None, Some(name), None) => Ok(Self::Query(name)),
            (None, Some(_), Some(_)) => Err(SlotError::FormatWithoutHeader),
            (Some(_), Some(_), _) | (None, None, _) => Err(SlotError::Ambiguous),
        }
    }
}

/// Accepts the string `"basic"` or a slot table; anything else is an error rather than a guess.
struct SlotVisitor;

impl<'de> Visitor<'de> for SlotVisitor {
    type Value = Slot;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"{BASIC}\" or a table with `header` (and optional `format`) or `query`")
    }

    fn visit_str<E: de::Error>(self, s: &str) -> Result<Slot, E> {
        match s {
            BASIC => Ok(Slot::Basic),
            other => Err(E::invalid_value(de::Unexpected::Str(&other.escape_default().to_string()), &self)),
        }
    }

    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Slot, A::Error> {
        let table = SlotTable::deserialize(MapAccessDeserializer::new(map))?;
        Slot::try_from(table).map_err(de::Error::custom)
    }
}

impl<'de> Deserialize<'de> for Slot {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(SlotVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Deserialize)]
    struct Route {
        slot: Slot,
    }

    fn parse(slot: &str) -> Result<Slot, toml::de::Error> {
        toml::from_str::<Route>(&format!("slot = {slot}")).map(|r| r.slot)
    }

    fn header(name: &str, format: &str) -> Slot {
        Slot::Header(HeaderSlot::new(name.parse().unwrap(), format.parse().unwrap()).unwrap())
    }

    #[test]
    fn header_written_names_the_header_in_lowercase() {
        assert_eq!(header("X-Subscription-Token", "{}").header_written(), Some("x-subscription-token"));
        assert_eq!(Slot::Basic.header_written(), Some("authorization"));
        assert_eq!(parse(r#"{ query = "access_key" }"#).unwrap().header_written(), None);
    }

    #[test]
    fn specification_examples_parse() {
        assert_eq!(parse(r#"{ query = "access_key" }"#).unwrap(), Slot::Query("access_key".parse().unwrap()));
        assert_eq!(parse(r#"{ header = "Authorization", format = "Bearer {}" }"#).unwrap(), header("Authorization", "Bearer {}"));
        assert_eq!(parse(r#"{ header = "X-Subscription-Token" }"#).unwrap(), header("X-Subscription-Token", "{}"));
        assert_eq!(parse(r#""basic""#).unwrap(), Slot::Basic);
    }

    #[test]
    fn header_slot_exposes_name_and_format() {
        let Slot::Header(slot) = parse(r#"{ header = "Authorization", format = "Bearer {}" }"#).unwrap() else {
            panic!("expected a header slot");
        };
        assert_eq!(slot.name().as_str(), "Authorization");
        assert_eq!(slot.format().to_string(), "Bearer {}");
    }

    #[test]
    fn rejects_bad_formats() {
        let error = parse(r#"{ header = "Authorization", format = "Bearer {} {}" }"#).unwrap_err().to_string();
        assert!(error.contains("exactly one {}"), "{error}");
        let error = parse(r#"{ header = "Authorization", format = "x\r\ny: {}" }"#).unwrap_err().to_string();
        assert!(error.contains("only printable ASCII"), "{error}");
    }

    #[test]
    fn rejects_reserved_headers() {
        [
            "Host",
            "X-Forwarded-For",
            "Proxy-Authorization",
            "transfer-encoding",
            "X-Host",
            "x-original-host",
            "X-HTTP-Host-Override",
            "True-Client-IP",
            "x-client-ip",
            "CF-Connecting-IP",
        ]
        .iter().for_each(|h| {
            let error = parse(&format!(r#"{{ header = "{h}" }}"#)).unwrap_err().to_string();
            assert!(error.contains("reserved"), "{h}: {error}");
        });
    }

    #[test]
    fn rejects_bad_query_names() {
        ["a&b", "a=b", "a#b", "a b", "a\\tb", "a\\u0000", ""].iter().for_each(|q| {
            assert!(parse(&format!(r#"{{ query = "{q}" }}"#)).is_err(), "{q:?}");
        });
    }

    #[test]
    fn query_name_rules() {
        assert_eq!(QueryParamName::try_from("a&b"), Err(SlotError::InvalidQueryChar { name: "\"a&b\"".into(), found: '&' }));
        assert_eq!(QueryParamName::try_from(""), Err(SlotError::EmptyQueryName));
        assert_eq!(QueryParamName::try_from("api-key.v2").unwrap().as_str(), "api-key.v2");
    }

    #[test]
    fn rejects_percent_escapes_in_query_names() {
        assert_eq!(QueryParamName::try_from("api%5Fkey"), Err(SlotError::InvalidQueryChar { name: "\"api%5Fkey\"".into(), found: '%' }));
    }

    #[test]
    fn rejects_plus_in_query_names() {
        assert_eq!(QueryParamName::try_from("api+key"), Err(SlotError::InvalidQueryChar { name: "\"api+key\"".into(), found: '+' }));
    }

    #[test]
    fn rejects_ambiguous_or_incomplete_tables() {
        [
            r#"{ header = "X-Key", query = "key" }"#,
            r#"{}"#,
            r#"{ format = "Bearer {}" }"#,
            r#"{ query = "key", format = "Bearer {}" }"#,
            r#"{ header = "X-Key", basic = true }"#,
            r#"{ header = "X-Key", extra = "x" }"#,
        ]
        .iter()
        .for_each(|s| assert!(parse(s).is_err(), "{s}"));
    }

    #[test]
    fn rejects_other_shapes() {
        [r#""Basic""#, r#""header""#, "true", "1", r#"["basic"]"#].iter().for_each(|s| assert!(parse(s).is_err(), "{s}"));
    }

    #[test]
    fn basic_header_slot_writes_authorization_and_is_not_reserved() {
        assert_eq!(Slot::Header(HeaderSlot::basic()), header("Authorization", "Basic {}"));
        assert_eq!(Slot::Header(HeaderSlot::basic()).header_written(), Slot::Basic.header_written());
    }

    #[test]
    fn authorization_header_is_allowed() {
        assert!(HeaderSlot::new("authorization".parse().unwrap(), SlotFormat::default()).is_ok());
    }
}
