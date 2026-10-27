//! The request-path prefix that selects a route (spec §3.3, §3.6).

use std::fmt;
use std::str::FromStr;

use serde::Deserialize;
use thiserror::Error;

use crate::display::quoted;
use crate::path_pattern::{PathPattern, PathPatternError};

/// A route's prefix, such as `/fx` or `/api/fx`: one or more literal segments with no wildcard or trailing slash.
///
/// Segments follow the same literal rules as a [`PathPattern`], so they are in decoded form and never contain `%`. A
/// request segment that still holds a percent escape therefore never equals a prefix segment, and a request that
/// spells its prefix with escapes matches no route: the comparison fails closed instead of decoding twice.
///
/// `/` alone is rejected so that no route can claim every request path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct RoutePrefix {
    text: String,
    segments: Vec<String>,
}

/// Why a route prefix was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RoutePrefixError {
    /// The prefix breaks a literal-segment rule shared with path patterns.
    #[error("invalid route prefix: {0}")]
    Segment(#[from] PathPatternError),
    /// The prefix is `/`, which would match every request path.
    #[error("route prefix must not be \"/\"; it would match every request path")]
    Root,
    /// The prefix contains a `*` or `**` segment.
    #[error("route prefix {prefix} must not contain a wildcard segment")]
    Wildcard {
        /// The rejected prefix, escaped.
        prefix: String,
    },
}

impl RoutePrefix {
    /// The prefix as written in configuration.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The prefix's segments without slashes, in order; never empty.
    pub fn segments(&self) -> &[String] {
        &self.segments
    }
}

impl TryFrom<&str> for RoutePrefix {
    type Error = RoutePrefixError;

    fn try_from(text: &str) -> Result<Self, Self::Error> {
        let segments = PathPattern::parse(text)?.literal_segments().ok_or_else(|| RoutePrefixError::Wildcard { prefix: quoted(text) })?;
        match segments.is_empty() {
            true => Err(RoutePrefixError::Root),
            false => Ok(Self { text: text.to_owned(), segments }),
        }
    }
}

impl TryFrom<String> for RoutePrefix {
    type Error = RoutePrefixError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::try_from(text.as_str())
    }
}

impl FromStr for RoutePrefix {
    type Err = RoutePrefixError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

impl fmt::Display for RoutePrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_prefixes_parse() {
        let fx: RoutePrefix = "/fx".parse().unwrap();
        assert_eq!(fx.segments(), ["fx"]);
        assert_eq!(fx.to_string(), "/fx");
        let nested: RoutePrefix = "/api/v1.2".parse().unwrap();
        assert_eq!(nested.segments(), ["api", "v1.2"]);
    }

    #[test]
    fn root_is_rejected() {
        assert_eq!("/".parse::<RoutePrefix>(), Err(RoutePrefixError::Root));
    }

    #[test]
    fn wildcards_are_rejected() {
        ["/fx/*", "/fx/**", "/**", "/*/fx"]
            .iter()
            .for_each(|s| assert!(matches!(s.parse::<RoutePrefix>(), Err(RoutePrefixError::Wildcard { .. })), "{s}"));
    }

    #[test]
    fn segment_rules_are_shared_with_path_patterns() {
        let cases = [
            ("fx", PathPatternError::NotAbsolute { pattern: "fx".to_owned() }),
            ("/fx/", PathPatternError::EmptySegment { pattern: "/fx/".to_owned() }),
            ("/fx//a", PathPatternError::EmptySegment { pattern: "/fx//a".to_owned() }),
            ("/fx/..", PathPatternError::DotSegment { pattern: "/fx/..".to_owned() }),
            ("/f%78", PathPatternError::DisallowedCharacter { pattern: "/f%78".to_owned(), character: '%' }),
            ("/fx*", PathPatternError::PartialWildcard { pattern: "/fx*".to_owned(), segment: "fx*".to_owned() }),
        ];
        cases.into_iter().for_each(|(s, err)| assert_eq!(s.parse::<RoutePrefix>(), Err(RoutePrefixError::Segment(err)), "{s}"));
    }

    #[test]
    fn errors_escape_control_characters() {
        ["/a\u{1b}[31m", "/\u{7}/*"].iter().for_each(|s| {
            let err = s.parse::<RoutePrefix>().unwrap_err().to_string();
            assert!(!err.chars().any(char::is_control), "{err}");
        });
    }
}
