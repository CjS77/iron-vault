//! Path patterns: the route restriction that decides which upstream paths a route may reach (specification §3.3).
//!
//! A pattern is written as an absolute path whose segments are literals, `*` (exactly one segment) or `**` (zero or
//! more complete segments). Patterns match the whole normalized upstream path, never its query. Normalizing a request
//! path into segments is [`NormalizedPath`](crate::NormalizedPath)'s job; matching here assumes segments in that form:
//! validated, with unreserved characters decoded and every other escape kept as uppercase `%XX`.
//!
//! A literal pattern segment never contains `%`, so a request segment that still holds an escape (`caf%C3%A9`) can be
//! matched only by `*` or `**`. Matching therefore fails closed: no literal can match a spelling it did not name.

use std::fmt;

use serde::Deserialize;
use thiserror::Error;

/// A reason a path pattern, or a route's list of them, is invalid.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PathPatternError {
    /// The pattern does not begin with `/`.
    #[error("path pattern {pattern:?} must start with '/'")]
    NotAbsolute {
        /// The rejected pattern.
        pattern: String,
    },
    /// The pattern contains an empty segment (`//`) or ends in a trailing slash.
    #[error("path pattern {pattern:?} contains an empty segment or trailing slash")]
    EmptySegment {
        /// The rejected pattern.
        pattern: String,
    },
    /// The pattern contains a `.` or `..` segment.
    #[error("path pattern {pattern:?} contains a dot segment")]
    DotSegment {
        /// The rejected pattern.
        pattern: String,
    },
    /// A segment mixes `*` with other characters, such as `a*` or `**b`.
    #[error("path pattern {pattern:?} has a partial wildcard segment {segment:?}")]
    PartialWildcard {
        /// The rejected pattern.
        pattern: String,
        /// The offending segment.
        segment: String,
    },
    /// The pattern contains a character outside the literal-segment set, such as `%`, `\`, `?`, `#`, whitespace, a
    /// control character, or non-ASCII text.
    #[error("path pattern {pattern:?} contains disallowed character {character:?}")]
    DisallowedCharacter {
        /// The rejected pattern.
        pattern: String,
        /// The first disallowed character.
        character: char,
    },
    /// A route declared no path patterns; there is no implicit "allow all".
    #[error("path patterns must not be empty; use [\"/**\"] to allow every path explicitly")]
    EmptyList,
    /// A route lists the same pattern twice.
    #[error("path pattern {pattern:?} is listed more than once")]
    Duplicate {
        /// The repeated pattern.
        pattern: String,
    },
}

/// One segment of a parsed path pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    /// Matches a request segment equal to this text.
    Literal(String),
    /// `*`: matches exactly one non-empty segment.
    One,
    /// `**`: matches zero or more complete segments.
    Any,
}

impl Segment {
    /// Whether this segment consumes exactly the given request segment; `Any` is handled by the matcher.
    fn matches_one(&self, segment: &str) -> bool {
        match self {
            Self::Literal(text) => text == segment,
            Self::One => !segment.is_empty(),
            Self::Any => false,
        }
    }
}

/// A validated path pattern such as `/historical/**`.
///
/// `/` alone has zero segments and matches only the root path. A trailing slash (`/latest/`) is rejected rather than
/// normalized away: request paths reach the matcher without their trailing slash, so accepting one in a pattern would
/// suggest a distinction the matcher cannot make.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct PathPattern {
    text: String,
    segments: Vec<Segment>,
}

impl PathPattern {
    /// Parses and validates a pattern.
    pub fn parse(text: &str) -> Result<Self, PathPatternError> {
        let rest = text
            .strip_prefix('/')
            .ok_or_else(|| PathPatternError::NotAbsolute { pattern: text.to_owned() })?;
        if let Some(character) = text.chars().find(|c| !is_pattern_char(*c)) {
            return Err(PathPatternError::DisallowedCharacter {
                pattern: text.to_owned(),
                character,
            });
        }
        let segments = match rest {
            "" => Vec::new(),
            _ => rest.split('/').map(|raw| parse_segment(text, raw)).collect::<Result<_, _>>()?,
        };
        Ok(Self {
            text: text.to_owned(),
            segments,
        })
    }

    /// The pattern as written in configuration.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Whether the pattern matches the whole of a normalized request path, given as its segments without the leading
    /// slash, trailing slash or query. The root path is the empty slice.
    ///
    /// Uses greedy two-pointer matching that backtracks only to the most recent `**`, so the worst case is
    /// O(pattern × path) rather than exponential in the number of `**` segments.
    pub fn matches(&self, path: &[&str]) -> bool {
        let pattern = &self.segments;
        let (mut p, mut s) = (0, 0);
        // Pattern index just after the last `**` seen, and the path index that `**` currently extends to.
        let mut backtrack: Option<(usize, usize)> = None;
        while let Some(segment) = path.get(s) {
            match pattern.get(p) {
                Some(Segment::Any) => {
                    p += 1;
                    backtrack = Some((p, s));
                }
                Some(current) if current.matches_one(segment) => {
                    p += 1;
                    s += 1;
                }
                _ => match backtrack {
                    Some((after_any, extent)) => {
                        p = after_any;
                        s = extent + 1;
                        backtrack = Some((after_any, s));
                    }
                    None => return false,
                },
            }
        }
        pattern.get(p..).is_some_and(|tail| tail.iter().all(|seg| *seg == Segment::Any))
    }

    /// The segments' text when every segment is a literal, or `None` when the pattern has a wildcard.
    ///
    /// Lets a route prefix share this type's literal-segment rules without accepting wildcards.
    pub(crate) fn literal_segments(&self) -> Option<Vec<String>> {
        self.segments
            .iter()
            .map(|segment| match segment {
                Segment::Literal(text) => Some(text.clone()),
                Segment::One | Segment::Any => None,
            })
            .collect()
    }
}

impl TryFrom<String> for PathPattern {
    type Error = PathPatternError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::parse(&text)
    }
}

impl fmt::Display for PathPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// Whether a character may appear in a pattern: `/`, `*`, or an RFC 3986 `pchar` other than `%`.
///
/// Excluding `%` gives each literal exactly one spelling. A normalized segment ([`NormalizedPath`](crate::NormalizedPath))
/// never escapes an unreserved character, but keeps an escaped sub-delimiter such as `%3B` encoded and distinct from a
/// literal `;`, so a literal here matches only the literal spelling. A normalized segment that still holds a `%XX`
/// escape is matched only by a wildcard. `?` and `#` are excluded because patterns never cover a query or fragment.
fn is_pattern_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "/*-._~!$&'()+,;=:@".contains(c)
}

/// Parses one `/`-separated piece of `pattern`.
fn parse_segment(pattern: &str, raw: &str) -> Result<Segment, PathPatternError> {
    match raw {
        "" => Err(PathPatternError::EmptySegment {
            pattern: pattern.to_owned(),
        }),
        "." | ".." => Err(PathPatternError::DotSegment {
            pattern: pattern.to_owned(),
        }),
        "*" => Ok(Segment::One),
        "**" => Ok(Segment::Any),
        _ if raw.contains('*') => Err(PathPatternError::PartialWildcard {
            pattern: pattern.to_owned(),
            segment: raw.to_owned(),
        }),
        _ => Ok(Segment::Literal(raw.to_owned())),
    }
}

/// A route's non-empty, duplicate-free list of path patterns; a path is allowed when any pattern matches it.
///
/// An empty list is invalid so that a missing restriction never widens into "allow all"; operators who want every
/// path write `["/**"]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "Vec<String>")]
pub struct PathPatterns(Vec<PathPattern>);

impl PathPatterns {
    /// Builds a list from validated patterns, rejecting an empty list or a repeated pattern.
    pub fn new(patterns: Vec<PathPattern>) -> Result<Self, PathPatternError> {
        if patterns.is_empty() {
            return Err(PathPatternError::EmptyList);
        }
        let duplicate = patterns
            .iter()
            .enumerate()
            .find(|(i, p)| patterns.iter().take(*i).any(|earlier| earlier == *p));
        match duplicate {
            Some((_, pattern)) => Err(PathPatternError::Duplicate {
                pattern: pattern.text.clone(),
            }),
            None => Ok(Self(patterns)),
        }
    }

    /// Whether any pattern matches the normalized request path segments.
    pub fn matches(&self, path: &[&str]) -> bool {
        self.0.iter().any(|pattern| pattern.matches(path))
    }

    /// The patterns in configuration order.
    pub fn iter(&self) -> impl Iterator<Item = &PathPattern> {
        self.0.iter()
    }
}

impl TryFrom<Vec<String>> for PathPatterns {
    type Error = PathPatternError;

    fn try_from(texts: Vec<String>) -> Result<Self, Self::Error> {
        texts
            .into_iter()
            .map(PathPattern::try_from)
            .collect::<Result<Vec<_>, _>>()
            .and_then(Self::new)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;

    fn pattern(text: &str) -> PathPattern {
        PathPattern::parse(text).unwrap()
    }

    fn segments(path: &str) -> Vec<&str> {
        path.split('/').filter(|s| !s.is_empty()).collect()
    }

    fn matches(pat: &str, path: &str) -> bool {
        pattern(pat).matches(&segments(path))
    }

    #[test]
    fn literal_matches_only_itself() {
        assert!(matches("/latest", "/latest"));
        assert!(!matches("/latest", "/"));
        assert!(!matches("/latest", "/latest/x"));
        assert!(!matches("/latest", "/Latest"));
        assert!(!matches("/latest", "/latestx"));
    }

    #[test]
    fn trailing_double_star_matches_zero_or_more() {
        ["/historical", "/historical/2024", "/historical/2024/01"]
            .iter()
            .for_each(|p| assert!(matches("/historical/**", p)));
        assert!(!matches("/historical/**", "/"));
        assert!(!matches("/historical/**", "/historicalx"));
        assert!(!matches("/historical/**", "/latest/historical"));
    }

    #[test]
    fn long_literal_matches_exactly() {
        assert!(matches("/api/v1/chat/completions", "/api/v1/chat/completions"));
        assert!(!matches("/api/v1/chat/completions", "/api/v1/chat"));
        assert!(!matches("/api/v1/chat/completions", "/api/v1/chat/completions/x"));
    }

    #[test]
    fn single_star_matches_exactly_one_segment() {
        assert!(matches("/a/*/c", "/a/b/c"));
        assert!(!matches("/a/*/c", "/a/c"));
        assert!(!matches("/a/*/c", "/a/b/x/c"));
        assert!(!pattern("/a/*/c").matches(&["a", "", "c"]));
    }

    #[test]
    fn root_double_star_matches_everything() {
        ["/", "/a", "/a/b/c"].iter().for_each(|p| assert!(matches("/**", p)));
    }

    #[test]
    fn root_pattern_matches_only_root() {
        assert!(matches("/", "/"));
        assert!(!matches("/", "/a"));
    }

    #[test]
    fn interior_double_star_backtracks() {
        assert!(matches("/a/**/c", "/a/c"));
        assert!(matches("/a/**/c", "/a/b/c"));
        assert!(matches("/a/**/c", "/a/c/c/c"));
        assert!(!matches("/a/**/c", "/a/c/d"));
        assert!(matches("/**/b/*", "/x/b/b/y"));
        assert!(!matches("/**/b/*", "/x/b"));
        assert!(matches("/**/**", "/"));
    }

    #[test]
    fn many_double_stars_complete_quickly() {
        let pat = pattern(&"/**/a".repeat(30));
        let path = vec!["a"; 29].into_iter().chain(std::iter::repeat_n("b", 2000)).collect::<Vec<_>>();
        let start = Instant::now();
        assert!(!pat.matches(&path));
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    /// Exponential but obviously correct reference matcher.
    fn reference(pattern: &[Segment], path: &[&str]) -> bool {
        match pattern.split_first() {
            None => path.is_empty(),
            Some((Segment::Any, rest)) => (0..=path.len()).any(|k| reference(rest, &path[k..])),
            Some((seg, rest)) => path
                .split_first()
                .is_some_and(|(head, tail)| seg.matches_one(head) && reference(rest, tail)),
        }
    }

    /// Every sequence of length up to `max` over `alphabet`.
    fn sequences<'a>(alphabet: &[&'a str], max: usize) -> Vec<Vec<&'a str>> {
        (0..max).fold(vec![Vec::new()], |acc, _| {
            let longer = acc.iter().filter(|s| s.len() == acc.last().map_or(0, Vec::len)).flat_map(|s| {
                alphabet
                    .iter()
                    .map(move |a| s.iter().copied().chain(std::iter::once(*a)).collect::<Vec<_>>())
            });
            acc.iter().cloned().chain(longer.collect::<Vec<_>>()).collect()
        })
    }

    #[test]
    fn agrees_with_reference_matcher() {
        let patterns = sequences(&["a", "b", "*", "**"], 4);
        let paths = sequences(&["a", "b"], 5);
        assert_eq!((patterns.len(), paths.len()), (341, 63));
        patterns.iter().for_each(|segs| {
            let pat = pattern(&format!("/{}", segs.join("/")));
            paths
                .iter()
                .for_each(|path| assert_eq!(pat.matches(path), reference(&pat.segments, path), "{pat} vs {path:?}"));
        });
    }

    #[test]
    fn rejects_invalid_patterns() {
        let cases = [
            ("", "NotAbsolute"),
            ("latest", "NotAbsolute"),
            ("//a", "EmptySegment"),
            ("/a//b", "EmptySegment"),
            ("/latest/", "EmptySegment"),
            ("/a/./b", "DotSegment"),
            ("/a/..", "DotSegment"),
            ("/a%2Fb", "DisallowedCharacter"),
            ("/a\\b", "DisallowedCharacter"),
            ("/a\u{0}b", "DisallowedCharacter"),
            ("/a\tb", "DisallowedCharacter"),
            ("/a b", "DisallowedCharacter"),
            ("/caf\u{e9}", "DisallowedCharacter"),
            ("/a?x=1", "DisallowedCharacter"),
            ("/a#frag", "DisallowedCharacter"),
            ("/a*", "PartialWildcard"),
            ("/**b", "PartialWildcard"),
            ("/***", "PartialWildcard"),
        ];
        cases.iter().for_each(|(text, kind)| {
            let err = PathPattern::parse(text).unwrap_err();
            assert!(format!("{err:?}").starts_with(kind), "{text:?} gave {err:?}, expected {kind}");
        });
    }

    #[test]
    fn accepts_dots_inside_segments() {
        assert!(matches("/v1.2/.well-known/a..b", "/v1.2/.well-known/a..b"));
    }

    #[test]
    fn list_matches_any_pattern() {
        let list = PathPatterns::try_from(vec!["/latest".to_owned(), "/historical/**".to_owned()]).unwrap();
        assert!(list.matches(&["latest"]));
        assert!(list.matches(&["historical", "2024"]));
        assert!(!list.matches(&["other"]));
        assert_eq!(
            list.iter().map(PathPattern::as_str).collect::<Vec<_>>(),
            ["/latest", "/historical/**"]
        );
    }

    #[test]
    fn list_rejects_empty_and_duplicates() {
        assert_eq!(PathPatterns::try_from(Vec::new()), Err(PathPatternError::EmptyList));
        let dup = PathPatterns::try_from(vec!["/a".to_owned(), "/b".to_owned(), "/a".to_owned()]);
        assert_eq!(dup, Err(PathPatternError::Duplicate { pattern: "/a".to_owned() }));
    }

    #[derive(Debug, Deserialize)]
    struct Route {
        paths: PathPatterns,
    }

    #[test]
    fn deserializes_from_toml() {
        let route: Route = toml::from_str(r#"paths = ["/latest", "/historical/**"]"#).unwrap();
        assert!(route.paths.matches(&["historical"]));
        assert_eq!(
            route.paths.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["/latest", "/historical/**"]
        );
    }

    #[test]
    fn deserialization_rejects_invalid_lists() {
        assert!(toml::from_str::<Route>("paths = []").is_err());
        assert!(toml::from_str::<Route>(r#"paths = ["/a*"]"#).is_err());
    }
}
