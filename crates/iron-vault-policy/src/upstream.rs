//! Configured upstream URLs.
//!
//! A route's upstream is parsed here once. Validation runs on the raw text, because the `url` crate silently resolves
//! dot segments, strips tabs and newlines, and treats `\` as `/` for `https`, which would erase exactly the evidence
//! §3.6 requires us to reject. The canonical result is then checked to be a fixed point of the `url` parser, so a
//! later URL built from it through the `url` API means what was validated.

use std::fmt;
use std::str::FromStr;

use serde::Deserialize;
use thiserror::Error;
use url::Url;

use crate::escape::{EscapeAction, EscapeError, is_path_char, is_unreserved, walk_escapes};
use crate::host::{Host, HostError};
use crate::port::{Port, PortError};

const SCHEME_PREFIX: &str = "https://";

/// The HTTPS origin and base path that a route forwards to.
///
/// The scheme is always `https`; there is no user-info, query or fragment. The port is explicit ([`Port::HTTPS`] when
/// omitted). The base path is a list of validated segments, still percent-encoded as written but with escape hex
/// digits uppercased; `https://h/a/` and `https://h/a` are the same upstream, as are `https://h/` and `https://h`.
///
/// The canonical form's parsed `url::Url` is kept, so every request URL starts from the one parse that was checked
/// to be a fixed point rather than parsing the upstream again (§3.6).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct UpstreamUrl {
    host: Host,
    port: Port,
    base_segments: Vec<String>,
    url: Url,
}

/// Why an upstream URL was rejected.
///
/// Variants never echo the whole URL, because a rejected URL may carry user-info.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum UpstreamUrlError {
    /// The URL contains whitespace, a control character or a backslash, which URL parsers strip or reinterpret.
    #[error("upstream URL contains {0:?}; whitespace, control characters and backslashes are not allowed")]
    ForbiddenCharacter(char),
    /// The URL does not start with lowercase `https://`; cleartext and other schemes are never allowed.
    #[error("upstream URL must start with \"{SCHEME_PREFIX}\"")]
    NotHttps,
    /// The authority contains user-info (`user@host` or `user:password@host`).
    #[error("upstream URL must not contain user-info")]
    UserInfo,
    /// The URL has a query component.
    #[error("upstream URL must not contain a query")]
    Query,
    /// The URL has a fragment component.
    #[error("upstream URL must not contain a fragment")]
    Fragment,
    /// The authority has text after a bracketed IPv6 literal that is not a port.
    #[error("upstream URL authority is malformed")]
    MalformedAuthority,
    /// The host is not acceptable.
    #[error("upstream URL host is invalid: {0}")]
    Host(#[from] HostError),
    /// The port is not acceptable.
    #[error("upstream URL port is invalid: {0}")]
    Port(#[from] PortError),
    /// The base path has an empty segment other than one trailing slash.
    #[error("upstream URL base path has an empty segment")]
    EmptySegment,
    /// The base path has a `.` or `..` segment.
    #[error("upstream URL base path segment {0:?} is a dot segment")]
    DotSegment(String),
    /// A base path segment contains a character outside the RFC 3986 path character set.
    #[error("upstream URL base path contains {0:?}, which must not appear unencoded in a path")]
    ForbiddenPathCharacter(char),
    /// A `%` in the base path is not followed by two hex digits.
    #[error("upstream URL base path segment {0:?} has a malformed percent escape")]
    MalformedEscape(String),
    /// A base path escape encodes a separator, a dot or other unreserved character, `%`, or a control character,
    /// any of which another decoding pass could turn into traversal; or the escapes decode to bytes that are not UTF-8.
    #[error("upstream URL base path segment {0:?} percent-encodes a character that must not be encoded, or invalid UTF-8")]
    ForbiddenEscape(String),
    /// The `url` crate serializes the canonical form differently, so a URL built later would not mean what was
    /// validated.
    #[error("upstream URL would be reinterpreted by the URL parser")]
    Reinterpreted,
}

impl UpstreamUrl {
    /// The canonical upstream host.
    pub fn host(&self) -> &Host {
        &self.host
    }

    /// The upstream port, 443 when the URL omitted it.
    pub fn port(&self) -> Port {
        self.port
    }

    /// The base path segments, percent-encoded as written with uppercase escape hex. Empty for a root base path.
    pub fn base_segments(&self) -> &[String] {
        &self.base_segments
    }

    /// The canonical form parsed as a URL: the base for every request URL on this upstream.
    pub fn as_url(&self) -> &Url {
        &self.url
    }
}

impl FromStr for UpstreamUrl {
    type Err = UpstreamUrlError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        check_raw_characters(raw)?;
        let rest = raw.strip_prefix(SCHEME_PREFIX).ok_or(UpstreamUrlError::NotHttps)?;
        check_no_query_or_fragment(rest)?;
        let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
        let (host, port) = parse_authority(authority)?;
        let base_segments = parse_base_path(path)?;
        let url = check_url_fixed_point(&canonical(&host, port, &base_segments))?;
        Ok(UpstreamUrl {
            host,
            port,
            base_segments,
            url,
        })
    }
}

impl TryFrom<String> for UpstreamUrl {
    type Error = UpstreamUrlError;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        raw.parse()
    }
}

/// The canonical form: lowercase scheme, canonical host, port only when it is not 443, and the base path without a
/// trailing slash (`/` for a root base path).
impl fmt::Display for UpstreamUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&canonical(&self.host, self.port, &self.base_segments))
    }
}

fn canonical(host: &Host, port: Port, base_segments: &[String]) -> String {
    let path = base_segments.join("/");
    match port {
        Port::HTTPS => format!("{SCHEME_PREFIX}{host}/{path}"),
        _ => format!("{SCHEME_PREFIX}{host}:{port}/{path}"),
    }
}

/// The raw-text checks should already exclude anything the `url` crate rewrites; this makes that a guarantee.
fn check_url_fixed_point(canonical: &str) -> Result<Url, UpstreamUrlError> {
    match Url::parse(canonical) {
        Ok(parsed) if parsed.as_str() == canonical => Ok(parsed),
        _ => Err(UpstreamUrlError::Reinterpreted),
    }
}

fn check_raw_characters(raw: &str) -> Result<(), UpstreamUrlError> {
    raw.chars()
        .find(|c| c.is_control() || c.is_whitespace() || *c == '\\')
        .map_or(Ok(()), |c| Err(UpstreamUrlError::ForbiddenCharacter(c)))
}

fn check_no_query_or_fragment(rest: &str) -> Result<(), UpstreamUrlError> {
    match rest.chars().find(|c| matches!(c, '?' | '#')) {
        Some('?') => Err(UpstreamUrlError::Query),
        Some(_) => Err(UpstreamUrlError::Fragment),
        None => Ok(()),
    }
}

fn parse_authority(authority: &str) -> Result<(Host, Port), UpstreamUrlError> {
    if authority.contains('@') {
        return Err(UpstreamUrlError::UserInfo);
    }
    let (host, port) = split_host_port(authority)?;
    let port = port.map(str::parse).transpose()?.unwrap_or(Port::HTTPS);
    Ok((host.parse()?, port))
}

/// Splits on the port separator, which for an IPv6 literal is the first `:` after the closing bracket.
fn split_host_port(authority: &str) -> Result<(&str, Option<&str>), UpstreamUrlError> {
    let host_end = match authority.starts_with('[') {
        true => authority.find(']').map_or(authority.len(), |i| i + 1),
        false => authority.find(':').unwrap_or(authority.len()),
    };
    let (host, after) = authority.split_at(host_end);
    match after {
        "" => Ok((host, None)),
        _ => after
            .strip_prefix(':')
            .map(|port| (host, Some(port)))
            .ok_or(UpstreamUrlError::MalformedAuthority),
    }
}

/// `path` is empty or starts with `/`. One trailing slash is dropped; any other empty segment is an error.
fn parse_base_path(path: &str) -> Result<Vec<String>, UpstreamUrlError> {
    let trimmed = path.strip_prefix('/').unwrap_or(path);
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    trimmed.strip_suffix('/').unwrap_or(trimmed).split('/').map(parse_segment).collect()
}

fn parse_segment(segment: &str) -> Result<String, UpstreamUrlError> {
    match segment {
        "" => Err(UpstreamUrlError::EmptySegment),
        "." | ".." => Err(UpstreamUrlError::DotSegment(segment.to_owned())),
        _ => {
            check_path_characters(segment)?;
            normalize_escapes(segment)
        }
    }
}

/// Anything outside [`is_path_char`] would be percent-encoded by a URL serializer and so change meaning.
fn check_path_characters(segment: &str) -> Result<(), UpstreamUrlError> {
    segment
        .chars()
        .find(|c| !is_path_char(*c))
        .map_or(Ok(()), |c| Err(UpstreamUrlError::ForbiddenPathCharacter(c)))
}

/// Uppercases escape hex digits and checks each escape, then requires the decoded segment to be UTF-8 so overlong
/// encodings such as `%C0%AE` (a lenient decoder's `.`) cannot slip through.
fn normalize_escapes(segment: &str) -> Result<String, UpstreamUrlError> {
    let policy = |byte| match is_forbidden_escape(byte) {
        true => EscapeAction::Reject(()),
        false => EscapeAction::Keep,
    };
    walk_escapes(segment, policy).map(|walked| walked.normalized).map_err(|e| match e {
        EscapeError::Malformed => UpstreamUrlError::MalformedEscape(segment.to_owned()),
        EscapeError::Rejected(()) | EscapeError::InvalidUtf8 => UpstreamUrlError::ForbiddenEscape(segment.to_owned()),
    })
}

/// Encoded unreserved characters (including `.`) have an unencoded equivalent, so encoding them only hides intent;
/// encoded separators, `%` and controls are what double decoding turns into traversal.
fn is_forbidden_escape(byte: u8) -> bool {
    let c = char::from(byte);
    is_unreserved(c) || matches!(c, '/' | '\\' | '%') || c.is_ascii_control()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upstream(raw: &str) -> UpstreamUrl {
        raw.parse().unwrap_or_else(|e| panic!("{raw:?} should parse: {e}"))
    }

    fn reject(raw: &str) -> UpstreamUrlError {
        raw.parse::<UpstreamUrl>().expect_err(raw)
    }

    fn segments(raw: &str) -> Vec<String> {
        upstream(raw).base_segments().to_vec()
    }

    #[test]
    fn spec_example_upstreams_are_accepted() {
        let fx = upstream("https://api.fx.example");
        assert_eq!(
            (fx.host().as_str(), fx.port(), fx.base_segments()),
            ("api.fx.example", Port::HTTPS, &[][..])
        );
        let venice = upstream("https://api.venice.ai/api/v1");
        assert_eq!((venice.host().as_str(), venice.port()), ("api.venice.ai", Port::HTTPS));
        assert_eq!(venice.base_segments(), ["api", "v1"]);
        assert_eq!(upstream("https://api.search.brave.com").host().as_str(), "api.search.brave.com");
    }

    #[test]
    fn display_is_canonical() {
        assert_eq!(
            upstream("https://API.Venice.AI./api/v1/").to_string(),
            "https://api.venice.ai/api/v1"
        );
        assert_eq!(upstream("https://api.fx.example").to_string(), "https://api.fx.example/");
        assert_eq!(
            upstream("https://api.fx.example:8443/x").to_string(),
            "https://api.fx.example:8443/x"
        );
        assert_eq!(upstream("https://[2001:DB8::1]:443/").to_string(), "https://[2001:db8::1]/");
    }

    #[test]
    fn omitted_and_explicit_443_are_equal() {
        assert_eq!(upstream("https://api.fx.example:443"), upstream("https://api.fx.example"));
        assert_eq!(upstream("https://api.fx.example:8443").port().get(), 8443);
    }

    #[test]
    fn one_trailing_slash_is_normalized_away() {
        assert_eq!(upstream("https://h.example/"), upstream("https://h.example"));
        assert_eq!(upstream("https://h.example/api/v1/"), upstream("https://h.example/api/v1"));
    }

    #[test]
    fn ipv6_upstreams_split_host_and_port() {
        let ip = upstream("https://[::1]:8443/base");
        assert_eq!(
            (ip.host().as_str(), ip.port().get(), ip.base_segments()),
            ("[::1]", 8443, &["base".to_owned()][..])
        );
        assert_eq!(reject("https://[::1]x"), UpstreamUrlError::MalformedAuthority);
        assert_eq!(reject("https://[::1"), UpstreamUrlError::Host(HostError::InvalidIpv6));
    }

    #[test]
    fn non_https_schemes_are_rejected() {
        [
            "http://api.fx.example",
            "HTTPS://api.fx.example",
            "https:api.fx.example",
            "https:/api.fx.example",
            "ftp://h",
            "//h",
            "h",
        ]
        .into_iter()
        .for_each(|raw| assert_eq!(reject(raw), UpstreamUrlError::NotHttps, "{raw}"));
    }

    #[test]
    fn user_info_is_rejected() {
        [
            "https://user@host.example",
            "https://user:pw@host.example",
            "https://host.example:443@evil.example",
            "https://@host.example",
        ]
        .into_iter()
        .for_each(|raw| assert_eq!(reject(raw), UpstreamUrlError::UserInfo, "{raw}"));
    }

    #[test]
    fn user_info_is_not_echoed_in_errors() {
        let message = reject("https://user:secret@host.example").to_string();
        assert!(!message.contains("secret"), "{message}");
    }

    #[test]
    fn query_and_fragment_are_rejected() {
        assert_eq!(reject("https://host/?q"), UpstreamUrlError::Query);
        assert_eq!(reject("https://host?"), UpstreamUrlError::Query);
        assert_eq!(reject("https://host/#f"), UpstreamUrlError::Fragment);
        assert_eq!(reject("https://host#"), UpstreamUrlError::Fragment);
    }

    #[test]
    fn bad_ports_are_rejected() {
        assert_eq!(reject("https://host:0"), UpstreamUrlError::Port(PortError::Zero));
        [
            "https://host:",
            "https://host:0443",
            "https://host:65536",
            "https://host:+1",
            "https://host:1:2",
        ]
        .into_iter()
        .for_each(|raw| assert_eq!(reject(raw), UpstreamUrlError::Port(PortError::NotCanonical), "{raw}"));
    }

    #[test]
    fn bad_hosts_are_rejected() {
        assert_eq!(reject("https://"), UpstreamUrlError::Host(HostError::Empty));
        assert_eq!(reject("https:///path"), UpstreamUrlError::Host(HostError::Empty));
        assert_eq!(reject("https://:443"), UpstreamUrlError::Host(HostError::Empty));
        assert_eq!(
            reject("https://*.example.com"),
            UpstreamUrlError::Host(HostError::ForbiddenCharacter('*'))
        );
        assert_eq!(
            reject("https://ho%73t.example"),
            UpstreamUrlError::Host(HostError::ForbiddenCharacter('%'))
        );
        assert_eq!(reject("https://127.1"), UpstreamUrlError::Host(HostError::NonCanonicalIp));
    }

    #[test]
    fn stripped_or_reinterpreted_characters_are_rejected() {
        assert_eq!(reject("https://host.example/a\\b"), UpstreamUrlError::ForbiddenCharacter('\\'));
        assert_eq!(
            reject("https://evil.example\\@host.example"),
            UpstreamUrlError::ForbiddenCharacter('\\')
        );
        assert_eq!(reject("https://host.example/a\tb"), UpstreamUrlError::ForbiddenCharacter('\t'));
        assert_eq!(reject("https://ho\nst.example"), UpstreamUrlError::ForbiddenCharacter('\n'));
        assert_eq!(reject(" https://host.example"), UpstreamUrlError::ForbiddenCharacter(' '));
        assert_eq!(reject("https://host.example/\0"), UpstreamUrlError::ForbiddenCharacter('\0'));
    }

    #[test]
    fn dot_segments_are_rejected() {
        assert_eq!(reject("https://host/a/../b"), UpstreamUrlError::DotSegment("..".to_owned()));
        assert_eq!(reject("https://host/./b"), UpstreamUrlError::DotSegment(".".to_owned()));
        assert_eq!(reject("https://host/a/.."), UpstreamUrlError::DotSegment("..".to_owned()));
        assert_eq!(reject("https://host/a/../"), UpstreamUrlError::DotSegment("..".to_owned()));
    }

    #[test]
    fn empty_interior_segments_are_rejected() {
        ["https://host//", "https://host//a", "https://host/a//b", "https://host/a//"]
            .into_iter()
            .for_each(|raw| assert_eq!(reject(raw), UpstreamUrlError::EmptySegment, "{raw}"));
    }

    #[test]
    fn encoded_dots_and_separators_are_rejected_in_every_case_mix() {
        let encodings = ["%2e", "%2E", "%2f", "%2F", "%5c", "%5C", "%25", "%00", "%7f", "%7F", "%41", "%7e"];
        let shapes = [
            "https://host/{}",
            "https://host/a/{}/b",
            "https://host/{}{}",
            "https://host/.{}",
            "https://host/a{}b",
        ];
        shapes
            .iter()
            .flat_map(|shape| encodings.iter().map(move |enc| shape.replace("{}", enc)))
            .for_each(|raw| {
                assert!(matches!(reject(&raw), UpstreamUrlError::ForbiddenEscape(_)), "{raw}");
            });
    }

    #[test]
    fn double_encoded_traversal_is_rejected() {
        [
            "https://host/%252e%252e",
            "https://host/%252E",
            "https://host/a/%252f/b",
            "https://host/%255c",
        ]
        .into_iter()
        .for_each(|raw| assert!(matches!(reject(raw), UpstreamUrlError::ForbiddenEscape(_)), "{raw}"));
    }

    #[test]
    fn overlong_and_invalid_utf8_escapes_are_rejected() {
        [
            "https://host/%C0%AE",
            "https://host/%c0%ae%c0%ae",
            "https://host/%E0%80%AE",
            "https://host/%FF",
            "https://host/%C3",
        ]
        .into_iter()
        .for_each(|raw| assert!(matches!(reject(raw), UpstreamUrlError::ForbiddenEscape(_)), "{raw}"));
        assert_eq!(segments("https://host/caf%c3%a9"), ["caf%C3%A9"]);
    }

    #[test]
    fn malformed_escapes_are_rejected() {
        [
            "https://host/%",
            "https://host/%2",
            "https://host/%zz",
            "https://host/%+f",
            "https://host/a%",
        ]
        .into_iter()
        .for_each(|raw| assert!(matches!(reject(raw), UpstreamUrlError::MalformedEscape(_)), "{raw}"));
    }

    #[test]
    fn harmless_escapes_are_kept_with_uppercase_hex() {
        assert_eq!(segments("https://host/a%20b/c%3a"), ["a%20b", "c%3A"]);
        assert_eq!(upstream("https://host/a%3a"), upstream("https://host/a%3A"));
    }

    #[test]
    fn unencoded_non_path_characters_are_rejected() {
        [
            "https://host/a\"b",
            "https://host/a<b",
            "https://host/a{b",
            "https://host/a^b",
            "https://host/é",
            "https://host/a|b",
        ]
        .into_iter()
        .for_each(|raw| assert!(matches!(reject(raw), UpstreamUrlError::ForbiddenPathCharacter(_)), "{raw}"));
        assert_eq!(reject("https://host/a b"), UpstreamUrlError::ForbiddenCharacter(' '));
    }

    #[test]
    fn rfc3986_path_characters_are_accepted() {
        assert_eq!(
            segments("https://host/a-b_c~d.e/f:g@h/!$&'()*+,;="),
            ["a-b_c~d.e", "f:g@h", "!$&'()*+,;="]
        );
        assert_eq!(segments("https://host/...").len(), 1);
    }

    #[test]
    fn canonical_display_is_a_fixed_point() {
        [
            "https://API.example.com./v1/",
            "https://[::ffff:192.0.2.1]:8443/a%3a",
            "https://bücher.example/x",
        ]
        .into_iter()
        .map(upstream)
        .for_each(|u| assert_eq!(upstream(&u.to_string()), u));
    }

    #[test]
    fn deserializes_through_validation() {
        use serde::de::IntoDeserializer;
        use serde::de::value::{Error, StringDeserializer};

        let ok: StringDeserializer<Error> = "https://api.venice.ai/api/v1".to_owned().into_deserializer();
        assert_eq!(
            UpstreamUrl::deserialize(ok).map(|u| u.to_string()),
            Ok("https://api.venice.ai/api/v1".to_owned())
        );
        let bad: StringDeserializer<Error> = "http://api.venice.ai".to_owned().into_deserializer();
        assert!(UpstreamUrl::deserialize(bad).is_err());
    }
}
