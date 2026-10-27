//! Caller request targets: the one path representation used for both authorization and forwarding (specification
//! §3.3, §3.5 steps 2 and 4, §3.6).
//!
//! Caller paths are hostile. Every check runs on the raw target before anything is decoded, so normalization can never
//! erase evidence of traversal. A target is accepted only in origin form (`/path?query`); the path is split into
//! segments and each segment is rewritten into its normalized form:
//!
//! - percent-encoded RFC 3986 unreserved characters (letters, digits, `-`, `_`, `~`) are decoded;
//! - every other escape is kept, with uppercase hex digits;
//! - literal characters are kept as written.
//!
//! This is the same canonical form [`UpstreamUrl`](crate::UpstreamUrl) stores for its base segments (unreserved
//! characters never escaped, other escapes uppercase), so the upstream base segments followed by the request segments
//! form one path in one representation. Escaped and literal sub-delimiters (`%3B` and `;`) stay distinct, as RFC 3986
//! requires.
//!
//! The segments produced here never contain `/`, are never empty, and are never `.` or `..`; [`PathPattern`] relies
//! on that, because its `*` and `**` accept any non-empty segment.
//!
//! [`PathPattern`]: crate::PathPattern

use std::fmt;

use thiserror::Error;

use crate::escape::{EscapeAction, EscapeError, decode_hex_pair, is_path_char, is_unreserved, walk_escapes};

/// Decoded characters that a Unicode-folding decoder (NFKC, or a "best fit" code-page conversion) could turn into
/// `.`, `/`, `\` or `%`, and so into traversal or a second decoding pass.
const LOOK_ALIKES: [char; 11] = [
    '\u{2024}', // ONE DOT LEADER
    '\u{2025}', // TWO DOT LEADER
    '\u{FE52}', // SMALL FULL STOP
    '\u{FF0E}', // FULLWIDTH FULL STOP
    '\u{2044}', // FRACTION SLASH
    '\u{2215}', // DIVISION SLASH
    '\u{FF0F}', // FULLWIDTH SOLIDUS
    '\u{FE68}', // SMALL REVERSE SOLIDUS
    '\u{FF3C}', // FULLWIDTH REVERSE SOLIDUS
    '\u{FE6A}', // SMALL PERCENT SIGN
    '\u{FF05}', // FULLWIDTH PERCENT SIGN
];

/// Why a caller's request target was rejected; the request interface answers every variant with `400` (§3.12).
///
/// Messages never echo the target, because it is caller-controlled and may carry a secret placed in the query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TargetError {
    /// The target does not start with `/`: absolute form, authority form, asterisk form, or empty.
    #[error("request target must be in origin form, starting with '/'")]
    NotOriginForm,
    /// The target contains `#`; clients never send fragments, so one is evidence of a hostile or broken caller.
    #[error("request target must not contain a fragment")]
    Fragment,
    /// The target contains a byte outside ASCII; HTTP/1.1 targets are ASCII, and raw UTF-8 would be a second spelling
    /// of its percent-encoded form.
    #[error("request target contains a non-ASCII character")]
    NonAscii,
    /// The target contains a control character, NUL or a space.
    #[error("request target contains a control character or space")]
    ControlOrSpace,
    /// The target contains `\`, which some servers treat as `/`.
    #[error("request target contains a backslash")]
    Backslash,
    /// The path contains an ASCII character outside RFC 3986 `pchar` and `%`, such as `"`, `<`, `|` or `[`.
    #[error("request path contains a character that must be percent-encoded")]
    ForbiddenPathCharacter,
    /// The query contains an ASCII character outside the RFC 3986 query set.
    #[error("request query contains a character that must be percent-encoded")]
    ForbiddenQueryCharacter,
    /// A `%` is not followed by two hex digits.
    #[error("request target contains a malformed percent escape")]
    MalformedEscape,
    /// The path percent-encodes `.`, `/` or `\`.
    #[error("request path percent-encodes a dot, slash or backslash")]
    EncodedDotOrSeparator,
    /// The path percent-encodes `%`, which a second decoding pass would turn into a new escape.
    #[error("request path percent-encodes '%' (double encoding)")]
    EncodedPercent,
    /// The path percent-encodes NUL or another control character.
    #[error("request path percent-encodes a control character")]
    EncodedControl,
    /// A segment's escapes do not decode to valid UTF-8, which includes overlong forms such as `%C0%AE`.
    #[error("request path escapes do not decode to valid UTF-8")]
    InvalidUtf8,
    /// A segment encodes a Unicode look-alike of `.`, `/`, `\` or `%`.
    #[error("request path encodes a look-alike of a dot, slash, backslash or percent sign")]
    LookAlike,
    /// A segment is `.` or `..`, alone or before a `;` path parameter (`..;x`).
    #[error("request path contains a dot segment")]
    DotSegment,
    /// The path has an empty segment other than one trailing slash, or a segment that is empty before its `;`.
    #[error("request path contains an empty segment")]
    EmptySegment,
}

/// A validated origin-form request target: its normalized path and optional query.
///
/// [`Display`](fmt::Display) renders the exact target to forward, and parsing that rendering gives back an equal value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestTarget {
    path: NormalizedPath,
    query: Option<RawQuery>,
}

impl RequestTarget {
    /// Validates a raw request target and normalizes its path.
    ///
    /// An empty query (`/fx?`) is the same target as no query (`/fx`): `query` is `None` and the rendering has no `?`.
    pub fn parse(raw: &str) -> Result<Self, TargetError> {
        if !raw.starts_with('/') {
            return Err(TargetError::NotOriginForm);
        }
        raw.chars().try_for_each(check_target_char)?;
        let (path, query) = raw.split_once('?').map_or((raw, None), |(path, query)| (path, Some(query)));
        let query = query.filter(|q| !q.is_empty()).map(RawQuery::parse).transpose()?;
        Ok(Self { path: NormalizedPath::parse(path)?, query })
    }

    /// The normalized path.
    pub fn path(&self) -> &NormalizedPath {
        &self.path
    }

    /// The query, if the target had a non-empty one.
    pub fn query(&self) -> Option<&RawQuery> {
        self.query.as_ref()
    }

    /// Splits the target into its path and query.
    pub fn into_parts(self) -> (NormalizedPath, Option<RawQuery>) {
        (self.path, self.query)
    }
}

impl fmt::Display for RequestTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.path)?;
        self.query.as_ref().map_or(Ok(()), |query| write!(f, "?{query}"))
    }
}

/// A caller path in its single normalized representation (see the module documentation).
///
/// The root path `/` has zero segments and no trailing slash; any other path may keep one trailing slash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedPath {
    segments: Vec<String>,
    trailing_slash: bool,
}

impl NormalizedPath {
    /// The normalized segments, without separators; empty for the root path.
    pub fn segments(&self) -> &[String] {
        &self.segments
    }

    /// Whether the path ends in one `/` after a segment.
    pub fn has_trailing_slash(&self) -> bool {
        self.trailing_slash
    }

    /// Parses the path part of a target whose characters [`check_target_char`] already accepted.
    fn parse(path: &str) -> Result<Self, TargetError> {
        if !path.chars().all(|c| is_path_char(c) || c == '/') {
            return Err(TargetError::ForbiddenPathCharacter);
        }
        let body = path.strip_prefix('/').ok_or(TargetError::NotOriginForm)?;
        if body.is_empty() {
            return Ok(Self { segments: Vec::new(), trailing_slash: false });
        }
        let (body, trailing_slash) = body.strip_suffix('/').map_or((body, false), |trimmed| (trimmed, true));
        let segments = body.split('/').map(normalize_segment).collect::<Result<_, _>>()?;
        Ok(Self { segments, trailing_slash })
    }
}

/// Renders the forwarded path: `/`, the segments joined by `/`, and the trailing slash if there was one.
impl fmt::Display for NormalizedPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let trailing = if self.trailing_slash { "/" } else { "" };
        write!(f, "/{}{trailing}", self.segments.join("/"))
    }
}

/// A non-empty query string, validated but otherwise kept exactly as the caller sent it.
///
/// It contains only RFC 3986 query characters and well-formed escapes; structural parsing belongs to query slots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawQuery(String);

impl RawQuery {
    /// The query text without its leading `?`.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn parse(query: &str) -> Result<Self, TargetError> {
        if !query.chars().all(|c| is_path_char(c) || matches!(c, '/' | '?')) {
            return Err(TargetError::ForbiddenQueryCharacter);
        }
        query.split('%').skip(1).try_for_each(|part| match part.get(..2).and_then(decode_hex_pair) {
            Some(_) => Ok(()),
            None => Err(TargetError::MalformedEscape),
        })?;
        Ok(Self(query.to_owned()))
    }
}

impl fmt::Display for RawQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Rejects characters that are invalid anywhere in an origin-form target.
fn check_target_char(c: char) -> Result<(), TargetError> {
    match c {
        _ if !c.is_ascii() => Err(TargetError::NonAscii),
        _ if c.is_ascii_control() || c == ' ' => Err(TargetError::ControlOrSpace),
        '#' => Err(TargetError::Fragment),
        '\\' => Err(TargetError::Backslash),
        _ => Ok(()),
    }
}

/// Normalizes one raw segment, then checks the fully decoded text for traversal that a later decoder could see.
fn normalize_segment(raw: &str) -> Result<String, TargetError> {
    if raw.is_empty() {
        return Err(TargetError::EmptySegment);
    }
    let walked = walk_escapes(raw, escape_action).map_err(|e| match e {
        EscapeError::Malformed => TargetError::MalformedEscape,
        EscapeError::Rejected(e) => e,
        EscapeError::InvalidUtf8 => TargetError::InvalidUtf8,
    })?;
    check_decoded_segment(&walked.decoded)?;
    Ok(walked.normalized)
}

/// The single path representation: unreserved characters decoded, other escapes kept with uppercase hex, and escapes
/// rejected when a second decoding pass or a lenient server could turn them into traversal.
fn escape_action(byte: u8) -> EscapeAction<TargetError> {
    match byte {
        b'.' | b'/' | b'\\' => EscapeAction::Reject(TargetError::EncodedDotOrSeparator),
        b'%' => EscapeAction::Reject(TargetError::EncodedPercent),
        _ if byte.is_ascii_control() => EscapeAction::Reject(TargetError::EncodedControl),
        _ if is_unreserved(char::from(byte)) => EscapeAction::Decode,
        _ => EscapeAction::Keep,
    }
}

/// Checks the fully decoded segment, so encoded and literal spellings of the same text get the same verdict.
///
/// Servers such as Tomcat and Spring strip a `;` path parameter before resolving dot segments, so `..;x` and `..%3B`
/// act as `..` and `;x` as an empty segment there.
fn check_decoded_segment(decoded: &str) -> Result<(), TargetError> {
    if decoded.chars().any(|c| LOOK_ALIKES.contains(&c)) {
        return Err(TargetError::LookAlike);
    }
    match decoded.split(';').next().unwrap_or_default() {
        "" => Err(TargetError::EmptySegment),
        "." | ".." => Err(TargetError::DotSegment),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(raw: &str) -> RequestTarget {
        RequestTarget::parse(raw).unwrap_or_else(|e| panic!("{raw:?} should parse: {e}"))
    }

    fn reject(raw: &str) -> TargetError {
        RequestTarget::parse(raw).expect_err(raw)
    }

    fn segments(raw: &str) -> Vec<String> {
        parse(raw).path().segments().to_vec()
    }

    #[test]
    fn root_has_no_segments() {
        let root = parse("/");
        assert!(root.path().segments().is_empty());
        assert!(!root.path().has_trailing_slash());
        assert_eq!((root.query(), root.to_string().as_str()), (None, "/"));
    }

    #[test]
    fn plain_path_is_accepted() {
        let target = parse("/fx/latest");
        assert_eq!(target.path().segments(), ["fx", "latest"]);
        assert!(!target.path().has_trailing_slash());
    }

    #[test]
    fn one_trailing_slash_is_kept() {
        let target = parse("/fx/latest/");
        assert_eq!(target.path().segments(), ["fx", "latest"]);
        assert!(target.path().has_trailing_slash());
        assert_eq!(target.to_string(), "/fx/latest/");
    }

    #[test]
    fn query_is_kept_opaque() {
        let target = parse("/fx/latest?base=USD");
        assert_eq!(target.path().segments(), ["fx", "latest"]);
        assert_eq!(target.query().map(RawQuery::as_str), Some("base=USD"));
        assert_eq!(parse("/a?x=%2e%2E&y=/?%25").query().map(RawQuery::as_str), Some("x=%2e%2E&y=/?%25"));
    }

    #[test]
    fn empty_query_is_no_query() {
        let target = parse("/fx?");
        assert_eq!((target.query(), target.to_string().as_str()), (None, "/fx"));
    }

    #[test]
    fn unreserved_escapes_are_decoded() {
        assert_eq!(parse("/a/%41b").to_string(), "/a/Ab");
        assert_eq!(segments("/%2d%5F%7e%30"), ["-_~0"]);
    }

    #[test]
    fn other_escapes_get_uppercase_hex() {
        assert_eq!(parse("/a/%c3%a9").to_string(), "/a/%C3%A9");
        assert_eq!(segments("/a%3bb/%20/%3A"), ["a%3Bb", "%20", "%3A"]);
    }

    #[test]
    fn rfc3986_path_characters_are_accepted() {
        assert_eq!(segments("/a-b_c~d.e/f:g@h/!$&'()*+,;=/.../.x/x."), ["a-b_c~d.e", "f:g@h", "!$&'()*+,;=", "...", ".x", "x."]);
        assert_eq!(segments("/cars;color=red"), ["cars;color=red"]);
    }

    #[test]
    fn rendering_round_trips() {
        ["/", "/fx/latest", "/fx/latest/", "/fx/latest?base=USD", "/a/%41b", "/a/%c3%a9/", "/x;y=%3b?a=b?c", "/*"]
            .into_iter()
            .map(parse)
            .for_each(|target| assert_eq!(parse(&target.to_string()), target));
    }

    #[test]
    fn rendering_is_a_fixed_point_of_the_url_parser() {
        ["/fx/latest/", "/a/%c3%a9", "/!$&'()*+,;=:@/x", "/a%20b?q=%20&r=/?"].into_iter().map(parse).for_each(|target| {
            let url = url::Url::parse(&format!("https://host.example{target}")).unwrap();
            let forwarded = format!("{}{}", url.path(), url.query().map(|q| format!("?{q}")).unwrap_or_default());
            assert_eq!(forwarded, target.to_string());
        });
    }

    #[test]
    fn into_parts_returns_path_and_query() {
        let (path, query) = parse("/fx?a=1").into_parts();
        assert_eq!((path.to_string(), query.map(|q| q.to_string())), ("/fx".to_owned(), Some("a=1".to_owned())));
    }

    #[test]
    fn rejects_absolute_form() {
        assert_eq!(reject("http://x/fx"), TargetError::NotOriginForm);
    }

    #[test]
    fn rejects_authority_form() {
        assert_eq!(reject("x:443"), TargetError::NotOriginForm);
    }

    #[test]
    fn rejects_asterisk_form() {
        assert_eq!(reject("*"), TargetError::NotOriginForm);
        assert_eq!(reject(""), TargetError::NotOriginForm);
    }

    #[test]
    fn rejects_dot_dot_segment() {
        assert_eq!(reject("/fx/../x"), TargetError::DotSegment);
    }

    #[test]
    fn rejects_dot_segment() {
        assert_eq!(reject("/fx/./x"), TargetError::DotSegment);
    }

    #[test]
    fn rejects_trailing_dot_segments() {
        ["/fx/..", "/fx/.", "/fx/../", "/..", "/./"].into_iter().for_each(|raw| assert_eq!(reject(raw), TargetError::DotSegment, "{raw}"));
    }

    #[test]
    fn rejects_encoded_dot_dot() {
        assert_eq!(reject("/fx/%2e%2e/x"), TargetError::EncodedDotOrSeparator);
    }

    #[test]
    fn rejects_encoded_dot() {
        assert_eq!(reject("/fx/%2E/x"), TargetError::EncodedDotOrSeparator);
    }

    #[test]
    fn rejects_encoded_slash() {
        assert_eq!(reject("/fx/a%2fb"), TargetError::EncodedDotOrSeparator);
        assert_eq!(reject("/fx/a%2Fb"), TargetError::EncodedDotOrSeparator);
    }

    #[test]
    fn rejects_encoded_backslash() {
        assert_eq!(reject("/fx/a%5Cb"), TargetError::EncodedDotOrSeparator);
        assert_eq!(reject("/fx/a%5cb"), TargetError::EncodedDotOrSeparator);
    }

    #[test]
    fn rejects_literal_backslash() {
        assert_eq!(reject("/fx\\x"), TargetError::Backslash);
    }

    #[test]
    fn rejects_encoded_nul() {
        assert_eq!(reject("/fx/%00"), TargetError::EncodedControl);
        assert_eq!(reject("/fx/a%0Ab"), TargetError::EncodedControl);
        assert_eq!(reject("/fx/%7f"), TargetError::EncodedControl);
    }

    #[test]
    fn rejects_double_encoding() {
        assert_eq!(reject("/fx/%252e%252e"), TargetError::EncodedPercent);
    }

    #[test]
    fn rejects_empty_interior_segment() {
        assert_eq!(reject("/fx//x"), TargetError::EmptySegment);
        ["//", "//x", "/fx//", "/fx///"].into_iter().for_each(|raw| assert_eq!(reject(raw), TargetError::EmptySegment, "{raw}"));
    }

    #[test]
    fn rejects_non_hex_escape() {
        assert_eq!(reject("/fx/%zz"), TargetError::MalformedEscape);
        assert_eq!(reject("/fx/%+f"), TargetError::MalformedEscape);
    }

    #[test]
    fn rejects_truncated_escape() {
        assert_eq!(reject("/fx/%2"), TargetError::MalformedEscape);
        assert_eq!(reject("/fx/a%"), TargetError::MalformedEscape);
    }

    #[test]
    fn rejects_fragment() {
        assert_eq!(reject("/fx#frag"), TargetError::Fragment);
        assert_eq!(reject("/fx?a=1#frag"), TargetError::Fragment);
    }

    #[test]
    fn rejects_controls_and_spaces() {
        ["/fx\0", "/f x", "/fx\t", "/fx\r\n", "/fx\u{7f}", "/fx?a= b", "/fx?a=\u{1}"]
            .into_iter()
            .for_each(|raw| assert_eq!(reject(raw), TargetError::ControlOrSpace, "{raw:?}"));
    }

    #[test]
    fn rejects_literal_non_ascii() {
        assert_eq!(reject("/caf\u{e9}"), TargetError::NonAscii);
        assert_eq!(reject("/fx/\u{FF0E}\u{FF0E}"), TargetError::NonAscii);
        assert_eq!(reject("/fx?q=\u{e9}"), TargetError::NonAscii);
    }

    #[test]
    fn rejects_non_pchar_path_characters() {
        ["/a\"b", "/a<b", "/a>b", "/a^b", "/a`b", "/a{b", "/a|b", "/a}b", "/a[b", "/a]b"]
            .into_iter()
            .for_each(|raw| assert_eq!(reject(raw), TargetError::ForbiddenPathCharacter, "{raw}"));
    }

    #[test]
    fn rejects_non_rfc3986_query_characters() {
        ["/fx?a=\"", "/fx?a[]=1", "/fx?a=<b>", "/fx?a=|", "/fx?a=`"]
            .into_iter()
            .for_each(|raw| assert_eq!(reject(raw), TargetError::ForbiddenQueryCharacter, "{raw}"));
        assert_eq!(reject("/fx?a=\\"), TargetError::Backslash);
    }

    #[test]
    fn rejects_malformed_query_escapes() {
        ["/fx?a=%", "/fx?a=%2", "/fx?a=%zz", "/fx?%+1"]
            .into_iter()
            .for_each(|raw| assert_eq!(reject(raw), TargetError::MalformedEscape, "{raw}"));
    }

    #[test]
    fn rejects_path_parameter_dot_segments() {
        ["/fx/..;/x", "/fx/..;jsessionid=1/x", "/fx/.;x", "/fx/..%3B/x", "/fx/..%3b"]
            .into_iter()
            .for_each(|raw| assert_eq!(reject(raw), TargetError::DotSegment, "{raw}"));
    }

    #[test]
    fn rejects_path_parameter_only_segments() {
        ["/fx/;/x", "/fx/;x", "/fx/%3B"].into_iter().for_each(|raw| assert_eq!(reject(raw), TargetError::EmptySegment, "{raw}"));
    }

    #[test]
    fn rejects_unicode_look_alikes() {
        let escapes = [
            "%E2%80%A4", "%E2%80%A5", "%EF%B9%92", "%EF%BC%8E", "%E2%81%84", "%E2%88%95", "%EF%BC%8F", "%EF%B9%A8", "%EF%BC%BC",
            "%EF%B9%AA", "%EF%BC%85",
        ];
        assert_eq!(escapes.len(), LOOK_ALIKES.len());
        escapes.iter().flat_map(|e| [format!("/fx/{e}"), format!("/fx/a{e}b"), format!("/fx/{}", e.to_ascii_lowercase())]).for_each(|raw| {
            assert_eq!(reject(&raw), TargetError::LookAlike, "{raw}");
        });
    }

    #[test]
    fn rejects_overlong_and_invalid_utf8() {
        ["/fx/%C0%AE", "/fx/%c0%af", "/fx/%E0%80%AE", "/fx/%C0%AE%C0%AE", "/fx/%FF", "/fx/%C3"]
            .into_iter()
            .for_each(|raw| assert_eq!(reject(raw), TargetError::InvalidUtf8, "{raw}"));
    }

    #[test]
    fn errors_do_not_echo_the_target() {
        ["/secret\0", "/secret/%2e", "/secret/../x", "http://secret/", "/secret?k=%zz"].into_iter().for_each(|raw| {
            let message = reject(raw).to_string();
            assert!(!message.contains("secret"), "{message}");
        });
    }

    #[test]
    fn normalized_segments_never_hold_separators_or_dot_segments() {
        ["/%41/%2d.%7e", "/a;b/x.y", "/.../..x"].into_iter().map(parse).for_each(|target| {
            target.path().segments().iter().for_each(|segment| {
                assert!(!segment.is_empty() && !segment.contains('/') && segment != "." && segment != "..", "{segment}");
            });
        });
    }
}
