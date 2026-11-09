//! The three content-coding decisions of spec §11, each a pure function so the handler only applies them: which coding
//! the upstream used, which coding the caller needs the response in, and which headers no longer describe the body.
//!
//! The service decodes a response so the scrubber can screen it, and re-encodes it only when the caller's
//! `Accept-Encoding` leaves no other choice ("recompress only when required").
//!
//! Stacked codings (`gzip, br`) and repeated `Content-Encoding` headers are refused rather than decoded layer by layer:
//! they are rare, and an unsupported layer would leave an opaque body the scrubber cannot read.

// reqwest's re-export of the `http` header types, which hyper shares, so these decisions build where hyper is absent.
use reqwest::header::{ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH, ETAG, HeaderMap, HeaderName, HeaderValue, VARY};

use super::ContentCoding;

/// The `Accept-Encoding` sent upstream: exactly the codings [`ResponseDecoder`](super::ResponseDecoder) decodes, so an
/// upstream cannot answer in a coding the service would have to refuse. The caller's own value is never forwarded.
pub const UPSTREAM_ACCEPT_ENCODING: HeaderValue = HeaderValue::from_static("gzip, deflate, br");

/// Headers that vouch for the exact bytes of the upstream body, which decoding, scrubbing or recoding changes.
const INTEGRITY_HEADERS: [HeaderName; 4] = [
    HeaderName::from_static("content-md5"),
    HeaderName::from_static("digest"),
    HeaderName::from_static("content-digest"),
    HeaderName::from_static("repr-digest"),
];

/// The coding order that breaks a tie between equally preferred codings.
const TIE_ORDER: [ContentCoding; 3] = [ContentCoding::Gzip, ContentCoding::Br, ContentCoding::Deflate];

/// An upstream `Content-Encoding` the service will not decode. It never carries the header value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("response uses a content coding the service does not decode")]
pub struct UnsupportedCoding;

/// The coding the upstream applied to the response body: `None` when it sent none (absent or `identity`).
///
/// Anything but one lone supported coding is refused: an unknown coding, a stacked list, repeated headers or an empty value.
pub fn parse_content_encoding(headers: &HeaderMap) -> Result<Option<ContentCoding>, UnsupportedCoding> {
    let mut values = headers.get_all(CONTENT_ENCODING).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(UnsupportedCoding);
    }
    let token = value.to_str().map_err(|_| UnsupportedCoding)?.trim().to_ascii_lowercase();
    match token.as_str() {
        "identity" => Ok(None),
        other => coding_named(other).map(Some).ok_or(UnsupportedCoding),
    }
}

/// The supported coding a lowercase token names.
fn coding_named(token: &str) -> Option<ContentCoding> {
    match token {
        "gzip" | "x-gzip" => Some(ContentCoding::Gzip),
        "deflate" => Some(ContentCoding::Deflate),
        "br" => Some(ContentCoding::Br),
        _ => None,
    }
}

/// The coding to send the caller: `None` (identity) unless its `Accept-Encoding` rules identity out, then the supported
/// coding it prefers most. When it accepts nothing we can produce, identity is sent anyway, which RFC 9110 §12.5.3
/// permits, rather than a `406`. A missing or malformed header accepts anything.
pub fn choose_emitted(accept_encoding: Option<&HeaderValue>) -> Option<ContentCoding> {
    let preferences = accept_encoding.and_then(Preferences::parse).unwrap_or_default();
    if preferences.accepts_identity() {
        return None;
    }
    TIE_ORDER
        .into_iter()
        .map(|coding| (coding, preferences.quality_of(coding)))
        .filter(|(_, quality)| *quality > 0)
        // `max_by_key` keeps the last maximum, so the tie order is walked in reverse.
        .rev()
        .max_by_key(|(_, quality)| *quality)
        .map(|(coding, _)| coding)
}

/// A parsed `Accept-Encoding`: each quality is in thousandths, `None` when the header did not mention the coding.
#[derive(Debug, Default)]
struct Preferences {
    gzip: Option<u16>,
    deflate: Option<u16>,
    br: Option<u16>,
    identity: Option<u16>,
    any: Option<u16>,
}

impl Preferences {
    /// The preferences in `value`, or `None` when it is malformed.
    fn parse(value: &HeaderValue) -> Option<Self> {
        value
            .to_str()
            .ok()?
            .split(',')
            .map(str::trim)
            .filter(|member| !member.is_empty())
            .try_fold(Self::default(), |mut preferences, member| {
                let (name, quality) = parse_member(member)?;
                let slot = match name.as_str() {
                    "gzip" | "x-gzip" => &mut preferences.gzip,
                    "deflate" => &mut preferences.deflate,
                    "br" => &mut preferences.br,
                    "identity" => &mut preferences.identity,
                    "*" => &mut preferences.any,
                    _ => return Some(preferences),
                };
                *slot = Some(quality);
                Some(preferences)
            })
    }

    /// Identity is acceptable unless it, or a `*` that names it implicitly, has quality 0.
    fn accepts_identity(&self) -> bool {
        self.identity.or(self.any).unwrap_or(1000) > 0
    }

    fn quality_of(&self, coding: ContentCoding) -> u16 {
        let named = match coding {
            ContentCoding::Gzip => self.gzip,
            ContentCoding::Deflate => self.deflate,
            ContentCoding::Br => self.br,
        };
        named.or(self.any).unwrap_or(0)
    }
}

/// One list member as its lowercase coding name and quality, or `None` when malformed.
fn parse_member(member: &str) -> Option<(String, u16)> {
    let (name, params) = match member.split_once(';') {
        Some((name, params)) => (name, Some(params)),
        None => (member, None),
    };
    let quality = params.map_or(Some(1000), parse_quality)?;
    Some((name.trim().to_ascii_lowercase(), quality))
}

/// The thousandths in a `q=0.5` parameter (RFC 9110 §12.4.2: at most three decimals, at most 1).
fn parse_quality(param: &str) -> Option<u16> {
    let (key, value) = param.split_once('=')?;
    if !key.trim().eq_ignore_ascii_case("q") {
        return None;
    }
    let (whole, fraction) = value.trim().split_once('.').unwrap_or((value.trim(), ""));
    let whole: u16 = match whole {
        "0" => 0,
        "1" => 1,
        _ => return None,
    };
    if fraction.len() > 3 || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let fraction: u16 = format!("{fraction:0<3}").parse().ok()?;
    Some(whole * 1000 + fraction).filter(|quality| *quality <= 1000)
}

/// Makes the response headers describe the body the service emits.
///
/// With `body_changed` false the body is forwarded as received and the headers are left alone. Otherwise
/// `Content-Encoding` is set to `emitted`, or removed for identity; the `Content-Length` and the integrity headers
/// (`Content-MD5`, `Digest`, `Content-Digest`, `Repr-Digest`) go, because the bytes they describe are gone; a strong
/// `ETag` becomes weak, because the representation is no longer byte-identical; and recompressing adds
/// `Accept-Encoding` to `Vary`, because the choice depended on the caller's request.
pub fn rewrite_headers(headers: &mut HeaderMap, emitted: Option<ContentCoding>, body_changed: bool) {
    if !body_changed {
        return;
    }
    match emitted {
        Some(coding) => headers.insert(CONTENT_ENCODING, HeaderValue::from_static(coding_token(coding))),
        None => headers.remove(CONTENT_ENCODING),
    };
    headers.remove(CONTENT_LENGTH);
    INTEGRITY_HEADERS.iter().for_each(|name| {
        headers.remove(name);
    });
    weaken_etag(headers);
    if emitted.is_some() {
        add_vary_accept_encoding(headers);
    }
}

fn coding_token(coding: ContentCoding) -> &'static str {
    match coding {
        ContentCoding::Gzip => "gzip",
        ContentCoding::Deflate => "deflate",
        ContentCoding::Br => "br",
    }
}

/// Prefixes a strong `ETag` with `W/`; an `ETag` that cannot be rewritten is dropped.
fn weaken_etag(headers: &mut HeaderMap) {
    let Some(etag) = headers.get(ETAG) else {
        return;
    };
    if etag.as_bytes().starts_with(b"W/") {
        return;
    }
    let weak = HeaderValue::from_bytes(&[b"W/", etag.as_bytes()].concat());
    match weak {
        Ok(weak) => headers.insert(ETAG, weak),
        Err(_) => headers.remove(ETAG),
    };
}

/// Appends `Accept-Encoding` to `Vary` unless a `Vary` value already covers it (it names it or is `*`).
fn add_vary_accept_encoding(headers: &mut HeaderMap) {
    let covered = headers
        .get_all(VARY)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .any(|token| token == "*" || token.eq_ignore_ascii_case(ACCEPT_ENCODING.as_str()));
    if !covered {
        headers.append(VARY, HeaderValue::from_static("Accept-Encoding"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with(values: &[&str]) -> HeaderMap {
        values.iter().fold(HeaderMap::new(), |mut map, value| {
            map.append(CONTENT_ENCODING, HeaderValue::from_str(value).unwrap());
            map
        })
    }

    type Parsed = Result<Option<ContentCoding>, UnsupportedCoding>;

    #[test]
    fn parses_upstream_coding() {
        use ContentCoding::*;
        let table: [(&[&str], Parsed); 14] = [
            (&[], Ok(None)),
            (&["identity"], Ok(None)),
            (&["Identity"], Ok(None)),
            (&["gzip"], Ok(Some(Gzip))),
            (&["GZip"], Ok(Some(Gzip))),
            (&["x-gzip"], Ok(Some(Gzip))),
            (&["  deflate \t"], Ok(Some(Deflate))),
            (&["BR"], Ok(Some(Br))),
            (&["gzip, br"], Err(UnsupportedCoding)),
            (&["gzip", "br"], Err(UnsupportedCoding)),
            (&["gzip", "gzip"], Err(UnsupportedCoding)),
            (&["compress"], Err(UnsupportedCoding)),
            (&[""], Err(UnsupportedCoding)),
            (&["identity, gzip"], Err(UnsupportedCoding)),
        ];
        table
            .iter()
            .for_each(|(values, expected)| assert_eq!(parse_content_encoding(&headers_with(values)), *expected, "{values:?}"));
    }

    #[test]
    fn unsupported_error_does_not_echo_the_value() {
        assert!(!UnsupportedCoding.to_string().contains("compress"));
    }

    fn emitted(value: Option<&str>) -> Option<ContentCoding> {
        choose_emitted(value.map(|v| HeaderValue::from_str(v).unwrap()).as_ref())
    }

    #[test]
    fn chooses_emitted_coding() {
        use ContentCoding::*;
        let table: [(Option<&str>, Option<ContentCoding>); 18] = [
            (None, None),
            (Some("gzip"), None),
            (Some(""), None),
            (Some("identity;q=0, gzip"), Some(Gzip)),
            (Some("identity;q=0, deflate;q=0.3, br;q=0.8"), Some(Br)),
            (Some("*;q=0"), None),
            (Some("*;q=0, identity;q=0.5"), None),
            (Some("*;q=0, gzip"), Some(Gzip)),
            (Some("identity;q=0, *;q=0.4"), Some(Gzip)),
            (Some("br;q=1, gzip;q=1, identity;q=0"), Some(Gzip)),
            (Some("deflate;q=1, br;q=1, identity;q=0"), Some(Br)),
            (Some("identity;q=0, X-GZIP;Q=0.5"), Some(Gzip)),
            (Some("identity;q=0, gzip;q=0"), None),
            (Some("identity;q=0, zstd"), None),
            (Some("identity;q=0, gzip;q=1.5"), None),
            (Some("identity;q=0, gzip;q=abc"), None),
            (Some("identity;q=0, gzip;level=1"), None),
            (Some("gzip;;;"), None),
        ];
        table
            .iter()
            .for_each(|(accept, expected)| assert_eq!(emitted(*accept), *expected, "{accept:?}"));
    }

    fn full_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("10"));
        headers.insert(ETAG, HeaderValue::from_static("\"abc\""));
        INTEGRITY_HEADERS
            .iter()
            .for_each(|name| drop(headers.insert(name.clone(), HeaderValue::from_static("x"))));
        headers
    }

    #[test]
    fn rewrite_drops_stale_headers_and_sets_identity() {
        let mut headers = full_headers();
        rewrite_headers(&mut headers, None, true);
        assert!(!headers.contains_key(CONTENT_ENCODING));
        assert!(!headers.contains_key(CONTENT_LENGTH));
        INTEGRITY_HEADERS
            .iter()
            .for_each(|name| assert!(!headers.contains_key(name), "{name}"));
        assert_eq!(headers[ETAG], "W/\"abc\"");
        assert!(!headers.contains_key(VARY));
    }

    #[test]
    fn rewrite_sets_recompressed_coding_and_vary() {
        let mut headers = full_headers();
        headers.insert(VARY, HeaderValue::from_static("Origin"));
        rewrite_headers(&mut headers, Some(ContentCoding::Br), true);
        assert_eq!(headers[CONTENT_ENCODING], "br");
        let vary: Vec<_> = headers.get_all(VARY).iter().map(|v| v.to_str().unwrap()).collect();
        assert_eq!(vary, ["Origin", "Accept-Encoding"]);
    }

    #[test]
    fn rewrite_keeps_vary_that_already_covers_accept_encoding() {
        ["accept-encoding", "Origin, Accept-Encoding", "*"].iter().for_each(|existing| {
            let mut headers = HeaderMap::new();
            headers.insert(VARY, HeaderValue::from_str(existing).unwrap());
            rewrite_headers(&mut headers, Some(ContentCoding::Gzip), true);
            assert_eq!(headers.get_all(VARY).iter().count(), 1, "{existing}");
        });
    }

    #[test]
    fn rewrite_leaves_weak_etag_alone() {
        let mut headers = HeaderMap::new();
        headers.insert(ETAG, HeaderValue::from_static("W/\"abc\""));
        rewrite_headers(&mut headers, None, true);
        assert_eq!(headers[ETAG], "W/\"abc\"");
    }

    #[test]
    fn rewrite_leaves_an_unchanged_body_alone() {
        let mut headers = full_headers();
        rewrite_headers(&mut headers, None, false);
        assert_eq!(headers, full_headers());
    }

    #[test]
    fn upstream_accept_encoding_names_the_decodable_codings() {
        assert_eq!(UPSTREAM_ACCEPT_ENCODING, "gzip, deflate, br");
    }
}
