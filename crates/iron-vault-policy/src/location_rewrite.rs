//! Location rewrite: what the caller sees of an upstream redirect's `Location` (spec §8, §11).
//!
//! The upstream client never follows a redirect, so the `Location` it returns is the caller's to follow. The value is
//! resolved against the URL actually sent (RFC 3986 §5) and then:
//!
//! - a same-origin destination inside the upstream base path is rewritten under the route prefix, as an absolute path,
//!   because the service does not know which listener origin the caller used;
//! - a same-origin destination outside the base path, an out-of-base redirect, is refused, so it cannot land in another
//!   local route;
//! - a destination on any other origin, `http` on the upstream's host included, passes through untouched when it is
//!   written as an absolute `scheme://authority` URL; response header scrubbing still applies to it. Written any other
//!   way (`//host/x`, `http:/x`), it is a relative cross-origin redirect and is refused: the caller resolves those bytes
//!   against the proxy listener's URL, possibly `http`, where they could land in another local route or fall back to
//!   cleartext.
//!
//! An empty or fragment-only `Location` inherits the request's query, and a query slot's credential is in that query,
//! so every parameter that decodes to the slot's name is removed from a rewritten value.

use std::str;

use thiserror::Error;
use url::{Position, Url};

use crate::escape::is_path_char;
use crate::header_value::HeaderValue;
use crate::host::Host;
use crate::query_value::decode_name;
use crate::request_target::normalize_segment;
use crate::route::RouteConfig;
use crate::slot::Slot;
use crate::upstream::UpstreamUrl;
use crate::upstream_target::{has_path, segments_path};

/// What the caller sees of an upstream `Location`.
#[derive(Debug, PartialEq, Eq)]
pub enum LocationRewrite {
    /// A same-origin destination inside the upstream base path, as an absolute path under the route prefix (`/fx/...`)
    /// with any query slot parameter removed.
    Rewritten(HeaderValue),
    /// A cross-origin destination written as an absolute `scheme://authority` URL, which means the same against any
    /// base: return the upstream's value byte for byte, subject to header scrubbing.
    PassThrough,
    /// The `Location` must not reach the caller.
    Refused(LocationRefusal),
}

/// Why a `Location` was refused.
///
/// Variants carry nothing: the `Location` and the request URL it resolves against may both hold the credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum LocationRefusal {
    /// The value is not visible ASCII, holds a `\`, does not parse as a URI reference, or did not rebuild exactly.
    #[error("upstream Location is not a valid URI reference")]
    Malformed,
    /// A same-origin destination carries user-info.
    #[error("upstream Location carries user-info")]
    UserInfo,
    /// A same-origin destination outside the upstream base path: an out-of-base redirect.
    #[error("upstream Location leaves the upstream base path")]
    OutOfBase,
    /// A same-origin path breaks a request-target path rule (§9), or would be reinterpreted when rebuilt.
    #[error("upstream Location has an ambiguous path")]
    AmbiguousPath,
    /// A cross-origin destination not written as an absolute `scheme://authority` URL: a relative cross-origin redirect.
    #[error("upstream Location reaches another origin without an absolute URL")]
    RelativeCrossOrigin,
}

/// A rewritten path below the upstream base, in [`NormalizedPath`](crate::NormalizedPath) form.
struct RemainingPath {
    segments: Vec<String>,
    trailing_slash: bool,
}

/// Decides what the caller sees of `location`, an upstream response's `Location` value, on `route`.
///
/// `request_url` must be the URL actually sent, [`CheckedRequest::url`](crate::CheckedRequest::url), because relative
/// references resolve against it; with a query slot it holds the credential, which this removes from a rewritten value.
pub fn rewrite_location(route: &RouteConfig, request_url: &Url, location: &[u8]) -> LocationRewrite {
    match decide(route, request_url, location) {
        Ok(Some(value)) => LocationRewrite::Rewritten(value),
        Ok(None) => LocationRewrite::PassThrough,
        Err(refusal) => LocationRewrite::Refused(refusal),
    }
}

/// The rewritten value, `None` to pass the value through, or the refusal.
fn decide(route: &RouteConfig, request_url: &Url, location: &[u8]) -> Result<Option<HeaderValue>, LocationRefusal> {
    let text = uri_characters(location)?;
    let resolved = request_url.join(text).map_err(|_| LocationRefusal::Malformed)?;
    if !is_same_origin(&resolved, route.upstream()) {
        return require(has_scheme_and_authority(text), LocationRefusal::RelativeCrossOrigin).map(|()| None);
    }
    require(
        resolved.username().is_empty() && resolved.password().is_none(),
        LocationRefusal::UserInfo,
    )?;
    check_raw_path(text)?;
    let remaining = remaining_path(&resolved, route.upstream())?;
    let query = kept_query(resolved.query(), route.slot());
    rewritten(route, &remaining, query.as_deref(), resolved.fragment()).map(Some)
}

fn require(holds: bool, refusal: LocationRefusal) -> Result<(), LocationRefusal> {
    holds.then_some(()).ok_or(refusal)
}

/// Visible ASCII other than `\`: a URI reference has no spaces, controls or raw non-ASCII bytes, which the `url` crate
/// would strip or encode rather than refuse.
///
/// `\` is refused anywhere in the text, not only in the path. RFC 3986 allows it nowhere, and the `url` crate reads it
/// as `/` in the authority too, so `https://other.example\@api.svc.example/` names one host to this resolver and another
/// to an RFC 3986 parser, whether the value is rewritten or passed through.
fn uri_characters(bytes: &[u8]) -> Result<&str, LocationRefusal> {
    bytes
        .iter()
        .all(|byte| byte.is_ascii_graphic() && *byte != b'\\')
        .then(|| str::from_utf8(bytes).ok())
        .flatten()
        .ok_or(LocationRefusal::Malformed)
}

/// Scheme `https`, the upstream's host after the one canonical [`Host`] conversion, and its port (443 when omitted).
fn is_same_origin(url: &Url, upstream: &UpstreamUrl) -> bool {
    url.scheme() == "https"
        && url.host_str().and_then(|host| host.parse::<Host>().ok()).as_ref() == Some(upstream.host())
        && url.port_or_known_default() == Some(upstream.port().get())
}

/// Checks the path as the upstream wrote it, because resolution turns `%2e` into a dot segment, which would erase
/// exactly the evidence the request-target rules refuse; [`uri_characters`] already refused `\`.
///
/// Literal `.` and `..` segments are allowed here: they are ordinary relative-reference syntax, which RFC 3986 §5.2.4
/// resolves one way for every client, and the resolved path is checked again in full.
fn check_raw_path(text: &str) -> Result<(), LocationRefusal> {
    let path = raw_path(text);
    require(path.chars().all(|c| is_path_char(c) || c == '/'), LocationRefusal::AmbiguousPath)?;
    path.split('/')
        .filter(|segment| !matches!(*segment, "" | "." | ".."))
        .try_for_each(|segment| normalize_segment(segment).map(drop))
        .map_err(|_| LocationRefusal::AmbiguousPath)
}

/// The path component of a URI reference (RFC 3986 §4.1): without query or fragment, scheme, or authority.
fn raw_path(text: &str) -> &str {
    let before_query = text.split(['?', '#']).next().unwrap_or_default();
    let after_scheme = before_query
        .split_once(':')
        .filter(|(scheme, _)| is_scheme(scheme))
        .map_or(before_query, |(_, rest)| rest);
    match after_scheme.strip_prefix("//") {
        Some(authority) => authority.find('/').and_then(|start| authority.get(start..)).unwrap_or_default(),
        None => after_scheme,
    }
}

/// `scheme://`: an absolute URL with an authority, which resolves to the same URL against every base.
fn has_scheme_and_authority(text: &str) -> bool {
    text.split_once(':')
        .is_some_and(|(scheme, rest)| is_scheme(scheme) && rest.starts_with("//"))
}

/// RFC 3986 `scheme`: a letter, then letters, digits, `+`, `-` or `.`.
fn is_scheme(text: &str) -> bool {
    let mut chars = text.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic()) && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// The resolved path below the upstream base on whole segments, each normalized as a caller's path segment is.
///
/// Segments are normalized before the base comparison, so `caf%c3%a9` meets a base written `caf%C3%A9`.
fn remaining_path(resolved: &Url, upstream: &UpstreamUrl) -> Result<RemainingPath, LocationRefusal> {
    let raw: Vec<&str> = resolved.path_segments().ok_or(LocationRefusal::Malformed)?.collect();
    let (raw, trailing_slash) = match raw.split_last() {
        Some((&"", init)) => (init, true),
        _ => (raw.as_slice(), false),
    };
    let mut segments = raw
        .iter()
        .map(|segment| normalize_segment(segment))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| LocationRefusal::AmbiguousPath)?;
    let base = upstream.base_segments();
    require(segments.starts_with(base), LocationRefusal::OutOfBase)?;
    Ok(RemainingPath {
        segments: segments.split_off(base.len()),
        trailing_slash,
    })
}

/// The query without any parameter whose decoded name is a query slot's, other parameters kept in order; untouched for
/// a header or Basic slot. `None` when nothing is left.
fn kept_query(query: Option<&str>, slot: &Slot) -> Option<String> {
    let query = query?;
    let Slot::Query(name) = slot else {
        return Some(query.to_owned());
    };
    let kept: Vec<&str> = query
        .split('&')
        .filter(|param| !decode_name(param).is_some_and(|decoded| decoded == name.as_str()))
        .collect();
    (!kept.is_empty()).then(|| kept.join("&"))
}

/// `<route prefix>/<remaining segments>`, the query and the fragment, set through the `url` API on the upstream URL and
/// read back, then taken from the path onwards.
///
/// The segments are already percent-encoded, so they go through `Url::set_path`, which keeps existing escapes, as
/// [`UpstreamTarget`](crate::UpstreamTarget) does; the read-back catches anything the parser would reinterpret.
fn rewritten(
    route: &RouteConfig,
    remaining: &RemainingPath,
    query: Option<&str>,
    fragment: Option<&str>,
) -> Result<HeaderValue, LocationRefusal> {
    let segments: Vec<&str> = route
        .prefix()
        .segments()
        .iter()
        .chain(&remaining.segments)
        .map(String::as_str)
        .collect();
    let mut url = route.upstream().as_url().clone();
    url.set_path(&segments_path(&segments, remaining.trailing_slash));
    url.set_query(query);
    url.set_fragment(fragment);
    require(has_path(&url, &segments, remaining.trailing_slash), LocationRefusal::AmbiguousPath)?;
    require(url.query() == query && url.fragment() == fragment, LocationRefusal::Malformed)?;
    HeaderValue::try_from(url[Position::BeforePath..].as_bytes()).map_err(|_| LocationRefusal::Malformed)
}

#[cfg(test)]
mod tests;
