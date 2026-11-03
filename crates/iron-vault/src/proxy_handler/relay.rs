//! Relaying an upstream response to the caller (specification §3.5 step 10, §3.8): its status, its headers without
//! connection-scoped or caller-authentication headers and scrubbed, and its body scrubbed chunk by chunk.
//!
//! Every response passes through the scrubber with the scrub patterns of the credential injected for its request; no
//! path relays a response without it. One it cannot screen, because a content coding hides the bytes, is refused with
//! `502` before anything is sent (§3.8: no content coding is forwarded opaquely).

use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use futures_core::Stream;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame};
use hyper::header::{CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, HeaderMap, HeaderName as HttpHeaderName};
use hyper::{Response, StatusCode};
use iron_vault_kinds::ScrubPatterns;
use iron_vault_policy::reserved_headers::HOP_BY_HOP_HEADERS;
use iron_vault_policy::{CredentialName, HeaderName, Method, RouteName};

use crate::pipeline::RefusalResponse;
use crate::request_server::{BoxError, ResponseBody};
use crate::scrub::{Scrubber, scrub_headers};
use crate::upstream::client::{ResponseChunks, UpstreamResponse};
use crate::upstream::transport_error::TransportError;

/// Integrity headers computed over the upstream's bytes, which a scrub may change, so they would no longer verify.
const INTEGRITY_HEADERS: &[&str] = &["content-md5", "digest", "repr-digest", "content-digest"];

/// What the response stage takes from the request the pipeline accepted.
pub(crate) struct ResponseContext {
    /// The request's method: a `HEAD` response has no body.
    pub(crate) method: Method,
    /// The forms of the injected secret to scrub; the response body owns them until it ends.
    pub(crate) patterns: ScrubPatterns,
    /// The route the request was authorized on, for the scrub event.
    pub(crate) route: RouteName,
    /// The credential injected, for the scrub event.
    pub(crate) credential: CredentialName,
}

/// The caller's response for `upstream`: the upstream's status, its headers less those [`strip_headers`] removes and
/// scrubbed, and its body as a [`RelayedBody`]. `token_header` is the caller-token header of the listener the request
/// arrived on. A response with a content coding is refused with `502`.
pub(super) fn relay(
    upstream: UpstreamResponse,
    token_header: Option<HeaderName>,
    context: ResponseContext,
) -> Result<Response<ResponseBody>, RefusalResponse> {
    let (status, mut headers, chunks) = upstream.into_parts();
    strip_headers(&mut headers, token_header.as_ref());
    if !is_identity_coded(&headers) {
        tracing::warn!(route = %context.route, "response refused: its content coding cannot be scrubbed");
        return Err(RefusalResponse::fixed(StatusCode::BAD_GATEWAY.as_u16()));
    }
    let header_matches = scrub_headers(&mut headers, &context.patterns);
    // EP-21: rewrite an eligible `Location` back under the route's prefix here, after the scrub; until then it passes
    // through scrubbed but otherwise unchanged. Redirects are never followed: the upstream client refuses them.
    reframe(&mut headers, has_no_body(context.method, status), !context.patterns.is_empty());
    Ok(response(status, headers, RelayedBody::new(chunks, context, header_matches)))
}

/// Removes the headers that must not reach the caller: the hop-by-hop headers and every header a `Connection` header
/// names, which describe the upstream connection only, and the caller-authentication headers, which an upstream may
/// echo back: `Proxy-Authenticate` and `Proxy-Authorization` (both hop-by-hop) and the listener's token header.
fn strip_headers(headers: &mut HeaderMap, token_header: Option<&HeaderName>) {
    let named: Vec<HttpHeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .flat_map(|value| value.as_bytes().split(|b| *b == b','))
        .filter_map(|member| HttpHeaderName::from_bytes(member.trim_ascii()).ok())
        .collect();
    named.iter().for_each(|name| {
        headers.remove(name);
    });
    HOP_BY_HOP_HEADERS
        .iter()
        .copied()
        .chain(token_header.map(HeaderName::lowercase))
        .for_each(|name| {
            headers.remove(name);
        });
}

/// Whether the body is sent as the upstream's bytes: no `Content-Encoding`, or only `identity`.
///
/// EP-20 replaces this check, and the pipeline's removal of `Accept-Encoding`, by decoding the body before the scrubber.
fn is_identity_coded(headers: &HeaderMap) -> bool {
    headers
        .get_all(CONTENT_ENCODING)
        .iter()
        .flat_map(|value| value.as_bytes().split(|b| *b == b','))
        .map(<[u8]>::trim_ascii)
        .filter(|coding| !coding.is_empty())
        .all(|coding| coding.eq_ignore_ascii_case(b"identity"))
}

/// Whether the response has no body whatever its headers say (RFC 9110 §6.4.1): one to `HEAD`, a `204` or a `304`.
fn has_no_body(method: Method, status: StatusCode) -> bool {
    method == Method::Head || matches!(status, StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED)
}

/// Removes the headers a scrub may falsify. Scrubbing can change the body's length, so `Content-Length` goes and the
/// request server frames the body itself, chunked; a body that ends short then still never looks complete, because the
/// caller's connection is aborted before the last chunk. A response with no body keeps its `Content-Length`, which
/// there describes the representation, not bytes sent. Integrity headers go whenever there is anything to scrub.
fn reframe(headers: &mut HeaderMap, no_body: bool, scrubbing: bool) {
    if !no_body {
        headers.remove(CONTENT_LENGTH);
    }
    if scrubbing {
        INTEGRITY_HEADERS.iter().for_each(|name| {
            headers.remove(*name);
        });
    }
}

fn response(status: StatusCode, headers: HeaderMap, body: RelayedBody) -> Response<ResponseBody> {
    let mut response = Response::new(body.map_err(BoxError::from).boxed_unsync());
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response
}

/// What the response stage knows about a response once it has ended cleanly, for the request event (EP-26).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseOutcome {
    /// Whether any scrub pattern matched in the response's headers or body.
    pub scrubbed: bool,
}

/// An upstream response body on its way to the caller, each chunk scrubbed and passed on as it arrives, never buffered
/// to the end. Only bytes that could still begin a secret are held back between chunks.
///
/// It owns the request's scrub patterns: they and the held bytes are wiped when the body ends, fails or is dropped.
/// Decompression ahead of the scrubber (EP-20) attaches here too.
///
/// A failure is returned as an error, never as the end of the body. The held bytes are dropped unreleased, since they
/// may be a secret prefix, and the request server's HTTP stack aborts the caller's connection instead of finishing the
/// response, so a truncated body never looks complete.
///
/// Dropping it raises the scrub event if any pattern matched: drop is the one point every response reaches, whether it
/// ended, failed or the caller went away, so the event is raised exactly once.
pub struct RelayedBody {
    chunks: ResponseChunks,
    /// `None` once the body has ended or failed, so the patterns are gone with the response.
    scrubber: Option<Scrubber<'static>>,
    route: RouteName,
    credential: CredentialName,
    /// Matches replaced in the headers, and in the body once the scrubber is gone.
    matches: u64,
    ended: bool,
}

impl RelayedBody {
    fn new(chunks: ResponseChunks, context: ResponseContext, header_matches: u64) -> Self {
        Self {
            chunks,
            scrubber: Some(Scrubber::owning(context.patterns)),
            route: context.route,
            credential: context.credential,
            matches: header_matches,
            ended: false,
        }
    }

    /// The outcome once the body has ended cleanly; `None` before then or after a failure.
    pub fn outcome(&self) -> Option<ResponseOutcome> {
        self.ended.then_some(ResponseOutcome {
            scrubbed: self.matches > 0,
        })
    }

    /// Every match replaced so far, in the headers and the body.
    fn total_matches(&self) -> u64 {
        self.matches + self.scrubber.as_ref().map_or(0, Scrubber::matches)
    }

    /// Ends the body: releases the held bytes, scrubbed, unless there are none.
    fn end(&mut self) -> Option<Bytes> {
        let finished = self.scrubber.take()?.finish();
        self.matches += finished.matches;
        self.ended = true;
        Some(finished.tail).filter(|tail| !tail.is_empty())
    }

    /// Drops the scrubber without releasing its held bytes, keeping its match count for the scrub event.
    fn fail(&mut self) {
        self.matches = self.total_matches();
        self.scrubber = None;
    }
}

impl Body for RelayedBody {
    type Data = Bytes;
    type Error = TransportError;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, TransportError>>> {
        let this = self.get_mut();
        loop {
            let Some(scrubber) = this.scrubber.as_mut() else {
                return Poll::Ready(None);
            };
            match ready!(Pin::new(&mut this.chunks).poll_next(cx)) {
                Some(Ok(chunk)) => {
                    // A chunk wholly held back yields nothing; the next one is read rather than sending an empty frame.
                    let released = scrubber.push(&chunk);
                    if !released.is_empty() {
                        return Poll::Ready(Some(Ok(Frame::data(released))));
                    }
                }
                Some(Err(error)) => {
                    this.fail();
                    return Poll::Ready(Some(Err(error)));
                }
                None => return Poll::Ready(this.end().map(|tail| Ok(Frame::data(tail)))),
            }
        }
    }
}

impl Drop for RelayedBody {
    fn drop(&mut self) {
        let matches = self.total_matches();
        if matches > 0 {
            tracing::warn!(route = %self.route, credential = %self.credential, matches, "scrubbed a secret from a response");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::task::Waker;

    use hyper::header::HeaderValue;

    use super::*;

    /// A relayed body over `chunks` with no scrub patterns, after `header_matches` matches in the headers.
    fn body(chunks: &[&'static [u8]], header_matches: u64) -> RelayedBody {
        let context = ResponseContext {
            method: Method::Get,
            patterns: ScrubPatterns::default(),
            route: "fx".parse().unwrap(),
            credential: "fx_key".parse().unwrap(),
        };
        let chunks = ResponseChunks::of(chunks.iter().copied().map(Bytes::from_static).collect());
        RelayedBody::new(chunks, context, header_matches)
    }

    /// Every frame of `body`, each of which must be data and not empty; the chunks are all ready, so nothing waits.
    fn drain(body: &mut RelayedBody) -> Vec<Bytes> {
        let mut cx = Context::from_waker(Waker::noop());
        std::iter::from_fn(|| match Pin::new(&mut *body).poll_frame(&mut cx) {
            Poll::Ready(Some(frame)) => Some(frame.unwrap().into_data().unwrap()),
            Poll::Ready(None) | Poll::Pending => None,
        })
        .collect()
    }

    #[test]
    fn the_outcome_is_known_once_the_body_has_ended_and_empty_chunks_send_no_frame() {
        let mut relayed = body(&[b"a", b"", b"b"], 0);
        assert_eq!(relayed.outcome(), None);
        assert_eq!(drain(&mut relayed), [Bytes::from_static(b"a"), Bytes::from_static(b"b")]);
        assert_eq!(relayed.outcome(), Some(ResponseOutcome { scrubbed: false }));
    }

    #[test]
    fn a_match_in_the_headers_alone_marks_the_response_scrubbed() {
        let mut relayed = body(&[], 2);
        assert!(drain(&mut relayed).is_empty());
        assert_eq!(relayed.outcome(), Some(ResponseOutcome { scrubbed: true }));
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        pairs
            .iter()
            .map(|(name, value)| (name.parse().unwrap(), HeaderValue::from_str(value).unwrap()))
            .collect()
    }

    fn names(headers: &HeaderMap) -> Vec<&str> {
        headers.keys().map(HttpHeaderName::as_str).collect()
    }

    #[test]
    fn connection_scoped_and_caller_auth_headers_are_removed() {
        let mut map = headers(&[
            ("content-type", "text/plain"),
            ("content-length", "2"),
            ("connection", "X-Hop, , keep-alive"),
            ("connection", "x-other"),
            ("x-hop", "1"),
            ("x-other", "1"),
            ("keep-alive", "timeout=5"),
            ("transfer-encoding", "chunked"),
            ("proxy-authenticate", "Basic"),
            ("proxy-authorization", "Bearer ivt_x"),
            ("x-iron-vault-token", "ivt_x"),
            ("location", "/next"),
        ]);
        strip_headers(&mut map, Some(&"X-Iron-Vault-Token".parse().unwrap()));
        assert_eq!(names(&map), ["content-type", "content-length", "location"]);
    }

    #[test]
    fn without_a_token_header_only_the_connection_scoped_headers_go() {
        let mut map = headers(&[("x-api-key", "echo"), ("upgrade", "h2c"), ("te", "trailers")]);
        strip_headers(&mut map, None);
        assert_eq!(names(&map), ["x-api-key"]);
    }

    #[test]
    fn only_absent_or_identity_content_coding_is_relayed() {
        [
            &[][..],
            &[("content-encoding", "identity")],
            &[("content-encoding", " Identity , ")],
        ]
        .iter()
        .for_each(|pairs| assert!(is_identity_coded(&headers(pairs)), "{pairs:?}"));
        [
            &[("content-encoding", "gzip")][..],
            &[("content-encoding", "identity, br")],
            &[("content-encoding", "identity"), ("content-encoding", "zstd")],
            &[("content-encoding", "x-unknown")],
        ]
        .iter()
        .for_each(|pairs| assert!(!is_identity_coded(&headers(pairs)), "{pairs:?}"));
    }

    #[test]
    fn a_body_loses_its_length_and_integrity_headers_when_scrubbed() {
        let all = [
            ("content-length", "5"),
            ("content-md5", "x"),
            ("digest", "sha-256=x"),
            ("repr-digest", "sha-256=:x:"),
            ("content-digest", "sha-256=:x:"),
            ("etag", "\"1\""),
        ];
        let mut map = headers(&all);
        reframe(&mut map, false, true);
        assert_eq!(names(&map), ["etag"]);

        let mut map = headers(&all);
        reframe(&mut map, false, false);
        let mut left = names(&map);
        left.sort_unstable();
        assert_eq!(left, ["content-digest", "content-md5", "digest", "etag", "repr-digest"]);
    }

    #[test]
    fn a_response_without_a_body_keeps_its_length() {
        let mut map = headers(&[("content-length", "5"), ("digest", "sha-256=x")]);
        reframe(&mut map, true, true);
        assert_eq!(names(&map), ["content-length"]);
    }

    #[test]
    fn head_204_and_304_have_no_body() {
        assert!(has_no_body(Method::Head, StatusCode::OK));
        assert!(has_no_body(Method::Get, StatusCode::NO_CONTENT));
        assert!(has_no_body(Method::Get, StatusCode::NOT_MODIFIED));
        assert!(!has_no_body(Method::Get, StatusCode::OK));
        assert!(!has_no_body(Method::Post, StatusCode::CREATED));
    }
}
