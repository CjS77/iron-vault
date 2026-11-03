//! Relaying an upstream response to the caller (specification §3.5 step 10): its status, its headers without
//! connection-scoped or caller-authentication headers, and its body chunk by chunk.

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_core::Stream;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame};
use hyper::header::{CONNECTION, HeaderMap, HeaderName as HttpHeaderName};
use hyper::{Response, StatusCode};
use iron_vault_policy::HeaderName;
use iron_vault_policy::reserved_headers::HOP_BY_HOP_HEADERS;

use crate::request_server::{BoxError, ResponseBody};
use crate::upstream::client::{ResponseChunks, UpstreamResponse};
use crate::upstream::transport_error::TransportError;

/// The caller's response for `upstream`: the upstream's status, its headers less those [`strip_headers`] removes, and
/// its body as a [`RelayedBody`]. `token_header` is the caller-token header of the listener the request arrived on.
pub(super) fn relay(upstream: UpstreamResponse, token_header: Option<HeaderName>) -> Response<ResponseBody> {
    let (status, mut headers, chunks) = upstream.into_parts();
    strip_headers(&mut headers, token_header.as_ref());
    // EP-21: rewrite an eligible `Location` back under the route's prefix here; until then it passes through unchanged.
    // Redirects are never followed: the upstream client refuses them.
    response(status, headers, RelayedBody::new(chunks))
}

/// Removes the headers that must not reach the caller: the hop-by-hop headers and every header a `Connection` header
/// names, which describe the upstream connection only, and the caller-authentication headers, which an upstream may
/// echo back: `Proxy-Authenticate` and `Proxy-Authorization` (both hop-by-hop) and the listener's token header.
///
/// `Content-Length` stays, so the caller's response is framed by the upstream's declared length and a body that ends
/// short cannot look complete.
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

fn response(status: StatusCode, headers: HeaderMap, body: RelayedBody) -> Response<ResponseBody> {
    let mut response = Response::new(body.map_err(BoxError::from).boxed_unsync());
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response
}

/// An upstream response body on its way to the caller, each chunk passed on as it arrives, never buffered to the end.
///
/// This is the one place the response body passes through, so the later response-body stages attach here: secret
/// scrubbing (EP-19), decompression ahead of it (EP-20), and, with the `Location` rewrite beside [`relay`]'s headers,
/// redirect handling (EP-21). For now it passes bytes unchanged.
///
/// A failure is returned as an error, never as the end of the body. The request server's HTTP stack then aborts the
/// caller's connection instead of finishing the response, so a truncated body never looks complete.
pub struct RelayedBody {
    chunks: ResponseChunks,
}

impl RelayedBody {
    fn new(chunks: ResponseChunks) -> Self {
        Self { chunks }
    }
}

impl Body for RelayedBody {
    type Data = Bytes;
    type Error = TransportError;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, TransportError>>> {
        Pin::new(&mut self.chunks)
            .poll_next(cx)
            .map(|chunk| chunk.map(|chunk| chunk.map(Frame::data)))
    }
}

#[cfg(test)]
mod tests {
    use hyper::header::HeaderValue;

    use super::*;

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
}
