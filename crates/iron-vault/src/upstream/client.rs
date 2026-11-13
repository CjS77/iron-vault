//! The upstream client: the only way the service reaches an upstream ([spec §8][s8] step 9, [§10][s10],
//! [implementation spec §1][i1]).
//!
//! [`UpstreamClient::new`] is the one constructor. It hands reqwest the rustls config built from an [`UpstreamTrust`],
//! turns off proxies, redirects, retries and the `Referer` header, and refuses cleartext. `clippy.toml` refuses every
//! other way to build a reqwest client, to add a proxy, to set a retry policy or to switch certificate checks off.
//! [`UpstreamClient::send`] takes a [`CheckedRequest`] and a [`UpstreamBody`], so nothing reaches the network without
//! passing the final outgoing-request check. It sends exactly that request's method, URL and headers, plus the body,
//! which the final check never reads.
//!
//! [s8]: ../../../../design/iron-vault-specification.md#8-request-flow
//! [s10]: ../../../../design/iron-vault-specification.md#10-outbound-tls-and-environment
//! [i1]: ../../../../design/implementation-specification.md#1-implementation-structure

use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use futures_core::Stream;
use iron_vault_policy::{CheckedRequest, HeaderName, HeaderValue, Limits, Method};
use reqwest::header::{self, HeaderMap};
use reqwest::redirect::Policy;
use reqwest::retry;
use reqwest::{Client, Request, Response, StatusCode};
use rustls::ClientConfig;

use super::body::{Kind, UpstreamBody, settle_empty};
use super::transport_error::TransportError;
use super::trust::{ClientConfigError, UpstreamTrust};

/// The ALPN protocols the client offers, most preferred first: HTTP/2, then HTTP/1.1.
const ALPN_PROTOCOLS: [&[u8]; 2] = [b"h2", b"http/1.1"];

/// The time allowed to open an upstream's TCP connection and complete the TLS handshake. The config has no key for it.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the client waits on an upstream before giving up with [`TransportError::Timeout`].
///
/// [`UpstreamClients`](super::clients::UpstreamClients) builds a policy's clients with [`TransportLimits::of`] its
/// `[limits]`, so an approved `upstream_timeout_secs` takes effect with the snapshot that serves it. The request deadline
/// still bounds the whole request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportLimits {
    /// The time allowed to open the TCP connection and complete the TLS handshake.
    pub connect: Duration,
    /// The time allowed from starting to send the request until the response headers arrive, including connecting and
    /// the TLS handshake when no pooled connection is free. It does not bound the body, so a long streamed response is
    /// never cut off.
    pub response_headers: Duration,
}

impl TransportLimits {
    /// The deadlines for a policy with `limits`: the fixed connect timeout, and `upstream_timeout_secs` until the
    /// response headers arrive.
    pub fn of(limits: &Limits) -> Self {
        Self {
            connect: CONNECT_TIMEOUT,
            response_headers: Duration::from_secs(limits.upstream_timeout_secs()),
        }
    }
}

impl Default for TransportLimits {
    /// Returns the deadlines for the default `[limits]`.
    fn default() -> Self {
        Self::of(&Limits::default())
    }
}

/// Why an upstream client could not be built. No variant carries a library diagnostic.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ClientBuildError {
    /// The rustls config for the upstream trust could not be built.
    #[error(transparent)]
    Config(#[from] ClientConfigError),
    /// reqwest refused the client's settings.
    #[error("the upstream HTTP client could not be built")]
    Http,
}

/// An HTTP client over one upstream trust that sends only checked requests.
///
/// It keeps idle connections for reuse, and an idle connection's task holds the last request's headers, the injected
/// credential included. The service holds the pool only through this value: it is not `Clone` and never hands out its
/// reqwest client, so dropping it, which a lock does with the serving snapshot, closes every idle connection, or, if
/// hyper-util is still running a background connect (which holds the pool strongly), when that connect ends, at most
/// `TransportLimits::connect` later
/// ([secret handling: Upstream connections close with their snapshot][close]).
///
/// [close]: ../../../../design/secret-handling.md#upstream-connections-close-with-their-snapshot
pub struct UpstreamClient {
    client: Client,
    limits: TransportLimits,
}

/// An upstream's response: its status and headers, with the body still streaming from the upstream.
///
/// Nothing is buffered or decoded here; scrubbing and decompression attach to the body later. The headers may echo the
/// credential, so `Debug` shows only the status and how many headers there are.
pub struct UpstreamResponse {
    response: Response,
}

impl UpstreamClient {
    /// Builds the client for `trust`; the only way to build one.
    ///
    /// The client offers HTTP/2 and HTTP/1.1 through ALPN, verifies the upstream against exactly `trust`, uses no
    /// proxy (which also stops reqwest reading system proxy settings), never follows a redirect, refuses any scheme
    /// but `https`, never adds `Referer`, keeps no cookies and adds no default header of its own choosing.
    ///
    /// It never retries: one checked request is one send. reqwest's default policy would re-send a request an HTTP/2
    /// upstream refused with `GOAWAY` or `REFUSED_STREAM`. The final check
    /// ([implementation spec §1](../../../../design/implementation-specification.md#1-implementation-structure)) and
    /// the rate limits ([§8](../../../../design/iron-vault-specification.md#8-request-flow)) would never see that
    /// second send, and it repeats a non-idempotent request the upstream may have acted on. The caller decides whether
    /// to try again. `never()` alone still lets reqwest clone every request, credential included, for a retry it will
    /// not make; a limit of zero retries stops that copy too.
    // clippy.toml refuses `Client::builder` and `ClientBuilder::retry` everywhere else; this is the one constructor it
    // exists to protect.
    #[allow(clippy::disallowed_methods)]
    pub fn new(trust: &UpstreamTrust, limits: TransportLimits) -> Result<Self, ClientBuildError> {
        let client = Client::builder()
            .use_preconfigured_tls(tls_config(trust)?)
            .no_proxy()
            .redirect(Policy::none())
            .retry(retry::never().max_retries_per_request(0))
            .https_only(true)
            .referer(false)
            .connect_timeout(limits.connect)
            .build()
            .map_err(|_| ClientBuildError::Http)?;
        Ok(Self { client, limits })
    }

    /// Sends `request` and returns once the upstream's response headers arrive.
    ///
    /// The request carries the checked method, URL and headers, plus `body`, and nothing else. `Host` is never set here: reqwest
    /// derives it, or HTTP/2's `:authority`, from the URL, whose host the final check proved is
    /// [`CheckedRequest::host`], and TLS verifies that same name, so all three name the checked upstream
    /// ([§9](../../../../design/iron-vault-specification.md#9-url-header-and-slot-rules)).
    /// reqwest adds `Accept: */*` when the request has no `Accept`, and its builder offers no way to stop it.
    ///
    /// `body` is forwarded chunk by chunk, never buffered whole and never inspected. It is framed by its declared
    /// length when [`UpstreamBody::stream`] was given one, and as chunked (HTTP/1.1) otherwise; the caller's own framing
    /// headers were already dropped by `sanitize`. If the body stream fails, the upstream request is aborted, not
    /// completed with a short body, and `send` returns a [`TransportError`], which is answered `502`.
    ///
    /// There is no retry, and a streamed body could not be replayed if there were: its chunks are gone once sent. A
    /// caller that tries again sends a new body.
    ///
    /// The response-headers deadline starts when sending starts, so it also bounds how long the body may take to upload.
    ///
    /// It must run on a tokio runtime with its timer enabled, which both deadlines use.
    pub async fn send(&self, request: CheckedRequest, body: UpstreamBody) -> Result<UpstreamResponse, TransportError> {
        let request = to_reqwest(request)?;
        let response = tokio::time::timeout(self.limits.response_headers, self.execute(request, body))
            .await
            .map_err(|_| TransportError::Timeout)??;
        Ok(UpstreamResponse { response })
    }
}

impl UpstreamClient {
    /// Attaches `body` to `request` and executes it.
    async fn execute(&self, request: Request, body: UpstreamBody) -> Result<Response, TransportError> {
        let request = with_body(request, body).await?;
        self.client.execute(request).await.map_err(TransportError::classify)
    }
}

impl fmt::Debug for UpstreamClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpstreamClient")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl UpstreamResponse {
    /// The upstream's status code.
    pub fn status(&self) -> StatusCode {
        self.response.status()
    }

    /// The upstream's headers, unscrubbed.
    pub fn headers(&self) -> &HeaderMap {
        self.response.headers()
    }

    /// Waits for the next chunk of the body as it arrived; `None` at its end.
    pub async fn chunk(&mut self) -> Result<Option<Bytes>, TransportError> {
        self.response.chunk().await.map_err(TransportError::classify)
    }

    /// Splits the response into its status, its headers and its body still streaming, so the headers move without a
    /// copy.
    pub fn into_parts(self) -> (StatusCode, HeaderMap, ResponseChunks) {
        let status = self.response.status();
        let mut response = self.response;
        let headers = std::mem::take(response.headers_mut());
        (status, headers, ResponseChunks(Box::pin(response.bytes_stream())))
    }
}

/// An upstream response body as it arrives: each chunk unchanged, each failure classified as a [`TransportError`] and
/// the library error dropped unformatted.
pub struct ResponseChunks(Pin<Box<dyn Stream<Item = reqwest::Result<Bytes>> + Send>>);

impl Stream for ResponseChunks {
    type Item = Result<Bytes, TransportError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.0
            .as_mut()
            .poll_next(cx)
            .map(|chunk| chunk.map(|chunk| chunk.map_err(TransportError::classify)))
    }
}

#[cfg(test)]
impl ResponseChunks {
    /// A body of `chunks`, each ready at once, for the response stage's unit tests.
    pub(crate) fn of(chunks: Vec<Bytes>) -> Self {
        struct Ready(std::vec::IntoIter<Bytes>);

        impl Stream for Ready {
            type Item = reqwest::Result<Bytes>;

            fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
                Poll::Ready(self.0.next().map(Ok))
            }
        }

        Self(Box::pin(Ready(chunks.into_iter())))
    }
}

impl fmt::Debug for ResponseChunks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResponseChunks").finish_non_exhaustive()
    }
}

impl fmt::Debug for UpstreamResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpstreamResponse")
            .field("status", &self.status())
            .field("headers", &self.headers().len())
            .finish_non_exhaustive()
    }
}

/// Builds `trust`'s rustls config with ALPN set; reqwest leaves a preconfigured config's ALPN as it is.
fn tls_config(trust: &UpstreamTrust) -> Result<ClientConfig, ClientConfigError> {
    let mut config = Arc::unwrap_or_clone(trust.client_config()?);
    config.alpn_protocols = ALPN_PROTOCOLS.iter().map(|protocol| protocol.to_vec()).collect();
    Ok(config)
}

/// Converts `checked` into a reqwest request: its method, URL and headers, with no body.
///
/// The URL is moved, not cloned, because it may hold a filled query slot that `url::Url` cannot wipe. The policy's
/// header values are wiped when `headers` drops at the end of this function, leaving reqwest's copies.
fn to_reqwest(checked: CheckedRequest) -> Result<Request, TransportError> {
    let (checked_method, url, headers) = checked.into_parts();
    let mut request = Request::new(method(checked_method), url);
    let outgoing = request.headers_mut();
    headers.iter().try_for_each(|(name, value)| {
        outgoing.append(header_name(name)?, sensitive_value(value)?);
        Ok(())
    })?;
    Ok(request)
}

/// Attaches `body` to `request`.
///
/// reqwest's streamed body has no length of its own, so a declared length goes in as a `Content-Length` header, which
/// both hyper's HTTP/1.1 and HTTP/2 clients frame by; without one the body is chunked. A declared length of zero is
/// settled here, before anything is sent, and goes out as `Content-Length: 0` with no body: hyper's HTTP/1.1 client
/// never polls a zero-length body, so the stream could not be checked later.
async fn with_body(mut request: Request, body: UpstreamBody) -> Result<Request, TransportError> {
    match body.kind {
        Kind::Empty => {}
        Kind::Stream { length: Some(0), chunks } => {
            settle_empty(chunks).await.map_err(|_| TransportError::Body)?;
            request.headers_mut().insert(header::CONTENT_LENGTH, 0.into());
        }
        Kind::Stream { length, chunks } => {
            if let Some(length) = length {
                request.headers_mut().insert(header::CONTENT_LENGTH, length.into());
            }
            *request.body_mut() = Some(reqwest::Body::wrap_stream(chunks));
        }
    }
    Ok(request)
}

fn method(method: Method) -> reqwest::Method {
    match method {
        Method::Get => reqwest::Method::GET,
        Method::Head => reqwest::Method::HEAD,
        Method::Post => reqwest::Method::POST,
        Method::Put => reqwest::Method::PUT,
        Method::Patch => reqwest::Method::PATCH,
        Method::Delete => reqwest::Method::DELETE,
        Method::Options => reqwest::Method::OPTIONS,
    }
}

/// The policy's header names are RFC 9110 tokens, which `http` always accepts; a refusal would be a construction
/// defect, so the request is refused instead of sent without the header.
fn header_name(name: &HeaderName) -> Result<header::HeaderName, TransportError> {
    header::HeaderName::from_bytes(name.as_str().as_bytes()).map_err(|_| TransportError::Protocol)
}

/// Converts a header value and marks it sensitive, so HTTP/2's HPACK never adds it to the dynamic table and `http`'s
/// `Debug` hides it.
///
/// The policy's header values already exclude every byte `http` refuses; a refusal is treated as in [`header_name`].
fn sensitive_value(value: &HeaderValue) -> Result<header::HeaderValue, TransportError> {
    let mut value = header::HeaderValue::from_bytes(value.as_bytes()).map_err(|_| TransportError::Protocol)?;
    value.set_sensitive(true);
    Ok(value)
}

#[cfg(test)]
mod tests;
