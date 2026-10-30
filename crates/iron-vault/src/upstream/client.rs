//! The upstream client: the only way the service reaches an upstream (specification §3.5 step 9, §3.7, §7).
//!
//! [`UpstreamClient::new`] is the one constructor. It hands reqwest the rustls config built from an [`UpstreamTrust`],
//! turns off proxies, redirects and the `Referer` header, and refuses cleartext. `clippy.toml` refuses every other way
//! to build a reqwest client, to add a proxy or to switch certificate checks off. [`UpstreamClient::send`] takes only
//! a [`CheckedRequest`], so nothing reaches the network without passing the final outgoing-request check, and it
//! sends exactly that request's method, URL and headers.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use iron_vault_policy::{CheckedRequest, HeaderName, HeaderValue, Method};
use reqwest::header::{self, HeaderMap};
use reqwest::redirect::Policy;
use reqwest::{Client, Request, Response, StatusCode};
use rustls::ClientConfig;

use super::transport_error::TransportError;
use super::trust::{ClientConfigError, UpstreamTrust};

/// The ALPN protocols the client offers, most preferred first: HTTP/2, then HTTP/1.1.
const ALPN_PROTOCOLS: [&[u8]; 2] = [b"h2", b"http/1.1"];

/// How long the client waits on an upstream before giving up with [`TransportError::Timeout`].
///
/// The defaults are placeholders until the request pipeline (EP-18) and the operational limits of specification §9 are
/// published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportLimits {
    /// The time allowed to open the TCP connection and complete the TLS handshake.
    pub connect: Duration,
    /// The time allowed from starting to send the request until the response headers arrive, including connecting and
    /// the TLS handshake when no pooled connection is free. It does not bound the body, so a long streamed response is
    /// never cut off.
    pub response_headers: Duration,
}

impl Default for TransportLimits {
    /// 10 seconds to connect and 300 seconds until the response headers arrive: a language model may take minutes
    /// before it answers a non-streamed request. Both are placeholders until §9 publishes the limits.
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(10),
            response_headers: Duration::from_secs(300),
        }
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
    // clippy.toml refuses `Client::builder` everywhere else; this is the one constructor it exists to protect.
    #[allow(clippy::disallowed_methods)]
    pub fn new(trust: &UpstreamTrust, limits: TransportLimits) -> Result<Self, ClientBuildError> {
        let client = Client::builder()
            .use_preconfigured_tls(tls_config(trust)?)
            .no_proxy()
            .redirect(Policy::none())
            .https_only(true)
            .referer(false)
            .connect_timeout(limits.connect)
            .build()
            .map_err(|_| ClientBuildError::Http)?;
        Ok(Self { client, limits })
    }

    /// Sends `request` and returns once the upstream's response headers arrive.
    ///
    /// The request carries the checked method, URL and headers and nothing else. `Host` is never set here: reqwest
    /// derives it, or HTTP/2's `:authority`, from the URL, whose host the final check proved is
    /// [`CheckedRequest::host`], and TLS verifies that same name, so all three name the checked upstream (§3.6).
    /// reqwest adds `Accept: */*` when the request has no `Accept`, and its builder offers no way to stop it.
    ///
    /// It must run on a tokio runtime with its timer enabled, which both deadlines use.
    pub async fn send(&self, request: CheckedRequest) -> Result<UpstreamResponse, TransportError> {
        let request = to_reqwest(request)?;
        let response = tokio::time::timeout(self.limits.response_headers, self.client.execute(request))
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(TransportError::classify)?;
        Ok(UpstreamResponse { response })
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

    /// The next chunk of the body as it arrived, or `None` at its end.
    pub async fn chunk(&mut self) -> Result<Option<Bytes>, TransportError> {
        self.response.chunk().await.map_err(TransportError::classify)
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

/// `trust`'s rustls config with ALPN set; reqwest leaves a preconfigured config's ALPN as it is.
fn tls_config(trust: &UpstreamTrust) -> Result<ClientConfig, ClientConfigError> {
    let mut config = Arc::unwrap_or_clone(trust.client_config()?);
    config.alpn_protocols = ALPN_PROTOCOLS.iter().map(|protocol| protocol.to_vec()).collect();
    Ok(config)
}

/// The reqwest request for `checked`: its method, URL and headers, with no body.
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
/// defect, so the request is refused rather than sent without the header.
fn header_name(name: &HeaderName) -> Result<header::HeaderName, TransportError> {
    header::HeaderName::from_bytes(name.as_str().as_bytes()).map_err(|_| TransportError::Protocol)
}

/// The value marked sensitive, so HTTP/2's HPACK never adds it to the dynamic table and `http`'s `Debug` hides it.
///
/// The policy's header values already exclude every byte `http` refuses; a refusal is treated as in [`header_name`].
fn sensitive_value(value: &HeaderValue) -> Result<header::HeaderValue, TransportError> {
    let mut value = header::HeaderValue::from_bytes(value.as_bytes()).map_err(|_| TransportError::Protocol)?;
    value.set_sensitive(true);
    Ok(value)
}

#[cfg(test)]
mod tests;
