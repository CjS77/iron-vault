//! Why an upstream exchange failed, with nothing from the failure itself (specification §3.12).
//!
//! A `reqwest::Error` formats the request URL, whose query may hold a query-slot credential, and its source chain
//! carries hyper and rustls diagnostics. So an error is classified only through its predicates and its source types,
//! then dropped without ever being formatted, and [`TransportError`] keeps nothing but the class.

use std::error::Error;
use std::io;

use reqwest::StatusCode;

/// The class of a failed upstream exchange. Variants carry nothing, so neither `Display` nor `Debug` can show the URL
/// or a library diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TransportError {
    /// Connecting, or waiting for the response headers, took longer than the transport limits allow.
    #[error("the upstream did not respond in time")]
    Timeout,
    /// The TCP connection to the upstream could not be opened.
    #[error("the upstream could not be reached")]
    Connect,
    /// The TLS handshake failed, including when the upstream's certificate does not verify against the route's trust.
    #[error("the TLS session with the upstream failed")]
    Tls,
    /// The upstream broke HTTP, or the request could not be written.
    #[error("the upstream exchange broke the HTTP protocol")]
    Protocol,
    /// The response body stopped before its end.
    #[error("the upstream response body failed")]
    Body,
}

impl TransportError {
    /// The status the request interface returns for this failure: `504` for a timeout, `502` for the rest.
    pub fn status(self) -> StatusCode {
        match self {
            Self::Timeout => StatusCode::GATEWAY_TIMEOUT,
            Self::Connect | Self::Tls | Self::Protocol | Self::Body => StatusCode::BAD_GATEWAY,
        }
    }

    /// Classifies `error` and drops it unformatted.
    ///
    /// The timeout check comes first, since a connect timeout is also a connect error, and the TLS check before the
    /// connect check, since reqwest reports a failed handshake as a connect error.
    pub(crate) fn classify(error: reqwest::Error) -> Self {
        if error.is_timeout() {
            Self::Timeout
        } else if has_tls_source(&error) {
            Self::Tls
        } else if error.is_connect() {
            Self::Connect
        } else if error.is_body() || error.is_decode() {
            Self::Body
        } else {
            Self::Protocol
        }
    }
}

/// Whether a rustls error is anywhere in `error`'s source chain.
///
/// tokio-rustls wraps a handshake failure in an `io::Error`, and hyper wraps that in another; an `io::Error`'s
/// `source` skips the error it wraps, so the walk steps into each one instead.
fn has_tls_source(error: &(dyn Error + 'static)) -> bool {
    // `is` matches only this crate's rustls, which is reqwest's while the workspace has one rustls version. If they
    // split, a TLS failure is classified as `Connect`, which is still a 502.
    std::iter::successors(Some(error), |&error| next_cause(error)).any(|error| error.is::<rustls::Error>())
}

/// The error inside `error` if it is an `io::Error` wrapping one, else its source.
fn next_cause<'a>(error: &'a (dyn Error + 'static)) -> Option<&'a (dyn Error + 'static)> {
    match error.downcast_ref::<io::Error>().and_then(io::Error::get_ref) {
        Some(inner) => Some(inner),
        None => error.source(),
    }
}
