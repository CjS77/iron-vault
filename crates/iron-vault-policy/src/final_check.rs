//! The final outgoing-request check: the last decision before a credential leaves the service (spec §3.3, §3.6, §7).
//!
//! Every fact is read back from the assembled request's own URL and headers, never taken from the inputs that built
//! it, so a defect in URL construction or slot filling is caught here rather than repeated. The route's upstream is
//! compared with the credential record's permitted origins too, because destinations are bound to the record and a
//! route edit must not be able to send an existing secret elsewhere (R-4). A failure means a policy or construction
//! defect: the request is dropped unsent, and the service raises a high-severity event.

use std::collections::BTreeSet;
use std::fmt;

use thiserror::Error;
use url::{Position, Url};

use crate::authorization::AuthorizedRequest;
use crate::host::Host;
use crate::method::Method;
use crate::outgoing_headers::OutgoingHeaders;
use crate::outgoing_request::OutgoingRequest;
use crate::port::Port;
use crate::query_value::decode_name;
use crate::reserved_headers::is_reserved;
use crate::slot::{QueryParamName, Slot};
use crate::upstream::UpstreamUrl;
use crate::upstream_target::has_authorized_path;

/// An outgoing request that passed [`final_check`]; the only form the transport accepts.
///
/// Only `final_check` builds one and nothing changes it afterwards, so the transport sends exactly what was checked.
/// There is no `Clone`, so the credential is not copied further. `Debug` omits the query and shows header values only
/// by length, so a checked request is safe to log.
pub struct CheckedRequest {
    method: Method,
    url: Url,
    headers: OutgoingHeaders,
    host: Host,
}

/// Which final-check rule an outgoing request failed.
///
/// Each variant is a policy or construction defect, distinct from every caller error, so the service can refuse the
/// request and raise a high-severity event. Variants carry nothing, because the URL, its query and the header values
/// may hold the credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum FinalCheckError {
    /// The scheme is not `https`.
    #[error("final check: the scheme is not https")]
    Scheme,
    /// The URL has a username or a password.
    #[error("final check: the URL has user-info")]
    UserInfo,
    /// The URL has a fragment.
    #[error("final check: the URL has a fragment")]
    Fragment,
    /// The URL's host is missing, does not convert to a [`Host`], or is not the upstream's host.
    #[error("final check: the host is not the upstream's host")]
    Host,
    /// The URL's port, 443 when omitted, is not the upstream's port.
    #[error("final check: the port is not the upstream's port")]
    Port,
    /// The credential record does not permit the URL's host and port pair.
    #[error("final check: the credential record does not permit this host and port")]
    Origin,
    /// The path is outside the upstream base path, or is not the authorized upstream path.
    #[error("final check: the path is not the authorized upstream path")]
    Path,
    /// The method is not the authorized method.
    #[error("final check: the method is not the authorized method")]
    Method,
    /// A reserved header such as `Host`, which the transport sets from [`CheckedRequest::host`], or a pseudo-header
    /// is among the headers.
    #[error("final check: the headers hold a reserved header or pseudo-header")]
    ReservedHeader,
    /// The route's slot is missing or written more than once.
    #[error("final check: the slot is not present exactly once")]
    Slot,
}

/// Checks `request` against the plan it was built for, the selected route's `upstream` and `slot`, and the origins
/// its credential record `permitted`, immediately before sending (§3.6).
///
/// None of the arguments is trusted to belong to the others: each rule reads the request's own URL and headers and
/// compares them with every source that constrains them. Hosts compare by exact equality after the one [`Host`]
/// conversion, never by suffix. On failure the request is dropped here, which wipes its header values.
pub fn final_check(
    request: OutgoingRequest,
    authorized: &AuthorizedRequest,
    upstream: &UpstreamUrl,
    slot: &Slot,
    permitted: &BTreeSet<(Host, Port)>,
) -> Result<CheckedRequest, FinalCheckError> {
    let (method, url, headers) = request.into_parts();
    check_form(&url)?;
    let host = check_origin(&url, upstream, permitted)?;
    check_path(&url, authorized, upstream)?;
    require(method == authorized.method(), FinalCheckError::Method)?;
    check_headers(&headers)?;
    require(slot_count(&url, &headers, slot) == 1, FinalCheckError::Slot)?;
    Ok(CheckedRequest { method, url, headers, host })
}

impl CheckedRequest {
    /// The authorized method.
    pub fn method(&self) -> Method {
        self.method
    }

    /// The URL to send to, with a query slot filled.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// The headers to send, with a header or Basic slot filled; never `Host` or a pseudo-header.
    pub fn headers(&self) -> &OutgoingHeaders {
        &self.headers
    }

    /// The checked upstream host, which the `Host` header or `:authority` and TLS server-name verification must both
    /// use, so the authority the upstream sees is the one the record permits.
    ///
    /// The authority adds `:port` when [`Url::port`] is `Some`; otherwise the port is 443.
    pub fn host(&self) -> &Host {
        &self.host
    }
}

impl fmt::Debug for CheckedRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CheckedRequest")
            .field("method", &self.method)
            .field("url", &&self.url[..Position::AfterPath])
            .field("query", &self.url.query().map(|_| "<redacted>"))
            .field("headers", &self.headers)
            .field("host", &self.host)
            .finish()
    }
}

fn require(holds: bool, error: FinalCheckError) -> Result<(), FinalCheckError> {
    holds.then_some(()).ok_or(error)
}

/// `https`, no caller-controlled authority in user-info, and no fragment.
fn check_form(url: &Url) -> Result<(), FinalCheckError> {
    require(url.scheme() == "https", FinalCheckError::Scheme)?;
    require(url.username().is_empty() && url.password().is_none(), FinalCheckError::UserInfo)?;
    require(url.fragment().is_none(), FinalCheckError::Fragment)
}

/// The URL's host and port must equal the upstream's, and the pair must be one the record permits; returns the host.
fn check_origin(url: &Url, upstream: &UpstreamUrl, permitted: &BTreeSet<(Host, Port)>) -> Result<Host, FinalCheckError> {
    let host: Host = url.host_str().and_then(|raw| raw.parse().ok()).ok_or(FinalCheckError::Host)?;
    require(host == *upstream.host(), FinalCheckError::Host)?;
    let port = url.port_or_known_default().and_then(|port| Port::try_from(port).ok()).ok_or(FinalCheckError::Port)?;
    require(port == upstream.port(), FinalCheckError::Port)?;
    let origin = (host, port);
    require(permitted.contains(&origin), FinalCheckError::Origin)?;
    Ok(origin.0)
}

/// The path must start with this upstream's base segments and be exactly the authorized upstream path. The base check
/// stands on its own, so a plan authorized on another route cannot pass by matching itself.
fn check_path(url: &Url, authorized: &AuthorizedRequest, upstream: &UpstreamUrl) -> Result<(), FinalCheckError> {
    let in_base = url.path_segments().is_some_and(|mut segments| {
        upstream.base_segments().iter().all(|base| segments.next() == Some(base.as_str()))
    });
    require(in_base && has_authorized_path(url, authorized), FinalCheckError::Path)
}

/// The transport sets the authority itself, so no reserved header may remain, and no pseudo-header may slip past it.
fn check_headers(headers: &OutgoingHeaders) -> Result<(), FinalCheckError> {
    let controlled = headers.iter().any(|(name, _)| is_reserved(name) || name.as_str().starts_with(':'));
    require(!controlled, FinalCheckError::ReservedHeader)
}

/// How many times the slot appears: query parameters by decoded name, or headers by name in any case.
fn slot_count(url: &Url, headers: &OutgoingHeaders, slot: &Slot) -> usize {
    match (slot, slot.header_written()) {
        (Slot::Query(name), _) => query_param_count(url, name),
        (_, Some(written)) => headers.iter().filter(|(name, _)| name.lowercase() == written).count(),
        (_, None) => 0,
    }
}

fn query_param_count(url: &Url, name: &QueryParamName) -> usize {
    let params = url.query().map(|query| query.split('&')).into_iter().flatten();
    params.filter(|param| decode_name(param).is_some_and(|decoded| decoded == name.as_str())).count()
}

#[cfg(test)]
mod tests;
