//! The final outgoing-request check: the last decision before a credential leaves the service (spec §3.3, §3.6, §7).
//!
//! Every fact is read back from the assembled request's own URL and headers, never taken from the inputs that built
//! it, so a defect in URL construction or slot filling is caught here rather than repeated. The route's upstream is
//! compared with the credential record's permitted origins too, because destinations are bound to the record and a
//! route edit must not be able to send an existing secret elsewhere (R-4). The selected slot must hold the slot value
//! as the assembler renders it, and the value must appear nowhere else, so a slot filled through the wrong route, or a
//! caller copy left in the slot, is caught even when the slot is written exactly once. A failure means a policy or construction
//! defect: the request is dropped unsent, and the service raises a high-severity event.

use std::collections::BTreeSet;
use std::fmt;

use secrecy::ExposeSecret;
use secrecy::zeroize::Zeroizing;
use thiserror::Error;
use url::{Position, Url};

use crate::authorization::AuthorizedRequest;
use crate::bound_credential::BoundCredential;
use crate::host::Host;
use crate::method::Method;
use crate::outgoing_headers::OutgoingHeaders;
use crate::outgoing_request::{OutgoingRequest, render_header};
use crate::port::Port;
use crate::query_value::{decode_name, encode_query_value};
use crate::reserved_headers::is_reserved;
use crate::slot::{HeaderSlot, QueryParamName, Slot};
use crate::slot_value::SlotValue;
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
    /// The one entry in the route's slot is not the slot value as the assembler renders it.
    #[error("final check: the slot does not hold the credential")]
    SlotValue,
    /// The slot value, as stored or query-encoded, appears in the URL or a header outside the route's slot.
    #[error("final check: the credential appears outside the slot")]
    CredentialOutsideSlot,
}

/// Checks `request` against the plan it was built for, the selected route's `upstream` and `slot`, and the route's
/// `credential`: the slot value it produced and the origins its credential record permits, immediately before sending
/// (§3.6).
///
/// The value and origins arrive as one [`BoundCredential`], so both come from the same record. The value is borrowed
/// and rendered here with the assembler's own functions, so the expected wire form cannot drift from what filling
/// wrote; the rendered copies are wiped on drop. None of the arguments is trusted to belong to the
/// others: each rule reads the request's own URL and headers and compares them with every source that constrains them.
/// The URL's host must equal the upstream's canonical [`Host`] exactly, never by suffix. On failure the request is
/// dropped here, which wipes its header values.
pub fn final_check(
    request: OutgoingRequest,
    authorized: &AuthorizedRequest,
    upstream: &UpstreamUrl,
    slot: &Slot,
    credential: &BoundCredential<'_>,
) -> Result<CheckedRequest, FinalCheckError> {
    let (method, url, headers) = request.into_parts();
    check_form(&url)?;
    let host = check_origin(&url, upstream, credential.permitted())?;
    check_path(&url, authorized, upstream)?;
    require(method == authorized.method(), FinalCheckError::Method)?;
    check_headers(&headers)?;
    check_slot(&url, &headers, slot, credential.value())?;
    Ok(CheckedRequest {
        method,
        url,
        headers,
        host,
    })
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
///
/// The URL's host is compared exactly with the upstream's canonical [`Host`], which is the form the URL was built
/// with, so no second conversion can make a different spelling match.
fn check_origin(url: &Url, upstream: &UpstreamUrl, permitted: &BTreeSet<(Host, Port)>) -> Result<Host, FinalCheckError> {
    require(url.host_str() == Some(upstream.host().as_str()), FinalCheckError::Host)?;
    let host = upstream.host().clone();
    let port = url
        .port_or_known_default()
        .and_then(|port| Port::try_from(port).ok())
        .ok_or(FinalCheckError::Port)?;
    require(port == upstream.port(), FinalCheckError::Port)?;
    let origin = (host, port);
    require(permitted.contains(&origin), FinalCheckError::Origin)?;
    Ok(origin.0)
}

/// The path must start with this upstream's base segments and be exactly the authorized upstream path. The base check
/// stands on its own, so a plan authorized on another route cannot pass by matching itself.
fn check_path(url: &Url, authorized: &AuthorizedRequest, upstream: &UpstreamUrl) -> Result<(), FinalCheckError> {
    let in_base = url
        .path_segments()
        .is_some_and(|mut segments| upstream.base_segments().iter().all(|base| segments.next() == Some(base.as_str())));
    require(in_base && has_authorized_path(url, authorized), FinalCheckError::Path)
}

/// The transport sets the authority itself, so no reserved header may remain, and no pseudo-header may slip past it.
fn check_headers(headers: &OutgoingHeaders) -> Result<(), FinalCheckError> {
    let controlled = headers.iter().any(|(name, _)| is_reserved(name) || name.as_str().starts_with(':'));
    require(!controlled, FinalCheckError::ReservedHeader)
}

/// The slot is written once and holds the rendered slot value, which appears nowhere else in the URL or headers.
///
/// The value is looked for as stored and in its one query encoding, the two forms a construction defect could write.
fn check_slot(url: &Url, headers: &OutgoingHeaders, slot: &Slot, value: &SlotValue) -> Result<(), FinalCheckError> {
    let secret = value.expose_secret();
    let encoded = Zeroizing::new(encode_query_value(secret));
    let forms = [secret.as_bytes(), encoded.as_bytes()];
    match slot {
        Slot::Query(name) => check_query_slot(url, headers, name, &encoded, &forms),
        Slot::Header(header) => check_header_slot(url, headers, header, value, &forms),
        Slot::Basic => check_header_slot(url, headers, &HeaderSlot::basic(), value, &forms),
    }
}

/// Exactly one parameter decodes to the slot's name and its raw value is the encoded slot value; no other parameter,
/// no part of the URL before the query and no header carries the value.
fn check_query_slot(
    url: &Url,
    headers: &OutgoingHeaders,
    name: &QueryParamName,
    encoded: &str,
    forms: &[&[u8]],
) -> Result<(), FinalCheckError> {
    let params = url.query().map(|query| query.split('&')).into_iter().flatten();
    let (slot_params, others): (Vec<&str>, Vec<&str>) =
        params.partition(|param| decode_name(param).is_some_and(|decoded| decoded == name.as_str()));
    let [param] = slot_params.as_slice() else {
        return Err(FinalCheckError::Slot);
    };
    require(
        param.split_once('=').is_some_and(|(_, written)| written == encoded),
        FinalCheckError::SlotValue,
    )?;
    let before_query = [url[..Position::AfterPath].as_bytes()];
    let outside = others
        .iter()
        .map(|param| param.as_bytes())
        .chain(before_query)
        .chain(headers.iter().map(|(_, value)| value.as_bytes()));
    require(!carries_any(outside, forms), FinalCheckError::CredentialOutsideSlot)
}

/// Exactly one header has the slot's name in any case and its bytes are the rendered slot value; no other header and
/// no part of the URL carries the value.
fn check_header_slot(
    url: &Url,
    headers: &OutgoingHeaders,
    slot: &HeaderSlot,
    value: &SlotValue,
    forms: &[&[u8]],
) -> Result<(), FinalCheckError> {
    let written = slot.name().lowercase();
    let (entries, others): (Vec<_>, Vec<_>) = headers.iter().partition(|(name, _)| name.lowercase() == written);
    let [(_, entry)] = entries.as_slice() else {
        return Err(FinalCheckError::Slot);
    };
    let expected = render_header(slot, value).map_err(|_| FinalCheckError::SlotValue)?;
    require(entry.as_bytes() == expected.as_bytes(), FinalCheckError::SlotValue)?;
    let outside = others.iter().map(|(_, value)| value.as_bytes()).chain([url.as_str().as_bytes()]);
    require(!carries_any(outside, forms), FinalCheckError::CredentialOutsideSlot)
}

/// Whether any of `places` contains any of `forms`; compares borrowed bytes, so no copy of the value is made.
fn carries_any<'a>(mut places: impl Iterator<Item = &'a [u8]>, forms: &[&[u8]]) -> bool {
    places.any(|place| {
        forms
            .iter()
            .any(|form| !form.is_empty() && place.windows(form.len()).any(|window| window == *form))
    })
}

#[cfg(test)]
mod tests;
