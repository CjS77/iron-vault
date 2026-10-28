//! The outgoing request: the authorized method, the upstream target and the outgoing headers with the route's slot
//! filled exactly once (spec §3.5 step 7, §3.6).
//!
//! The slot is the only place a credential is written. Only the text the slot is about to replace is scanned for
//! markers; the body, the path, other headers and other query parameters are never read, so a marker there stays
//! inert (R-10). The credential always comes from the route, never from a marker (§3.5 step 6, §8.2 Q-1).

use secrecy::ExposeSecret;
use secrecy::zeroize::Zeroizing;
use thiserror::Error;
use url::Url;

use crate::authorization::AuthorizedRequest;
use crate::header_value::{HeaderValue, HeaderValueError};
use crate::marker::{MarkerError, markers};
use crate::method::Method;
use crate::name::CredentialName;
use crate::outgoing_headers::{OutgoingHeaders, OutgoingHeadersError};
use crate::query_value::{decode_param, encode_query_value};
use crate::slot::{HeaderSlot, QueryParamName, Slot};
use crate::slot_value::SlotValue;
use crate::upstream_target::{UpstreamTarget, UpstreamTargetError};

/// The request about to leave the service, holding the route's credential in its slot; the final outgoing-request
/// check inspects this.
///
/// Only [`OutgoingRequest::assemble`] builds one, and it fills the slot once. There is no `Clone`, so the credential
/// is not copied further. `Debug` is safe to log: [`UpstreamTarget`] omits the query and [`HeaderValue`] shows only a
/// length, so neither the filled query nor the filled header is printed.
///
/// The filled header's bytes are wiped when the request is dropped. The URL's copy of a filled query is not, because
/// `url::Url` owns its buffer. TODO(transport epic): wipe or avoid the URL's copy when the request is sent.
#[derive(Debug)]
pub struct OutgoingRequest {
    method: Method,
    target: UpstreamTarget,
    headers: OutgoingHeaders,
}

/// Why the outgoing request could not be assembled.
///
/// The text never contains a header value, query text or the slot value: each may hold a secret.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AssembleError {
    /// A marker in the slot names a credential other than the route's: `400` (§3.12), with no upstream request.
    #[error("a marker in the slot names a different credential")]
    ForeignMarker,
    /// A `{iv:` in the slot has an invalid name or no closing `}`: `400` (§3.12), with no upstream request.
    #[error("the slot holds a malformed {{iv:…}} marker")]
    MalformedMarker,
    /// The slot value for a header or Basic slot is not ASCII. A header value is sent as bytes that upstreams read as
    /// ASCII or Latin-1, so non-ASCII text would reach the upstream as a different credential: a construction error.
    #[error("the slot value is not ASCII and cannot be written to a header")]
    NonAsciiSlotValue,
    /// The rendered header value was refused: a construction error.
    #[error("the slot header value was refused: {0}")]
    HeaderValue(#[from] HeaderValueError),
    /// The slot header could not be added: a construction error.
    #[error(transparent)]
    Header(#[from] OutgoingHeadersError),
    /// The rebuilt query did not read back exactly: a construction error.
    #[error(transparent)]
    Target(#[from] UpstreamTargetError),
}

impl From<MarkerError> for AssembleError {
    fn from(error: MarkerError) -> Self {
        match error {
            MarkerError::Malformed => Self::MalformedMarker,
        }
    }
}

impl OutgoingRequest {
    /// Fills `slot` with `value` and combines the result with `request`'s method, `target` and the sanitized `headers`.
    ///
    /// `target` must be built from `request`, and `slot` and `credential` must be `request`'s route's. Every caller copy
    /// of the slot is scanned for markers and removed before the one generated value is written:
    ///
    /// - a header slot writes `format.prefix() + value + format.suffix()`;
    /// - a Basic slot writes `Authorization: Basic <value>`, where `value` is the encoded `user:password` its kind made;
    /// - a query slot appends `name=<encoded value>` after every other parameter, kept byte for byte and in order.
    pub fn assemble(
        request: &AuthorizedRequest,
        target: UpstreamTarget,
        mut headers: OutgoingHeaders,
        slot: &Slot,
        credential: &CredentialName,
        value: &SlotValue,
    ) -> Result<Self, AssembleError> {
        let target = match slot {
            Slot::Header(header) => fill_header(&mut headers, header, credential, value).map(|()| target)?,
            Slot::Basic => fill_header(&mut headers, &HeaderSlot::basic(), credential, value).map(|()| target)?,
            Slot::Query(name) => fill_query(target, name, credential, value)?,
        };
        Ok(Self {
            method: request.method(),
            target,
            headers,
        })
    }

    /// The authorized method.
    pub fn method(&self) -> Method {
        self.method
    }

    /// The URL to send to, with a query slot filled.
    pub fn target(&self) -> &UpstreamTarget {
        &self.target
    }

    /// The headers to send, with a header or Basic slot filled.
    pub fn headers(&self) -> &OutgoingHeaders {
        &self.headers
    }

    /// The method, URL and headers, for the final check to inspect and then own.
    pub(crate) fn into_parts(self) -> (Method, Url, OutgoingHeaders) {
        (self.method, self.target.into_url(), self.headers)
    }

    /// Combines parts without assembling them, so final-check tests can build requests `assemble` would refuse.
    #[cfg(test)]
    pub(crate) fn unchecked(method: Method, url: Url, headers: OutgoingHeaders) -> Self {
        Self {
            method,
            target: UpstreamTarget::unchecked(url),
            headers,
        }
    }
}

/// Refuses `text` if it holds a malformed marker or a marker naming any credential but `credential`.
fn check_markers(text: &str, credential: &CredentialName) -> Result<(), AssembleError> {
    markers(text).try_for_each(|marker| match marker? {
        name if name == *credential => Ok(()),
        _ => Err(AssembleError::ForeignMarker),
    })
}

/// Scans every caller copy of the slot header, whatever its case, then replaces them all with one rendered value.
fn fill_header(
    headers: &mut OutgoingHeaders,
    slot: &HeaderSlot,
    credential: &CredentialName,
    value: &SlotValue,
) -> Result<(), AssembleError> {
    headers
        .get_all(slot.name())
        .try_for_each(|caller| check_markers(&String::from_utf8_lossy(caller.as_bytes()), credential))?;
    let rendered = render_header(slot, value)?;
    headers.remove_all(slot.name());
    Ok(headers.insert(slot.name().clone(), rendered)?)
}

/// `prefix + value + suffix`, built in a buffer that is wiped on drop and sized so it never reallocates.
///
/// The final check renders the expected slot value with this same function, so filling and checking cannot disagree.
pub(crate) fn render_header(slot: &HeaderSlot, value: &SlotValue) -> Result<HeaderValue, AssembleError> {
    let secret = value.expose_secret();
    if !secret.is_ascii() {
        return Err(AssembleError::NonAsciiSlotValue);
    }
    let parts = [slot.format().prefix(), secret, slot.format().suffix()];
    let mut bytes = Zeroizing::new(Vec::with_capacity(parts.iter().map(|part| part.len()).sum()));
    parts.iter().for_each(|part| bytes.extend_from_slice(part.as_bytes()));
    Ok(HeaderValue::try_from(bytes.as_slice())?)
}

/// Removes every parameter whose decoded name is the slot's, scans their decoded values, and appends the credential.
fn fill_query(
    target: UpstreamTarget,
    name: &QueryParamName,
    credential: &CredentialName,
    value: &SlotValue,
) -> Result<UpstreamTarget, AssembleError> {
    let params: Vec<&str> = target.query().map_or_else(Vec::new, |query| query.split('&').collect());
    let (slot_params, kept): (Vec<&str>, Vec<&str>) = params.into_iter().partition(|param| is_slot_param(param, name));
    slot_params
        .iter()
        .filter_map(|param| decode_param(param))
        .try_for_each(|(_, caller)| check_markers(&caller, credential))?;
    let query = filled_query(&kept, name, value);
    Ok(target.with_query(&query)?)
}

/// Whether `param`'s name, percent-decoded with `+` read as a space, is exactly the slot's name.
fn is_slot_param(param: &str, name: &QueryParamName) -> bool {
    decode_param(param).is_some_and(|(decoded, _)| decoded == name.as_str())
}

/// The kept parameters joined by `&`, then `name=<encoded value>`, in a buffer that is wiped on drop.
fn filled_query(kept: &[&str], name: &QueryParamName, value: &SlotValue) -> Zeroizing<String> {
    let encoded = Zeroizing::new(encode_query_value(value.expose_secret()));
    let kept_len: usize = kept.iter().map(|param| param.len() + 1).sum();
    let mut query = Zeroizing::new(String::with_capacity(kept_len + name.as_str().len() + 1 + encoded.len()));
    kept.iter().for_each(|param| {
        query.push_str(param);
        query.push('&');
    });
    query.push_str(name.as_str());
    query.push('=');
    query.push_str(&encoded);
    query
}

#[cfg(test)]
mod tests;
