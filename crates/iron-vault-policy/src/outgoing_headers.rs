//! The header list an upstream request carries (specification §3.6).
//!
//! [`OutgoingHeaders`] can never hold a reserved header, so `Host`, framing, forwarding, override and caller
//! authentication headers cannot reach an upstream through it: the transport sets authority and framing itself.

mod sanitize;

use thiserror::Error;

use crate::header_name::HeaderName;
use crate::header_value::HeaderValue;
use crate::reserved_headers::is_reserved;

pub use sanitize::{SanitizeError, sanitize};

/// An ordered list of header fields for an upstream request.
///
/// Order and duplicates are kept as given, because some upstreams read repeated fields in order. Every name lookup is
/// case-insensitive through [`HeaderName`]'s equality.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OutgoingHeaders {
    entries: Vec<(HeaderName, HeaderValue)>,
}

/// A header that may not be added to an outgoing request.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OutgoingHeadersError {
    /// The header is reserved for the service's own transport and routing control.
    #[error("{name} is a reserved header and cannot be added to an outgoing request")]
    Reserved {
        /// The rejected header name.
        name: HeaderName,
    },
}

impl OutgoingHeaders {
    /// An empty list.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a field after every existing one, unless its name is reserved.
    pub fn insert(&mut self, name: HeaderName, value: HeaderValue) -> Result<(), OutgoingHeadersError> {
        if is_reserved(&name) {
            return Err(OutgoingHeadersError::Reserved { name });
        }
        self.entries.push((name, value));
        Ok(())
    }

    /// Every value of the fields called `name`, in order.
    pub fn get_all<'a>(&'a self, name: &'a HeaderName) -> impl Iterator<Item = &'a HeaderValue> + 'a {
        self.entries.iter().filter(move |(n, _)| n == name).map(|(_, v)| v)
    }

    /// Removes every field called `name`, whatever its case.
    pub fn remove_all(&mut self, name: &HeaderName) {
        self.entries.retain(|(n, _)| n != name);
    }

    /// Every field, in order.
    pub fn iter(&self) -> impl Iterator<Item = (&HeaderName, &HeaderValue)> {
        self.entries.iter().map(|(n, v)| (n, v))
    }

    /// Appends a field even if it is reserved, so final-check tests can build headers `insert` would refuse.
    #[cfg(test)]
    pub(crate) fn push_unchecked(&mut self, name: HeaderName, value: HeaderValue) {
        self.entries.push((name, value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(s: &str) -> HeaderName {
        s.parse().unwrap()
    }

    fn value(s: &str) -> HeaderValue {
        HeaderValue::try_from(s).unwrap()
    }

    #[test]
    fn insert_rejects_reserved_headers() {
        let mut headers = OutgoingHeaders::new();
        ["Host", "X-Forwarded-For", "content-length", "Transfer-Encoding", "Proxy-Authorization"].iter().for_each(|h| {
            assert_eq!(headers.insert(name(h), value("x")), Err(OutgoingHeadersError::Reserved { name: name(h) }), "{h}");
        });
        assert_eq!(headers, OutgoingHeaders::new());
    }

    #[test]
    fn get_all_and_remove_all_ignore_case() {
        let mut headers = OutgoingHeaders::new();
        headers.insert(name("Accept"), value("a")).unwrap();
        headers.insert(name("X-Api-Key"), value("1")).unwrap();
        headers.insert(name("x-api-key"), value("2")).unwrap();
        let key = name("X-API-KEY");
        let found: Vec<_> = headers.get_all(&key).map(HeaderValue::as_bytes).collect();
        assert_eq!(found, [b"1".as_slice(), b"2"]);
        headers.remove_all(&key);
        let left: Vec<_> = headers.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(left, ["Accept"]);
    }

    #[test]
    fn error_names_the_header() {
        let error = OutgoingHeaders::new().insert(name("Host"), value("evil.example")).unwrap_err();
        assert_eq!(error.to_string(), "Host is a reserved header and cannot be added to an outgoing request");
    }
}
