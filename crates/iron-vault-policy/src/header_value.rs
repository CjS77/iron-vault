//! HTTP header field values as received from callers or written for upstreams (specification §3.6).

use std::fmt;

use thiserror::Error;

/// The bytes of one HTTP field value.
///
/// CR, LF and NUL are rejected (RFC 9110 §5.5) because they split or truncate a header when the request is written.
/// Bytes from 0x80 upwards (`obs-text`) are kept: callers may legitimately send them, and the value is forwarded as
/// bytes, never decoded as text.
///
/// Values can carry caller tokens or credentials, so `Debug` shows only the length and there is no `Display`.
#[derive(Clone, PartialEq, Eq)]
pub struct HeaderValue(Vec<u8>);

/// Bytes that are not a valid HTTP field value. The text names the offending byte, never the value.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HeaderValueError {
    /// The value contains a carriage return.
    #[error("header value contains a carriage return")]
    CarriageReturn,
    /// The value contains a line feed.
    #[error("header value contains a line feed")]
    LineFeed,
    /// The value contains a NUL byte.
    #[error("header value contains a NUL byte")]
    Nul,
}

impl HeaderValue {
    /// The value's bytes, exactly as received.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The number of bytes in the value.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the value is empty, which HTTP allows.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// The error for the first byte that may not appear in a field value.
fn forbidden_byte(bytes: &[u8]) -> Option<HeaderValueError> {
    bytes.iter().find_map(|b| match b {
        b'\r' => Some(HeaderValueError::CarriageReturn),
        b'\n' => Some(HeaderValueError::LineFeed),
        b'\0' => Some(HeaderValueError::Nul),
        _ => None,
    })
}

impl TryFrom<Vec<u8>> for HeaderValue {
    type Error = HeaderValueError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        forbidden_byte(&bytes).map_or(Ok(Self(bytes)), Err)
    }
}

impl TryFrom<&[u8]> for HeaderValue {
    type Error = HeaderValueError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from(bytes.to_vec())
    }
}

impl TryFrom<&str> for HeaderValue {
    type Error = HeaderValueError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::try_from(s.as_bytes())
    }
}

impl fmt::Debug for HeaderValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HeaderValue").field("len", &self.0.len()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_bytes_including_obs_text() {
        let bytes = b"Bearer \x80\xff tab\there".as_slice();
        let value = HeaderValue::try_from(bytes).unwrap();
        assert_eq!(value.as_bytes(), bytes);
        assert_eq!(value.len(), bytes.len());
        assert!(HeaderValue::try_from("").unwrap().is_empty());
    }

    #[test]
    fn rejects_cr_lf_and_nul() {
        assert_eq!(HeaderValue::try_from("a\rb"), Err(HeaderValueError::CarriageReturn));
        assert_eq!(HeaderValue::try_from("a\nb"), Err(HeaderValueError::LineFeed));
        assert_eq!(HeaderValue::try_from("a\0b"), Err(HeaderValueError::Nul));
        assert_eq!(HeaderValue::try_from("x\r\nHost: evil.example"), Err(HeaderValueError::CarriageReturn));
    }

    #[test]
    fn debug_shows_length_only() {
        let rendered = format!("{:?}", HeaderValue::try_from("secret-token").unwrap());
        assert_eq!(rendered, "HeaderValue { len: 12 }");
    }

    #[test]
    fn error_text_omits_the_value() {
        let message = HeaderValue::try_from("secret\n").unwrap_err().to_string();
        assert!(!message.contains("secret"), "{message}");
    }
}
