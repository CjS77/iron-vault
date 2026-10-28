//! HTTP header field values as received from callers or written for upstreams (specification §3.6).

use std::fmt;

use secrecy::zeroize::Zeroize;
use thiserror::Error;

/// The bytes of one HTTP field value.
///
/// CR, LF and NUL are rejected (RFC 9110 §5.5) because they split or truncate a header when the request is written.
/// Every other C0 control except HTAB, and DEL, is rejected too: RFC 9110 §5.5 forbids them, a lenient upstream may
/// parse them differently from Iron Vault (room for request smuggling), and refusing them here gives the caller a
/// clean `400` instead of a transport error when the request is sent. Bytes from 0x80 upwards (`obs-text`) are kept:
/// callers may legitimately send them, and the value is forwarded as bytes, never decoded as text.
///
/// Values can carry caller tokens or credentials, so `Debug` shows only the length, there is no `Display`, and the
/// bytes are wiped when the value is dropped (spec §3.11). A clone is a second copy that is wiped on its own drop.
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
    /// The value contains a control character other than HTAB, CR, LF or NUL, or DEL.
    #[error("header value contains a control character")]
    Control,
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
        b'\t' => None,
        0x01..=0x1f | 0x7f => Some(HeaderValueError::Control),
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

impl Drop for HeaderValue {
    fn drop(&mut self) {
        self.0.zeroize();
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
        assert_eq!(
            HeaderValue::try_from("x\r\nHost: evil.example"),
            Err(HeaderValueError::CarriageReturn)
        );
    }

    #[test]
    fn rejects_other_controls_and_del() {
        ["a\x01b", "a\x0bb", "a\x0cb", "a\x1fb", "a\x7fb"]
            .iter()
            .for_each(|v| assert_eq!(HeaderValue::try_from(*v), Err(HeaderValueError::Control), "{v:?}"));
    }

    #[test]
    fn every_c0_control_but_htab_is_rejected() {
        (0x00u8..=0x1f)
            .chain([0x7f])
            .filter(|b| *b != b'\t')
            .for_each(|b| assert!(HeaderValue::try_from([b].as_slice()).is_err(), "{b:#x}"));
        assert!(HeaderValue::try_from("a\tb").is_ok());
        assert!(HeaderValue::try_from(b"\x80\xff".as_slice()).is_ok());
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
