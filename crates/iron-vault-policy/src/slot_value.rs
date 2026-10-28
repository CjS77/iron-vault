//! The secret a kind hands to slot filling (spec §3.6, §3.11, §5.2).
//!
//! A slot value is written into a header or query parameter, so it must never carry a control character: a stored key
//! holding CR or LF would otherwise split the outgoing header and let its owner inject arbitrary headers.

use std::fmt;

use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;

/// Credential text a kind produced for a route's slot, before the slot's format or encoding is applied.
///
/// It wraps [`SecretString`] so the buffer is zeroized on drop, `Debug` is redacted, and every read goes through
/// [`ExposeSecret`], which keeps read sites greppable. There is deliberately no `Display` or `Serialize`.
pub struct SlotValue(SecretString);

/// A slot value that cannot be accepted. Its text names the rule broken, never the value or a position within it.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SlotValueError {
    /// The value is empty.
    #[error("slot value is empty")]
    Empty,
    /// The value contains CR, LF, NUL or another Unicode control character.
    #[error("slot value contains a control character")]
    ControlChar,
}

impl SlotValue {
    /// Accepts `secret` if it is non-empty and free of control characters, so it is safe to place in a header.
    pub fn new(secret: SecretString) -> Result<Self, SlotValueError> {
        Self::validate(secret.expose_secret()).map(|()| Self(secret))
    }

    /// Checks `text` against the slot-value rules without taking ownership, so a stored secret can be validated where
    /// it lies instead of being copied into a new [`SecretString`] first.
    pub fn validate(text: &str) -> Result<(), SlotValueError> {
        if text.is_empty() {
            Err(SlotValueError::Empty)
        } else if text.chars().any(char::is_control) {
            Err(SlotValueError::ControlChar)
        } else {
            Ok(())
        }
    }
}

impl ExposeSecret<str> for SlotValue {
    fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl fmt::Debug for SlotValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SlotValue(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make(s: &str) -> Result<SlotValue, SlotValueError> {
        SlotValue::new(SecretString::from(s))
    }

    #[test]
    fn accepts_plain_key_and_exposes_it() {
        let value = make("sk-live_abc123 xyz").unwrap();
        assert_eq!(value.expose_secret(), "sk-live_abc123 xyz");
    }

    #[test]
    fn rejects_empty() {
        assert_eq!(make("").unwrap_err(), SlotValueError::Empty);
    }

    #[test]
    fn rejects_control_characters_without_echoing_input() {
        ["a\r\nX-Evil: 1", "a\nb", "a\rb", "a\0b", "a\u{85}b", "a\tb", "a\u{7f}b"].iter().for_each(|input| {
            let err = make(input).unwrap_err();
            assert_eq!(err, SlotValueError::ControlChar, "{input:?}");
            let text = format!("{err} {err:?}");
            assert!(!text.contains("Evil") && !text.contains(" 1") && !text.contains("a\n"), "{text}");
        });
    }

    #[test]
    fn error_text_contains_no_input_byte() {
        let err = make("QZJW\nKV").unwrap_err();
        let text = format!("{err} {err:?}");
        assert!(!text.chars().any(|c| "QZJWKV\n".contains(c)), "{text}");
    }

    #[test]
    fn debug_is_redacted() {
        let debug = format!("{:?}", make("QQQQ").unwrap());
        assert_eq!(debug, "SlotValue(<redacted>)");
        assert!(!debug.contains('Q'));
    }
}
