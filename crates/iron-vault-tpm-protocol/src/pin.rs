//! Checks the TPM approval PIN and derives the authorization value the TPM approval key is created under
//! (`design/tpm-approval-signer.md` "The approval PIN").
//!
//! The service reads the PIN at a prompt, derives the value at once and drops the PIN; only the value crosses the
//! helper socket:
//!
//! ```text
//! PIN typed by the owner ──▶ TpmApprovalPin ──derive(approver ID)──▶ TpmAuthValue ──helper socket──▶ TPM
//!                             (dropped at once)                       (held for one exchange)
//! ```

use std::fmt;

use blake2::Blake2b256;
use blake2::digest::{CustomizedInit, Digest};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::APPROVER_ID_LEN;

/// The BLAKE2b personalization of the authorization value, which separates it from every other BLAKE2b use. BLAKE2b
/// takes at most 16 bytes of personalization; `v1` versions the derivation, so a change takes a new persona.
const AUTH_VALUE_PERSONA: &[u8] = b"iv-tpm-pin-v1";

/// The length of an authorization value: the SHA-256 `nameAlg` digest length, the most a TPM accepts for the key.
pub const AUTH_VALUE_LEN: usize = 32;

/// The fewest Unicode scalar values a TPM approval PIN has at enrollment.
///
/// The TPM's dictionary-attack lockout, not the PIN's length, limits guessing, so the minimum is short enough to type
/// at every approval.
pub const MIN_PIN_SCALARS: usize = 6;

/// Says why the two entries of a new TPM approval PIN do not make a valid PIN. No variant carries what was typed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PinRuleError {
    /// The entry and its repeat differ.
    #[error("the two entries of the TPM approval PIN differ")]
    Differ,
    /// The entry is not UTF-8.
    #[error("the TPM approval PIN is not valid UTF-8")]
    NotUtf8,
    /// The entry has fewer than [`MIN_PIN_SCALARS`] Unicode scalar values.
    #[error("the TPM approval PIN needs at least {MIN_PIN_SCALARS} Unicode scalar values")]
    TooShort,
}

/// Holds the TPM approval PIN exactly as the owner typed it, never trimmed or normalized.
///
/// The service turns it into a [`TpmAuthValue`] at once and drops it. Its text is cleared on drop and never shown by
/// `Debug`.
pub struct TpmApprovalPin(Zeroizing<String>);

impl TpmApprovalPin {
    /// Wraps text the owner typed, without checking the PIN rules.
    ///
    /// Enrollment checks the rules through [`from_entries`](Self::from_entries), and a prompt answer goes through
    /// [`answered`](Self::answered).
    pub fn new(text: String) -> Self {
        Self(Zeroizing::new(text))
    }

    /// Accepts a PIN typed at a prompt, or returns `None` when it is shorter than [`MIN_PIN_SCALARS`] scalar values,
    /// empty included.
    ///
    /// Enrollment refuses such a PIN, so it can never be right, and asking the TPM would only spend a lockout try.
    pub fn answered(text: &str) -> Option<Self> {
        (text.chars().count() >= MIN_PIN_SCALARS).then(|| Self::new(text.to_owned()))
    }

    /// Builds a new TPM approver's PIN from the owner's two entries.
    ///
    /// The entries must be equal (compared in constant time), UTF-8, and at least [`MIN_PIN_SCALARS`] scalar values.
    /// Nothing is trimmed or normalized, so `" 1234 "` is a valid six-character PIN with two spaces.
    pub fn from_entries(entry: &[u8], repeated: &[u8]) -> Result<Self, PinRuleError> {
        if !bool::from(entry.ct_eq(repeated)) {
            return Err(PinRuleError::Differ);
        }
        let text = std::str::from_utf8(entry).map_err(|_| PinRuleError::NotUtf8)?;
        match text.chars().count() >= MIN_PIN_SCALARS {
            true => Ok(Self::new(text.to_owned())),
            false => Err(PinRuleError::TooShort),
        }
    }
}

impl fmt::Debug for TpmApprovalPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TpmApprovalPin([hidden])")
    }
}

/// Holds the 32-byte authorization value of a TPM approval key: personalized BLAKE2b-256 of the approver ID's 16 bytes
/// followed by the PIN's UTF-8 bytes.
///
/// Hashing in the approver ID gives two keys that share a PIN different values. A fast hash is enough: nothing derived
/// from the PIN is written anywhere, a salted session keeps the value off the TPM bus, and the TPM's lockout limits
/// guessing. The value is cleared on drop and never shown by `Debug`.
#[derive(Clone)]
pub struct TpmAuthValue(Zeroizing<[u8; AUTH_VALUE_LEN]>);

impl TpmAuthValue {
    /// Derives the authorization value for approver `approver_id` under `pin`.
    pub fn derive(approver_id: &[u8; APPROVER_ID_LEN], pin: &TpmApprovalPin) -> Self {
        let mut value = Zeroizing::new([0; AUTH_VALUE_LEN]);
        let mut hasher = Blake2b256::new_customized(AUTH_VALUE_PERSONA);
        hasher.update(approver_id);
        hasher.update(pin.0.as_bytes());
        hasher.finalize_into((&mut *value).into());
        Self(value)
    }

    /// Wraps a value the helper read from the socket.
    pub fn from_bytes(bytes: [u8; AUTH_VALUE_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Returns the value's bytes, to send to the helper or hand to the TPM.
    pub fn as_bytes(&self) -> &[u8; AUTH_VALUE_LEN] {
        &self.0
    }
}

impl fmt::Debug for TpmAuthValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TpmAuthValue([hidden])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const APPROVER: [u8; 16] = *b"0123456789abcdef";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    // Known answer computed independently with Python's
    // `hashlib.blake2b(b"0123456789abcdef" + "123456".encode(), digest_size=32, person=b"iv-tpm-pin-v1")`.
    #[test]
    fn the_auth_value_matches_its_known_answer() {
        let value = TpmAuthValue::derive(&APPROVER, &TpmApprovalPin::new("123456".to_owned()));
        assert_eq!(
            hex(value.as_bytes()),
            "925371743c0410baef78d4755c5593145eea8c278fdc134347eca1d10e9d355f"
        );
    }

    #[test]
    fn two_approvers_with_one_pin_get_different_values() {
        let pin = TpmApprovalPin::new("123456".to_owned());
        let other = *b"fedcba9876543210";
        assert_ne!(
            TpmAuthValue::derive(&APPROVER, &pin).as_bytes(),
            TpmAuthValue::derive(&other, &pin).as_bytes()
        );
    }

    #[test]
    fn a_new_pin_needs_two_equal_entries_of_six_scalar_values() {
        let entries = |a: &[u8], b: &[u8]| TpmApprovalPin::from_entries(a, b).map(drop);
        assert_eq!(entries(b"123456", b"123456"), Ok(()));
        assert_eq!(entries("p\u{e9}pe\u{301}!".as_bytes(), "p\u{e9}pe\u{301}!".as_bytes()), Ok(()));
        assert_eq!(entries(b"12345", b"12345"), Err(PinRuleError::TooShort));
        assert_eq!(entries(b"123456", b"123457"), Err(PinRuleError::Differ));
        assert_eq!(entries(&[0xff; 6], &[0xff; 6]), Err(PinRuleError::NotUtf8));
        // Six scalar values, not six bytes: nothing is trimmed, and a space counts.
        assert_eq!(entries(b" 1234 ", b" 1234 "), Ok(()));
        assert_eq!(
            entries(
                "\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}".as_bytes(),
                "\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}".as_bytes()
            ),
            Err(PinRuleError::TooShort)
        );
    }

    #[test]
    fn an_answer_under_six_scalar_values_is_no_pin() {
        assert!(TpmApprovalPin::answered("").is_none());
        assert!(TpmApprovalPin::answered("12345").is_none());
        assert!(TpmApprovalPin::answered("ééééé").is_none());
        assert!(TpmApprovalPin::answered("123456").is_some());
    }

    #[test]
    fn debug_hides_the_pin_and_the_value() {
        let pin = TpmApprovalPin::new("secret-pin".to_owned());
        let value = TpmAuthValue::derive(&APPROVER, &pin);
        assert!(!format!("{pin:?}").contains("secret-pin"));
        assert!(!format!("{value:?}").contains(&hex(&value.as_bytes()[..2])));
    }

    static_assertions::assert_not_impl_any!(TpmApprovalPin: Clone, fmt::Display);
    static_assertions::assert_not_impl_any!(TpmAuthValue: fmt::Display, PartialEq);
}
