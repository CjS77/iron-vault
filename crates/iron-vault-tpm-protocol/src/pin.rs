//! The TPM approval PIN and the authorization value the service derives from it (`design/tpm-approval-signer.md`
//! "The approval PIN").

use std::fmt;

use blake2::Blake2b256;
use blake2::digest::{CustomizedInit, Digest};
use zeroize::Zeroizing;

use crate::APPROVER_ID_LEN;

/// The BLAKE2b personalization of the authorization value, which separates it from every other BLAKE2b use. BLAKE2b
/// takes at most 16 bytes of personalization; `v1` versions the derivation, so a change takes a new persona.
const AUTH_VALUE_PERSONA: &[u8] = b"iv-tpm-auth-v1";

/// The length of an authorization value: the SHA-256 `nameAlg` digest length, the most a TPM accepts for the key.
pub const AUTH_VALUE_LEN: usize = 32;

/// The secret that authorizes a TPM approval key, as the owner typed it: never trimmed or normalized.
///
/// Its text is cleared on drop and never shown by `Debug`. The service turns it into a [`TpmAuthValue`] at once and
/// drops it.
pub struct TpmApprovalPin(Zeroizing<String>);

impl TpmApprovalPin {
    /// The PIN the owner typed. The PIN rules are checked at enrollment, not here: at a prompt, a PIN that breaks them
    /// is simply wrong.
    pub fn new(text: String) -> Self {
        Self(Zeroizing::new(text))
    }
}

impl fmt::Debug for TpmApprovalPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TpmApprovalPin([hidden])")
    }
}

/// The 32-byte authorization value of a TPM approval key: BLAKE2b-256, personalized, of the approver ID's 16 bytes
/// followed by the PIN's UTF-8 bytes.
///
/// Binding the approver ID gives two keys with one PIN different values. A fast hash is enough: nothing derived from
/// the PIN is written anywhere, a salted session keeps it off the TPM bus, and the TPM's lockout limits guessing.
/// Cleared on drop and never shown by `Debug`.
#[derive(Clone)]
pub struct TpmAuthValue(Zeroizing<[u8; AUTH_VALUE_LEN]>);

impl TpmAuthValue {
    /// The authorization value for approver `approver_id` under `pin`.
    pub fn derive(approver_id: &[u8; APPROVER_ID_LEN], pin: &TpmApprovalPin) -> Self {
        let mut value = Zeroizing::new([0; AUTH_VALUE_LEN]);
        let mut hasher = Blake2b256::new_customized(AUTH_VALUE_PERSONA);
        hasher.update(approver_id);
        hasher.update(pin.0.as_bytes());
        hasher.finalize_into((&mut *value).into());
        Self(value)
    }

    /// The value as it crossed the helper socket.
    pub fn from_bytes(bytes: [u8; AUTH_VALUE_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// The value's bytes, for the TPM.
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
    // `hashlib.blake2b(b"0123456789abcdef" + "123456".encode(), digest_size=32, person=b"iv-tpm-auth-v1")`.
    #[test]
    fn the_auth_value_matches_its_known_answer() {
        let value = TpmAuthValue::derive(&APPROVER, &TpmApprovalPin::new("123456".to_owned()));
        assert_eq!(
            hex(value.as_bytes()),
            "7dd28a5d69a46a94893988917bc59d669a827c2d3e971b4934aa1750c847cec0"
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
    fn debug_hides_the_pin_and_the_value() {
        let pin = TpmApprovalPin::new("secret-pin".to_owned());
        let value = TpmAuthValue::derive(&APPROVER, &pin);
        assert!(!format!("{pin:?}").contains("secret-pin"));
        assert!(!format!("{value:?}").contains(&hex(&value.as_bytes()[..2])));
    }

    static_assertions::assert_not_impl_any!(TpmApprovalPin: Clone, fmt::Display);
    static_assertions::assert_not_impl_any!(TpmAuthValue: fmt::Display, PartialEq);
}
