// SPDX-License-Identifier: MPL-2.0
//! Converts the TPM's ECC values into the fixed-length forms the helper sends: a 65-byte public point and a 64-byte
//! signature ([TPM approval signer: the signing key](../../../design/tpm-approval-signer.md#the-signing-key)).

use iron_vault_tpm_protocol::{PUBLIC_KEY_LEN, SIGNATURE_LEN};
use p256::ecdsa::Signature;

/// Left-pads a TPM ECC parameter to 32 big-endian bytes, since the TPM may drop leading zeros. Returns `None` when the
/// value is longer than a P-256 coordinate.
fn left_padded(value: &[u8]) -> Option<[u8; 32]> {
    let mut out = [0; 32];
    let start = 32usize.checked_sub(value.len())?;
    out[start..].copy_from_slice(value);
    Some(out)
}

/// Builds the uncompressed SEC1 point `04 ‖ x ‖ y` from the two coordinates the TPM reports. Returns `None` when
/// either is longer than 32 bytes.
pub fn sec1_point(x: &[u8], y: &[u8]) -> Option<[u8; PUBLIC_KEY_LEN]> {
    let (x, y) = (left_padded(x)?, left_padded(y)?);
    let mut out = [0x04; PUBLIC_KEY_LEN];
    out[1..33].copy_from_slice(&x);
    out[33..].copy_from_slice(&y);
    Some(out)
}

/// Encodes a TPM ECDSA signature as the 64-byte `r ‖ s`, with `s` rewritten into the low half of the curve order.
///
/// ECDSA accepts both `s` and `n − s`. Iron Vault's verifiers refuse the high one, so each signature has exactly one
/// encoding. Returns `None` when `r` or `s` is not in `1..n`.
pub fn low_s_signature(r: &[u8], s: &[u8]) -> Option<[u8; SIGNATURE_LEN]> {
    let signature = Signature::from_scalars(left_padded(r)?, left_padded(s)?).ok()?;
    let signature = signature.normalize_s().unwrap_or(signature);
    Some(signature.to_bytes().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The P-256 group order `n`.
    const ORDER: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17,
        0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
    ];

    #[test]
    fn short_coordinates_are_left_padded() {
        let point = sec1_point(&[1], &[2; 32]).unwrap();
        assert_eq!((point[0], point[32], point[1..32].iter().all(|byte| *byte == 0)), (0x04, 1, true));
        assert_eq!(sec1_point(&[1; 33], &[2; 32]), None);
    }

    #[test]
    fn a_high_s_is_rewritten_to_the_low_one() {
        let mut high_s = ORDER;
        high_s[31] -= 1;
        let signature = low_s_signature(&[7], &high_s).unwrap();
        let mut one = [0; 32];
        one[31] = 1;
        assert_eq!(&signature[32..], &one);
        assert_eq!(&signature[..32], &left_padded(&[7]).unwrap());
    }

    #[test]
    fn a_low_s_is_kept_and_a_zero_is_refused() {
        let signature = low_s_signature(&[7], &[9]).unwrap();
        assert_eq!(&signature[32..], &left_padded(&[9]).unwrap());
        assert_eq!(low_s_signature(&[0], &[9]), None);
    }
}
