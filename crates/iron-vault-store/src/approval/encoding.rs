//! The approval payload v1 and approval envelope v1 encodings (`design/storage-formats.md`).

use super::{
    APPROVAL_PURPOSE, ApprovalDecodeError, ApprovalEnvelope, ApprovalPayload, ApprovalVersion, ApproverId, ConfigDigest,
    MAX_APPROVAL_ENVELOPE_LEN, SignatureAlgorithm,
};
use crate::vault_id::VaultId;
use crate::wire::{Reader, WireError};

/// The first bytes of every approval payload, distinct from the envelope magic so neither is read as the other.
const PAYLOAD_MAGIC: [u8; 4] = *b"IVAP";
/// The payload format version this code writes and the only one it reads.
const PAYLOAD_VERSION: u8 = 1;
/// The first bytes of every approval envelope.
const ENVELOPE_MAGIC: [u8; 4] = *b"IVAS";
/// The envelope format version this code writes and the only one it reads.
const ENVELOPE_VERSION: u8 = 1;

/// The payload's v1 encoding: magic, version, purpose field, vault ID, approval version, config digest.
pub(super) fn encode_payload(payload: &ApprovalPayload) -> Vec<u8> {
    let mut out = header(PAYLOAD_MAGIC, PAYLOAD_VERSION);
    put_field(&mut out, APPROVAL_PURPOSE.as_bytes());
    out.extend_from_slice(payload.vault_id.as_bytes());
    out.extend_from_slice(&payload.version.get().to_be_bytes());
    out.extend_from_slice(payload.digest.as_bytes());
    out
}

/// The payload a v1 encoding holds, accepted only if it is that payload's one encoding.
pub(super) fn decode_payload(bytes: &[u8]) -> Result<ApprovalPayload, ApprovalDecodeError> {
    let mut reader = Reader::new(bytes);
    read_header(&mut reader, PAYLOAD_MAGIC, PAYLOAD_VERSION)?;
    if reader.field()? != APPROVAL_PURPOSE.as_bytes() {
        return Err(ApprovalDecodeError::WrongPurpose);
    }
    let vault_id = VaultId::from_bytes(reader.array()?)?;
    let version = ApprovalVersion::new(reader.u64()?).ok_or(ApprovalDecodeError::ZeroVersion)?;
    let digest = ConfigDigest::from_bytes(reader.array()?);
    reader.finish()?;
    Ok(ApprovalPayload::new(vault_id, version, digest))
}

/// The envelope's v1 encoding: magic, version, algorithm ID, approver ID, payload field, signature field.
pub(super) fn encode_envelope(envelope: &ApprovalEnvelope) -> Vec<u8> {
    let mut out = header(ENVELOPE_MAGIC, ENVELOPE_VERSION);
    out.push(envelope.algorithm.id());
    out.extend_from_slice(envelope.approver_id.as_bytes());
    put_field(&mut out, &encode_payload(&envelope.payload));
    put_field(&mut out, &envelope.signature);
    out
}

/// The envelope a v1 encoding holds, after the size limit, accepted only if it is that envelope's one encoding.
///
/// Whether the approver ID is pinned is the verifier's check: decoding refuses only an ID that is no approver's ID.
pub(super) fn decode_envelope(bytes: &[u8]) -> Result<ApprovalEnvelope, ApprovalDecodeError> {
    if bytes.len() > MAX_APPROVAL_ENVELOPE_LEN {
        return Err(ApprovalDecodeError::TooLarge {
            limit: MAX_APPROVAL_ENVELOPE_LEN,
        });
    }
    let mut reader = Reader::new(bytes);
    read_header(&mut reader, ENVELOPE_MAGIC, ENVELOPE_VERSION)?;
    let algorithm = SignatureAlgorithm::from_id(reader.u8()?)?;
    let approver_id = ApproverId::from_bytes(reader.array()?).map_err(|_| ApprovalDecodeError::InvalidApproverId)?;
    let payload = decode_payload(reader.field()?)?;
    let signature = reader.field()?.to_vec();
    reader.finish()?;
    ApprovalEnvelope::new(algorithm, approver_id, payload, signature)
}

/// The magic, then the format version: the start of every approval encoding.
pub(super) fn header(magic: [u8; 4], version: u8) -> Vec<u8> {
    let mut out = magic.to_vec();
    out.push(version);
    out
}

/// Writes a `u64` length, then the bytes. `usize` is at most 64 bits on every Rust target, so the cast is lossless.
pub(super) fn put_field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// The magic, then the format version, which must be the one this code reads: the start of every approval encoding.
pub(super) fn read_header(reader: &mut Reader<'_>, magic: [u8; 4], version: u8) -> Result<(), ApprovalDecodeError> {
    if reader.array()? != magic {
        return Err(ApprovalDecodeError::BadMagic);
    }
    match reader.u8()? {
        found if found == version => Ok(()),
        found => Err(ApprovalDecodeError::UnknownFormatVersion(found)),
    }
}

impl From<WireError> for ApprovalDecodeError {
    fn from(error: WireError) -> Self {
        match error {
            WireError::Truncated => ApprovalDecodeError::Truncated,
            WireError::LengthPastEnd => ApprovalDecodeError::LengthPastEnd,
            WireError::TrailingBytes => ApprovalDecodeError::TrailingBytes,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use proptest::prelude::*;

    use super::*;

    const VAULT: &str = "3f2b8c1e5d4a4e6f9a7b1c2d3e4f5a6b";

    /// The documented envelope example's approver ID, 8d1c6f0e-2b7a-4c59-9e3d-5a4b3c2d1e0f.
    const APPROVER: &str = "8d1c6f0e2b7a4c599e3d5a4b3c2d1e0f";

    /// The documented payload example: vault 3f2b8c1e-…, version 1, the digest of an empty config.
    const PAYLOAD_HEX: &str = "49564150 01 0000000000000014 69726f6e2d7661756c742d636f6e6669672d7631 \
                               3f2b8c1e5d4a4e6f9a7b1c2d3e4f5a6b 0000000000000001 \
                               0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8";

    /// The documented TPM approver's ID, 5b0e9a1c-7d2f-4e83-b6a4-0c1d2e3f4a5b.
    const TPM_APPROVER: &str = "5b0e9a1c7d2f4e83b6a40c1d2e3f4a5b";

    /// The documented P-256 signature over the payload example: RFC 6979 deterministic, by the RFC 6979 A.2.5 key, low S.
    pub(crate) const P256_SIGNATURE_HEX: &str = "f362509db1d282d1d4bc973055ac5b6b2285126a0ea8bbcf7b531e613fd9a38a \
                                                 531bfbd0db1e248f7ffc34a45b2435b2cc42533bc5d887ef2f8d15b0c7519b85";

    /// The RFC 6979 A.2.5 P-256 public key, uncompressed: `04 ‖ x ‖ y`. The documented TPM approver's pinned key.
    pub(crate) const P256_KEY_HEX: &str = "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6\
                                           7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";

    /// The `n`th `text` block of the storage formats' section `heading`, as hex: comments start past column 48.
    pub(crate) fn documented_block(heading: &str, n: usize) -> String {
        let doc = include_str!("../../../../design/storage-formats.md");
        let section = doc.split(heading).nth(1).unwrap();
        let block = section.split("```text\n").nth(n).unwrap().split("```").next().unwrap();
        block
            .lines()
            .flat_map(|line| line.chars().take(48))
            .filter(|c| !c.is_whitespace())
            .collect()
    }

    /// The bytes of the `n`th `text` block of the storage formats' "Approval envelope v1" section, with the payload
    /// example in place of its `…` line: comments start past column 48.
    pub(crate) fn documented_envelope(n: usize) -> Vec<u8> {
        let doc = include_str!("../../../../design/storage-formats.md");
        let section = doc.split("## Approval envelope v1").nth(1).unwrap();
        let block = section.split("```text\n").nth(n).unwrap().split("```").next().unwrap();
        let hex: String = block
            .lines()
            .flat_map(|line| {
                if line.starts_with('…') {
                    PAYLOAD_HEX.to_owned()
                } else {
                    line.chars().take(48).collect()
                }
                .chars()
                .collect::<Vec<_>>()
            })
            .filter(|c| !c.is_whitespace())
            .collect();
        unhex(&hex)
    }

    pub(crate) fn unhex(hex: &str) -> Vec<u8> {
        hex.split_whitespace()
            .flat_map(|group| {
                (0..group.len())
                    .step_by(2)
                    .map(move |i| u8::from_str_radix(&group[i..i + 2], 16).unwrap())
            })
            .collect()
    }

    pub(crate) fn payload() -> ApprovalPayload {
        let vault_id = VaultId::from_bytes(unhex(VAULT).try_into().unwrap()).unwrap();
        ApprovalPayload::new(vault_id, ApprovalVersion::FIRST, ConfigDigest::of(b""))
    }

    fn approver() -> ApproverId {
        ApproverId::from_bytes(unhex(APPROVER).try_into().unwrap()).unwrap()
    }

    /// The documented envelope example: the payload above with a stand-in signature of 64 bytes of `5a`.
    fn envelope() -> ApprovalEnvelope {
        ApprovalEnvelope::new(SignatureAlgorithm::Ed25519, approver(), payload(), vec![0x5a; 64]).unwrap()
    }

    fn envelope_bytes(algorithm: u8, payload: &[u8], signature: &[u8]) -> Vec<u8> {
        let mut out = b"IVAS\x01".to_vec();
        out.push(algorithm);
        out.extend_from_slice(&unhex(APPROVER));
        put_field(&mut out, payload);
        put_field(&mut out, signature);
        out
    }

    /// The payload bytes with `range` replaced by `with`, so each rejection test breaks exactly one field.
    fn payload_with(range: std::ops::Range<usize>, with: &[u8]) -> Vec<u8> {
        let mut bytes = unhex(PAYLOAD_HEX);
        bytes.splice(range, with.iter().copied());
        bytes
    }

    #[test]
    fn documented_payload_example_matches() {
        assert_eq!(payload().encode(), unhex(PAYLOAD_HEX));
        assert_eq!(ApprovalPayload::decode(&unhex(PAYLOAD_HEX)), Ok(payload()));
    }

    #[test]
    fn documented_envelope_example_matches() {
        let hex = format!(
            "49564153 01 01 {APPROVER} 0000000000000059 {PAYLOAD_HEX} 0000000000000040 {}",
            "5a".repeat(64)
        );
        let bytes = unhex(&hex);
        assert_eq!(bytes.len(), 191);
        assert_eq!(documented_envelope(1), bytes);
        assert_eq!(envelope().encode(), bytes);
        assert_eq!(ApprovalEnvelope::decode(&bytes), Ok(envelope()));
    }

    #[test]
    fn documented_p256_envelope_example_matches() {
        let hex = format!("49564153 01 02 {TPM_APPROVER} 0000000000000059 {PAYLOAD_HEX} 0000000000000040 {P256_SIGNATURE_HEX}");
        let bytes = unhex(&hex);
        assert_eq!(bytes.len(), 191);
        assert_eq!(documented_envelope(2), bytes);
        let approver = ApproverId::from_bytes(unhex(TPM_APPROVER).try_into().unwrap()).unwrap();
        let p256 = ApprovalEnvelope::new(SignatureAlgorithm::EcdsaP256, approver, payload(), unhex(P256_SIGNATURE_HEX)).unwrap();
        assert_eq!(p256.encode(), bytes);
        assert_eq!(ApprovalEnvelope::decode(&bytes), Ok(p256));
    }

    #[test]
    fn encoding_is_deterministic() {
        assert_eq!(payload().encode(), payload().encode());
        assert_eq!(envelope().encode(), envelope().encode());
    }

    #[test]
    fn wrong_purpose_is_rejected() {
        let other = payload_with(5..33, &[&20u64.to_be_bytes()[..], b"iron-vault-config-v2"].concat());
        assert_eq!(ApprovalPayload::decode(&other), Err(ApprovalDecodeError::WrongPurpose));
        let shorter = payload_with(5..33, &[&19u64.to_be_bytes()[..], b"iron-vault-config-v"].concat());
        assert_eq!(ApprovalPayload::decode(&shorter), Err(ApprovalDecodeError::WrongPurpose));
    }

    #[test]
    fn version_zero_and_invalid_vault_ids_are_rejected() {
        assert_eq!(
            ApprovalPayload::decode(&payload_with(49..57, &[0; 8])),
            Err(ApprovalDecodeError::ZeroVersion)
        );
        assert!(matches!(
            ApprovalPayload::decode(&payload_with(33..49, &[0; 16])),
            Err(ApprovalDecodeError::InvalidVaultId(_))
        ));
    }

    #[test]
    fn wrong_magic_and_unknown_format_versions_are_rejected() {
        assert_eq!(
            ApprovalPayload::decode(&payload_with(0..1, b"X")),
            Err(ApprovalDecodeError::BadMagic)
        );
        assert_eq!(
            ApprovalPayload::decode(&payload_with(4..5, &[2])),
            Err(ApprovalDecodeError::UnknownFormatVersion(2))
        );
        let mut envelope = envelope().encode();
        envelope[4] = 2;
        assert_eq!(
            ApprovalEnvelope::decode(&envelope),
            Err(ApprovalDecodeError::UnknownFormatVersion(2))
        );
        envelope[0] = b'X';
        assert_eq!(ApprovalEnvelope::decode(&envelope), Err(ApprovalDecodeError::BadMagic));
        assert_eq!(ApprovalEnvelope::decode(&unhex(PAYLOAD_HEX)), Err(ApprovalDecodeError::BadMagic));
    }

    #[test]
    fn unknown_algorithms_and_wrong_signature_lengths_are_rejected() {
        let payload = unhex(PAYLOAD_HEX);
        [0x00, 0x03, 0xff].into_iter().for_each(|id| {
            let decoded = ApprovalEnvelope::decode(&envelope_bytes(id, &payload, &[0x5a; 64]));
            assert_eq!(decoded, Err(ApprovalDecodeError::UnknownAlgorithm(id)));
        });
        [(1, SignatureAlgorithm::Ed25519), (2, SignatureAlgorithm::EcdsaP256)]
            .into_iter()
            .for_each(|(id, algorithm)| {
                [0, 63, 65, 72].into_iter().for_each(|len| {
                    let decoded = ApprovalEnvelope::decode(&envelope_bytes(id, &payload, &vec![0x5a; len]));
                    assert_eq!(decoded, Err(ApprovalDecodeError::SignatureLength { algorithm, len }));
                });
            });
    }

    #[test]
    fn every_truncation_and_trailing_bytes_are_rejected() {
        let payload = unhex(PAYLOAD_HEX);
        (0..payload.len()).for_each(|len| {
            let err = ApprovalPayload::decode(&payload[..len]);
            assert!(
                matches!(err, Err(ApprovalDecodeError::Truncated | ApprovalDecodeError::LengthPastEnd)),
                "{len}: {err:?}"
            );
        });
        let envelope = envelope().encode();
        (0..envelope.len()).for_each(|len| {
            let err = ApprovalEnvelope::decode(&envelope[..len]);
            assert!(
                matches!(err, Err(ApprovalDecodeError::Truncated | ApprovalDecodeError::LengthPastEnd)),
                "{len}: {err:?}"
            );
        });
        assert_eq!(
            ApprovalPayload::decode(&[&payload[..], &[0]].concat()),
            Err(ApprovalDecodeError::TrailingBytes)
        );
        assert_eq!(
            ApprovalEnvelope::decode(&[&envelope[..], &[0]].concat()),
            Err(ApprovalDecodeError::TrailingBytes)
        );
        let padded_payload = envelope_bytes(1, &[&payload[..], &[0]].concat(), &[0x5a; 64]);
        assert_eq!(ApprovalEnvelope::decode(&padded_payload), Err(ApprovalDecodeError::TrailingBytes));
    }

    #[test]
    fn oversized_envelopes_are_refused_before_parsing() {
        let huge = vec![0; MAX_APPROVAL_ENVELOPE_LEN + 1];
        assert_eq!(
            ApprovalEnvelope::decode(&huge),
            Err(ApprovalDecodeError::TooLarge {
                limit: MAX_APPROVAL_ENVELOPE_LEN
            })
        );
        let length_past_end = envelope_bytes(1, &[], &[])
            .into_iter()
            .take(22)
            .chain(u64::MAX.to_be_bytes())
            .collect::<Vec<_>>();
        assert_eq!(ApprovalEnvelope::decode(&length_past_end), Err(ApprovalDecodeError::LengthPastEnd));
    }

    /// Bytes 6 to 21 are the approver ID; byte 12 holds its version nibble and byte 14 its variant bits.
    #[test]
    fn approver_ids_that_are_not_version_4_are_rejected() {
        let with = |at: usize, byte: u8| {
            let mut bytes = envelope().encode();
            bytes[at] = byte;
            ApprovalEnvelope::decode(&bytes)
        };
        assert_eq!(with(12, 0x1c), Err(ApprovalDecodeError::InvalidApproverId));
        assert_eq!(with(14, 0x1e), Err(ApprovalDecodeError::InvalidApproverId));
        let mut zero = envelope().encode();
        zero[6..22].fill(0);
        assert_eq!(ApprovalEnvelope::decode(&zero), Err(ApprovalDecodeError::InvalidApproverId));
        assert_eq!(with(21, 0x0e).map(|envelope| envelope.approver_id() == approver()), Ok(false));
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = ApprovalPayload::decode(&bytes);
            let _ = ApprovalEnvelope::decode(&bytes);
        }

        #[test]
        fn mutated_valid_envelopes_never_panic(index in any::<prop::sample::Index>(), byte in any::<u8>()) {
            let mut bytes = envelope().encode();
            let at = index.index(bytes.len());
            bytes[at] = byte;
            let _ = ApprovalEnvelope::decode(&bytes);
            let _ = ApprovalPayload::decode(&bytes[30..119]);
        }

        #[test]
        fn payloads_round_trip(version in 1..=u64::MAX, config in proptest::collection::vec(any::<u8>(), 0..64)) {
            let original = ApprovalPayload::new(payload().vault_id(), ApprovalVersion::new(version).unwrap(), ConfigDigest::of(&config));
            prop_assert_eq!(ApprovalPayload::decode(&original.encode()), Ok(original));
        }
    }
}
