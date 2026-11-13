// SPDX-License-Identifier: MPL-2.0
//! Encodes and decodes the plaintext that `approval.age` seals, the
//! [approval state payload v1](../../../../../design/storage-formats.md#approval-state-payload-v1).
//!
//! Every integer is a big-endian `u64` unless a width is given, and a "field" is a `u64` length followed by its bytes:
//!
//! ```text
//! "IVAM" 01 | vault ID (16) | state generation | peer generation | approver count (1 to 16)
//!   per approver: approver ID (16) | algorithm ID (1) | signer kind (1) | public key field | label field | enrolled at
//! highest reserved version | committed tag (1): 00, or 01 then committed version and config digest (32)
//! ```

use super::{ApprovalState, ApprovalStateError, ApproverId, ApproverLabel, ApproverPublicKey, MAX_APPROVERS, PinnedApprover, SignerKind};
use crate::UtcSecond;
use crate::approval::encoding::{header, put_field, read_header};
use crate::approval::{ApprovalDecodeError, ApprovalVersion, ConfigDigest, SignatureAlgorithm};
use crate::state_generation::StateGeneration;
use crate::vault_id::VaultId;
use crate::wire::{Reader, WireError};

/// The first bytes of every approval state payload, distinct from the file magic so neither is read as the other.
const MAGIC: [u8; 4] = *b"IVAM";
/// The payload format version this code writes and the only one it reads.
const VERSION: u8 = 1;
/// The committed-approval tag when nothing has been committed; no version or digest follows.
const NOT_COMMITTED: u8 = 0x00;
/// The committed-approval tag when a version and digest follow.
const COMMITTED: u8 = 0x01;

/// Encodes `state` as a v1 payload: magic, format version, vault ID, state and peer generations, approvers, highest
/// reserved version, committed approval.
pub(super) fn encode(state: &ApprovalState) -> Vec<u8> {
    let mut out = header(MAGIC, VERSION);
    out.extend_from_slice(state.vault_id.as_bytes());
    out.extend_from_slice(&state.state_generation.get().to_be_bytes());
    out.extend_from_slice(&state.peer_generation.get().to_be_bytes());
    // At most MAX_APPROVERS (16), so the widening cast is lossless.
    out.extend_from_slice(&(state.approvers.len() as u64).to_be_bytes());
    state.approvers.iter().for_each(|approver| put_approver(&mut out, approver));
    out.extend_from_slice(&state.highest_reserved.to_be_bytes());
    match &state.committed {
        None => out.push(NOT_COMMITTED),
        Some((version, digest)) => {
            out.push(COMMITTED);
            out.extend_from_slice(&version.get().to_be_bytes());
            out.extend_from_slice(digest.as_bytes());
        }
    }
    out
}

/// Encodes one approver entry: ID, algorithm, signer kind, public key field, label field, enrolment time.
fn put_approver(out: &mut Vec<u8>, approver: &PinnedApprover) {
    out.extend_from_slice(approver.id().as_bytes());
    out.push(approver.algorithm().id());
    out.push(approver.kind().code());
    put_field(out, approver.public_key().as_bytes());
    put_field(out, approver.label().as_str().as_bytes());
    out.extend_from_slice(&approver.enrolled_at().unix_seconds().to_be_bytes());
}

/// Decodes a v1 payload, accepting it only if it is that state's one encoding and the state's invariants hold.
pub(super) fn decode(payload: &[u8]) -> Result<ApprovalState, ApprovalStateError> {
    let mut reader = Reader::new(payload);
    read_header(&mut reader, MAGIC, VERSION)?;
    let vault_id = VaultId::from_bytes(reader.array()?).map_err(ApprovalDecodeError::from)?;
    let state_generation = read_generation(&mut reader)?;
    let peer_generation = read_generation(&mut reader)?;
    let approvers = read_approvers(&mut reader)?;
    let highest_reserved = reader.u64()?;
    let committed = read_committed(&mut reader)?;
    reader.finish()?;
    ApprovalState::from_parts(
        vault_id,
        (state_generation, peer_generation),
        approvers,
        highest_reserved,
        committed,
    )
}

/// Reads the approver entries. The count is checked against its limits before any entry is read, so a huge count never
/// drives a long loop. [`ApprovalState::from_parts`] checks their order and distinct keys once all are read.
fn read_approvers(reader: &mut Reader<'_>) -> Result<Vec<PinnedApprover>, ApprovalStateError> {
    let count = reader.u64()?;
    let count = usize::try_from(count)
        .ok()
        .filter(|count| (1..=MAX_APPROVERS).contains(count))
        .ok_or(ApprovalStateError::ApproverCount(count))?;
    (0..count).map(|_| read_approver(reader)).collect()
}

fn read_approver(reader: &mut Reader<'_>) -> Result<PinnedApprover, ApprovalStateError> {
    let id = ApproverId::from_bytes(reader.array()?)?;
    let algorithm = SignatureAlgorithm::from_id(reader.u8()?)?;
    let kind = SignerKind::from_code(reader.u8()?)?;
    let key = ApproverPublicKey::new(algorithm, reader.field()?.to_vec())?;
    let label = std::str::from_utf8(reader.field()?).map_err(|_| ApprovalStateError::ApproverLabelNotUtf8)?;
    let label = ApproverLabel::new(label).map_err(ApprovalStateError::InvalidApproverLabel)?;
    let enrolled_at = UtcSecond::from_unix_seconds(reader.u64()?).map_err(|_| ApprovalStateError::BadEnrolmentTime)?;
    PinnedApprover::new(id, kind, key, label, enrolled_at)
}

/// Reads a state or peer generation, refusing 0: the approval state always has a manifest to name, so neither is
/// ever 0.
fn read_generation(reader: &mut Reader<'_>) -> Result<StateGeneration, ApprovalStateError> {
    StateGeneration::new(reader.u64()?).ok_or(ApprovalStateError::ZeroStateGeneration)
}

fn read_committed(reader: &mut Reader<'_>) -> Result<Option<(ApprovalVersion, ConfigDigest)>, ApprovalStateError> {
    match reader.u8()? {
        NOT_COMMITTED => Ok(None),
        COMMITTED => {
            let version = ApprovalVersion::new(reader.u64()?).ok_or(ApprovalDecodeError::ZeroVersion)?;
            Ok(Some((version, ConfigDigest::from_bytes(reader.array()?))))
        }
        tag => Err(ApprovalStateError::BadCommittedTag(tag)),
    }
}

/// The payload shares the approval encodings' framing, so its framing failures map to the same format errors.
impl From<WireError> for ApprovalStateError {
    fn from(error: WireError) -> Self {
        ApprovalStateError::Format(error.into())
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Range;

    use proptest::prelude::*;

    use super::*;
    use crate::RecipientLabelError;
    use crate::approval::InvalidKeyReason;
    use crate::approval::encoding::tests::{P256_KEY_HEX, documented_block, unhex};

    /// The documented example: vault 3f2b8c1e-…, state generation 6 with peer generation 3, one Ed25519 software
    /// signer approver (the RFC 8032 test 1 public key) labelled `approval passphrase`, versions 1 and 2 reserved,
    /// version 1 committed for an empty config.
    const EXAMPLE_HEX: &str = "4956414d 01 3f2b8c1e5d4a4e6f9a7b1c2d3e4f5a6b 0000000000000006 0000000000000003 0000000000000001 \
                               8d1c6f0e2b7a4c599e3d5a4b3c2d1e0f 01 01 0000000000000020 \
                               d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a \
                               0000000000000013 617070726f76616c2070617373706872617365 000000006aeda299 0000000000000002 \
                               01 0000000000000001 0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8";

    /// The documented second example: the first after `approver add --kind tpm`, at state generation 7, with a TPM
    /// approver labelled `laptop TPM` (the RFC 6979 A.2.5 P-256 public key) before the software approver.
    const TPM_EXAMPLE_HEX: &str = "4956414d 01 3f2b8c1e5d4a4e6f9a7b1c2d3e4f5a6b 0000000000000007 0000000000000003 0000000000000002 \
                                   5b0e9a1c7d2f4e83b6a40c1d2e3f4a5b 02 02 0000000000000041 \
                                   04 60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6 \
                                   7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299 \
                                   000000000000000a 6c6170746f702054504d 000000006af2cf00 \
                                   8d1c6f0e2b7a4c599e3d5a4b3c2d1e0f 01 01 0000000000000020 \
                                   d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a \
                                   0000000000000013 617070726f76616c2070617373706872617365 000000006aeda299 0000000000000002 \
                                   01 0000000000000001 0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8";

    /// Where the TPM approver's algorithm, kind and key field sit in the second example.
    const TPM_ALGORITHM: Range<usize> = 61..62;
    const TPM_KIND: Range<usize> = 62..63;
    const TPM_KEY: Range<usize> = 71..136;

    /// Where each field of the example sits.
    const COUNT: Range<usize> = 37..45;
    const ID: Range<usize> = 45..61;
    const ALGORITHM: Range<usize> = 61..62;
    const KIND: Range<usize> = 62..63;
    const KEY_FIELD: Range<usize> = 63..103;
    const LABEL_FIELD: Range<usize> = 103..130;
    const ENROLLED_AT: Range<usize> = 130..138;
    const ENTRY: Range<usize> = 45..138;
    const HIGHEST_RESERVED: Range<usize> = 138..146;
    const TAG: Range<usize> = 146..147;
    const COMMITTED_VERSION: Range<usize> = 147..155;

    fn generation(value: u64) -> StateGeneration {
        StateGeneration::new(value).unwrap()
    }

    fn example_approver() -> PinnedApprover {
        let id = ApproverId::from_bytes(unhex("8d1c6f0e2b7a4c599e3d5a4b3c2d1e0f").try_into().unwrap()).unwrap();
        let key = unhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let key = ApproverPublicKey::new(SignatureAlgorithm::Ed25519, key).unwrap();
        let label = ApproverLabel::new("approval passphrase").unwrap();
        PinnedApprover::new(
            id,
            SignerKind::Software,
            key,
            label,
            UtcSecond::from_unix_seconds(0x6aed_a299).unwrap(),
        )
        .unwrap()
    }

    fn tpm_approver() -> PinnedApprover {
        let id = ApproverId::from_bytes(unhex("5b0e9a1c7d2f4e83b6a40c1d2e3f4a5b").try_into().unwrap()).unwrap();
        let key = ApproverPublicKey::new(SignatureAlgorithm::EcdsaP256, unhex(P256_KEY_HEX)).unwrap();
        let label = ApproverLabel::new("laptop TPM").unwrap();
        PinnedApprover::new(id, SignerKind::Tpm, key, label, UtcSecond::from_unix_seconds(0x6af2_cf00).unwrap()).unwrap()
    }

    fn tpm_example() -> ApprovalState {
        let approvers = vec![tpm_approver(), example_approver()];
        ApprovalState::from_parts(vault_id(), (generation(7), generation(3)), approvers, 2, example().committed).unwrap()
    }

    fn vault_id() -> VaultId {
        VaultId::from_bytes(unhex("3f2b8c1e5d4a4e6f9a7b1c2d3e4f5a6b").try_into().unwrap()).unwrap()
    }

    fn example() -> ApprovalState {
        let committed = Some((ApprovalVersion::FIRST, ConfigDigest::of(b"")));
        ApprovalState::from_parts(vault_id(), (generation(6), generation(3)), vec![example_approver()], 2, committed).unwrap()
    }

    /// The example bytes with `range` replaced by `with`, so each rejection test breaks exactly one field.
    fn example_with(range: Range<usize>, with: &[u8]) -> Vec<u8> {
        let mut bytes = unhex(EXAMPLE_HEX);
        bytes.splice(range, with.iter().copied());
        bytes
    }

    /// One approver's encoded entry.
    fn entry(approver: &PinnedApprover) -> Vec<u8> {
        let mut out = Vec::new();
        put_approver(&mut out, approver);
        out
    }

    /// The example with `entries` in place of its approver, and a count of `count`.
    fn example_with_entries(count: u64, entries: &[Vec<u8>]) -> Vec<u8> {
        let replaced = [&count.to_be_bytes()[..], &entries.concat()].concat();
        example_with(COUNT.start..ENTRY.end, &replaced)
    }

    #[test]
    fn documented_example_matches() {
        let bytes = unhex(EXAMPLE_HEX);
        assert_eq!(bytes.len(), 187);
        assert_eq!(encode(&example()), bytes);
        assert_eq!(decode(&bytes), Ok(example()));
    }

    /// Checks that these bytes are the hex column of the example in
    /// [storage formats](../../../../../design/storage-formats.md#approval-state-payload-v1); comments start past column 48.
    #[test]
    fn documented_examples_are_the_ones_in_the_storage_formats() {
        assert_eq!(
            documented_block("## Approval state payload v1", 1),
            EXAMPLE_HEX.split_whitespace().collect::<String>()
        );
        assert_eq!(
            documented_block("## Approval state payload v1", 2),
            TPM_EXAMPLE_HEX.split_whitespace().collect::<String>()
        );
    }

    #[test]
    fn documented_tpm_example_matches() {
        let bytes = unhex(TPM_EXAMPLE_HEX);
        assert_eq!(bytes.len(), 304);
        assert_eq!(entry(&tpm_approver()).len(), 117);
        assert_eq!(encode(&tpm_example()), bytes);
        let decoded = decode(&bytes).unwrap();
        assert_eq!(decoded, tpm_example());
        let tpm = &decoded.approvers[0];
        assert_eq!((tpm.kind(), tpm.algorithm()), (SignerKind::Tpm, SignatureAlgorithm::EcdsaP256));
        assert_eq!(tpm.public_key().as_bytes(), &unhex(P256_KEY_HEX)[..]);
    }

    #[test]
    fn a_new_vault_encodes_with_nothing_reserved_or_committed() {
        let new = ApprovalState {
            highest_reserved: 0,
            committed: None,
            ..example()
        };
        let bytes = encode(&new);
        assert_eq!(bytes.len(), 147);
        assert_eq!(
            bytes,
            [&unhex(EXAMPLE_HEX)[..HIGHEST_RESERVED.start], &[0; 8], &[NOT_COMMITTED]].concat()
        );
        assert_eq!(decode(&bytes), Ok(new));
    }

    #[test]
    fn a_committed_version_above_the_highest_reserved_is_rejected() {
        assert_eq!(
            decode(&example_with(HIGHEST_RESERVED, &1u64.to_be_bytes())),
            Ok(ApprovalState {
                highest_reserved: 1,
                ..example()
            })
        );
        assert_eq!(
            decode(&example_with(HIGHEST_RESERVED, &0u64.to_be_bytes())),
            Err(ApprovalStateError::CommittedNotReserved)
        );
        let built = ApprovalState::from_parts(
            vault_id(),
            (generation(6), generation(3)),
            vec![example_approver()],
            0,
            example().committed,
        );
        assert_eq!(built, Err(ApprovalStateError::CommittedNotReserved));
    }

    #[test]
    fn bad_committed_tags_and_a_zero_committed_version_are_rejected() {
        [0x02, 0xff].into_iter().for_each(|tag| {
            assert_eq!(decode(&example_with(TAG, &[tag])), Err(ApprovalStateError::BadCommittedTag(tag)));
        });
        let zero = ApprovalStateError::Format(ApprovalDecodeError::ZeroVersion);
        assert_eq!(decode(&example_with(COMMITTED_VERSION, &[0; 8])), Err(zero));
        // `00` with a version and digest after it leaves them as trailing bytes.
        let trailing = ApprovalStateError::Format(ApprovalDecodeError::TrailingBytes);
        assert_eq!(decode(&example_with(TAG, &[NOT_COMMITTED])), Err(trailing));
    }

    #[test]
    fn unknown_algorithms_and_wrong_key_lengths_are_rejected() {
        [0x00, 0x03, 0xff].into_iter().for_each(|id| {
            assert_eq!(
                decode(&example_with(ALGORITHM, &[id])),
                Err(ApprovalDecodeError::UnknownAlgorithm(id).into())
            );
        });
        let short = example_with(KEY_FIELD, &[&31u64.to_be_bytes()[..], &[0x42; 31]].concat());
        assert_eq!(
            decode(&short),
            Err(ApprovalStateError::PublicKeyLength {
                algorithm: SignatureAlgorithm::Ed25519,
                len: 31
            })
        );
        // An Ed25519-sized key under the P-256 algorithm, and the compressed form of the P-256 key.
        assert_eq!(
            decode(&example_with(ALGORITHM, &[0x02])),
            Err(ApprovalStateError::PublicKeyLength {
                algorithm: SignatureAlgorithm::EcdsaP256,
                len: 32
            })
        );
        let compressed: Vec<u8> = [0x03].into_iter().chain(unhex(P256_KEY_HEX)[1..33].iter().copied()).collect();
        assert_eq!(
            p256(compressed),
            Err(ApprovalStateError::PublicKeyLength {
                algorithm: SignatureAlgorithm::EcdsaP256,
                len: 33
            })
        );
    }

    #[test]
    fn reserved_and_unknown_signer_kinds_are_rejected() {
        [SignerKind::Software, SignerKind::Tpm]
            .into_iter()
            .for_each(|kind| assert_eq!(SignerKind::from_code(kind.code()), Ok(kind)));
        assert_eq!((SignerKind::Tpm.code(), SignerKind::Tpm.name()), (2, "tpm"));
        assert_eq!(decode(&example_with(KIND, &[0])), Err(ApprovalStateError::UnknownSignerKind(0)));
        assert_eq!(decode(&example_with(KIND, &[3])), Err(ApprovalStateError::ReservedSignerKind(3)));
        [4, 0xff].into_iter().for_each(|code| {
            assert_eq!(
                decode(&example_with(KIND, &[code])),
                Err(ApprovalStateError::UnknownSignerKind(code))
            );
        });
    }

    /// `software` allows only Ed25519 and `tpm` only ECDSA P-256; any other pairing is refused, read or built.
    #[test]
    fn a_kind_with_an_algorithm_it_does_not_allow_is_rejected() {
        let mismatch = |kind, algorithm| ApprovalStateError::KindAlgorithmMismatch { kind, algorithm };
        let tpm_with_ed25519 = mismatch(SignerKind::Tpm, SignatureAlgorithm::Ed25519);
        assert_eq!(decode(&example_with(KIND, &[2])).err(), Some(tpm_with_ed25519.clone()));
        let software_with_p256 = mismatch(SignerKind::Software, SignatureAlgorithm::EcdsaP256);
        let tpm_bytes = unhex(TPM_EXAMPLE_HEX);
        let mut software = tpm_bytes.clone();
        software.splice(TPM_KIND, [1]);
        assert_eq!(decode(&software).err(), Some(software_with_p256.clone()));
        let mut ed25519_algorithm = tpm_bytes;
        ed25519_algorithm.splice(TPM_ALGORITHM, [1]);
        let length = ApprovalStateError::PublicKeyLength {
            algorithm: SignatureAlgorithm::Ed25519,
            len: 65,
        };
        assert_eq!(decode(&ed25519_algorithm), Err(length));
        let approver = tpm_approver();
        let built = |kind, key| PinnedApprover::new(approver.id(), kind, key, approver.label().clone(), approver.enrolled_at());
        assert_eq!(built(SignerKind::Software, *approver.public_key()).err(), Some(software_with_p256));
        assert_eq!(
            built(SignerKind::Tpm, *example_approver().public_key()).err(),
            Some(tpm_with_ed25519)
        );
    }

    /// `MAX_APPROVERS` TPM approvers, each with the longest key and label, make the largest payload the size limit allows
    /// for.
    #[test]
    fn the_largest_state_is_the_documented_size() {
        let tpm = |seed: u8| {
            let key = p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
            let key = p256(key.verifying_key().to_encoded_point(false).as_bytes().to_vec()).unwrap();
            let label = ApproverLabel::new(&"x".repeat(64)).unwrap();
            PinnedApprover::new(ApproverId::for_tests(&key), SignerKind::Tpm, key, label, UtcSecond::EPOCH).unwrap()
        };
        let mut approvers: Vec<_> = (1..=MAX_APPROVERS as u8).map(tpm).collect();
        approvers.sort_by_key(PinnedApprover::id);
        assert!(approvers.iter().all(|approver| entry(approver).len() == 171));
        let state = ApprovalState::from_parts(vault_id(), (generation(2), generation(1)), approvers, 2, example().committed).unwrap();
        let bytes = encode(&state);
        assert_eq!(bytes.len(), 2_830);
        assert_eq!(decode(&bytes), Ok(state));
    }

    fn p256(key: Vec<u8>) -> Result<ApproverPublicKey, ApprovalStateError> {
        ApproverPublicKey::new(SignatureAlgorithm::EcdsaP256, key)
    }

    /// Only the uncompressed SEC1 encoding of a point on the curve is pinned.
    #[test]
    fn p256_keys_off_the_curve_or_in_another_form_are_rejected() {
        let key = unhex(P256_KEY_HEX);
        assert_eq!(p256(key.clone()).map(|k| k.as_bytes().to_vec()), Ok(key.clone()));
        let not_a_point = Err(ApprovalStateError::InvalidApproverKey {
            algorithm: SignatureAlgorithm::EcdsaP256,
            reason: InvalidKeyReason::NotAPoint,
        });
        let with = |at: usize, byte: u8| {
            let mut changed = key.clone();
            changed[at] = byte;
            changed
        };
        // y + 1 is off the curve; tags 00, 02, 05 and 06 are other forms; x of all ones is above the field prime.
        let off_curve = with(64, key[64] ^ 0x01);
        let other_forms = [0x00, 0x02, 0x05, 0x06].map(|tag| with(0, tag));
        let x_too_large: Vec<u8> = [0x04].into_iter().chain([0xff; 32]).chain(key[33..].iter().copied()).collect();
        [off_curve.clone(), x_too_large, vec![0; 65], vec![0x04; 65]]
            .into_iter()
            .chain(other_forms)
            .for_each(|bad| assert_eq!(p256(bad.clone()), not_a_point, "{bad:02x?}"));
        // Decoding applies the same checks.
        let mut bytes = unhex(TPM_EXAMPLE_HEX);
        bytes.splice(TPM_KEY, off_curve);
        assert_eq!(decode(&bytes).err(), not_a_point.err());
    }

    #[test]
    fn a_truncation_inside_the_signer_kind_is_rejected() {
        let full = unhex(EXAMPLE_HEX);
        assert_eq!(decode(&full[..KIND.start]), Err(ApprovalDecodeError::Truncated.into()));
    }

    fn ed25519(key: Vec<u8>) -> Result<ApproverPublicKey, ApprovalStateError> {
        ApproverPublicKey::new(SignatureAlgorithm::Ed25519, key)
    }

    fn refused(reason: InvalidKeyReason) -> Result<ApproverPublicKey, ApprovalStateError> {
        Err(ApprovalStateError::InvalidApproverKey {
            algorithm: SignatureAlgorithm::Ed25519,
            reason,
        })
    }

    #[test]
    fn approver_keys_are_validated_when_pinned() {
        let generated = ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key();
        assert_eq!(
            ed25519(generated.to_bytes().to_vec()).map(|key| key.as_bytes().to_vec()),
            Ok(generated.to_bytes().to_vec())
        );
        // y = 2 has no x on the curve.
        let not_a_point: Vec<u8> = [2u8].into_iter().chain([0; 31]).collect();
        assert_eq!(ed25519(not_a_point.clone()), refused(InvalidKeyReason::NotAPoint));
        // The identity point and the order-2 point (0, -1).
        let identity: Vec<u8> = [1u8].into_iter().chain([0; 31]).collect();
        let order_two = [0xec_u8].into_iter().chain([0xff; 30]).chain([0x7f]).collect();
        assert_eq!(ed25519(identity.clone()), refused(InvalidKeyReason::WeakKey));
        assert_eq!(ed25519(order_two), refused(InvalidKeyReason::WeakKey));
        [31, 33].into_iter().for_each(|len| {
            let error = ApprovalStateError::PublicKeyLength {
                algorithm: SignatureAlgorithm::Ed25519,
                len,
            };
            assert_eq!(
                ed25519(generated.to_bytes().iter().copied().cycle().take(len).collect()),
                Err(error)
            );
        });
        // Decoding applies the same checks.
        let with_key = |key: &[u8]| example_with(KEY_FIELD.start + 8..KEY_FIELD.end, key);
        assert_eq!(decode(&with_key(&not_a_point)).err(), refused(InvalidKeyReason::NotAPoint).err());
        assert_eq!(decode(&with_key(&identity)).err(), refused(InvalidKeyReason::WeakKey).err());
    }

    #[test]
    fn an_approver_count_of_zero_or_above_sixteen_is_rejected() {
        [0, 17, u64::MAX].into_iter().for_each(|count| {
            assert_eq!(
                decode(&example_with(COUNT, &count.to_be_bytes())),
                Err(ApprovalStateError::ApproverCount(count))
            );
        });
        let seventeen: Vec<_> = (1..=17).map(|seed| entry(&PinnedApprover::from_seed(seed))).collect();
        assert_eq!(
            decode(&example_with_entries(17, &seventeen)),
            Err(ApprovalStateError::ApproverCount(17))
        );
    }

    #[test]
    fn an_approver_id_that_is_not_version_4_is_rejected() {
        let mut nil = [0u8; 16];
        assert_eq!(decode(&example_with(ID, &nil)), Err(ApprovalStateError::InvalidApproverId));
        // Version 4 with the wrong variant bits, and version 1 with the right ones.
        nil[6] = 0x40;
        assert_eq!(decode(&example_with(ID, &nil)), Err(ApprovalStateError::InvalidApproverId));
        let mut v1 = unhex("8d1c6f0e2b7a4c599e3d5a4b3c2d1e0f");
        v1[6] = 0x1c;
        assert_eq!(decode(&example_with(ID, &v1)), Err(ApprovalStateError::InvalidApproverId));
    }

    /// Two approvers, the first with the lower ID.
    fn ordered_pair() -> [PinnedApprover; 2] {
        let mut pair = [PinnedApprover::from_seed(1), PinnedApprover::from_seed(2)];
        pair.sort_by_key(PinnedApprover::id);
        pair
    }

    #[test]
    fn approver_ids_out_of_order_or_repeated_are_rejected() {
        let [low, high] = ordered_pair();
        let sorted = example_with_entries(2, &[entry(&low), entry(&high)]);
        assert_eq!(decode(&sorted).map(|state| state.approvers), Ok(vec![low.clone(), high.clone()]));
        assert_eq!(
            decode(&example_with_entries(2, &[entry(&high), entry(&low)])),
            Err(ApprovalStateError::UnsortedApprovers)
        );
        let same_id = PinnedApprover::software_for_tests(low.id(), *high.public_key(), high.label().clone(), high.enrolled_at());
        assert_eq!(
            decode(&example_with_entries(2, &[entry(&low), entry(&same_id)])),
            Err(ApprovalStateError::DuplicateApproverId(low.id()))
        );
    }

    #[test]
    fn a_public_key_pinned_twice_is_rejected() {
        let [low, high] = ordered_pair();
        let same_key = PinnedApprover::software_for_tests(high.id(), *low.public_key(), high.label().clone(), high.enrolled_at());
        assert_eq!(
            decode(&example_with_entries(2, &[entry(&low), entry(&same_key)])),
            Err(ApprovalStateError::DuplicateApproverKey)
        );
    }

    #[test]
    fn a_label_that_breaks_the_rule_is_rejected() {
        let with_label = |label: &[u8]| example_with(LABEL_FIELD, &[&(label.len() as u64).to_be_bytes()[..], label].concat());
        let invalid = |rule| Err(ApprovalStateError::InvalidApproverLabel(rule));
        assert_eq!(decode(&with_label(&[0xff])), Err(ApprovalStateError::ApproverLabelNotUtf8));
        assert_eq!(decode(&with_label(b"")), invalid(RecipientLabelError::Empty));
        assert_eq!(decode(&with_label(&[b'a'; 65])), invalid(RecipientLabelError::TooLong));
        assert_eq!(decode(&with_label(b"a\nb")), invalid(RecipientLabelError::ControlOrFormat));
        assert_eq!(
            decode(&with_label(" a".as_bytes())),
            invalid(RecipientLabelError::SurroundingWhitespace)
        );
        assert!(decode(&with_label(&[b'a'; 64])).is_ok());
    }

    #[test]
    fn an_enrolment_time_outside_the_utc_second_range_is_rejected() {
        [253_402_300_800, u64::MAX].into_iter().for_each(|at| {
            assert_eq!(
                decode(&example_with(ENROLLED_AT, &at.to_be_bytes())),
                Err(ApprovalStateError::BadEnrolmentTime)
            );
        });
        assert!(decode(&example_with(ENROLLED_AT, &253_402_300_799u64.to_be_bytes())).is_ok());
    }

    #[test]
    fn a_zero_state_or_peer_generation_is_rejected() {
        [21..29, 29..37].into_iter().for_each(|range| {
            assert_eq!(decode(&example_with(range, &[0; 8])), Err(ApprovalStateError::ZeroStateGeneration));
        });
    }

    #[test]
    fn a_peer_generation_not_below_the_state_generation_is_rejected() {
        [6, 7, u64::MAX].into_iter().for_each(|peer| {
            let bytes = example_with(29..37, &peer.to_be_bytes());
            assert_eq!(decode(&bytes), Err(ApprovalStateError::PeerNotOlder), "{peer}");
        });
        assert_eq!(
            decode(&example_with(29..37, &5u64.to_be_bytes())).map(|s| s.peer_generation.get()),
            Ok(5)
        );
    }

    #[test]
    fn wrong_magic_unknown_versions_and_invalid_vault_ids_are_rejected() {
        assert_eq!(decode(&example_with(0..1, b"X")), Err(ApprovalDecodeError::BadMagic.into()));
        assert_eq!(
            decode(&example_with(4..5, &[2])),
            Err(ApprovalDecodeError::UnknownFormatVersion(2).into())
        );
        assert!(matches!(
            decode(&example_with(5..21, &[0; 16])),
            Err(ApprovalStateError::Format(ApprovalDecodeError::InvalidVaultId(_)))
        ));
    }

    #[test]
    fn every_truncation_and_trailing_bytes_are_rejected() {
        let full = unhex(EXAMPLE_HEX);
        (0..full.len()).for_each(|len| {
            let err = decode(&full[..len]);
            let short = matches!(
                err,
                Err(ApprovalStateError::Format(
                    ApprovalDecodeError::Truncated | ApprovalDecodeError::LengthPastEnd
                ))
            );
            assert!(short, "{len}: {err:?}");
        });
        assert_eq!(decode(&[&full[..], &[0]].concat()), Err(ApprovalDecodeError::TrailingBytes.into()));
    }

    /// From 1 to 16 distinct approvers, in approver ID order.
    fn approvers() -> impl Strategy<Value = Vec<PinnedApprover>> {
        proptest::sample::subsequence((1..=40u8).collect::<Vec<_>>(), 1..=MAX_APPROVERS).prop_map(|seeds| {
            let mut approvers: Vec<_> = seeds.into_iter().map(PinnedApprover::from_seed).collect();
            approvers.sort_by_key(PinnedApprover::id);
            approvers
        })
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = decode(&bytes);
        }

        #[test]
        fn mutated_valid_payloads_never_panic(index in any::<prop::sample::Index>(), byte in any::<u8>()) {
            let mut bytes = unhex(EXAMPLE_HEX);
            let at = index.index(bytes.len());
            bytes[at] = byte;
            let _ = decode(&bytes);
        }

        #[test]
        fn states_round_trip(
            state in 2..=u64::MAX,
            peer in any::<u64>(),
            approvers in approvers(),
            highest in 0..=u64::MAX,
            committed in any::<Option<u64>>(),
            config in proptest::collection::vec(any::<u8>(), 0..64),
            with_tpm in any::<bool>(),
        ) {
            let mut approvers = approvers;
            if with_tpm && approvers.len() < MAX_APPROVERS {
                approvers.push(tpm_approver());
                approvers.sort_by_key(PinnedApprover::id);
            }
            let committed = committed.and_then(|c| ApprovalVersion::new(c.min(highest))).map(|v| (v, ConfigDigest::of(&config)));
            // Any peer generation from 1 to one below the state generation.
            let generations = (generation(state), generation(1 + peer % (state - 1)));
            let original = ApprovalState::from_parts(vault_id(), generations, approvers, highest, committed).unwrap();
            prop_assert_eq!(decode(&encode(&original)), Ok(original));
        }
    }
}
