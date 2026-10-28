//! The approval state payload v1 encoding: the plaintext an approval state file seals (`design/storage-formats.md`).

use super::{ApprovalState, ApprovalStateError, PinnedApprover};
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

/// The state's v1 payload: magic, version, vault ID, state and peer generations, approver, highest reserved version,
/// committed approval.
pub(super) fn encode(state: &ApprovalState) -> Vec<u8> {
    let mut out = header(MAGIC, VERSION);
    out.extend_from_slice(state.vault_id.as_bytes());
    out.extend_from_slice(&state.state_generation.get().to_be_bytes());
    out.extend_from_slice(&state.peer_generation.get().to_be_bytes());
    out.push(state.approver.algorithm().id());
    put_field(&mut out, state.approver.public_key());
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

/// The state a v1 payload holds, accepted only if it is that state's one encoding and the state's invariant holds.
pub(super) fn decode(payload: &[u8]) -> Result<ApprovalState, ApprovalStateError> {
    let mut reader = Reader::new(payload);
    read_header(&mut reader, MAGIC, VERSION)?;
    let vault_id = VaultId::from_bytes(reader.array()?).map_err(ApprovalDecodeError::from)?;
    let state_generation = read_generation(&mut reader)?;
    let peer_generation = read_generation(&mut reader)?;
    let algorithm = SignatureAlgorithm::from_id(reader.u8()?)?;
    let approver = PinnedApprover::new(algorithm, reader.field()?.to_vec())?;
    let highest_reserved = reader.u64()?;
    let committed = read_committed(&mut reader)?;
    reader.finish()?;
    ApprovalState::from_parts(vault_id, state_generation, peer_generation, approver, highest_reserved, committed)
}

/// A state or peer generation; the approval state always has a manifest to name, so neither is ever 0.
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

/// The payload shares the approval encodings' layout, so its framing failures are the same format errors theirs are.
impl From<WireError> for ApprovalStateError {
    fn from(error: WireError) -> Self {
        ApprovalStateError::Format(error.into())
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::approval::InvalidKeyReason;

    /// The documented example: vault 3f2b8c1e-…, state generation 6 with peer generation 3, the RFC 8032 test 1
    /// Ed25519 public key, versions 1 and 2 reserved, version 1 committed for an empty config.
    const EXAMPLE_HEX: &str = "4956414d 01 3f2b8c1e5d4a4e6f9a7b1c2d3e4f5a6b 0000000000000006 0000000000000003 01 0000000000000020 \
                               d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a 0000000000000002 \
                               01 0000000000000001 0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8";

    fn unhex(hex: &str) -> Vec<u8> {
        hex.split_whitespace()
            .flat_map(|group| {
                (0..group.len())
                    .step_by(2)
                    .map(move |i| u8::from_str_radix(&group[i..i + 2], 16).unwrap())
            })
            .collect()
    }

    fn generation(value: u64) -> StateGeneration {
        StateGeneration::new(value).unwrap()
    }

    fn example() -> ApprovalState {
        let vault_id = VaultId::from_bytes(unhex("3f2b8c1e5d4a4e6f9a7b1c2d3e4f5a6b").try_into().unwrap()).unwrap();
        let key = unhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let approver = PinnedApprover::new(SignatureAlgorithm::Ed25519, key).unwrap();
        let committed = Some((ApprovalVersion::FIRST, ConfigDigest::of(b"")));
        ApprovalState::from_parts(vault_id, generation(6), generation(3), approver, 2, committed).unwrap()
    }

    /// The example bytes with `range` replaced by `with`, so each rejection test breaks exactly one field.
    fn example_with(range: std::ops::Range<usize>, with: &[u8]) -> Vec<u8> {
        let mut bytes = unhex(EXAMPLE_HEX);
        bytes.splice(range, with.iter().copied());
        bytes
    }

    #[test]
    fn documented_example_matches() {
        let bytes = unhex(EXAMPLE_HEX);
        assert_eq!(bytes.len(), 127);
        assert_eq!(encode(&example()), bytes);
        assert_eq!(decode(&bytes), Ok(example()));
    }

    /// The example's hex column in `design/storage-formats.md` is these bytes; comments start past column 48.
    #[test]
    fn documented_example_is_the_one_in_the_storage_formats() {
        let doc = include_str!("../../../../../design/storage-formats.md");
        let section = doc.split("## Approval state payload v1").nth(1).unwrap();
        let block = section.split("```text\n").nth(1).unwrap().split("```").next().unwrap();
        let hex: String = block
            .lines()
            .flat_map(|line| line.chars().take(48))
            .filter(|c| !c.is_whitespace())
            .collect();
        assert_eq!(hex, EXAMPLE_HEX.split_whitespace().collect::<String>());
    }

    #[test]
    fn a_new_vault_encodes_with_nothing_reserved_or_committed() {
        let new = ApprovalState {
            highest_reserved: 0,
            committed: None,
            ..example()
        };
        let bytes = encode(&new);
        assert_eq!(bytes, [&unhex(EXAMPLE_HEX)[..78], &[0; 8], &[NOT_COMMITTED]].concat());
        assert_eq!(decode(&bytes), Ok(new));
    }

    #[test]
    fn a_committed_version_above_the_highest_reserved_is_rejected() {
        assert_eq!(
            decode(&example_with(78..86, &1u64.to_be_bytes())),
            Ok(ApprovalState {
                highest_reserved: 1,
                ..example()
            })
        );
        assert_eq!(
            decode(&example_with(78..86, &0u64.to_be_bytes())),
            Err(ApprovalStateError::CommittedNotReserved)
        );
        let built = ApprovalState::from_parts(
            example().vault_id,
            generation(6),
            generation(3),
            example().approver,
            0,
            example().committed,
        );
        assert_eq!(built, Err(ApprovalStateError::CommittedNotReserved));
    }

    #[test]
    fn bad_committed_tags_and_a_zero_committed_version_are_rejected() {
        [0x02, 0xff].into_iter().for_each(|tag| {
            assert_eq!(decode(&example_with(86..87, &[tag])), Err(ApprovalStateError::BadCommittedTag(tag)));
        });
        let zero = ApprovalStateError::Format(ApprovalDecodeError::ZeroVersion);
        assert_eq!(decode(&example_with(87..95, &[0; 8])), Err(zero));
        // `00` with a version and digest after it leaves them as trailing bytes.
        let trailing = ApprovalStateError::Format(ApprovalDecodeError::TrailingBytes);
        assert_eq!(decode(&example_with(86..87, &[NOT_COMMITTED])), Err(trailing));
    }

    #[test]
    fn unknown_algorithms_and_wrong_key_lengths_are_rejected() {
        [0x00, 0x02, 0xff].into_iter().for_each(|id| {
            assert_eq!(
                decode(&example_with(37..38, &[id])),
                Err(ApprovalDecodeError::UnknownAlgorithm(id).into())
            );
        });
        let short = example_with(38..78, &[&31u64.to_be_bytes()[..], &[0x42; 31]].concat());
        assert_eq!(
            decode(&short),
            Err(ApprovalStateError::PublicKeyLength {
                algorithm: SignatureAlgorithm::Ed25519,
                len: 31
            })
        );
        let built = PinnedApprover::new(SignatureAlgorithm::Ed25519, vec![0; 33]);
        assert_eq!(
            built,
            Err(ApprovalStateError::PublicKeyLength {
                algorithm: SignatureAlgorithm::Ed25519,
                len: 33
            })
        );
    }

    fn ed25519(key: Vec<u8>) -> Result<PinnedApprover, ApprovalStateError> {
        PinnedApprover::new(SignatureAlgorithm::Ed25519, key)
    }

    fn refused(reason: InvalidKeyReason) -> Result<PinnedApprover, ApprovalStateError> {
        Err(ApprovalStateError::InvalidApproverKey {
            algorithm: SignatureAlgorithm::Ed25519,
            reason,
        })
    }

    #[test]
    fn approver_keys_are_validated_when_pinned() {
        let generated = ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key();
        assert_eq!(
            ed25519(generated.to_bytes().to_vec()).map(|a| a.public_key().to_vec()),
            Ok(generated.to_bytes().to_vec())
        );
        // y = 2 has no x on the curve.
        assert_eq!(
            ed25519([2u8].into_iter().chain([0; 31]).collect()),
            refused(InvalidKeyReason::NotAPoint)
        );
        // The identity point and the order-2 point (0, -1).
        let identity = [1u8].into_iter().chain([0; 31]).collect();
        let order_two = [0xec_u8].into_iter().chain([0xff; 30]).chain([0x7f]).collect();
        assert_eq!(ed25519(identity), refused(InvalidKeyReason::WeakKey));
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
    }

    #[test]
    fn a_zero_state_or_peer_generation_is_rejected() {
        [21..29, 29..37].into_iter().for_each(|range| {
            assert_eq!(decode(&example_with(range, &[0; 8])), Err(ApprovalStateError::ZeroStateGeneration));
        });
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
            state in any::<u64>(),
            peer in any::<u64>(),
            highest in 0..=u64::MAX,
            committed in any::<Option<u64>>(),
            config in proptest::collection::vec(any::<u8>(), 0..64),
        ) {
            let committed = committed.and_then(|c| ApprovalVersion::new(c.min(highest))).map(|v| (v, ConfigDigest::of(&config)));
            let (state, peer) = (generation(state.max(1)), generation(peer.max(1)));
            let original = ApprovalState::from_parts(example().vault_id, state, peer, example().approver, highest, committed).unwrap();
            prop_assert_eq!(decode(&encode(&original)), Ok(original));
        }
    }
}
