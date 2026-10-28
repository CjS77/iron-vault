//! The approval state file v1: a clear header, the payload sealed to the vault public key, then a MAC
//! (`design/storage-formats.md`).
//!
//! It is a MAC'd file like the manifest file (`crate::mac_file`), with its own magic, MAC key persona and domain tag, so
//! a MAC from one file never verifies the other.

use super::{ApprovalState, ApprovalStateError, MAX_APPROVAL_STATE_LEN, encoding};
use crate::approval::ApprovalDecodeError;
use crate::mac_file::MacFileKind;
use crate::sealed::SealError;
use crate::vault_identity::VaultIdentity;

/// The approval state's MAC'd file frame: magic `IVAF`, version 1, and a key persona and domain tag of its own, so a
/// MAC from the manifest never verifies here.
const KIND: MacFileKind<ApprovalStateError> = MacFileKind {
    magic: *b"IVAF",
    version: 1,
    persona: b"iv-approval-v1",
    domain_tag: b"iron-vault approval file v1 mac\0",
    max_len: MAX_APPROVAL_STATE_LEN,
    too_large: ApprovalStateError::TooLarge { limit: MAX_APPROVAL_STATE_LEN },
    truncated: ApprovalStateError::Format(ApprovalDecodeError::Truncated),
    bad_magic: ApprovalStateError::Format(ApprovalDecodeError::BadMagic),
    unknown_version: |version| ApprovalDecodeError::UnknownFormatVersion(version).into(),
    damaged: ApprovalStateError::Damaged,
    invalid_vault_id: |error| ApprovalDecodeError::InvalidVaultId(error).into(),
};

/// The approval state file's bytes: header, the payload sealed to the vault public key, then the MAC.
pub fn seal_approval_state(identity: &VaultIdentity, state: &ApprovalState) -> Result<Vec<u8>, SealError> {
    KIND.seal(identity, state.vault_id, &encoding::encode(state))
}

/// The approval state a file holds, after its size, header and MAC are checked and before anything is decrypted.
///
/// A MAC mismatch, a payload for another vault or a broken invariant is damaged shared state (spec §3.10).
pub fn open_approval_state(identity: &VaultIdentity, file: &[u8]) -> Result<ApprovalState, ApprovalStateError> {
    let (vault_id, payload) = KIND.open(identity, file)?;
    let state = encoding::decode(&payload)?;
    (state.vault_id == vault_id).then_some(state).ok_or(ApprovalStateError::VaultIdMismatch)
}

#[cfg(test)]
mod tests {
    use blake2::Blake2bMac;
    use blake2::digest::{Mac, consts::U32};
    use proptest::prelude::*;

    use super::*;
    use crate::approval::{ApprovalVersion, ConfigDigest, InvalidKeyReason, PinnedApprover, SignatureAlgorithm};
    use crate::mac_file::{HEADER_LEN, MAC_LEN};
    use crate::manifest::tests::KAT_IDENTITY;
    use crate::sealed::{self, OpenError};
    use crate::vault_id::VaultId;

    const FILE_MAGIC: [u8; 4] = KIND.magic;
    const FILE_VERSION: u8 = KIND.version;
    const APPROVAL_KEY_PERSONA: &[u8] = KIND.persona;

    /// The approval key of [`KAT_IDENTITY`].
    const KAT_APPROVAL_KEY: &str =
        "16774b3a8005def61dba01300f8d95323135bdc40e911fadd247058656d40372dc06a4d9099da2e01ddec5c2c017772f903cf6083fb0f38d1ca5fbac6b8df64c";
    /// The MAC'd bytes of the known-answer file: header for vault 3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b, then the stand-in
    /// ciphertext `not really age`.
    const KAT_SIGNED: &str = "49564146013f2b8c1e5d4a4e6f9a7b1c2d3e4f5a6b6e6f74207265616c6c7920616765";
    /// The MAC of [`KAT_SIGNED`] under [`KAT_APPROVAL_KEY`].
    const KAT_TAG: &str = "432bf6223d8cfcab01ea4ba4f7e3757ed426bb724c440ccbf42d2ecdeca76e3f";

    fn unhex(hex: &str) -> Vec<u8> {
        (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn mac(identity: &VaultIdentity, signed: &[u8]) -> Blake2bMac<U32> {
        keyed_mac(&identity.derive_key(APPROVAL_KEY_PERSONA), signed)
    }

    fn keyed_mac(key: &[u8; 64], signed: &[u8]) -> Blake2bMac<U32> {
        KIND.mac(key, signed)
    }

    /// A state with a committed approval, so every payload field is present.
    fn state(vault_id: VaultId) -> ApprovalState {
        let approver = PinnedApprover::from_signing_key(&ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]));
        ApprovalState::from_parts(vault_id, approver, 3, ApprovalVersion::new(2).map(|v| (v, ConfigDigest::of(b"config")))).unwrap()
    }


    /// A file with the given header vault ID and payload, MACed under `key`: what anyone could build who holds the
    /// vault public key, plus whatever key they claim.
    fn forged(identity: &VaultIdentity, header_id: VaultId, payload: &[u8], key: &[u8; 64]) -> Vec<u8> {
        let mut file = [&FILE_MAGIC[..], &[FILE_VERSION], header_id.as_bytes()].concat();
        file.extend_from_slice(&sealed::seal(&identity.public_key(), payload).unwrap());
        let tag: [u8; MAC_LEN] = keyed_mac(key, &file).finalize().into_bytes().into();
        [file, tag.to_vec()].concat()
    }

    /// Known answer computed independently with Python's `hashlib.blake2b`; age output is randomized, so the
    /// ciphertext is a fixed stand-in.
    #[test]
    fn mac_matches_its_known_answer() {
        let identity = VaultIdentity::from_secret(KAT_IDENTITY);
        assert_eq!(hex(&*identity.derive_key(APPROVAL_KEY_PERSONA)), KAT_APPROVAL_KEY);
        let key: [u8; 64] = unhex(KAT_APPROVAL_KEY).try_into().unwrap();
        let signed = unhex(KAT_SIGNED);
        assert_eq!(&signed[..HEADER_LEN], [&FILE_MAGIC[..], &[FILE_VERSION], &unhex("3f2b8c1e5d4a4e6f9a7b1c2d3e4f5a6b")].concat());
        assert_eq!(hex(&keyed_mac(&key, &signed).finalize().into_bytes()), KAT_TAG);
    }

    #[test]
    fn known_answers_are_published_in_the_storage_formats() {
        let doc: String = include_str!("../../../../../design/storage-formats.md").split_whitespace().collect();
        [KAT_APPROVAL_KEY, KAT_SIGNED, KAT_TAG].iter().for_each(|kat| assert!(doc.contains(kat), "{kat}"));
    }

    #[test]
    fn round_trip_preserves_every_field() {
        let identity = VaultIdentity::generate();
        let original = state(VaultId::new_random());
        let file = seal_approval_state(&identity, &original).unwrap();
        assert!(file.len() < MAX_APPROVAL_STATE_LEN / 4, "{}", file.len());
        assert_eq!(open_approval_state(&identity, &file), Ok(original));
    }

    #[test]
    fn a_state_forged_with_only_the_public_key_is_damaged() {
        let identity = VaultIdentity::generate();
        let original = state(VaultId::new_random());
        let payload = encoding::encode(&original);
        let manifest_key = identity.derive_key(crate::manifest::MANIFEST_KEY_PERSONA);
        [[0; 64], [0x5a; 64], *VaultIdentity::generate().derive_key(APPROVAL_KEY_PERSONA), *manifest_key].iter().for_each(|key| {
            let file = forged(&identity, original.vault_id(), &payload, key);
            assert_eq!(open_approval_state(&identity, &file), Err(ApprovalStateError::Damaged));
        });
        // The same construction under the real key opens, so the refusal above is the MAC's doing.
        let file = forged(&identity, original.vault_id(), &payload, &identity.derive_key(APPROVAL_KEY_PERSONA));
        assert_eq!(open_approval_state(&identity, &file), Ok(original));
    }

    #[test]
    fn every_bit_flip_is_rejected() {
        let identity = VaultIdentity::generate();
        let file = seal_approval_state(&identity, &state(VaultId::new_random())).unwrap();
        (0..file.len() * 8).for_each(|bit| {
            let mut flipped = file.clone();
            flipped[bit / 8] ^= 1 << (bit % 8);
            let expected = match bit / 8 {
                0..4 => ApprovalDecodeError::BadMagic.into(),
                4 => ApprovalDecodeError::UnknownFormatVersion(FILE_VERSION ^ 1 << (bit % 8)).into(),
                _ => ApprovalStateError::Damaged,
            };
            assert_eq!(open_approval_state(&identity, &flipped), Err(expected), "bit {bit}");
        });
    }

    #[test]
    fn a_state_from_another_vault_identity_is_damaged() {
        let file = seal_approval_state(&VaultIdentity::generate(), &state(VaultId::new_random())).unwrap();
        assert_eq!(open_approval_state(&VaultIdentity::generate(), &file), Err(ApprovalStateError::Damaged));
    }

    #[test]
    fn a_payload_naming_another_vault_is_rejected() {
        let identity = VaultIdentity::generate();
        let payload = encoding::encode(&state(VaultId::new_random()));
        let file = forged(&identity, VaultId::new_random(), &payload, &identity.derive_key(APPROVAL_KEY_PERSONA));
        assert_eq!(open_approval_state(&identity, &file), Err(ApprovalStateError::VaultIdMismatch));
    }

    #[test]
    fn a_broken_invariant_behind_a_valid_mac_is_rejected() {
        let identity = VaultIdentity::generate();
        let mut payload = encoding::encode(&state(VaultId::new_random()));
        // Highest reserved is the u64 at 62..70 (see the payload layout); 1 is below the committed version 2.
        payload[62..70].copy_from_slice(&1u64.to_be_bytes());
        let id = VaultId::from_bytes(payload[5..21].try_into().unwrap()).unwrap();
        let file = forged(&identity, id, &payload, &identity.derive_key(APPROVAL_KEY_PERSONA));
        assert_eq!(open_approval_state(&identity, &file), Err(ApprovalStateError::CommittedNotReserved));
    }

    #[test]
    fn a_weak_approver_key_behind_a_valid_mac_is_rejected() {
        let identity = VaultIdentity::generate();
        let mut payload = encoding::encode(&state(VaultId::new_random()));
        // The public key is the 32 bytes at 30..62; the identity point is small-order.
        payload[30..62].copy_from_slice(&[[1u8].as_slice(), &[0; 31]].concat());
        let id = VaultId::from_bytes(payload[5..21].try_into().unwrap()).unwrap();
        let file = forged(&identity, id, &payload, &identity.derive_key(APPROVAL_KEY_PERSONA));
        let weak = ApprovalStateError::InvalidApproverKey { algorithm: SignatureAlgorithm::Ed25519, reason: InvalidKeyReason::WeakKey };
        assert_eq!(open_approval_state(&identity, &file), Err(weak));
    }

    #[test]
    fn authentic_ciphertext_that_does_not_open_is_reported() {
        let identity = VaultIdentity::generate();
        let mut file = [&FILE_MAGIC[..], &[FILE_VERSION], VaultId::new_random().as_bytes(), b"not age"].concat();
        let tag: [u8; MAC_LEN] = mac(&identity, &file).finalize().into_bytes().into();
        file.extend_from_slice(&tag);
        assert_eq!(open_approval_state(&identity, &file), Err(ApprovalStateError::Sealed(OpenError::Malformed)));
    }

    #[test]
    fn oversized_and_short_files_are_rejected_before_any_key_work() {
        let identity = VaultIdentity::generate();
        let huge = vec![0; MAX_APPROVAL_STATE_LEN + 1];
        assert_eq!(open_approval_state(&identity, &huge), Err(ApprovalStateError::TooLarge { limit: MAX_APPROVAL_STATE_LEN }));
        let truncated = ApprovalStateError::Format(ApprovalDecodeError::Truncated);
        (0..HEADER_LEN + MAC_LEN)
            .map(|len| [&FILE_MAGIC[..], &[FILE_VERSION], &[0; 64]].concat()[..len].to_vec())
            .for_each(|short| assert_eq!(open_approval_state(&identity, &short), Err(truncated.clone()), "{}", short.len()));
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = open_approval_state(&VaultIdentity::generate(), &bytes);
        }

        #[test]
        fn arbitrary_bytes_behind_a_valid_header_never_panic(tail in proptest::collection::vec(any::<u8>(), 0..512)) {
            let file = [&FILE_MAGIC[..], &[FILE_VERSION], VaultId::new_random().as_bytes(), &tail].concat();
            prop_assert!(open_approval_state(&VaultIdentity::generate(), &file).is_err());
        }
    }
}
