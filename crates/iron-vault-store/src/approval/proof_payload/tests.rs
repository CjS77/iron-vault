//! The presence and migration proof payloads: the documented examples, and a refusal for every malformed input.

use proptest::prelude::*;

use super::*;
use crate::VaultIdError;

/// The documented presence payload: vault `3f2b8c1e-…`, approver `5b0e9a1c-…`, nonce `00 01 … 1f`.
const PRESENCE_HEX: &str = "49565050 01 3f2b8c1e5d4a4e6f9a7b1c2d3e4f5a6b 5b0e9a1c7d2f4e83b6a40c1d2e3f4a5b \
                            000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

/// The documented migration proof payload: binding digest `20 21 … 3f`.
const MIGRATION_PROOF_HEX: &str = "49564d41 01 202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";

/// Where the vault ID and approver ID sit in a presence payload.
const VAULT_ID_AT: usize = 5;
const APPROVER_ID_AT: usize = 21;

fn unhex(hex: &str) -> Vec<u8> {
    let digits: String = hex.split_whitespace().collect();
    (0..digits.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&digits[i..i + 2], 16).unwrap())
        .collect()
}

fn presence() -> PresencePayload {
    let vault_id = VaultId::from_bytes(unhex("3f2b8c1e5d4a4e6f9a7b1c2d3e4f5a6b").try_into().unwrap()).unwrap();
    let approver_id = ApproverId::from_bytes(unhex("5b0e9a1c7d2f4e83b6a40c1d2e3f4a5b").try_into().unwrap()).unwrap();
    PresencePayload::new(vault_id, approver_id, std::array::from_fn(|i| i as u8))
}

fn migration_proof() -> MigrationProofPayload {
    MigrationProofPayload::new(std::array::from_fn(|i| 0x20 + i as u8))
}

/// The `text` block of the storage formats' section `heading`, as hex: comments start past column 48.
fn documented(heading: &str) -> String {
    let doc = include_str!("../../../../../design/storage-formats.md");
    let section = doc.split(heading).nth(1).unwrap();
    let block = section.split("```text\n").nth(1).unwrap().split("```").next().unwrap();
    block
        .lines()
        .flat_map(|line| line.chars().take(48))
        .filter(|c| !c.is_whitespace())
        .collect()
}

#[test]
fn documented_examples_are_the_ones_in_the_storage_formats() {
    assert_eq!(
        documented("## Presence payload v1"),
        PRESENCE_HEX.split_whitespace().collect::<String>()
    );
    assert_eq!(
        documented("## Migration proof payload v1"),
        MIGRATION_PROOF_HEX.split_whitespace().collect::<String>()
    );
}

#[test]
fn documented_presence_example_round_trips() {
    let bytes = unhex(PRESENCE_HEX);
    assert_eq!(bytes.len(), 69);
    assert_eq!(presence().encode(), bytes);
    let decoded = PresencePayload::decode(&bytes).unwrap();
    assert_eq!(decoded, presence());
    assert_eq!(decoded.vault_id().as_bytes(), &bytes[VAULT_ID_AT..APPROVER_ID_AT]);
    assert_eq!(decoded.approver_id().as_bytes(), &bytes[APPROVER_ID_AT..37]);
    assert_eq!(decoded.nonce(), &bytes[37..]);
}

#[test]
fn documented_migration_proof_example_round_trips() {
    let bytes = unhex(MIGRATION_PROOF_HEX);
    assert_eq!(bytes.len(), 37);
    assert_eq!(migration_proof().encode(), bytes);
    let decoded = MigrationProofPayload::decode(&bytes).unwrap();
    assert_eq!(decoded, migration_proof());
    assert_eq!(decoded.binding_digest(), &bytes[5..]);
}

/// Each payload refuses the other's magic and the approval payload's, so no signature can be read as another kind.
#[test]
fn wrong_magic_and_unknown_versions_are_rejected() {
    let presence = unhex(PRESENCE_HEX);
    let proof = unhex(MIGRATION_PROOF_HEX);
    let with = |bytes: &[u8], at: usize, value: &[u8]| {
        let mut changed = bytes.to_vec();
        changed.splice(at..at + value.len(), value.iter().copied());
        changed
    };
    [b"IVMA", b"IVAP", b"IVPQ"].into_iter().for_each(|magic| {
        assert_eq!(
            PresencePayload::decode(&with(&presence, 0, magic)),
            Err(ApprovalDecodeError::BadMagic)
        )
    });
    [b"IVPP", b"IVAP", b"IVMB"].into_iter().for_each(|magic| {
        assert_eq!(
            MigrationProofPayload::decode(&with(&proof, 0, magic)),
            Err(ApprovalDecodeError::BadMagic)
        );
    });
    [0u8, 2, 0xff].into_iter().for_each(|version| {
        assert_eq!(
            PresencePayload::decode(&with(&presence, 4, &[version])),
            Err(ApprovalDecodeError::UnknownFormatVersion(version))
        );
        assert_eq!(
            MigrationProofPayload::decode(&with(&proof, 4, &[version])),
            Err(ApprovalDecodeError::UnknownFormatVersion(version))
        );
    });
}

#[test]
fn ids_that_are_not_version_4_uuids_are_rejected() {
    let mut bytes = unhex(PRESENCE_HEX);
    // The version nibble of each UUID sits in its seventh byte.
    bytes[VAULT_ID_AT + 6] = 0x1e;
    assert_eq!(PresencePayload::decode(&bytes), Err(VaultIdError::NotVersion4.into()));
    let mut bytes = unhex(PRESENCE_HEX);
    bytes[APPROVER_ID_AT + 6] = 0x1e;
    assert_eq!(PresencePayload::decode(&bytes), Err(ApprovalDecodeError::InvalidApproverId));
}

#[test]
fn every_truncation_and_trailing_bytes_are_rejected() {
    let presence = unhex(PRESENCE_HEX);
    (0..presence.len()).for_each(|len| {
        assert_eq!(
            PresencePayload::decode(&presence[..len]),
            Err(ApprovalDecodeError::Truncated),
            "{len}"
        );
    });
    let proof = unhex(MIGRATION_PROOF_HEX);
    (0..proof.len()).for_each(|len| {
        assert_eq!(
            MigrationProofPayload::decode(&proof[..len]),
            Err(ApprovalDecodeError::Truncated),
            "{len}"
        );
    });
    assert_eq!(
        PresencePayload::decode(&[&presence[..], &[0]].concat()),
        Err(ApprovalDecodeError::TrailingBytes)
    );
    assert_eq!(
        MigrationProofPayload::decode(&[&proof[..], &[0]].concat()),
        Err(ApprovalDecodeError::TrailingBytes)
    );
}

proptest! {
    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..128)) {
        let _ = PresencePayload::decode(&bytes);
        let _ = MigrationProofPayload::decode(&bytes);
    }

    #[test]
    fn any_payload_round_trips(nonce in any::<[u8; 32]>(), digest in any::<[u8; 32]>()) {
        let payload = PresencePayload::new(presence().vault_id(), presence().approver_id(), nonce);
        prop_assert_eq!(PresencePayload::decode(&payload.encode()), Ok(payload));
        let proof = MigrationProofPayload::new(digest);
        prop_assert_eq!(MigrationProofPayload::decode(&proof.encode()), Ok(proof));
    }
}
