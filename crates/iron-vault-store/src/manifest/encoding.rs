//! The manifest payload v1 encoding: the plaintext a manifest file seals (`design/storage-formats.md`).

use std::collections::BTreeMap;

use iron_vault_policy::CredentialName;

use super::{MAX_MANIFEST_ENTRIES, ManifestEntry, ManifestError, VaultManifest};
use crate::record_id::RecordId;
use crate::state_generation::StateGeneration;
use crate::vault_id::VaultId;
use crate::wire::{Reader, WireError};

/// The first bytes of every manifest payload, distinct from the file magic so neither is read as the other.
const MAGIC: [u8; 4] = *b"IVMP";
/// The payload version this code writes and the only one it reads.
const VERSION: u8 = 1;

/// The manifest's v1 payload. Entries are written in ascending record ID order, so a manifest has one encoding.
pub(super) fn encode(manifest: &VaultManifest) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.extend_from_slice(manifest.vault_id.as_bytes());
    out.extend_from_slice(&manifest.state_generation.get().to_be_bytes());
    // No state generation is 0, so 0 is free to mean that no approval state had been written.
    out.extend_from_slice(&manifest.peer_generation.map_or(0, StateGeneration::get).to_be_bytes());
    put_len(&mut out, manifest.entries.len());
    manifest.entries.iter().for_each(|(id, entry)| {
        out.extend_from_slice(id.as_bytes());
        put_len(&mut out, entry.name.as_str().len());
        out.extend_from_slice(entry.name.as_str().as_bytes());
        out.extend_from_slice(&entry.file_digest);
    });
    out
}

/// The manifest a v1 payload holds, accepted only if it is that manifest's one encoding.
pub(super) fn decode(payload: &[u8]) -> Result<VaultManifest, ManifestError> {
    let mut reader = Reader::new(payload);
    if reader.take(MAGIC.len())? != MAGIC {
        return Err(ManifestError::BadMagic);
    }
    match reader.u8()? {
        VERSION => decode_v1(&mut reader),
        version => Err(ManifestError::UnknownVersion(version)),
    }
}

fn decode_v1(reader: &mut Reader<'_>) -> Result<VaultManifest, ManifestError> {
    let vault_id = VaultId::from_bytes(reader.array()?)?;
    let state_generation = StateGeneration::new(reader.u64()?).ok_or(ManifestError::ZeroStateGeneration)?;
    let peer_generation = StateGeneration::new(reader.u64()?);
    let entries = read_entries(reader)?;
    reader.finish()?;
    VaultManifest::new(vault_id, state_generation, peer_generation, entries)
}

/// Writes a length as a `u64`. `usize` is at most 64 bits on every Rust target, so the widening cast is lossless.
fn put_len(out: &mut Vec<u8>, len: usize) {
    out.extend_from_slice(&(len as u64).to_be_bytes());
}

/// Reads the entries, requiring record IDs strictly ascending; [`VaultManifest::new`] then checks names are unique.
fn read_entries(reader: &mut Reader<'_>) -> Result<BTreeMap<RecordId, ManifestEntry>, ManifestError> {
    let count = reader.len()?;
    if count > MAX_MANIFEST_ENTRIES {
        return Err(ManifestError::TooManyEntries {
            limit: MAX_MANIFEST_ENTRIES,
        });
    }
    (0..count).try_fold(BTreeMap::new(), |mut entries, _| {
        let (id, entry) = read_entry(reader)?;
        match entries.last_key_value() {
            Some((last, _)) if *last == id => return Err(ManifestError::DuplicateRecordId),
            Some((last, _)) if *last > id => return Err(ManifestError::UnsortedEntries),
            _ => entries.insert(id, entry),
        };
        Ok(entries)
    })
}

fn read_entry(reader: &mut Reader<'_>) -> Result<(RecordId, ManifestEntry), ManifestError> {
    let id = RecordId::from_bytes(reader.array()?)?;
    let name = std::str::from_utf8(reader.field()?).map_err(|_| ManifestError::NameNotUtf8)?;
    let name = CredentialName::try_from(name)?;
    Ok((id, ManifestEntry::new(name, reader.array()?)))
}

impl From<WireError> for ManifestError {
    fn from(error: WireError) -> Self {
        match error {
            WireError::Truncated => ManifestError::Truncated,
            WireError::LengthPastEnd => ManifestError::LengthPastEnd,
            WireError::TrailingBytes => ManifestError::TrailingBytes,
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::record_id::RecordIdError;
    use crate::vault_id::VaultIdError;

    const VAULT: &str = "3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b";
    const RECORD: &str = "7c9e6679-7425-40de-944b-e07fc1f90ae7";
    const LATER_RECORD: &str = "9d4f0b52-0c6e-4b1a-8f3d-2a7e5c9b1d04";

    /// The 16 bytes of a UUID; vault and record IDs share the form.
    fn uuid_bytes(text: &str) -> [u8; 16] {
        *text.parse::<RecordId>().unwrap().as_bytes()
    }

    fn vault_id() -> VaultId {
        VaultId::from_bytes(uuid_bytes(VAULT)).unwrap()
    }

    /// Hand-assembled payloads, so each rejection test can break exactly one field.
    struct Payload(Vec<u8>);

    impl Payload {
        /// A header at state generation 3 with peer generation 2, as in the documented example.
        fn header(count: u64) -> Self {
            Self::header_at(3, 2, count)
        }

        fn header_at(state_generation: u64, peer_generation: u64, count: u64) -> Self {
            let bytes = [
                &b"IVMP\x01"[..],
                &uuid_bytes(VAULT),
                &state_generation.to_be_bytes(),
                &peer_generation.to_be_bytes(),
                &count.to_be_bytes(),
            ]
            .concat();
            Payload(bytes)
        }

        fn raw(mut self, bytes: &[u8]) -> Self {
            self.0.extend_from_slice(bytes);
            self
        }

        fn entry(self, id: &str, name: &[u8], digest: u8) -> Self {
            self.raw(&uuid_bytes(id))
                .raw(&(name.len() as u64).to_be_bytes())
                .raw(name)
                .raw(&[digest; 32])
        }

        fn valid() -> Self {
            Self::header(1).entry(RECORD, b"fx_key", 0x11)
        }

        fn decode(&self) -> Result<VaultManifest, ManifestError> {
            decode(&self.0)
        }
    }

    fn generation(value: u64) -> StateGeneration {
        StateGeneration::new(value).unwrap()
    }

    fn manifest(entries: &[(&str, &str, u8)]) -> VaultManifest {
        let entries = entries
            .iter()
            .map(|(id, name, d)| (id.parse().unwrap(), ManifestEntry::new(name.parse().unwrap(), [*d; 32])));
        VaultManifest::new(vault_id(), generation(3), Some(generation(2)), entries.collect()).unwrap()
    }

    #[test]
    fn round_trip_preserves_every_field() {
        let original = manifest(&[(LATER_RECORD, "brave", 2), (RECORD, "fx_key", 0x11)]);
        assert_eq!(decode(&encode(&original)), Ok(original));
    }

    #[test]
    fn encoding_is_deterministic_and_independent_of_insertion_order() {
        let forward = manifest(&[(RECORD, "fx_key", 1), (LATER_RECORD, "brave", 2)]);
        let backward = manifest(&[(LATER_RECORD, "brave", 2), (RECORD, "fx_key", 1)]);
        assert_eq!(encode(&forward), encode(&backward));
        let expected = Payload::header(2).entry(RECORD, b"fx_key", 1).entry(LATER_RECORD, b"brave", 2);
        assert_eq!(encode(&forward), expected.0);
    }

    /// The example in `design/storage-formats.md`, byte for byte.
    #[test]
    fn documented_example_decodes() {
        let hex = "49564d50 01 3f2b8c1e5d4a4e6f9a7b1c2d3e4f5a6b 0000000000000003 0000000000000002 0000000000000001 \
                   7c9e6679742540de944be07fc1f90ae7 0000000000000006 66785f6b6579 \
                   1111111111111111111111111111111111111111111111111111111111111111";
        let bytes: Vec<u8> = hex
            .split_whitespace()
            .flat_map(|group| {
                (0..group.len())
                    .step_by(2)
                    .map(move |i| u8::from_str_radix(&group[i..i + 2], 16).unwrap())
            })
            .collect();
        assert_eq!(bytes, Payload::valid().0);
        assert_eq!(encode(&decode(&bytes).unwrap()), bytes);
    }

    #[test]
    fn a_zero_state_generation_is_rejected_and_a_zero_peer_generation_is_none() {
        let zero = Payload::header_at(0, 0, 1).entry(RECORD, b"fx_key", 0x11);
        assert_eq!(zero.decode(), Err(ManifestError::ZeroStateGeneration));
        let first = Payload::header_at(1, 0, 0).decode().unwrap();
        assert_eq!((first.state_generation(), first.peer_generation()), (StateGeneration::FIRST, None));
        assert_eq!(encode(&first), Payload::header_at(1, 0, 0).0);
    }

    #[test]
    fn a_peer_generation_not_below_the_state_generation_is_rejected() {
        [(3, 3), (3, 4), (u64::MAX, u64::MAX)].into_iter().for_each(|(state, peer)| {
            let payload = Payload::header_at(state, peer, 0);
            assert_eq!(payload.decode(), Err(ManifestError::PeerNotOlder), "{state} {peer}");
        });
        assert!(Payload::header_at(4, 3, 0).decode().is_ok());
    }

    #[test]
    fn wrong_magic_and_unknown_versions_are_rejected() {
        let mut bad_magic = Payload::valid();
        bad_magic.0[0] = b'X';
        assert_eq!(bad_magic.decode(), Err(ManifestError::BadMagic));
        let mut v2 = Payload::valid();
        v2.0[4] = 2;
        assert_eq!(v2.decode(), Err(ManifestError::UnknownVersion(2)));
    }

    #[test]
    fn every_truncation_and_trailing_bytes_are_rejected() {
        let full = Payload::valid().0;
        (0..full.len()).for_each(|len| {
            let err = decode(&full[..len]);
            assert!(
                matches!(err, Err(ManifestError::Truncated | ManifestError::LengthPastEnd)),
                "{len}: {err:?}"
            );
        });
        assert_eq!(Payload::valid().raw(&[0]).decode(), Err(ManifestError::TrailingBytes));
    }

    #[test]
    fn counts_and_lengths_past_the_end_are_rejected() {
        assert_eq!(Payload::header(u64::MAX).decode(), Err(ManifestError::LengthPastEnd));
        let long_name = Payload::header(1).raw(&uuid_bytes(RECORD)).raw(&u64::MAX.to_be_bytes());
        assert_eq!(long_name.decode(), Err(ManifestError::LengthPastEnd));
        let count = MAX_MANIFEST_ENTRIES as u64 + 1;
        let too_many = Payload::header(count).raw(&vec![0; MAX_MANIFEST_ENTRIES * 64]);
        assert_eq!(
            too_many.decode(),
            Err(ManifestError::TooManyEntries {
                limit: MAX_MANIFEST_ENTRIES
            })
        );
    }

    #[test]
    fn invalid_ids_are_rejected() {
        let mut vault = Payload::valid();
        vault.0[5..21].fill(0);
        assert_eq!(vault.decode(), Err(ManifestError::InvalidVaultId(VaultIdError::NotVersion4)));
        let mut record = Payload::valid();
        record.0[45..61].fill(0);
        assert_eq!(record.decode(), Err(ManifestError::InvalidRecordId(RecordIdError::NotVersion4)));
    }

    #[test]
    fn invalid_names_are_rejected() {
        assert!(matches!(
            Payload::header(1).entry(RECORD, b"Fx", 0).decode(),
            Err(ManifestError::InvalidName(_))
        ));
        assert_eq!(
            Payload::header(1).entry(RECORD, &[0xff], 0).decode(),
            Err(ManifestError::NameNotUtf8)
        );
    }

    #[test]
    fn duplicate_names_and_record_ids_and_unsorted_entries_are_rejected() {
        let names = Payload::header(2).entry(RECORD, b"fx_key", 1).entry(LATER_RECORD, b"fx_key", 2);
        assert_eq!(names.decode(), Err(ManifestError::DuplicateName("fx_key".parse().unwrap())));
        let ids = Payload::header(2).entry(RECORD, b"fx_key", 1).entry(RECORD, b"brave", 2);
        assert_eq!(ids.decode(), Err(ManifestError::DuplicateRecordId));
        let unsorted = Payload::header(2).entry(LATER_RECORD, b"brave", 2).entry(RECORD, b"fx_key", 1);
        assert_eq!(unsorted.decode(), Err(ManifestError::UnsortedEntries));
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = decode(&bytes);
        }

        #[test]
        fn mutated_valid_payloads_never_panic(index in any::<prop::sample::Index>(), byte in any::<u8>()) {
            let mut payload = Payload::valid().0;
            let at = index.index(payload.len());
            payload[at] = byte;
            let _ = decode(&payload);
        }
    }
}
