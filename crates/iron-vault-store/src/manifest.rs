//! The vault manifest: the service's own index of which credential records exist (spec §3.3, §3.10).
//!
//! `age` does not authenticate the sender, so anyone holding the vault public key can plant a well-formed record file.
//! The manifest names every record the service wrote and the digest of its file, so a planted, swapped or deleted record
//! is detected. The manifest is sealed to the same public key and therefore carries a MAC keyed from the vault identity:
//! only the service, holding the private identity, can write one that opens. The file layout and the MAC construction
//! are in `design/storage-formats.md`.

mod encoding;

use std::collections::{BTreeMap, BTreeSet};

use blake2::{Blake2b256, Digest};
use iron_vault_policy::{CredentialName, NameError};
use thiserror::Error;

use crate::mac_file::MacFileKind;
use crate::record_id::{RecordId, RecordIdError};
use crate::sealed::{OpenError, SealError};
use crate::vault_id::{VaultId, VaultIdError};
use crate::vault_identity::VaultIdentity;

/// The largest manifest file accepted, in bytes on disk, checked before any other work.
///
/// A full manifest holds [`MAX_MANIFEST_ENTRIES`] entries of at most 120 bytes each (16-byte record ID, 8-byte name
/// length, 64-byte name, 32-byte digest), so its payload is under 492,000 bytes. `age` adds a few hundred header bytes
/// plus one 16-byte payload nonce and a 16-byte tag per 64 KiB chunk, and the file adds 53 bytes of header and MAC: a
/// full manifest is under half this limit.
pub const MAX_MANIFEST_LEN: usize = 1 << 20;

/// The most entries one manifest may hold, so every manifest the service can build also fits [`MAX_MANIFEST_LEN`].
pub const MAX_MANIFEST_ENTRIES: usize = 4096;

/// The BLAKE2b personalization of the manifest key, which keeps it independent of any other key derived from the
/// vault identity.
pub(crate) const MANIFEST_KEY_PERSONA: &[u8] = b"iv-manifest-v1";
/// The manifest's MAC'd file frame: magic `IVMF`, version 1, its own key persona and domain tag.
const KIND: MacFileKind<ManifestError> = MacFileKind {
    magic: *b"IVMF",
    version: 1,
    persona: MANIFEST_KEY_PERSONA,
    domain_tag: b"iron-vault manifest file v1 mac\0",
    max_len: MAX_MANIFEST_LEN,
    too_large: ManifestError::TooLarge { limit: MAX_MANIFEST_LEN },
    truncated: ManifestError::Truncated,
    bad_magic: ManifestError::BadMagic,
    unknown_version: ManifestError::UnknownVersion,
    damaged: ManifestError::Damaged,
    invalid_vault_id: ManifestError::InvalidVaultId,
};

/// One record the manifest vouches for: its credential name and the digest of its file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestEntry {
    name: CredentialName,
    file_digest: [u8; 32],
}

impl ManifestEntry {
    /// An entry for the record file whose ciphertext has digest `file_digest` (see [`record_digest`]).
    pub fn new(name: CredentialName, file_digest: [u8; 32]) -> Self {
        Self { name, file_digest }
    }

    /// The credential name the record holds.
    pub fn name(&self) -> &CredentialName {
        &self.name
    }

    /// The BLAKE2b-256 digest of the record file's ciphertext bytes.
    pub fn file_digest(&self) -> &[u8; 32] {
        &self.file_digest
    }
}

/// The set of records a vault holds, at one generation.
///
/// Names are unique across entries and there are at most [`MAX_MANIFEST_ENTRIES`], whether the manifest was built or
/// decoded. The generation increases by one with every write, so a stale copy can be told from the current one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultManifest {
    vault_id: VaultId,
    generation: u64,
    entries: BTreeMap<RecordId, ManifestEntry>,
}

/// A manifest cannot be built or opened. No variant carries key material or MAC bytes.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ManifestError {
    /// The file is larger than [`MAX_MANIFEST_LEN`]; nothing else was read.
    #[error("vault manifest exceeds the {limit}-byte limit")]
    TooLarge {
        /// The limit that was exceeded.
        limit: usize,
    },
    /// The file or payload ends inside a fixed-width field.
    #[error("vault manifest is truncated")]
    Truncated,
    /// The file or payload does not start with the manifest magic.
    #[error("not a vault manifest")]
    BadMagic,
    /// The file or payload has a version this build cannot read.
    #[error("unknown vault manifest version {0}")]
    UnknownVersion(u8),
    /// The MAC does not match: the manifest was altered, or written by someone without this vault's identity.
    #[error("vault manifest failed its integrity check; it is damaged or was not written by this vault, and the vault may need recovery")]
    Damaged,
    /// The MAC matched but the ciphertext did not open.
    #[error("vault manifest ciphertext cannot be opened: {0}")]
    Sealed(#[from] OpenError),
    /// The payload names a different vault from the authenticated header.
    #[error("vault manifest payload belongs to a different vault from its header")]
    VaultIdMismatch,
    /// A length prefix or count reaches past the end of the payload.
    #[error("vault manifest field length runs past the end of the payload")]
    LengthPastEnd,
    /// Bytes follow the last entry.
    #[error("vault manifest payload has trailing bytes")]
    TrailingBytes,
    /// The vault ID is not a random version 4 UUID.
    #[error(transparent)]
    InvalidVaultId(#[from] VaultIdError),
    /// A record ID is not a random version 4 UUID.
    #[error(transparent)]
    InvalidRecordId(#[from] RecordIdError),
    /// A credential name is not UTF-8.
    #[error("vault manifest credential name is not UTF-8")]
    NameNotUtf8,
    /// A credential name breaks the name rule.
    #[error(transparent)]
    InvalidName(#[from] NameError),
    /// Two entries hold the same credential name.
    #[error("vault manifest lists credential {0} twice")]
    DuplicateName(CredentialName),
    /// Two entries have the same record ID.
    #[error("vault manifest lists a record ID twice")]
    DuplicateRecordId,
    /// The entries are not in ascending record ID order, so the payload is not the one encoding of its manifest.
    #[error("vault manifest entries are not in ascending record ID order")]
    UnsortedEntries,
    /// There are more than [`MAX_MANIFEST_ENTRIES`] entries.
    #[error("vault manifest has more than {limit} entries")]
    TooManyEntries {
        /// The limit that was exceeded.
        limit: usize,
    },
    /// The generation is already `u64::MAX`, so no later manifest can be written.
    #[error("vault manifest generation is exhausted")]
    GenerationExhausted,
}

impl VaultManifest {
    /// A manifest of `entries` at `generation`, refusing a repeated name or more than [`MAX_MANIFEST_ENTRIES`].
    pub fn new(vault_id: VaultId, generation: u64, entries: BTreeMap<RecordId, ManifestEntry>) -> Result<Self, ManifestError> {
        if entries.len() > MAX_MANIFEST_ENTRIES {
            return Err(ManifestError::TooManyEntries { limit: MAX_MANIFEST_ENTRIES });
        }
        entries.values().try_fold(BTreeSet::new(), |mut names, entry| match names.insert(&entry.name) {
            true => Ok(names),
            false => Err(ManifestError::DuplicateName(entry.name.clone())),
        })?;
        Ok(Self { vault_id, generation, entries })
    }

    /// The manifest to write after this one: the same vault, the next generation, and `entries`.
    pub fn next(&self, entries: BTreeMap<RecordId, ManifestEntry>) -> Result<Self, ManifestError> {
        let generation = self.generation.checked_add(1).ok_or(ManifestError::GenerationExhausted)?;
        Self::new(self.vault_id, generation, entries)
    }

    /// The vault this manifest indexes.
    pub fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    /// The write count this manifest was written at.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Every record the vault holds, by record ID.
    pub fn entries(&self) -> &BTreeMap<RecordId, ManifestEntry> {
        &self.entries
    }
}

/// The BLAKE2b-256 digest of a record file's ciphertext bytes, as a [`ManifestEntry`] stores it.
pub fn record_digest(ciphertext: &[u8]) -> [u8; 32] {
    Blake2b256::digest(ciphertext).into()
}

/// The manifest file's bytes: header, the payload sealed to the vault public key, then the MAC.
pub fn seal_manifest(identity: &VaultIdentity, manifest: &VaultManifest) -> Result<Vec<u8>, SealError> {
    KIND.seal(identity, manifest.vault_id, &encoding::encode(manifest))
}

/// The manifest a file holds, after its size, header and MAC are checked and before anything is decrypted.
pub fn open_manifest(identity: &VaultIdentity, file: &[u8]) -> Result<VaultManifest, ManifestError> {
    let (vault_id, payload) = KIND.open(identity, file)?;
    let manifest = encoding::decode(&payload)?;
    (manifest.vault_id == vault_id).then_some(manifest).ok_or(ManifestError::VaultIdMismatch)
}

#[cfg(test)]
pub(crate) mod tests {
    use blake2::Blake2bMac;
    use blake2::digest::{Mac, consts::U32};
    use proptest::prelude::*;

    use super::*;
    use crate::mac_file::{HEADER_LEN, MAC_LEN};
    use crate::sealed;

    const FILE_MAGIC: [u8; 4] = KIND.magic;
    const FILE_VERSION: u8 = KIND.version;

    /// The known-answer identity: the `age` secret-key text of the X25519 key bytes 01 02 … 20.
    pub(crate) const KAT_IDENTITY: &str = "AGE-SECRET-KEY-1QYPQXPQ9QCRSSZG2PVXQ6RS0ZQG3YYC5Z5TPWXQERGD3C8G7RUSQGPQYEE";
    /// The manifest key of [`KAT_IDENTITY`].
    pub(crate) const KAT_MANIFEST_KEY: &str =
        "54b3475d66332fd31a99dd0cf3632ec70381dbae5167db31dd4d13b3fb59a04f3a9171433d19abd09ad7e9adaa6f1e45c87291b03a6a76546702074436e7d75e";
    /// The MAC'd bytes of the known-answer file: header for vault 3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b, then the stand-in
    /// ciphertext `not really age`.
    const KAT_SIGNED: &str = "49564d46013f2b8c1e5d4a4e6f9a7b1c2d3e4f5a6b6e6f74207265616c6c7920616765";
    /// The MAC of [`KAT_SIGNED`] under [`KAT_MANIFEST_KEY`].
    const KAT_TAG: &str = "57773e0c4c341207ffc71eb80ccb19c399bab8042a1d3c9f38603af1c7cc1ab2";

    fn unhex(hex: &str) -> Vec<u8> {
        (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn mac(identity: &VaultIdentity, signed: &[u8]) -> Blake2bMac<U32> {
        keyed_mac(&identity.derive_key(MANIFEST_KEY_PERSONA), signed)
    }

    fn keyed_mac(key: &[u8; 64], signed: &[u8]) -> Blake2bMac<U32> {
        KIND.mac(key, signed)
    }

    fn entry(name: &str, digest: u8) -> ManifestEntry {
        ManifestEntry::new(name.parse().unwrap(), [digest; 32])
    }

    fn manifest(vault_id: VaultId) -> VaultManifest {
        let entries = [("fx_key", 1), ("brave", 2), ("venice", 3)].map(|(name, digest)| (RecordId::new_random(), entry(name, digest)));
        VaultManifest::new(vault_id, 7, entries.into()).unwrap()
    }

    /// A manifest file with the given header vault ID and payload, MACed under `key`: what anyone could build who
    /// holds the vault public key, plus whatever key they claim.
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
        let key: [u8; 64] = unhex(KAT_MANIFEST_KEY).try_into().unwrap();
        let signed = unhex(KAT_SIGNED);
        assert_eq!(&signed[..21], [&FILE_MAGIC[..], &[FILE_VERSION], &unhex("3f2b8c1e5d4a4e6f9a7b1c2d3e4f5a6b")].concat());
        assert_eq!(hex(&keyed_mac(&key, &signed).finalize().into_bytes()), KAT_TAG);
    }

    #[test]
    fn known_answers_are_published_in_the_storage_formats() {
        let doc: String = include_str!("../../../design/storage-formats.md").split_whitespace().collect();
        [KAT_IDENTITY, KAT_MANIFEST_KEY, KAT_SIGNED, KAT_TAG].iter().for_each(|kat| assert!(doc.contains(kat), "{kat}"));
    }

    #[test]
    fn round_trip_preserves_every_field() {
        let identity = VaultIdentity::generate();
        let original = manifest(VaultId::new_random());
        let opened = open_manifest(&identity, &seal_manifest(&identity, &original).unwrap()).unwrap();
        assert_eq!(opened, original);
        assert_eq!((opened.vault_id(), opened.generation(), opened.entries().len()), (original.vault_id(), 7, 3));
    }

    #[test]
    fn next_increments_the_generation_and_never_wraps() {
        let first = manifest(VaultId::new_random());
        let second = first.next(BTreeMap::new()).unwrap();
        assert_eq!((second.vault_id(), second.generation()), (first.vault_id(), 8));
        let last = VaultManifest::new(first.vault_id(), u64::MAX, BTreeMap::new()).unwrap();
        assert_eq!(last.next(BTreeMap::new()), Err(ManifestError::GenerationExhausted));
    }

    #[test]
    fn construction_rejects_duplicate_names_and_too_many_entries() {
        let entries = [(RecordId::new_random(), entry("fx_key", 1)), (RecordId::new_random(), entry("fx_key", 2))];
        let duplicate = VaultManifest::new(VaultId::new_random(), 1, entries.into());
        assert_eq!(duplicate, Err(ManifestError::DuplicateName("fx_key".parse().unwrap())));
        let many = (0..=MAX_MANIFEST_ENTRIES).map(|i| (RecordId::new_random(), entry(&format!("n{i}"), 0))).collect();
        let too_many = VaultManifest::new(VaultId::new_random(), 1, many);
        assert_eq!(too_many, Err(ManifestError::TooManyEntries { limit: MAX_MANIFEST_ENTRIES }));
    }

    #[test]
    fn a_full_manifest_fits_the_size_limit() {
        let identity = VaultIdentity::generate();
        // 64 bytes is the longest credential name.
        let entries = (0..MAX_MANIFEST_ENTRIES).map(|i| (RecordId::new_random(), entry(&format!("n{i:063}"), 9))).collect();
        let full = VaultManifest::new(VaultId::new_random(), u64::MAX, entries).unwrap();
        let file = seal_manifest(&identity, &full).unwrap();
        assert!(file.len() <= MAX_MANIFEST_LEN / 2, "{}", file.len());
        assert_eq!(open_manifest(&identity, &file), Ok(full));
    }

    #[test]
    fn a_manifest_forged_with_only_the_public_key_is_damaged() {
        let identity = VaultIdentity::generate();
        let original = manifest(VaultId::new_random());
        let payload = encoding::encode(&original);
        [[0; 64], [0x5a; 64], *VaultIdentity::generate().derive_key(MANIFEST_KEY_PERSONA)].iter().for_each(|key| {
            let file = forged(&identity, original.vault_id(), &payload, key);
            assert_eq!(open_manifest(&identity, &file), Err(ManifestError::Damaged));
        });
        // The same construction under the real key opens, so the refusal above is the MAC's doing.
        let file = forged(&identity, original.vault_id(), &payload, &identity.derive_key(MANIFEST_KEY_PERSONA));
        assert_eq!(open_manifest(&identity, &file), Ok(original));
    }

    #[test]
    fn every_bit_flip_is_rejected() {
        let identity = VaultIdentity::generate();
        let file = seal_manifest(&identity, &manifest(VaultId::new_random())).unwrap();
        (0..file.len() * 8).for_each(|bit| {
            let mut flipped = file.clone();
            flipped[bit / 8] ^= 1 << (bit % 8);
            let expected = match bit / 8 {
                0..4 => ManifestError::BadMagic,
                4 => ManifestError::UnknownVersion(FILE_VERSION ^ 1 << (bit % 8)),
                _ => ManifestError::Damaged,
            };
            assert_eq!(open_manifest(&identity, &flipped), Err(expected), "bit {bit}");
        });
    }

    #[test]
    fn a_manifest_from_another_vault_is_damaged() {
        let file = seal_manifest(&VaultIdentity::generate(), &manifest(VaultId::new_random())).unwrap();
        assert_eq!(open_manifest(&VaultIdentity::generate(), &file), Err(ManifestError::Damaged));
    }

    #[test]
    fn duplicate_names_are_rejected_after_the_mac_passes() {
        let identity = VaultIdentity::generate();
        let id = VaultId::new_random();
        let one = |name: &str| encoding::encode(&VaultManifest::new(id, 1, [(RecordId::new_random(), entry(name, 1))].into()).unwrap());
        let (a, b) = (one("fx_key"), one("fx_key"));
        // Splice b's entry into a and set the count to 2; the record IDs differ, so only the names collide. The count
        // starts at byte 29 and the first entry's record ID at 37 (see the payload layout).
        let mut ids = [a[37..53].to_vec(), b[37..53].to_vec()];
        ids.sort();
        let tail = &a[53..];
        let payload = [&a[..29], &2u64.to_be_bytes(), &ids[0], tail, &ids[1], tail].concat();
        let file = forged(&identity, id, &payload, &identity.derive_key(MANIFEST_KEY_PERSONA));
        assert_eq!(open_manifest(&identity, &file), Err(ManifestError::DuplicateName("fx_key".parse().unwrap())));
    }

    #[test]
    fn a_payload_naming_another_vault_is_rejected() {
        let identity = VaultIdentity::generate();
        let payload = encoding::encode(&manifest(VaultId::new_random()));
        let file = forged(&identity, VaultId::new_random(), &payload, &identity.derive_key(MANIFEST_KEY_PERSONA));
        assert_eq!(open_manifest(&identity, &file), Err(ManifestError::VaultIdMismatch));
    }

    #[test]
    fn authentic_ciphertext_that_does_not_open_is_reported() {
        let identity = VaultIdentity::generate();
        let id = VaultId::new_random();
        let mut file = [&FILE_MAGIC[..], &[FILE_VERSION], id.as_bytes(), b"not age"].concat();
        let tag: [u8; MAC_LEN] = mac(&identity, &file).finalize().into_bytes().into();
        file.extend_from_slice(&tag);
        assert_eq!(open_manifest(&identity, &file), Err(ManifestError::Sealed(OpenError::Malformed)));
    }

    #[test]
    fn oversized_and_short_files_are_rejected_before_any_key_work() {
        let identity = VaultIdentity::generate();
        let huge = vec![0; MAX_MANIFEST_LEN + 1];
        assert_eq!(open_manifest(&identity, &huge), Err(ManifestError::TooLarge { limit: MAX_MANIFEST_LEN }));
        (0..HEADER_LEN + MAC_LEN)
            .map(|len| [&FILE_MAGIC[..], &[FILE_VERSION], &[0; 64]].concat()[..len].to_vec())
            .for_each(|short| assert_eq!(open_manifest(&identity, &short), Err(ManifestError::Truncated), "{}", short.len()));
    }

    #[test]
    fn record_digest_is_blake2b_256() {
        let empty = "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8";
        assert_eq!(hex(&record_digest(b"")), empty);
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = open_manifest(&VaultIdentity::generate(), &bytes);
        }

        #[test]
        fn arbitrary_bytes_behind_a_valid_header_never_panic(tail in proptest::collection::vec(any::<u8>(), 0..512)) {
            let file = [&FILE_MAGIC[..], &[FILE_VERSION], VaultId::new_random().as_bytes(), &tail].concat();
            prop_assert!(open_manifest(&VaultIdentity::generate(), &file).is_err());
        }
    }
}
