//! The vault manifest: the service's own index of which credential records exist (spec §3.3, §3.10).
//!
//! `age` does not authenticate the sender, so anyone holding the vault public key can plant a well-formed record file.
//! The manifest names every record the service wrote and the digest of its file, so a planted, swapped or deleted record
//! is detected. The manifest is sealed to the same public key and therefore carries a MAC keyed from the vault identity:
//! only the service, holding the private identity, can write one that opens. The file layout and the MAC construction
//! are in `design/storage-formats.md`.

mod encoding;

use std::collections::{BTreeMap, BTreeSet};

use blake2::digest::{KeyInit, Mac, consts::U32};
use blake2::{Blake2b256, Blake2bMac, Digest};
use iron_vault_policy::{CredentialName, NameError};
use thiserror::Error;

use crate::record_id::{RecordId, RecordIdError};
use crate::sealed::{self, OpenError, SealError};
use crate::vault_id::{VaultId, VaultIdError};
use crate::vault_identity::VaultIdentity;

/// The largest manifest file accepted, in bytes on disk, checked before any other work.
///
/// A full manifest holds [`MAX_MANIFEST_ENTRIES`] entries of at most 120 bytes each (16-byte record ID, 8-byte name
/// length, 64-byte name, 32-byte digest), so its payload is under 492,000 bytes. `age` adds a few hundred header bytes
/// and 16 bytes per 64 KiB chunk, and the file adds 53 bytes of header and MAC: a full manifest is under half this limit.
pub const MAX_MANIFEST_LEN: usize = 1 << 20;

/// The most entries one manifest may hold, so every manifest the service can build also fits [`MAX_MANIFEST_LEN`].
pub const MAX_MANIFEST_ENTRIES: usize = 4096;

/// The first bytes of every manifest file, so a file of another type is never read as a manifest.
const FILE_MAGIC: [u8; 4] = *b"IVMF";
/// The manifest file version this code writes and the only one it reads; it fixes the MAC construction.
const FILE_VERSION: u8 = 1;
/// Magic, version and vault ID, in clear and covered by the MAC.
const HEADER_LEN: usize = FILE_MAGIC.len() + 1 + 16;
/// The length of the trailing MAC.
const MAC_LEN: usize = 32;
/// Prefixed to the MAC input so a MAC under the manifest key can never be mistaken for one over other data.
const MAC_DOMAIN_TAG: &[u8] = b"iron-vault manifest file v1 mac\0";

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
    let ciphertext = sealed::seal(&identity.public_key(), &encoding::encode(manifest))?;
    let mut file = Vec::with_capacity(HEADER_LEN + ciphertext.len() + MAC_LEN);
    file.extend_from_slice(&FILE_MAGIC);
    file.push(FILE_VERSION);
    file.extend_from_slice(manifest.vault_id.as_bytes());
    file.extend_from_slice(&ciphertext);
    let tag: [u8; MAC_LEN] = mac(identity, &file).finalize().into_bytes().into();
    file.extend_from_slice(&tag);
    Ok(file)
}

/// The manifest a file holds, after its size, header and MAC are checked and before anything is decrypted.
pub fn open_manifest(identity: &VaultIdentity, file: &[u8]) -> Result<VaultManifest, ManifestError> {
    if file.len() > MAX_MANIFEST_LEN {
        return Err(ManifestError::TooLarge { limit: MAX_MANIFEST_LEN });
    }
    let (signed, tag) = file.split_at_checked(file.len().saturating_sub(MAC_LEN)).ok_or(ManifestError::Truncated)?;
    let (header, ciphertext) = signed.split_at_checked(HEADER_LEN).ok_or(ManifestError::Truncated)?;
    let vault_id = read_header(header)?;
    mac(identity, signed).verify_slice(tag).map_err(|_| ManifestError::Damaged)?;
    let vault_id = VaultId::from_bytes(vault_id)?;
    let manifest = encoding::decode(&sealed::open(identity, ciphertext, MAX_MANIFEST_LEN)?)?;
    match manifest.vault_id == vault_id {
        true => Ok(manifest),
        false => Err(ManifestError::VaultIdMismatch),
    }
}

/// The header's vault ID bytes, after its magic and version. The version is read before the MAC is checked because it
/// decides how the MAC is computed; the ID is not trusted until the MAC passes.
fn read_header(header: &[u8]) -> Result<[u8; 16], ManifestError> {
    let (magic, rest) = header.split_at_checked(FILE_MAGIC.len()).ok_or(ManifestError::Truncated)?;
    if magic != FILE_MAGIC {
        return Err(ManifestError::BadMagic);
    }
    match rest {
        [FILE_VERSION, id @ ..] => id.try_into().map_err(|_| ManifestError::Truncated),
        [version, ..] => Err(ManifestError::UnknownVersion(*version)),
        [] => Err(ManifestError::Truncated),
    }
}

/// The keyed BLAKE2b-256 MAC over the domain tag and `signed`, the file's header and ciphertext.
fn mac(identity: &VaultIdentity, signed: &[u8]) -> Blake2bMac<U32> {
    keyed_mac(&identity.manifest_key(), signed)
}

fn keyed_mac(key: &[u8; 64], signed: &[u8]) -> Blake2bMac<U32> {
    <Blake2bMac<U32> as KeyInit>::new(key.into()).chain_update(MAC_DOMAIN_TAG).chain_update(signed)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

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
        [[0; 64], [0x5a; 64], *VaultIdentity::generate().manifest_key()].iter().for_each(|key| {
            let file = forged(&identity, original.vault_id(), &payload, key);
            assert_eq!(open_manifest(&identity, &file), Err(ManifestError::Damaged));
        });
        // The same construction under the real key opens, so the refusal above is the MAC's doing.
        let file = forged(&identity, original.vault_id(), &payload, &identity.manifest_key());
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
        let file = forged(&identity, id, &payload, &identity.manifest_key());
        assert_eq!(open_manifest(&identity, &file), Err(ManifestError::DuplicateName("fx_key".parse().unwrap())));
    }

    #[test]
    fn a_payload_naming_another_vault_is_rejected() {
        let identity = VaultIdentity::generate();
        let payload = encoding::encode(&manifest(VaultId::new_random()));
        let file = forged(&identity, VaultId::new_random(), &payload, &identity.manifest_key());
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
        let hex: String = record_digest(b"").iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, empty);
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
