//! The bundle header: the migration bundle's first entry and its format version gate.

use thiserror::Error;

use crate::{MAX_APPROVERS, MAX_MANIFEST_ENTRIES, VaultId};

/// The bundle format version this code writes and the only one it reads.
pub const BUNDLE_FORMAT_VERSION: u8 = 1;

/// The bundle header's length in bytes: magic, version, vault ID and two `u64` counts.
pub const BUNDLE_HEADER_LEN: usize = 37;

const MAGIC: [u8; 4] = *b"IVBH";
const VERSION_AT: usize = 4;
const VAULT_ID_AT: usize = 5;
const APPROVERS_AT: usize = 21;
const RECORDS_AT: usize = 29;

/// The vault ID and entry counts a migration bundle announces, valid on construction: from 1 to [`MAX_APPROVERS`]
/// approvers and at most [`MAX_MANIFEST_ENTRIES`] records.
///
/// It is not authenticated. It lets import refuse a foreign or oversized file before any prompt; import trusts none of
/// it until the files the vault identity opens agree with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BundleHeader {
    vault_id: VaultId,
    approver_count: usize,
    record_count: usize,
}

/// A bundle header that is malformed or out of range. The header is public, but the error carries no input either way.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BundleHeaderError {
    /// The entry is not exactly [`BUNDLE_HEADER_LEN`] bytes.
    #[error("bundle header is not {BUNDLE_HEADER_LEN} bytes")]
    WrongLength,
    /// The entry does not start with the magic `IVBH`.
    #[error("bundle header has the wrong magic")]
    WrongMagic,
    /// The bundle format version is not one this code reads.
    #[error("unknown bundle format version {0}")]
    UnknownVersion(u8),
    /// The vault ID is not a random version 4 UUID.
    #[error("bundle header vault ID is not a random version 4 UUID")]
    InvalidVaultId,
    /// The approver count is 0 or above [`MAX_APPROVERS`].
    #[error("bundle header approver count is out of range")]
    ApproverCount,
    /// The record count is above [`MAX_MANIFEST_ENTRIES`].
    #[error("bundle header record count is out of range")]
    RecordCount,
}

impl BundleHeader {
    /// A header for a vault with these counts, refusing counts no vault can have.
    pub fn new(vault_id: VaultId, approver_count: usize, record_count: usize) -> Result<Self, BundleHeaderError> {
        if !(1..=MAX_APPROVERS).contains(&approver_count) {
            return Err(BundleHeaderError::ApproverCount);
        }
        if record_count > MAX_MANIFEST_ENTRIES {
            return Err(BundleHeaderError::RecordCount);
        }
        Ok(Self {
            vault_id,
            approver_count,
            record_count,
        })
    }

    /// The vault the bundle claims to hold.
    pub fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    /// How many bundled approver keys the bundle holds.
    pub fn approver_count(&self) -> usize {
        self.approver_count
    }

    /// How many record files the bundle holds.
    pub fn record_count(&self) -> usize {
        self.record_count
    }

    /// The header's bytes, as the `bundle-header` entry holds them.
    pub fn encode(&self) -> [u8; BUNDLE_HEADER_LEN] {
        let mut bytes = [0; BUNDLE_HEADER_LEN];
        bytes[..VERSION_AT].copy_from_slice(&MAGIC);
        bytes[VERSION_AT] = BUNDLE_FORMAT_VERSION;
        bytes[VAULT_ID_AT..APPROVERS_AT].copy_from_slice(self.vault_id.as_bytes());
        bytes[APPROVERS_AT..RECORDS_AT].copy_from_slice(&(self.approver_count as u64).to_be_bytes());
        bytes[RECORDS_AT..].copy_from_slice(&(self.record_count as u64).to_be_bytes());
        bytes
    }

    /// The header in a `bundle-header` entry, refusing any length but [`BUNDLE_HEADER_LEN`], a wrong magic, an unknown
    /// version, a vault ID that is not a version 4 UUID and counts out of range.
    pub fn decode(bytes: &[u8]) -> Result<Self, BundleHeaderError> {
        let bytes: &[u8; BUNDLE_HEADER_LEN] = bytes.try_into().map_err(|_| BundleHeaderError::WrongLength)?;
        if field(bytes, 0) != MAGIC {
            return Err(BundleHeaderError::WrongMagic);
        }
        match bytes[VERSION_AT] {
            BUNDLE_FORMAT_VERSION => Self::new(
                VaultId::from_bytes(field(bytes, VAULT_ID_AT)).map_err(|_| BundleHeaderError::InvalidVaultId)?,
                count(field(bytes, APPROVERS_AT), BundleHeaderError::ApproverCount)?,
                count(field(bytes, RECORDS_AT), BundleHeaderError::RecordCount)?,
            ),
            other => Err(BundleHeaderError::UnknownVersion(other)),
        }
    }
}

/// The `N` bytes of the header starting at `at`; every caller's field lies inside the header.
fn field<const N: usize>(bytes: &[u8; BUNDLE_HEADER_LEN], at: usize) -> [u8; N] {
    std::array::from_fn(|i| bytes[at + i])
}

/// A big-endian `u64` count as a `usize`; a count too large for `usize` is out of range for any bundle.
fn count(bytes: [u8; 8], out_of_range: BundleHeaderError) -> Result<usize, BundleHeaderError> {
    usize::try_from(u64::from_be_bytes(bytes)).map_err(|_| out_of_range)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The worked example in storage-formats.md, "Migration bundle v1", "Example".
    const EXAMPLE: [u8; BUNDLE_HEADER_LEN] = [
        0x49, 0x56, 0x42, 0x48, 0x01, 0x3f, 0x2b, 0x8c, 0x1e, 0x5d, 0x4a, 0x4e, 0x6f, 0x9a, 0x7b, 0x1c, 0x2d, 0x3e, 0x4f, 0x5a, 0x6b, 0, 0,
        0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1,
    ];

    fn example_header() -> BundleHeader {
        let vault_id = VaultId::from_bytes(EXAMPLE[5..21].try_into().unwrap()).unwrap();
        BundleHeader::new(vault_id, 1, 1).unwrap()
    }

    #[test]
    fn example_encodes_to_the_documented_bytes() {
        assert_eq!(example_header().vault_id().to_string(), "3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b");
        assert_eq!(example_header().encode(), EXAMPLE);
        assert_eq!(BundleHeader::decode(&EXAMPLE), Ok(example_header()));
    }

    #[test]
    fn counts_are_checked_on_construction() {
        let vault_id = VaultId::new_random();
        assert_eq!(BundleHeader::new(vault_id, 0, 0), Err(BundleHeaderError::ApproverCount));
        assert_eq!(
            BundleHeader::new(vault_id, MAX_APPROVERS + 1, 0),
            Err(BundleHeaderError::ApproverCount)
        );
        assert_eq!(
            BundleHeader::new(vault_id, 1, MAX_MANIFEST_ENTRIES + 1),
            Err(BundleHeaderError::RecordCount)
        );
        let full = BundleHeader::new(vault_id, MAX_APPROVERS, MAX_MANIFEST_ENTRIES).unwrap();
        assert_eq!(BundleHeader::decode(&full.encode()), Ok(full));
    }

    fn altered(at: usize, byte: u8) -> [u8; BUNDLE_HEADER_LEN] {
        let mut bytes = EXAMPLE;
        bytes[at] = byte;
        bytes
    }

    #[test]
    fn malformed_headers_are_refused() {
        let cases = [
            (altered(0, b'X'), BundleHeaderError::WrongMagic),
            (altered(4, 2), BundleHeaderError::UnknownVersion(2)),
            (altered(11, 0x1e), BundleHeaderError::InvalidVaultId),
            (altered(28, 0), BundleHeaderError::ApproverCount),
            (altered(21, 1), BundleHeaderError::ApproverCount),
            (altered(28, 17), BundleHeaderError::ApproverCount),
            (altered(35, 0x10), BundleHeaderError::RecordCount),
            (altered(29, 0x80), BundleHeaderError::RecordCount),
        ];
        cases
            .into_iter()
            .for_each(|(bytes, error)| assert_eq!(BundleHeader::decode(&bytes), Err(error.clone()), "{error}"));
        assert_eq!(BundleHeader::decode(&EXAMPLE[..36]), Err(BundleHeaderError::WrongLength));
        assert_eq!(
            BundleHeader::decode(&[EXAMPLE.as_slice(), &[0]].concat()),
            Err(BundleHeaderError::WrongLength)
        );
    }
}
