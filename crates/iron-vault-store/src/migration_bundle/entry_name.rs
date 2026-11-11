//! The closed list of migration bundle entry names, in bundle order.

use std::fmt;

use thiserror::Error;
use uuid::Uuid;

use super::{BUNDLE_HEADER_LEN, MAX_BUNDLED_APPROVER_LEN};
use crate::{
    ApproverId, MAX_APPROVAL_STATE_LEN, MAX_CONFIG_LEN, MAX_MANIFEST_LEN, MAX_PASSPHRASE_ENVELOPE_LEN, MAX_RECORD_FILE_LEN, RecordId,
};

const APPROVER_PREFIX: &[u8] = b"approver-";
const RECORD_PREFIX: &[u8] = b"record-";
const AGE_SUFFIX: &[u8] = b".age";

/// One entry of a migration bundle, named by what it holds.
///
/// The variants are declared in bundle order and approver and record IDs order by their bytes, so the derived ordering
/// is bundle order: entries strictly ascending under it never repeat. The text form is always formatted from the
/// variant and its parsed ID, never copied from input, so an entry has exactly one name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EntryName {
    /// `bundle-header`: the bundle header.
    BundleHeader,
    /// `exported-identity.age`: the exported identity envelope.
    ExportedIdentity,
    /// `manifest.age`: the manifest file, byte for byte.
    Manifest,
    /// `approval.age`: the approval state file, byte for byte.
    ApprovalState,
    /// `config.toml`: the committed config, byte for byte.
    Config,
    /// `approver-<approver ID>.age`: a bundled approver key.
    Approver(ApproverId),
    /// `record-<record ID>.age`: a record file, byte for byte.
    Record(RecordId),
}

/// Bytes that are not a migration bundle entry name. Names are public, but the error carries no input either way.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EntryNameError {
    /// The name is not one the bundle format lists.
    #[error("not a migration bundle entry name")]
    Unknown,
    /// The approver or record name's ID is not a lowercase hyphenated version 4 UUID.
    #[error("migration bundle entry name has an invalid ID")]
    InvalidId,
}

impl EntryName {
    /// The entry with this name, refusing a name the format does not list or an ID in any other form than the one
    /// [`fmt::Display`] writes.
    pub fn parse(name: &[u8]) -> Result<Self, EntryNameError> {
        match name {
            b"bundle-header" => Ok(Self::BundleHeader),
            b"exported-identity.age" => Ok(Self::ExportedIdentity),
            b"manifest.age" => Ok(Self::Manifest),
            b"approval.age" => Ok(Self::ApprovalState),
            b"config.toml" => Ok(Self::Config),
            _ => Self::parse_id_entry(name),
        }
    }

    /// The most bytes this entry may hold; the bundle header is exactly this long.
    pub fn size_limit(&self) -> u64 {
        let limit = match self {
            Self::BundleHeader => BUNDLE_HEADER_LEN,
            Self::ExportedIdentity => MAX_PASSPHRASE_ENVELOPE_LEN,
            Self::Manifest => MAX_MANIFEST_LEN,
            Self::ApprovalState => MAX_APPROVAL_STATE_LEN,
            Self::Config => MAX_CONFIG_LEN,
            Self::Approver(_) => MAX_BUNDLED_APPROVER_LEN,
            Self::Record(_) => return MAX_RECORD_FILE_LEN,
        };
        limit as u64
    }

    fn parse_id_entry(name: &[u8]) -> Result<Self, EntryNameError> {
        let id_between = |prefix: &[u8]| name.strip_prefix(prefix).and_then(|rest| rest.strip_suffix(AGE_SUFFIX));
        match (id_between(APPROVER_PREFIX), id_between(RECORD_PREFIX)) {
            (Some(id), _) => ApproverId::from_bytes(canonical_uuid(id)?)
                .map(Self::Approver)
                .map_err(|_| EntryNameError::InvalidId),
            (_, Some(id)) => RecordId::from_bytes(canonical_uuid(id)?)
                .map(Self::Record)
                .map_err(|_| EntryNameError::InvalidId),
            _ => Err(EntryNameError::Unknown),
        }
    }
}

/// The bytes of a UUID written in lowercase hyphenated form, refusing every other spelling the `uuid` parser accepts.
fn canonical_uuid(text: &[u8]) -> Result<[u8; 16], EntryNameError> {
    let uuid = Uuid::try_parse_ascii(text).map_err(|_| EntryNameError::InvalidId)?;
    let canonical = uuid.hyphenated().to_string();
    (canonical.as_bytes() == text)
        .then_some(*uuid.as_bytes())
        .ok_or(EntryNameError::InvalidId)
}

impl fmt::Display for EntryName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BundleHeader => f.write_str("bundle-header"),
            Self::ExportedIdentity => f.write_str("exported-identity.age"),
            Self::Manifest => f.write_str("manifest.age"),
            Self::ApprovalState => f.write_str("approval.age"),
            Self::Config => f.write_str("config.toml"),
            Self::Approver(id) => write!(f, "approver-{id}.age"),
            Self::Record(id) => write!(f, "record-{id}.age"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const APPROVER: &str = "8d1c6f0e-2b7a-4c59-9e3d-5a4b3c2d1e0f";
    const RECORD: &str = "7c9e6679-7425-40de-944b-e07fc1f90ae7";

    fn approver() -> EntryName {
        EntryName::parse(format!("approver-{APPROVER}.age").as_bytes()).unwrap()
    }

    fn record() -> EntryName {
        EntryName::parse(format!("record-{RECORD}.age").as_bytes()).unwrap()
    }

    #[test]
    fn every_name_round_trips_through_text() {
        [
            EntryName::BundleHeader,
            EntryName::ExportedIdentity,
            EntryName::Manifest,
            EntryName::ApprovalState,
            EntryName::Config,
            approver(),
            record(),
        ]
        .into_iter()
        .for_each(|name| assert_eq!(EntryName::parse(name.to_string().as_bytes()), Ok(name), "{name}"));
    }

    #[test]
    fn approver_and_record_names_carry_their_id() {
        assert_eq!(approver().to_string(), format!("approver-{APPROVER}.age"));
        assert_eq!(record().to_string(), format!("record-{RECORD}.age"));
    }

    #[test]
    fn longest_names_fit_the_ustar_name_field() {
        assert_eq!(approver().to_string().len(), 49);
        assert_eq!(record().to_string().len(), 47);
    }

    #[test]
    fn derived_order_is_bundle_order() {
        let names = [
            EntryName::BundleHeader,
            EntryName::ExportedIdentity,
            EntryName::Manifest,
            EntryName::ApprovalState,
            EntryName::Config,
            approver(),
            record(),
        ];
        assert!(names.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn unknown_names_are_refused() {
        [
            "",
            "identity.age",
            "config.toml.sig",
            "manifest.age\0",
            "./manifest.age",
            "approver-.age",
            "record-",
            "approvers-8d1c6f0e-2b7a-4c59-9e3d-5a4b3c2d1e0f.age",
        ]
        .into_iter()
        .for_each(|name| assert!(EntryName::parse(name.as_bytes()).is_err(), "{name:?}"));
        assert_eq!(EntryName::parse(b"operational.age"), Err(EntryNameError::Unknown));
    }

    #[test]
    fn ids_in_any_other_spelling_are_refused() {
        [
            "record-7C9E6679-7425-40DE-944B-E07FC1F90AE7.age",
            "record-7c9e6679742540de944be07fc1f90ae7.age",
            "record-{7c9e6679-7425-40de-944b-e07fc1f90ae7}.age",
            "record-urn:uuid:7c9e6679-7425-40de-944b-e07fc1f90ae7.age",
            "record-7c9e6679-7425-10de-944b-e07fc1f90ae7.age",
            "approver-00000000-0000-0000-0000-000000000000.age",
            "approver-../7c9e6679-7425-40de-944b-e07fc1f90.age",
        ]
        .into_iter()
        .for_each(|name| assert_eq!(EntryName::parse(name.as_bytes()), Err(EntryNameError::InvalidId), "{name}"));
    }

    #[test]
    fn size_limits_follow_the_entry_table() {
        let limits = [
            (EntryName::BundleHeader, 37),
            (EntryName::ExportedIdentity, 1024),
            (EntryName::Manifest, 1 << 20),
            (EntryName::ApprovalState, 4096),
            (EntryName::Config, 61_440),
            (approver(), 2048),
            (record(), 64 * 1024),
        ];
        limits
            .into_iter()
            .for_each(|(name, limit)| assert_eq!(name.size_limit(), limit, "{name}"));
    }
}
