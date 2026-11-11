//! Import exchange steps 3 and 4: open a decoded migration bundle with the export passphrase, then verify that its
//! contents belong together before import trusts or writes any of it (specification §16 steps 3 to 5;
//! `design/migration-bundle.md`, "Admin exchanges", "Import").
//!
//! The decoder checked the bundle's form only. Here the vault identity from the exported identity envelope opens the
//! manifest and the approval state, whose MACs are keyed from it, and the bundle header and every other entry are held
//! to what those two files name. `age` does not authenticate the envelope's sender, so the identity itself is trusted
//! only once the manifest's MAC verifies with it.
//!
//! The checks on file bytes are public through [`ControlFiles`], so the write order can run them again on the files it
//! reads back from disk.

use std::collections::BTreeMap;
use std::fmt;

use thiserror::Error;

use crate::migration_bundle::{BundleHeader, DecodedBundle, EntryName};
use crate::partial_restore::check_control_generations;
use crate::{
    ApprovalState, ApprovalVersion, ApproverId, BundledApproverKeyError, ConfigDigest, EnvelopeError, ExportPassphrase, OpenError,
    PinnedApprover, RecordId, VaultId, VaultIdentity, VaultManifest, check_approver_key_form, check_config_digest, check_record_digest,
    open_approval_state, open_bundled_approver_key, open_exported_identity, open_manifest,
};

/// A bundle check that a migration bundle failed: one check of import step 4, or the exported identity envelope's form
/// at step 3.
///
/// Import names the check in its `bundle-invalid` message and the `migration.import-refused` event's `detail`, so each
/// variant has a fixed short name, [`BundleCheckError::name`], and none carries a byte of the bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum BundleCheckError {
    /// The exported identity envelope is over its size limit, is not exactly one scrypt stanza at the export work
    /// factor, or does not hold an X25519 identity.
    #[error("the exported identity envelope is not one import opens")]
    ExportedIdentity,
    /// The manifest does not open with the vault identity: its MAC does not verify, or it is malformed.
    #[error("the manifest does not open with the vault identity")]
    ManifestOpen,
    /// The manifest names a different vault from the bundle header.
    #[error("the manifest names a different vault from the bundle header")]
    ManifestVault,
    /// The approval state does not open with the vault identity.
    #[error("the approval state does not open with the vault identity")]
    ApprovalOpen,
    /// The approval state names a different vault from the manifest.
    #[error("the approval state names a different vault from the manifest")]
    ApprovalVault,
    /// The manifest and the approval state are not a pair any sequence of writes leaves, as when one is from an older
    /// state generation.
    #[error("the approval state does not pair with the manifest")]
    ApprovalPair,
    /// The approval state has no committed approval, so there is no config digest to hold the config to.
    #[error("the approval state has no committed approval")]
    NoCommittedApproval,
    /// The bundle header's counts differ from the records the manifest names or the approvers the approval state pins.
    #[error("the bundle header's counts differ from the manifest's and the approval state's")]
    Counts,
    /// The config's BLAKE2b-256 differs from the committed config digest.
    #[error("the config's digest differs from the committed config digest")]
    ConfigDigest,
    /// The record files name different record IDs from the manifest.
    #[error("the record files name different record IDs from the manifest")]
    RecordIds,
    /// A record file's BLAKE2b-256 differs from its manifest entry's.
    #[error("a record file's digest differs from its manifest entry's")]
    RecordDigest,
    /// The approver keys name different approvers from the ones the approval state pins.
    #[error("the approver keys name different approvers from the pinned ones")]
    ApproverIds,
    /// A bundled approver key does not open with the vault identity.
    #[error("a bundled approver key does not open with the vault identity")]
    ApproverKeyOpen,
    /// An approver key is not an approver key envelope within the size and work factor bounds.
    #[error("an approver key is not an approver key envelope")]
    ApproverKeyForm,
}

impl BundleCheckError {
    /// The check's fixed short name, for the `bundle-invalid` message and the audit event's `detail`.
    pub fn name(&self) -> &'static str {
        match self {
            Self::ExportedIdentity => "exported_identity",
            Self::ManifestOpen => "manifest_open",
            Self::ManifestVault => "manifest_vault",
            Self::ApprovalOpen => "approval_open",
            Self::ApprovalVault => "approval_vault",
            Self::ApprovalPair => "approval_pair",
            Self::NoCommittedApproval => "committed_approval",
            Self::Counts => "counts",
            Self::ConfigDigest => "config_digest",
            Self::RecordIds => "record_ids",
            Self::RecordDigest => "record_digest",
            Self::ApproverIds => "approver_ids",
            Self::ApproverKeyOpen => "approver_key_open",
            Self::ApproverKeyForm => "approver_key_form",
        }
    }
}

/// Why import step 3 refused a bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum OpenBundleError {
    /// The export passphrase does not open the exported identity envelope; import answers `import-denied`. There is no
    /// attempt limit: whoever holds the bundle can guess at it offline.
    #[error("the export passphrase does not open the migration bundle")]
    WrongPassphrase,
    /// The exported identity envelope is not one import opens; import answers `bundle-invalid`.
    #[error(transparent)]
    Invalid(#[from] BundleCheckError),
}

/// A decoded migration bundle whose exported identity envelope opened: import step 3 done, nothing in it trusted yet.
pub struct OpenedBundle {
    header: BundleHeader,
    entries: BTreeMap<EntryName, Vec<u8>>,
    identity: VaultIdentity,
}

/// Shows the header and the identity's public key; the entries are left out.
impl fmt::Debug for OpenedBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenedBundle")
            .field("header", &self.header)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

/// Import step 3: opens the exported identity envelope with `passphrase`, with `open_exported_identity`'s checks.
///
/// A passphrase that does not open it is [`OpenBundleError::WrongPassphrase`]; `age` cannot tell it from a damaged
/// scrypt stanza. The envelope is dropped once opened: it is never written anywhere.
pub fn open_bundle(decoded: DecodedBundle, passphrase: &ExportPassphrase) -> Result<OpenedBundle, OpenBundleError> {
    let (header, mut entries) = decoded.into_parts();
    let envelope = entries
        .remove(&EntryName::ExportedIdentity)
        .ok_or(BundleCheckError::ExportedIdentity)?;
    let identity = open_exported_identity(&envelope, passphrase).map_err(|error| match error {
        EnvelopeError::WrongPassphrase => OpenBundleError::WrongPassphrase,
        _ => BundleCheckError::ExportedIdentity.into(),
    })?;
    Ok(OpenedBundle { header, entries, identity })
}

/// The manifest and the approval state of one vault, opened with its vault identity and checked against each other:
/// the two MAC'd files that every other bundle check is held to.
#[derive(Debug)]
pub struct ControlFiles {
    manifest: VaultManifest,
    approval: ApprovalState,
    committed: (ApprovalVersion, ConfigDigest),
}

impl ControlFiles {
    /// Opens `manifest` and `approval` with `identity`, and requires both to name `vault_id`, the two to be a pair some
    /// sequence of writes leaves, and the approval state to hold a committed approval.
    pub fn open(identity: &VaultIdentity, vault_id: VaultId, manifest: &[u8], approval: &[u8]) -> Result<Self, BundleCheckError> {
        let manifest = open_manifest(identity, manifest).map_err(|_| BundleCheckError::ManifestOpen)?;
        require(manifest.vault_id() == vault_id, BundleCheckError::ManifestVault)?;
        let approval = open_approval_state(identity, approval).map_err(|_| BundleCheckError::ApprovalOpen)?;
        require(approval.vault_id() == vault_id, BundleCheckError::ApprovalVault)?;
        check_control_generations(manifest.generations(), Some(approval.generations())).map_err(|_| BundleCheckError::ApprovalPair)?;
        let committed = approval.committed().ok_or(BundleCheckError::NoCommittedApproval)?;
        Ok(Self {
            manifest,
            approval,
            committed,
        })
    }

    /// Requires the bundle header's counts to equal the records the manifest names and the approvers the approval state
    /// pins, so nothing taken from the unauthenticated header can differ from what the vault says.
    pub fn check_counts(&self, header: &BundleHeader) -> Result<(), BundleCheckError> {
        let records = header.record_count() == self.manifest.entries().len();
        let approvers = header.approver_count() == self.approval.approvers().len();
        require(records && approvers, BundleCheckError::Counts)
    }

    /// Requires `config`'s BLAKE2b-256 to equal the committed config digest.
    pub fn check_config(&self, config: &[u8]) -> Result<(), BundleCheckError> {
        check_config_digest(config, &self.committed.1).map_err(|_| BundleCheckError::ConfigDigest)
    }

    /// Requires `ids`, in ascending order, to be exactly the record IDs the manifest names.
    pub fn check_record_ids(&self, ids: impl IntoIterator<Item = RecordId>) -> Result<(), BundleCheckError> {
        let named = self.manifest.entries().keys().copied();
        require(ids.into_iter().eq(named), BundleCheckError::RecordIds)
    }

    /// Requires record `id` to be in the manifest and `file`'s BLAKE2b-256 to equal its entry's. One file at a time,
    /// so a caller reading records back from disk holds one record at most.
    pub fn check_record(&self, id: RecordId, file: &[u8]) -> Result<(), BundleCheckError> {
        let entry = self.manifest.entries().get(&id).ok_or(BundleCheckError::RecordIds)?;
        check_record_digest(file, entry).map_err(|_| BundleCheckError::RecordDigest)
    }

    /// Requires `ids`, in ascending order, to be exactly the approver IDs the approval state pins.
    pub fn check_approver_ids(&self, ids: impl IntoIterator<Item = ApproverId>) -> Result<(), BundleCheckError> {
        let pinned = self.approval.approvers().iter().map(PinnedApprover::id);
        require(ids.into_iter().eq(pinned), BundleCheckError::ApproverIds)
    }

    /// Requires `file` to have the form of an approver key envelope, by [`check_approver_key_form`]. It reads the header
    /// only, so it needs no approval passphrase.
    pub fn check_approver_key(&self, file: &[u8]) -> Result<(), BundleCheckError> {
        check_approver_key_form(file).map_err(|_| BundleCheckError::ApproverKeyForm)
    }
}

/// A migration bundle that passed every bundle check with the vault identity: what import summarizes and writes.
///
/// Only [`verify_bundle`] constructs it, so holding one means every file in it belongs to the vault its MAC'd files
/// name.
pub struct VerifiedBundle {
    identity: VaultIdentity,
    control: ControlFiles,
    manifest_file: Vec<u8>,
    approval_file: Vec<u8>,
    config: Vec<u8>,
    approver_keys: BTreeMap<ApproverId, Vec<u8>>,
    records: BTreeMap<RecordId, Vec<u8>>,
}

impl VerifiedBundle {
    /// The vault's ID, as the manifest and the approval state name it.
    pub fn vault_id(&self) -> VaultId {
        self.control.manifest.vault_id()
    }

    /// The number of records the manifest names.
    pub fn record_count(&self) -> usize {
        self.control.manifest.entries().len()
    }

    /// The pinned approvers in ascending approver ID, whose labels the import summary lists.
    pub fn approvers(&self) -> &[PinnedApprover] {
        self.control.approval.approvers()
    }

    /// The committed approval version.
    pub fn committed_version(&self) -> ApprovalVersion {
        self.control.committed.0
    }

    /// The highest reserved approval version, above which the destination's first approval commits.
    pub fn highest_reserved(&self) -> u64 {
        self.control.approval.highest_reserved()
    }

    /// The committed config digest, which the config file matches.
    pub fn config_digest(&self) -> ConfigDigest {
        self.control.committed.1
    }

    /// The vault identity, for wrapping to the destination's recipients.
    pub fn identity(&self) -> &VaultIdentity {
        &self.identity
    }

    /// The manifest file, byte for byte.
    pub fn manifest_file(&self) -> &[u8] {
        &self.manifest_file
    }

    /// The approval state file, byte for byte.
    pub fn approval_file(&self) -> &[u8] {
        &self.approval_file
    }

    /// The committed config, byte for byte.
    pub fn config(&self) -> &[u8] {
        &self.config
    }

    /// Each pinned approver's approver key envelope, opened from its bundled approver key, in ascending approver ID.
    pub fn approver_keys(&self) -> &BTreeMap<ApproverId, Vec<u8>> {
        &self.approver_keys
    }

    /// Each record file, byte for byte, in ascending record ID.
    pub fn records(&self) -> &BTreeMap<RecordId, Vec<u8>> {
        &self.records
    }
}

/// Shows what the import summary shows and the identity's public key; no file's bytes.
impl fmt::Debug for VerifiedBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedBundle")
            .field("vault_id", &self.vault_id())
            .field("record_count", &self.record_count())
            .field("approver_count", &self.approvers().len())
            .field("committed_version", &self.committed_version())
            .field("highest_reserved", &self.highest_reserved())
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

/// Import step 4: verifies an opened bundle with its vault identity, returning the first failed bundle check.
///
/// In order: the manifest and the approval state ([`ControlFiles::open`]); the header's counts; the config's digest;
/// the record IDs, then each record file's digest; the approver IDs, then each bundled approver key, opened with the
/// vault identity to an approver key envelope of valid form. The header's counts are checked right after the two
/// files they are held to, so a bundle whose header counts an entry the manifest does not is refused as `counts`.
pub fn verify_bundle(opened: OpenedBundle) -> Result<VerifiedBundle, BundleCheckError> {
    let OpenedBundle {
        header,
        mut entries,
        identity,
    } = opened;
    let mut take = |name, missing| entries.remove(&name).ok_or(missing);
    let manifest_file = take(EntryName::Manifest, BundleCheckError::ManifestOpen)?;
    let approval_file = take(EntryName::ApprovalState, BundleCheckError::ApprovalOpen)?;
    let config = take(EntryName::Config, BundleCheckError::ConfigDigest)?;
    let control = ControlFiles::open(&identity, header.vault_id(), &manifest_file, &approval_file)?;
    control.check_counts(&header)?;
    control.check_config(&config)?;
    let (bundled_keys, records) = split_by_id(entries);
    control.check_record_ids(records.keys().copied())?;
    records.iter().try_for_each(|(id, file)| control.check_record(*id, file))?;
    control.check_approver_ids(bundled_keys.keys().copied())?;
    let approver_keys = open_approver_keys(&bundled_keys, &identity)?;
    Ok(VerifiedBundle {
        identity,
        control,
        manifest_file,
        approval_file,
        config,
        approver_keys,
        records,
    })
}

/// The bundled approver keys and the record files among `entries`; the fixed entries were taken out before.
type ById = (BTreeMap<ApproverId, Vec<u8>>, BTreeMap<RecordId, Vec<u8>>);

fn split_by_id(entries: BTreeMap<EntryName, Vec<u8>>) -> ById {
    entries
        .into_iter()
        .fold((BTreeMap::new(), BTreeMap::new()), |(mut approvers, mut records), (name, bytes)| {
            match name {
                EntryName::Approver(id) => {
                    approvers.insert(id, bytes);
                }
                EntryName::Record(id) => {
                    records.insert(id, bytes);
                }
                EntryName::BundleHeader
                | EntryName::ExportedIdentity
                | EntryName::Manifest
                | EntryName::ApprovalState
                | EntryName::Config => {}
            }
            (approvers, records)
        })
}

/// Opens each bundled approver key with the vault identity to the approver key envelope inside, whose form
/// `open_bundled_approver_key` checks.
fn open_approver_keys(
    bundled: &BTreeMap<ApproverId, Vec<u8>>,
    identity: &VaultIdentity,
) -> Result<BTreeMap<ApproverId, Vec<u8>>, BundleCheckError> {
    bundled
        .iter()
        .map(|(id, bytes)| {
            let envelope = open_bundled_approver_key(bytes, identity).map_err(|error| match error {
                // A plaintext over the envelope limit opened, so the key is the vault's; it is no approver key envelope.
                BundledApproverKeyError::Form(_) | BundledApproverKeyError::Open(OpenError::TooLarge { .. }) => {
                    BundleCheckError::ApproverKeyForm
                }
                _ => BundleCheckError::ApproverKeyOpen,
            })?;
            Ok((*id, envelope))
        })
        .collect()
}

fn require(holds: bool, check: BundleCheckError) -> Result<(), BundleCheckError> {
    holds.then_some(()).ok_or(check)
}

#[cfg(test)]
mod tests;
