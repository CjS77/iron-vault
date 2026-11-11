//! The export snapshot: the vault files `export` checks before any prompt and streams into a migration bundle after its
//! authorization is consumed (specification §16 steps 1 and 2; `design/migration-bundle.md`, "The snapshot").
//!
//! No record is ever decrypted: a record file is checked against its manifest digest and copied as it is. Nothing is
//! written to the state or config directory, and nothing to a temp file. The caller holds the service-wide lock from
//! exchange step 2 to the end, which is what makes the files read at the two steps one consistent vault.

use std::fmt;
use std::io::{self, Write};

use thiserror::Error;

use crate::migration_bundle::{BundleEncoder, BundleHeader, BundleHeaderError, EncodeError, EntryName};
use crate::{
    ApprovalState, ApprovalVersion, ApproverId, BundledApproverKeyError, ConfigDigest, ConfigDirLock, ConfigFileName, EnvelopeError,
    ErrorKindLabel, ExportPassphrase, MAX_APPROVAL_STATE_LEN, MAX_MANIFEST_LEN, MAX_PASSPHRASE_ENVELOPE_LEN, MAX_RECORD_FILE_LEN,
    ManifestEntry, RecordId, StateDirLock, StateFileName, StoreFs, VaultId, VaultIdentity, VaultManifest, check_approver_key_form,
    open_approval_state, open_manifest, read_config_file, read_state_file, record_digest, seal_bundled_approver_key,
    seal_exported_identity,
};

/// Where an export failed, as the `step` of the `migration.export-failed` event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotStep {
    /// The read-only checks of exchange step 3, before any prompt.
    Check,
    /// Reading and checking the files again at exchange step 10.
    Snapshot,
    /// Encrypting the bundled approver keys or the exported identity.
    Seal,
    /// Writing the bundle to the sink.
    Transfer,
}

impl SnapshotStep {
    /// The step's fixed name in a message and a log record.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Check => "check",
            Self::Snapshot => "snapshot",
            Self::Seal => "seal",
            Self::Transfer => "transfer",
        }
    }
}

impl fmt::Display for SnapshotStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a snapshot holds, for the export summary and the `migration.exported` event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotSummary {
    /// The vault's ID.
    pub vault_id: VaultId,
    /// The number of record files the manifest names.
    pub record_count: usize,
    /// The number of pinned approvers.
    pub approver_count: usize,
    /// The committed approval version.
    pub committed_version: ApprovalVersion,
    /// The highest reserved approval version.
    pub highest_reserved: u64,
}

/// A finished export: the bytes written to the sink, and what the snapshot held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportedBundle {
    /// The length of the bundle in bytes.
    pub byte_count: u64,
    /// What the bundle holds.
    pub summary: SnapshotSummary,
}

/// What is wrong with a file the snapshot read. No variant carries a byte of the file.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SnapshotDamage {
    /// The manifest or approval state does not open with the vault identity.
    #[error("it does not open with the vault identity")]
    NotOpened,
    /// The manifest or approval state belongs to a different vault from the one the service holds.
    #[error("it belongs to a different vault")]
    WrongVault,
    /// `approval.age` differs from the approval state the service holds.
    #[error("it differs from the approval state the service holds")]
    NotHeld,
    /// The approval state has no committed config, so there is no digest to check `config.toml` against.
    #[error("the approval state has no committed config")]
    NoCommittedConfig,
    /// The file's BLAKE2b-256 digest differs from the one the vault committed to.
    #[error("its digest differs from the committed one")]
    DigestMismatch,
    /// The approver key file is not one scrypt stanza within the work factor bounds.
    #[error("it is not an approver key envelope: {0}")]
    ApproverKeyForm(EnvelopeError),
}

/// Why a snapshot check or export failed. No message holds a byte of a file, a key or a passphrase.
#[derive(Debug, Error)]
pub enum SnapshotError {
    /// A file could not be read: missing, over its size limit, not a regular file or unreadable.
    #[error("export {step} step: cannot read {file}: {kind}")]
    Unreadable {
        /// The step that failed.
        step: SnapshotStep,
        /// The file, named as its bundle entry: for a record or an approver key, with its ID.
        file: EntryName,
        /// The kind of the failed read.
        kind: ErrorKindLabel,
    },
    /// A file was read but is damaged.
    #[error("export {step} step: {file} is damaged: {damage}")]
    Damaged {
        /// The step that failed.
        step: SnapshotStep,
        /// The file, named as its bundle entry.
        file: EntryName,
        /// What is wrong with it.
        damage: SnapshotDamage,
    },
    /// The vault identity could not be sealed to the export passphrase.
    #[error("export seal step: cannot seal the exported identity: {0}")]
    SealIdentity(EnvelopeError),
    /// An approver key file could not be encrypted to the vault public key.
    #[error("export seal step: cannot seal {file}: {cause}")]
    SealApprover {
        /// The approver key file.
        file: EntryName,
        /// Why sealing failed.
        cause: BundledApproverKeyError,
    },
    /// The snapshot does not fit the bundle format, as when it holds more entries than a bundle may.
    #[error("export snapshot step: the vault does not fit a bundle: {0}")]
    Header(BundleHeaderError),
    /// The bundle encoder refused an entry.
    #[error("export snapshot step: the bundle encoder refused an entry: {0}")]
    Bundle(EncodeError),
    /// The sink failed. The error is the sink's own, so the caller can tell a cancellation or a missed deadline from a
    /// store failure.
    #[error("export transfer step: writing the bundle failed: {0}")]
    Transfer(io::Error),
}

impl SnapshotError {
    /// The step that failed.
    pub fn step(&self) -> SnapshotStep {
        match self {
            Self::Unreadable { step, .. } | Self::Damaged { step, .. } => *step,
            Self::SealIdentity(_) | Self::SealApprover { .. } => SnapshotStep::Seal,
            Self::Header(_) | Self::Bundle(_) => SnapshotStep::Snapshot,
            Self::Transfer(_) => SnapshotStep::Transfer,
        }
    }

    /// The file that failed, when a file did.
    pub fn file(&self) -> Option<EntryName> {
        match self {
            Self::Unreadable { file, .. } | Self::Damaged { file, .. } | Self::SealApprover { file, .. } => Some(*file),
            _ => None,
        }
    }

    /// The kind of the failure as a label that holds no file name or error text.
    pub fn error_kind_label(&self) -> ErrorKindLabel {
        match self {
            Self::Unreadable { kind, .. } => kind.clone(),
            Self::Damaged { .. } => ErrorKindLabel::fixed("damaged"),
            Self::SealIdentity(_) | Self::SealApprover { .. } => ErrorKindLabel::fixed("seal_failed"),
            Self::Header(_) | Self::Bundle(_) => ErrorKindLabel::fixed("bundle_unfit"),
            Self::Transfer(error) => ErrorKindLabel::of_io(error),
        }
    }
}

/// Requires the BLAKE2b-256 of `config` to equal the digest the approval state committed.
pub fn check_config_digest(config: &[u8], committed: &ConfigDigest) -> Result<(), SnapshotDamage> {
    (ConfigDigest::of(config) == *committed)
        .then_some(())
        .ok_or(SnapshotDamage::DigestMismatch)
}

/// Requires the BLAKE2b-256 of a record file to equal its manifest entry's.
pub fn check_record_digest(file: &[u8], entry: &ManifestEntry) -> Result<(), SnapshotDamage> {
    (record_digest(file) == *entry.file_digest())
        .then_some(())
        .ok_or(SnapshotDamage::DigestMismatch)
}

/// Exchange step 3, before any prompt: checks the vault without decrypting a record, and keeps none of the files.
///
/// In order: the manifest and approval state open, and the approval state equals `held`; `config.toml` matches the
/// committed config digest; each pinned approver's key file, in ascending approver ID, has the form of an approver key
/// envelope and is not opened; each record file the manifest names matches its entry's digest.
pub fn check_export_snapshot(
    state: &StateDirLock,
    config: &ConfigDirLock,
    fs: &impl StoreFs,
    identity: &VaultIdentity,
    held: &ApprovalState,
) -> Result<SnapshotSummary, SnapshotError> {
    let reader = Reader::new(state, config, fs, identity, SnapshotStep::Check);
    let control = reader.control(held)?;
    control
        .manifest
        .entries()
        .iter()
        .try_for_each(|(id, entry)| reader.record(id, entry).map(drop))?;
    Ok(control.summary)
}

/// Exchange step 10, after the migration authorization is consumed: reads the vault again with the checks of
/// [`check_export_snapshot`], seals it and writes the bundle to `sink` in bundle order.
///
/// It holds at most one record, the manifest, the config and the bundled approver keys. A record file is read when its
/// turn comes and its digest is checked before any of its bytes reach the encoder. The export passphrase is dropped
/// once the identity is sealed. A write that `sink` reports as [`io::ErrorKind::Interrupted`] is retried. Any other
/// failure of `sink` is final: it is returned as [`SnapshotError::Transfer`] with the sink's own `io::Error`, and
/// `sink` is not called again after it.
///
/// On any error, `sink` may already hold bytes of the bundle, including bytes the gzip encoder wrote while it was
/// dropped. The caller must discard everything written to it: a partial bundle is never complete, and the CLI removes
/// its partial file.
pub fn stream_export_snapshot<W: Write>(
    state: &StateDirLock,
    config: &ConfigDirLock,
    fs: &impl StoreFs,
    identity: &VaultIdentity,
    held: &ApprovalState,
    passphrase: ExportPassphrase,
    sink: W,
) -> Result<ExportedBundle, SnapshotError> {
    let reader = Reader::new(state, config, fs, identity, SnapshotStep::Snapshot);
    let control = reader.control(held)?;
    let approvers = bundle_approver_keys(&control.approver_keys, identity)?;
    let envelope = seal_exported_identity(identity, &passphrase).map_err(SnapshotError::SealIdentity)?;
    drop(passphrase);
    write_bundle(&reader, &control, &envelope, &approvers, sink)
}

/// The files `control` read in step 1, kept for the bundle.
struct Control {
    manifest_file: Vec<u8>,
    manifest: VaultManifest,
    approval_file: Vec<u8>,
    config: Vec<u8>,
    approver_keys: Vec<(ApproverId, Vec<u8>)>,
    summary: SnapshotSummary,
}

/// Reads the vault's files for one step, naming that step in every failure.
struct Reader<'a, F> {
    state: &'a StateDirLock,
    config: &'a ConfigDirLock,
    fs: &'a F,
    identity: &'a VaultIdentity,
    step: SnapshotStep,
}

impl<'a, F: StoreFs> Reader<'a, F> {
    fn new(state: &'a StateDirLock, config: &'a ConfigDirLock, fs: &'a F, identity: &'a VaultIdentity, step: SnapshotStep) -> Self {
        Self {
            state,
            config,
            fs,
            identity,
            step,
        }
    }

    fn damaged(&self, file: EntryName, damage: SnapshotDamage) -> SnapshotError {
        SnapshotError::Damaged {
            step: self.step,
            file,
            damage,
        }
    }

    fn state_file(&self, file: EntryName, name: &StateFileName, max_len: u64) -> Result<Vec<u8>, SnapshotError> {
        read_state_file(self.state, self.fs, name, max_len).map_err(|e| SnapshotError::Unreadable {
            step: self.step,
            file,
            kind: e.error_kind_label(),
        })
    }

    /// Steps 1 to 3 of the check: the manifest, the approval state, the config and the approver key files.
    fn control(&self, held: &ApprovalState) -> Result<Control, SnapshotError> {
        let (manifest_file, manifest) = self.manifest(held)?;
        let (approval_file, version, digest) = self.approval(held)?;
        let config = self.config(&digest)?;
        let approver_keys = self.approver_keys(held)?;
        let summary = SnapshotSummary {
            vault_id: held.vault_id(),
            record_count: manifest.entries().len(),
            approver_count: approver_keys.len(),
            committed_version: version,
            highest_reserved: held.highest_reserved(),
        };
        Ok(Control {
            manifest_file,
            manifest,
            approval_file,
            config,
            approver_keys,
            summary,
        })
    }

    fn manifest(&self, held: &ApprovalState) -> Result<(Vec<u8>, VaultManifest), SnapshotError> {
        let file = EntryName::Manifest;
        // MAX_MANIFEST_LEN is 1 MiB, so it always fits in a u64.
        let bytes = self.state_file(file, &StateFileName::manifest(), MAX_MANIFEST_LEN as u64)?;
        let manifest = open_manifest(self.identity, &bytes).map_err(|_| self.damaged(file, SnapshotDamage::NotOpened))?;
        match manifest.vault_id() == held.vault_id() {
            true => Ok((bytes, manifest)),
            false => Err(self.damaged(file, SnapshotDamage::WrongVault)),
        }
    }

    fn approval(&self, held: &ApprovalState) -> Result<(Vec<u8>, ApprovalVersion, ConfigDigest), SnapshotError> {
        let file = EntryName::ApprovalState;
        // MAX_APPROVAL_STATE_LEN is 4 KiB, so it always fits in a u64.
        let bytes = self.state_file(file, &StateFileName::approval_state(), MAX_APPROVAL_STATE_LEN as u64)?;
        let on_disk = open_approval_state(self.identity, &bytes).map_err(|_| self.damaged(file, SnapshotDamage::NotOpened))?;
        if on_disk != *held {
            return Err(self.damaged(file, SnapshotDamage::NotHeld));
        }
        let (version, digest) = held
            .committed()
            .ok_or_else(|| self.damaged(file, SnapshotDamage::NoCommittedConfig))?;
        Ok((bytes, version, digest))
    }

    fn config(&self, committed: &ConfigDigest) -> Result<Vec<u8>, SnapshotError> {
        let file = EntryName::Config;
        let bytes = read_config_file(self.config, self.fs, ConfigFileName::Active).map_err(|e| SnapshotError::Unreadable {
            step: self.step,
            file,
            kind: e.error_kind_label(),
        })?;
        check_config_digest(&bytes, committed).map_err(|damage| self.damaged(file, damage))?;
        Ok(bytes)
    }

    /// Each pinned approver's key file, in ascending approver ID, checked for form and never opened.
    fn approver_keys(&self, held: &ApprovalState) -> Result<Vec<(ApproverId, Vec<u8>)>, SnapshotError> {
        held.approvers()
            .iter()
            .map(|approver| {
                let (id, file) = (approver.id(), EntryName::Approver(approver.id()));
                let bytes = self.state_file(file, &StateFileName::approver_key(id), MAX_PASSPHRASE_ENVELOPE_LEN as u64)?;
                check_approver_key_form(&bytes).map_err(|e| self.damaged(file, SnapshotDamage::ApproverKeyForm(e)))?;
                Ok((id, bytes))
            })
            .collect()
    }

    /// One record file, checked against its manifest entry and never decrypted.
    fn record(&self, id: &RecordId, entry: &ManifestEntry) -> Result<Vec<u8>, SnapshotError> {
        let file = EntryName::Record(*id);
        let bytes = self.state_file(file, &StateFileName::record(id), MAX_RECORD_FILE_LEN)?;
        check_record_digest(&bytes, entry).map_err(|damage| self.damaged(file, damage))?;
        Ok(bytes)
    }
}

/// Encrypts each approver key file, unopened, to the vault public key.
fn bundle_approver_keys(keys: &[(ApproverId, Vec<u8>)], identity: &VaultIdentity) -> Result<Vec<(ApproverId, Vec<u8>)>, SnapshotError> {
    let vault = identity.public_key();
    keys.iter()
        .map(|(id, key)| {
            let bundled = seal_bundled_approver_key(key, &vault).map_err(|cause| SnapshotError::SealApprover {
                file: EntryName::Approver(*id),
                cause,
            })?;
            Ok((*id, bundled))
        })
        .collect()
}

/// Encodes the bundle entry by entry, reading each record file when its turn comes.
fn write_bundle<W: Write>(
    reader: &Reader<'_, impl StoreFs>,
    control: &Control,
    envelope: &[u8],
    approvers: &[(ApproverId, Vec<u8>)],
    sink: W,
) -> Result<ExportedBundle, SnapshotError> {
    let summary = control.summary;
    let header = BundleHeader::new(summary.vault_id, summary.approver_count, summary.record_count).map_err(SnapshotError::Header)?;
    let mut encoder = BundleEncoder::new(Counted::new(sink), header).map_err(encode_error)?;
    [
        (EntryName::ExportedIdentity, envelope),
        (EntryName::Manifest, &control.manifest_file),
        (EntryName::ApprovalState, &control.approval_file),
        (EntryName::Config, &control.config),
    ]
    .into_iter()
    .chain(approvers.iter().map(|(id, bytes)| (EntryName::Approver(*id), bytes.as_slice())))
    .try_for_each(|(name, bytes)| encoder.write_entry(name, bytes))
    .map_err(encode_error)?;
    control.manifest.entries().iter().try_for_each(|(id, entry)| {
        let bytes = reader.record(id, entry)?;
        encoder.write_entry(EntryName::Record(*id), &bytes).map_err(encode_error)
    })?;
    let sink = encoder.finish().map_err(encode_error)?;
    Ok(ExportedBundle {
        byte_count: sink.count,
        summary,
    })
}

/// A sink's `io::Error` goes through the encoder unchanged; any other refusal is the snapshot's own.
fn encode_error(error: EncodeError) -> SnapshotError {
    match error {
        EncodeError::Io(error) => SnapshotError::Transfer(error),
        other => SnapshotError::Bundle(other),
    }
}

/// Counts the bytes that reach the sink, which is the bundle's length, and stops using the sink after its first
/// final error.
///
/// The gzip encoder writes its trailer when it is dropped, which on a failed export would put more bytes behind a
/// sink that has already refused some, such as one cancelled by `lock`. The first error passes out unchanged; every
/// later call fails with the same kind and never reaches the sink. An `Interrupted` error is not final: `write_all`
/// retries it, so it passes out unchanged and the retry reaches the sink.
struct Counted<W> {
    inner: W,
    count: u64,
    failed: Option<io::ErrorKind>,
}

impl<W> Counted<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            count: 0,
            failed: None,
        }
    }

    /// Runs `call` on the sink unless it has failed before, and remembers the kind of a new failure other than
    /// `Interrupted`, which the caller retries.
    fn through<T>(&mut self, call: impl FnOnce(&mut W) -> io::Result<T>) -> io::Result<T> {
        if let Some(kind) = self.failed {
            return Err(io::Error::from(kind));
        }
        call(&mut self.inner).inspect_err(|error| {
            if error.kind() != io::ErrorKind::Interrupted {
                self.failed = Some(error.kind());
            }
        })
    }
}

impl<W: Write> Write for Counted<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.through(|sink| sink.write(buf))?;
        self.count += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.through(W::flush)
    }
}

#[cfg(test)]
pub(crate) mod tests;
