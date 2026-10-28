//! Vault writes: add, replace and remove one credential record (spec §3.3, §3.10).
//!
//! Every write follows the same steps. Everything that can fail without the disk (validation, sealing, building the
//! next manifest) happens first. Then unindexed record files are removed, the new record file is written, and the
//! manifest is durably replaced at the next generation: that rename is the single commit point. Memory changes only
//! after it, and the superseded record file is removed last. A crash before the commit leaves the old vault plus at
//! most one unindexed record file; a crash after it leaves the new vault plus at most the superseded file.

use std::collections::BTreeSet;

use iron_vault_kinds::CredentialMaterial;
use iron_vault_policy::CredentialName;

use super::{Vault, VaultError, WriteReport, list_state_dir, unindexed_files};
use crate::{
    CredentialRecord, ManifestEntry, PermittedOrigins, RecordId, Source, StateDirLock, StateFileName, StoreFs, VaultIdentity,
    VaultManifest, WriteError, WriteStep, durable_remove, durable_replace, encode, record_digest, seal, seal_manifest,
};

/// A record and the sealed bytes of its file, which its manifest entry's digest covers.
struct SealedRecord {
    record: CredentialRecord,
    bytes: Vec<u8>,
}

/// One write with all its disk-free work done: the record to write, the record it supersedes and the manifest to commit.
struct Prepared {
    name: CredentialName,
    new: Option<SealedRecord>,
    old: Option<RecordId>,
    manifest: VaultManifest,
    manifest_bytes: Vec<u8>,
}

impl Vault {
    /// Adds a credential record named `name` under a new record ID, refusing a name the manifest already lists.
    ///
    /// This performs an already authorized change: the caller checks owner presence (spec §3.3). Returns the new
    /// record's ID and what else the write did, for the audit log.
    pub fn add(
        &mut self,
        lock: &StateDirLock,
        fs: &impl StoreFs,
        name: CredentialName,
        material: CredentialMaterial,
        origins: PermittedOrigins,
    ) -> Result<(RecordId, WriteReport), VaultError> {
        self.ensure_writable()?;
        if self.record_id_of(&name).is_some() {
            return Err(VaultError::NameTaken(name));
        }
        let record = new_record(name, material, origins)?;
        let id = record.id();
        let report = self.write(lock, fs, self.prepare(record.name().clone(), Some(record), None)?)?;
        Ok((id, report))
    }

    /// Replaces the record named `name` with a new record under a new record ID, so a swapped account shows as a new
    /// record identity rather than an edit (spec §3.3, R-5). The superseded file is removed after the commit.
    ///
    /// The record may be damaged: replacing it is how a damaged credential is repaired. This performs an already
    /// authorized change: the caller checks owner presence and the routes that use the credential.
    pub fn replace(
        &mut self,
        lock: &StateDirLock,
        fs: &impl StoreFs,
        name: CredentialName,
        material: CredentialMaterial,
        origins: PermittedOrigins,
    ) -> Result<(RecordId, WriteReport), VaultError> {
        self.ensure_writable()?;
        let old = self.record_id_of(&name).ok_or_else(|| VaultError::UnknownName(name.clone()))?;
        let record = new_record(name, material, origins)?;
        let id = record.id();
        let report = self.write(lock, fs, self.prepare(record.name().clone(), Some(record), Some(old))?)?;
        Ok((id, report))
    }

    /// Removes the record named `name`, healthy or damaged: commits a manifest without it, then removes its file.
    ///
    /// This performs an already authorized change: the caller checks owner presence and the routes that use the
    /// credential. A later `add` of the same name gets a new record ID, so the name never silently rebinds.
    pub fn remove(&mut self, lock: &StateDirLock, fs: &impl StoreFs, name: &CredentialName) -> Result<WriteReport, VaultError> {
        self.ensure_writable()?;
        let old = self.record_id_of(name).ok_or_else(|| VaultError::UnknownName(name.clone()))?;
        self.write(lock, fs, self.prepare(name.clone(), None, Some(old))?)
    }

    fn ensure_writable(&self) -> Result<(), VaultError> {
        match self.needs_reopen {
            true => Err(VaultError::ReopenRequired),
            false => Ok(()),
        }
    }

    /// The record ID the manifest lists under `name`, whether its record is healthy or damaged.
    pub(super) fn record_id_of(&self, name: &CredentialName) -> Option<RecordId> {
        self.manifest.entries().iter().find(|(_, entry)| entry.name() == name).map(|(id, _)| *id)
    }

    /// Seals the new record and builds and seals the next manifest, touching no file.
    fn prepare(&self, name: CredentialName, new: Option<CredentialRecord>, old: Option<RecordId>) -> Result<Prepared, VaultError> {
        let new = new.map(|record| seal_record(&self.identity, record)).transpose()?;
        let mut entries = self.manifest.entries().clone();
        if let Some(old) = old {
            entries.remove(&old);
        }
        if let Some(SealedRecord { record, bytes }) = &new {
            entries.insert(record.id(), ManifestEntry::new(record.name().clone(), record_digest(bytes)));
        }
        let manifest = self.manifest.next(entries).map_err(VaultError::NextManifest)?;
        let manifest_bytes = seal_manifest(&self.identity, &manifest).map_err(VaultError::Seal)?;
        Ok(Prepared { name, new, old, manifest, manifest_bytes })
    }

    /// Runs the file steps of a prepared write, then updates memory once the manifest has committed.
    fn write(&mut self, lock: &StateDirLock, fs: &impl StoreFs, prepared: Prepared) -> Result<WriteReport, VaultError> {
        let removed = self.remove_unindexed(lock, fs)?;
        if let Some(new) = &prepared.new {
            write_record_file(lock, fs, new)?;
        }
        commit_manifest(lock, fs, &prepared.manifest_bytes).inspect_err(|error| self.after_failed_commit(lock, fs, &prepared, error))?;
        let Prepared { name, new, old, manifest, .. } = prepared;
        self.manifest = manifest;
        match new {
            Some(new) => self.healthy.insert(name, new.record),
            None => self.healthy.remove(&name),
        };
        Ok(WriteReport::new(removed, old.and_then(|old| remove_superseded(lock, fs, old))))
    }

    /// Durably removes every record file the manifest does not list, so no interrupted write's file outlives the next one.
    ///
    /// Only names the manifest leaves out are touched, and memory matches the disk manifest whenever this runs (an
    /// uncertain commit blocks every later write), so no indexed record file is ever removed.
    fn remove_unindexed(&self, lock: &StateDirLock, fs: &impl StoreFs) -> Result<BTreeSet<StateFileName>, VaultError> {
        let unindexed = unindexed_files(&self.manifest, &list_state_dir(lock, fs)?);
        unindexed.iter().try_for_each(|file| remove_unindexed_file(lock, fs, file))?;
        Ok(unindexed)
    }

    /// After an uncertain commit the disk may hold the new manifest, so the new file stays and writes stop until a
    /// reopen; after any other failure the manifest is unchanged, so the new file is unindexed and can go now.
    fn after_failed_commit(&mut self, lock: &StateDirLock, fs: &impl StoreFs, prepared: &Prepared, error: &VaultError) {
        match (error, &prepared.new) {
            (VaultError::CommitUncertain(_), _) => self.needs_reopen = true,
            (_, Some(new)) => discard(lock, fs, new.record.id()),
            (_, None) => {}
        }
    }
}

/// Durably replaces the manifest: the commit point of every vault write.
///
/// A failure at the directory fsync comes after the rename, so the disk may already hold the new manifest; that is
/// [`VaultError::CommitUncertain`], never "unchanged".
pub(super) fn commit_manifest(lock: &StateDirLock, fs: &impl StoreFs, bytes: &[u8]) -> Result<(), VaultError> {
    durable_replace(lock, fs, &StateFileName::manifest(), bytes).map_err(|error| match error {
        WriteError::Io { step: WriteStep::SyncDir, .. } => {
            tracing::error!(
                error = %error,
                remediation = "reopen the vault: the write committed only if the reopened vault shows it",
                "vault manifest was replaced but the state directory fsync failed; the write may not survive power loss"
            );
            VaultError::CommitUncertain(error)
        }
        other => VaultError::Write(other),
    })
}

fn new_record(name: CredentialName, material: CredentialMaterial, origins: PermittedOrigins) -> Result<CredentialRecord, VaultError> {
    CredentialRecord::new(RecordId::new_random(), name, material, origins, Source::DirectEntry).map_err(VaultError::InvalidMaterial)
}

fn seal_record(identity: &VaultIdentity, record: CredentialRecord) -> Result<SealedRecord, VaultError> {
    let bytes = seal(&identity.public_key(), &encode(&record)).map_err(VaultError::Seal)?;
    Ok(SealedRecord { record, bytes })
}

/// Writes the new record file. On failure it may already be visible (a failed directory fsync), so it is discarded.
fn write_record_file(lock: &StateDirLock, fs: &impl StoreFs, new: &SealedRecord) -> Result<(), VaultError> {
    durable_replace(lock, fs, &StateFileName::record(&new.record.id()), &new.bytes).map_err(|error| {
        discard(lock, fs, new.record.id());
        VaultError::Write(error)
    })
}

/// Best effort: removes a new record file no manifest lists. A file left behind is unindexed and the next write
/// removes it, so the write's own error is the one worth reporting.
fn discard(lock: &StateDirLock, fs: &impl StoreFs, id: RecordId) {
    let _ = durable_remove(lock, fs, &StateFileName::record(&id));
}

fn remove_unindexed_file(lock: &StateDirLock, fs: &impl StoreFs, file: &StateFileName) -> Result<(), VaultError> {
    match durable_remove(lock, fs, file) {
        Ok(()) | Err(WriteError::NotFound { .. }) => {
            tracing::warn!(
                file = %file,
                remediation = "none if a vault write was interrupted; otherwise investigate who can write to the state directory",
                "removed a record file the vault manifest does not list"
            );
            Ok(())
        }
        Err(error) => Err(VaultError::Write(error)),
    }
}

/// Removes the record file a committed write superseded, returning its name if it may remain. The write has already
/// committed, so a failure here is not an error: the file is unindexed and the next write removes it.
fn remove_superseded(lock: &StateDirLock, fs: &impl StoreFs, old: RecordId) -> Option<StateFileName> {
    let file = StateFileName::record(&old);
    match durable_remove(lock, fs, &file) {
        // A damaged record's file may already be missing.
        Ok(()) | Err(WriteError::NotFound { .. }) => None,
        Err(error) => {
            tracing::warn!(
                file = %file,
                error = %error,
                remediation = "none: the next vault write removes it",
                "superseded record file could not be removed after the vault write committed"
            );
            Some(file)
        }
    }
}
