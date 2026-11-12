//! Vault writes: adds, replaces or removes one credential record, or records the approval state in the manifest
//! ([spec §6](../../../../design/iron-vault-specification.md#6-credential-records-and-configuration),
//! [spec §12](../../../../design/iron-vault-specification.md#12-configuration-approval-and-reload),
//! [spec §13](../../../../design/iron-vault-specification.md#13-vault-structure-and-durable-writes)). The service runs
//! them for `add`, `replace`, `rm` and `init`.
//!
//! Every write runs the same steps ([storage formats, "Writes"](../../../../design/storage-formats.md#writes)):
//!
//! ```text
//! prepare (no file written)                        file steps
//! ─────────────────────────                        ──────────
//! 1. check the manifest on disk is the one held    5. remove unindexed record files
//! 2. read the approval state's state generation    6. write the new record file
//! 3. seal the new record                           7. durably replace manifest.age   ← commit
//! 4. build and seal the next manifest              8. update memory
//!                                                  9. remove the superseded record file
//! ```
//!
//! The next manifest takes the next state generation after the approval state's and its own, and records the approval
//! state's as its peer. The state-directory lock makes the service the only writer, so the approval state on disk is the
//! current one and no two writes share a state generation. A crash before the commit leaves the old vault plus at most
//! one unindexed record file; a crash after it leaves the new vault plus at most the superseded file.

use std::collections::BTreeSet;

use iron_vault_kinds::CredentialMaterial;
use iron_vault_policy::CredentialName;

use super::{Vault, VaultError, WriteReport, approval_generations, list_state_dir, refuse_partial_restore, unindexed_files};
use crate::ErrorKindLabel;
use crate::{
    ApprovalState, CredentialRecord, MAX_MANIFEST_LEN, ManifestEntry, PermittedOrigins, PinnedApprover, RecordId, Source, StateDirLock,
    StateFileName, StateGeneration, StoreFs, VaultIdentity, VaultManifest, WriteError, WriteStep, durable_remove, durable_replace, encode,
    open_manifest, read_state_file, record_digest, seal, seal_manifest,
};

/// A record and the sealed bytes of its file, which its manifest entry's digest covers.
struct SealedRecord {
    record: CredentialRecord,
    bytes: Vec<u8>,
}

/// One write with its work that needs no file write done: the record to write, the record it supersedes and the
/// manifest to commit.
struct Prepared {
    /// The credential the write changes; `None` for a manifest-only write.
    name: Option<CredentialName>,
    new: Option<SealedRecord>,
    old: Option<RecordId>,
    manifest: VaultManifest,
    manifest_bytes: Vec<u8>,
}

impl Vault {
    /// Adds a credential record named `name` under a new record ID, refusing a name the manifest already lists.
    ///
    /// This performs an already authorized change: the caller checks owner presence
    /// ([spec §6](../../../../design/iron-vault-specification.md#6-credential-records-and-configuration)). Returns the
    /// new record's ID and what else the write did, including any short secret in the new record, for the audit log.
    pub fn add(
        &mut self,
        lock: &StateDirLock,
        fs: &impl StoreFs,
        name: CredentialName,
        material: CredentialMaterial,
        origins: PermittedOrigins,
    ) -> Result<(RecordId, WriteReport), VaultError> {
        self.ensure_same_dir(lock)?;
        if self.record_id_of(&name).is_some() {
            return Err(VaultError::NameTaken(name));
        }
        let short = material.short_secrets();
        let record = new_record(name, material, origins)?;
        let id = record.id();
        let report = self.write(lock, fs, self.prepare(lock, fs, Some(record.name().clone()), Some(record), None)?)?;
        Ok((id, report.with_short_secrets(short)))
    }

    /// Replaces the record named `name` with a new record under a new record ID, so a swapped account shows as a new
    /// record identity, not an edit
    /// ([spec §6](../../../../design/iron-vault-specification.md#6-credential-records-and-configuration)). The
    /// superseded file is removed after the commit.
    ///
    /// The record may be damaged: replacing it is how a damaged credential is repaired. This performs an already
    /// authorized change: the caller checks owner presence and the routes that use the credential. The report names
    /// any short secret in the new record.
    pub fn replace(
        &mut self,
        lock: &StateDirLock,
        fs: &impl StoreFs,
        name: CredentialName,
        material: CredentialMaterial,
        origins: PermittedOrigins,
    ) -> Result<(RecordId, WriteReport), VaultError> {
        self.ensure_same_dir(lock)?;
        let old = self.record_id_of(&name).ok_or_else(|| VaultError::UnknownName(name.clone()))?;
        let short = material.short_secrets();
        let record = new_record(name, material, origins)?;
        let id = record.id();
        let report = self.write(
            lock,
            fs,
            self.prepare(lock, fs, Some(record.name().clone()), Some(record), Some(old))?,
        )?;
        Ok((id, report.with_short_secrets(short)))
    }

    /// Removes the record named `name`, healthy or damaged: commits a manifest without it, then removes its file.
    ///
    /// This performs an already authorized change: the caller checks owner presence and the routes that use the
    /// credential. A later `add` of the same name gets a new record ID, so the name never silently rebinds.
    pub fn remove(&mut self, lock: &StateDirLock, fs: &impl StoreFs, name: &CredentialName) -> Result<WriteReport, VaultError> {
        self.ensure_same_dir(lock)?;
        let old = self.record_id_of(name).ok_or_else(|| VaultError::UnknownName(name.clone()))?;
        self.write(lock, fs, self.prepare(lock, fs, Some(name.clone()), None, Some(old))?)
    }

    /// Writes a manifest with unchanged entries that records the approval state's current state generation as its peer.
    ///
    /// Until a manifest records the approval state, deleting `approval.age` leaves a pair the partial restore check
    /// accepts, and creating the approval state again would reset its counters
    /// ([spec §12](../../../../design/iron-vault-specification.md#12-configuration-approval-and-reload)). Refuses with
    /// [`VaultError::NoApprovalState`] when there is none. Changes no record file.
    pub fn record_approval_state(&mut self, lock: &StateDirLock, fs: &impl StoreFs) -> Result<WriteReport, VaultError> {
        self.ensure_same_dir(lock)?;
        let prepared = self.prepare(lock, fs, None, None, None)?;
        match prepared.manifest.peer_generation() {
            Some(_) => self.write(lock, fs, prepared),
            None => Err(VaultError::NoApprovalState),
        }
    }

    /// Creates the approval state with `approver` pinned, then records it in the manifest, so a later deletion of
    /// `approval.age` is refused as a partial restore.
    ///
    /// If the approval state was written but the manifest write then failed, returns
    /// [`VaultError::ApprovalStateUnrecorded`] and leaves the approval state in place: creating it again would be
    /// refused, and [`Vault::record_approval_state`] records it. The caller has already authorized this.
    pub fn create_approval_state(
        &mut self,
        lock: &StateDirLock,
        fs: &impl StoreFs,
        approver: PinnedApprover,
    ) -> Result<(ApprovalState, WriteReport), VaultError> {
        self.ensure_same_dir(lock)?;
        self.ensure_disk_manifest_matches(lock, fs)?;
        let state = ApprovalState::create(lock, fs, &self.identity, approver).map_err(VaultError::ApprovalState)?;
        let report = self
            .record_approval_state(lock, fs)
            .map_err(|error| VaultError::ApprovalStateUnrecorded(Box::new(error)))?;
        Ok((state, report))
    }

    /// Refuses another state directory's lock: its files are not this vault's, and cleanup there would remove another
    /// vault's records.
    fn ensure_same_dir(&self, lock: &StateDirLock) -> Result<(), VaultError> {
        match lock.dir() == self.dir {
            true => Ok(()),
            false => Err(VaultError::WrongStateDir {
                vault_dir: self.dir.clone(),
                lock_dir: lock.dir().to_path_buf(),
            }),
        }
    }

    /// Refuses with [`VaultError::ReopenRequired`] unless the manifest on disk is exactly the one in memory.
    ///
    /// Cleanup removes every record file the in-memory manifest leaves out, so a stale `Vault` would remove records
    /// another writer committed, and its commit would overwrite theirs. An uncertain commit leaves the new manifest
    /// on disk, so this also stops every write after one until the vault is reopened.
    fn ensure_disk_manifest_matches(&self, lock: &StateDirLock, fs: &impl StoreFs) -> Result<(), VaultError> {
        // MAX_MANIFEST_LEN is 1 MiB, so it always fits in a u64.
        let bytes =
            read_state_file(lock, fs, &StateFileName::manifest(), MAX_MANIFEST_LEN as u64).map_err(|_| VaultError::ReopenRequired)?;
        match open_manifest(&self.identity, &bytes) {
            Ok(on_disk) if on_disk == self.manifest => Ok(()),
            _ => Err(VaultError::ReopenRequired),
        }
    }

    /// Returns the state generation of this vault's approval state on disk, or `None` while none has been written. An
    /// approval state that cannot be read or opened is damaged shared state, and the write is refused.
    ///
    /// A partial restore is refused too, never written over: the next manifest would record the restored approval state
    /// as its peer, or record no peer after a deletion, and the pair would agree again and hide the restore
    /// ([spec §12](../../../../design/iron-vault-specification.md#12-configuration-approval-and-reload)).
    /// The caller has checked that the manifest in memory is the one on disk.
    fn approval_generation(&self, lock: &StateDirLock, fs: &impl StoreFs) -> Result<Option<StateGeneration>, VaultError> {
        let approval = approval_generations(lock, fs, &self.identity, &self.manifest)?;
        refuse_partial_restore(&self.manifest, approval)?;
        Ok(approval.map(|(state, _)| state))
    }

    /// Returns the record ID the manifest lists under `name`, whether its record is healthy or damaged.
    pub(super) fn record_id_of(&self, name: &CredentialName) -> Option<RecordId> {
        self.manifest
            .entries()
            .iter()
            .find(|(_, entry)| entry.name() == name)
            .map(|(id, _)| *id)
    }

    /// Checks that the manifest on disk is the one in memory and reads the approval state's state generation, then
    /// seals the new record and builds and seals the next manifest. Writes no file.
    fn prepare(
        &self,
        lock: &StateDirLock,
        fs: &impl StoreFs,
        name: Option<CredentialName>,
        new: Option<CredentialRecord>,
        old: Option<RecordId>,
    ) -> Result<Prepared, VaultError> {
        self.ensure_disk_manifest_matches(lock, fs)?;
        let approval_generation = self.approval_generation(lock, fs)?;
        let new = new.map(|record| seal_record(&self.identity, record)).transpose()?;
        let mut entries = self.manifest.entries().clone();
        if let Some(old) = old {
            entries.remove(&old);
        }
        if let Some(SealedRecord { record, bytes }) = &new {
            entries.insert(record.id(), ManifestEntry::new(record.name().clone(), record_digest(bytes)));
        }
        let manifest = self.manifest.next(approval_generation, entries).map_err(VaultError::NextManifest)?;
        let manifest_bytes = seal_manifest(&self.identity, &manifest).map_err(VaultError::Seal)?;
        Ok(Prepared {
            name,
            new,
            old,
            manifest,
            manifest_bytes,
        })
    }

    /// Runs the file steps of a prepared write, then updates memory once the manifest has committed.
    ///
    /// A success reports its removed unindexed files in the [`WriteReport`], which the service audits. A failure has no
    /// report to carry them, so the store records each removal itself (`log_removed_before_failure`).
    fn write(&mut self, lock: &StateDirLock, fs: &impl StoreFs, prepared: Prepared) -> Result<WriteReport, VaultError> {
        let mut removed = BTreeSet::new();
        self.write_steps(lock, fs, prepared, &mut removed)
            .inspect_err(|_| log_removed_before_failure(&removed))
    }

    /// Runs steps 5 to 9: removes unindexed files, writes the new record file, commits the manifest, updates memory
    /// and removes the superseded file.
    fn write_steps(
        &mut self,
        lock: &StateDirLock,
        fs: &impl StoreFs,
        prepared: Prepared,
        removed: &mut BTreeSet<StateFileName>,
    ) -> Result<WriteReport, VaultError> {
        self.remove_unindexed(lock, fs, removed)?;
        if let Some(new) = &prepared.new {
            write_record_file(lock, fs, new)?;
        }
        commit_manifest(lock, fs, &prepared.manifest_bytes).inspect_err(|error| after_failed_commit(lock, fs, &prepared, error))?;
        let Prepared {
            name, new, old, manifest, ..
        } = prepared;
        self.manifest = manifest;
        match (name, new) {
            (Some(name), Some(new)) => _ = self.healthy.insert(name, new.record),
            (Some(name), None) => _ = self.healthy.remove(&name),
            (None, _) => {}
        };
        Ok(WriteReport::new(
            std::mem::take(removed),
            old.and_then(|old| remove_superseded(lock, fs, old)),
        ))
    }

    /// Durably removes every record file the manifest does not list, so no interrupted write's file outlives the next one.
    ///
    /// Only names the manifest leaves out are touched, and the write has just checked that the disk manifest is the one
    /// in memory, so no indexed record file is ever removed.
    fn remove_unindexed(&self, lock: &StateDirLock, fs: &impl StoreFs, removed: &mut BTreeSet<StateFileName>) -> Result<(), VaultError> {
        let unindexed = unindexed_files(&self.manifest, &list_state_dir(lock, fs)?);
        unindexed.into_iter().try_for_each(|file| {
            remove_unindexed_file(lock, fs, &file)?;
            removed.insert(file);
            Ok(())
        })
    }
}

/// Discards the new record file after a failed commit, unless the commit was uncertain. After an uncertain commit the
/// disk may hold the new manifest, which lists the new file, so it stays. After any other failure the manifest is
/// unchanged, so the new file is unindexed and can go now.
fn after_failed_commit(lock: &StateDirLock, fs: &impl StoreFs, prepared: &Prepared, error: &VaultError) {
    match (error, &prepared.new) {
        (VaultError::CommitUncertain(_), _) | (_, None) => {}
        (_, Some(new)) => discard(lock, fs, new.record.id()),
    }
}

/// Durably replaces the manifest: the commit point of every vault write.
///
/// A failure at the directory fsync comes after the rename, so the disk may already hold the new manifest; that is
/// [`VaultError::CommitUncertain`], never "unchanged".
pub(super) fn commit_manifest(lock: &StateDirLock, fs: &impl StoreFs, bytes: &[u8]) -> Result<(), VaultError> {
    durable_replace(lock, fs, &StateFileName::manifest(), bytes).map_err(|error| match error {
        WriteError::Io {
            step: WriteStep::SyncDir, ..
        } => VaultError::CommitUncertain(error),
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

/// Removes a new record file no manifest lists, ignoring a failure. A file left behind is unindexed and the next write
/// removes it, so the write's own error is the one to report.
fn discard(lock: &StateDirLock, fs: &impl StoreFs, id: RecordId) {
    let _ = durable_remove(lock, fs, &StateFileName::record(&id));
}

/// Logs the unindexed files a failed write had already removed, as a diagnostic record with a fixed message and the
/// file name only. The store does not know the audit event names; a successful write carries its removals in its
/// [`WriteReport`].
fn log_removed_before_failure(removed: &BTreeSet<StateFileName>) {
    removed
        .iter()
        .for_each(|file| tracing::warn!(file = %file, "a failed vault write had removed a record file the vault manifest does not list"));
}

fn remove_unindexed_file(lock: &StateDirLock, fs: &impl StoreFs, file: &StateFileName) -> Result<(), VaultError> {
    match durable_remove(lock, fs, file) {
        Ok(()) | Err(WriteError::NotFound { .. }) => Ok(()),
        Err(error) => Err(VaultError::Write(error)),
    }
}

/// Removes the record file a committed write superseded, returning its name if it may remain. The write has already
/// committed, so a failure here is not an error: the file is unindexed and the next write removes it. The failure's kind
/// goes into the write report, which the service audits.
fn remove_superseded(lock: &StateDirLock, fs: &impl StoreFs, old: RecordId) -> Option<(StateFileName, ErrorKindLabel)> {
    let file = StateFileName::record(&old);
    match durable_remove(lock, fs, &file) {
        // A damaged record's file may already be missing.
        Ok(()) | Err(WriteError::NotFound { .. }) => None,
        Err(error) => Some((file, error.error_kind_label())),
    }
}
