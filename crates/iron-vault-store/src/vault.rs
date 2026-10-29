//! Opening the vault: the manifest, then every record it lists, with damaged records isolated (spec §3.10, §3.12).
//!
//! The manifest is shared state: if it cannot be trusted, no record can be told from a planted one, so the whole vault
//! is unavailable. So is the approval state, whose state generation the manifest records: a pair of the two that no
//! sequence of writes leaves together is a partial restore, and refused. A record is not shared: a damaged one takes
//! down only the routes that use it, and the others load.
//!
//! Vault writes (spec §3.3, §3.10) make the durable replace of the manifest their single commit point: a new record file
//! is written before it and a superseded one removed after it, so a crash at any step leaves the old or the new vault.

mod create;
mod load;
mod report;
#[cfg(test)]
mod tests;
mod write;
#[cfg(test)]
mod write_tests;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io;
use std::path::PathBuf;

use iron_vault_kinds::{CredentialMaterial, KindError};
use iron_vault_policy::{CatalogEntry, CredentialCatalog, CredentialName};
use thiserror::Error;

use crate::{
    ApprovalState, ApprovalStateError, CredentialRecord, MAX_MANIFEST_LEN, ManifestError, PartialRestore, ReadError, SealError,
    StateDirLock, StateFileName, StateGeneration, StoreFs, VaultIdentity, VaultManifest, WriteError, open_manifest,
    partial_restore::check_control_generations, read_state_file,
};

pub use load::MAX_RECORD_FILE_LEN;
pub use report::{OpenReport, RecordDamage, WriteReport};

/// What the administrator should do about damaged shared state; recovery commands arrive with spec §3.13.
const SHARED_STATE_REMEDIATION: &str = "restore the state directory from a backup taken by this vault, or recover the vault; \
     do not delete or re-initialize the state directory, which would orphan every credential record";

/// The vault cannot be opened, created or written. No variant carries file contents or key material.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum VaultError {
    /// There is no manifest, no record file and no approval state: no vault has been created in this state directory.
    #[error("the vault is not initialized: the state directory holds no manifest and no credential records")]
    NotInitialized,
    /// Shared state cannot be trusted (spec §3.10, §3.12). An open refuses the whole vault, and a write refuses to change
    /// it and touches no file.
    #[error("vault shared state file {file} is damaged ({damage}); the vault is unavailable and may require recovery")]
    SharedStateDamaged {
        /// The damaged file.
        file: StateFileName,
        /// What is wrong with it.
        damage: SharedStateDamage,
    },
    /// The state directory could not be listed, so record files could not be checked against the manifest.
    #[error("cannot list the state directory: {kind}")]
    ListStateDir {
        /// The underlying error kind.
        kind: io::ErrorKind,
    },
    /// A vault cannot be created where a manifest already exists.
    #[error("the vault is already initialized: the state directory holds a manifest")]
    AlreadyInitialized,
    /// `add` refuses a name the manifest already lists, whether its record is healthy or damaged (spec §3.3).
    #[error("credential {0} already exists; replacing it requires an explicit replace")]
    NameTaken(CredentialName),
    /// `replace` and `remove` need a name the manifest lists.
    #[error("credential {0} does not exist")]
    UnknownName(CredentialName),
    /// The material breaks its kind's rules, so no record was built.
    #[error("the credential material is invalid: {0}")]
    InvalidMaterial(KindError),
    /// Sealing the record or the manifest failed; nothing was written.
    #[error("cannot seal the vault write: {0}")]
    Seal(SealError),
    /// The next manifest cannot be built: the vault holds the most records allowed, or the state generation is exhausted.
    #[error("cannot build the next vault manifest: {0}")]
    NextManifest(ManifestError),
    /// A file step failed before the commit point. The vault on disk and in memory is unchanged, apart from at most
    /// one unindexed record file that the next write removes.
    #[error("the vault write failed and changed nothing: {0}")]
    Write(WriteError),
    /// The new manifest was renamed into place but the state directory fsync failed, so the commit may not survive
    /// power loss. Disk may now hold the new vault while memory holds the old one: reopen the vault before using it.
    #[error("the vault write may or may not have committed ({0}); reopen the vault to see which")]
    CommitUncertain(WriteError),
    /// The manifest on disk is not the one this `Vault` holds, or cannot be read: another writer committed, an earlier
    /// commit was uncertain, or the manifest is gone or damaged. Nothing was written; reopen the vault.
    #[error("the vault manifest on disk differs from the open vault's; reopen the vault before writing")]
    ReopenRequired,
    /// A write was given the lock of a state directory other than the one this vault was opened or created in.
    #[error("the state directory lock is for {}, but the vault is in {}", .lock_dir.display(), .vault_dir.display())]
    WrongStateDir {
        /// The state directory the vault was opened or created in.
        vault_dir: PathBuf,
        /// The state directory the given lock holds.
        lock_dir: PathBuf,
    },
}

/// Why a shared state file cannot be trusted.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SharedStateDamage {
    /// The manifest is gone but record files remain, so the vault exists and has lost its index.
    #[error("it is missing, but credential record files exist")]
    MissingWithRecords,
    /// The manifest is gone but approval state remains, so a vault existed here and was damaged or half removed;
    /// creating a new one would reset its approval counters (spec §3.9).
    #[error("it is missing, but approval.age from an earlier vault remains; recover or reset the vault rather than initialize")]
    MissingWithApprovalState,
    /// The file could not be read, or is over its size limit.
    #[error(transparent)]
    Read(ReadError),
    /// The file was read but did not open as a manifest of this vault.
    #[error(transparent)]
    Manifest(ManifestError),
    /// The approval state, whose state generation every vault write records, cannot be read or opened as this vault's.
    #[error(transparent)]
    ApprovalState(ApprovalStateError),
    /// The manifest and the approval state are not a pair any sequence of writes leaves: the named file was restored
    /// from an older copy or deleted. It is never repaired automatically (spec §3.9); the owner recovers or resets.
    #[error(transparent)]
    PartialRestore(PartialRestore),
}

/// An open vault: its identity, its manifest and every healthy credential record.
///
/// Records the manifest lists but that failed to load are known by name only, so their routes can be refused rather
/// than reported as unknown. `Debug` shows credential names, never material.
pub struct Vault {
    /// The state directory the vault was opened or created in; a write refuses any other directory's lock.
    dir: PathBuf,
    identity: VaultIdentity,
    manifest: VaultManifest,
    healthy: BTreeMap<CredentialName, CredentialRecord>,
}

impl Vault {
    /// Opens the vault in the locked state directory, loading every record the manifest lists that is intact.
    ///
    /// A missing, unreadable or forged manifest fails the whole open, because without it no record can be trusted. A
    /// damaged record does not: it is left out, reported in the [`OpenReport`] and logged at ERROR, and the others
    /// load. Record files the manifest does not list are reported and logged at WARN, and never loaded or removed.
    ///
    /// The manifest and the approval state must be a pair some sequence of writes leaves together: a manifest or
    /// approval state restored alone from an older copy, or an approval state deleted, fails the open as a partial
    /// restore before any record is read. Restoring both together is not detected here: that needs an anchor outside
    /// the state directory (spec §3.9).
    pub fn open(lock: &StateDirLock, fs: &impl StoreFs, identity: VaultIdentity) -> Result<(Vault, OpenReport), VaultError> {
        let files = list_state_dir(lock, fs).inspect_err(log_vault_error)?;
        let manifest = read_manifest(lock, fs, &identity, &files).inspect_err(log_vault_error)?;
        let approval = approval_generations(lock, fs, &identity, &manifest).inspect_err(log_vault_error)?;
        refuse_partial_restore(&manifest, approval).inspect_err(log_vault_error)?;
        let (healthy, damaged) = load::load_records(lock, fs, &identity, &manifest);
        let unindexed = unindexed_files(&manifest, &files);
        unindexed.iter().for_each(load::log_unindexed);
        let dir = lock.dir().to_path_buf();
        Ok((
            Vault {
                dir,
                identity,
                manifest,
                healthy,
            },
            OpenReport::new(damaged, unindexed),
        ))
    }

    /// The manifest the vault was opened with.
    pub fn manifest(&self) -> &VaultManifest {
        &self.manifest
    }

    /// The secret material of the healthy record named `name`; `None` for a damaged or absent one.
    pub fn material(&self, name: &CredentialName) -> Option<&CredentialMaterial> {
        self.healthy.get(name).map(CredentialRecord::material)
    }
}

impl CredentialCatalog for Vault {
    fn entry(&self, name: &CredentialName) -> CatalogEntry {
        match self.healthy.get(name) {
            Some(record) => CatalogEntry::Usable {
                kind: record.kind(),
                origins: record.origins().as_set().clone(),
            },
            None if self.manifest.entries().values().any(|entry| entry.name() == name) => CatalogEntry::Unusable,
            None => CatalogEntry::Unknown,
        }
    }
}

/// Shows the identity's public key and the healthy credential names; material never appears.
impl fmt::Debug for Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vault")
            .field("identity", &self.identity)
            .field("vault_id", &self.manifest.vault_id())
            .field("state_generation", &self.manifest.state_generation())
            .field("healthy", &self.healthy.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

/// The UTF-8 names in the state directory; no store file has any other kind of name.
fn list_state_dir(lock: &StateDirLock, fs: &impl StoreFs) -> Result<Vec<String>, VaultError> {
    let names = fs.list_dir(lock.dir()).map_err(|e| VaultError::ListStateDir { kind: e.kind() })?;
    Ok(names.into_iter().filter_map(|name| name.into_string().ok()).collect())
}

fn read_manifest(lock: &StateDirLock, fs: &impl StoreFs, identity: &VaultIdentity, files: &[String]) -> Result<VaultManifest, VaultError> {
    let file = StateFileName::manifest();
    let damaged = |damage| VaultError::SharedStateDamaged {
        file: file.clone(),
        damage,
    };
    // MAX_MANIFEST_LEN is 1 MiB, so it always fits in a u64.
    match read_state_file(lock, fs, &file, MAX_MANIFEST_LEN as u64) {
        Err(ReadError::Io {
            kind: io::ErrorKind::NotFound,
            ..
        }) => Err(classify_missing_manifest(files).map_or(VaultError::NotInitialized, damaged)),
        Err(e) => Err(damaged(SharedStateDamage::Read(e))),
        Ok(bytes) => open_manifest(identity, &bytes).map_err(|e| damaged(SharedStateDamage::Manifest(e))),
    }
}

/// The approval state's state generation and peer generation on disk, or `None` while `approval.age` does not exist.
/// An approval state that cannot be read or opened as this vault's is damaged shared state.
fn approval_generations(
    lock: &StateDirLock,
    fs: &impl StoreFs,
    identity: &VaultIdentity,
    manifest: &VaultManifest,
) -> Result<Option<(StateGeneration, StateGeneration)>, VaultError> {
    match ApprovalState::read(lock, fs, identity, manifest.vault_id()) {
        Ok(state) => Ok(Some(state.generations())),
        Err(ApprovalStateError::Read(ReadError::Io {
            kind: io::ErrorKind::NotFound,
            ..
        })) => Ok(None),
        Err(error) => Err(VaultError::SharedStateDamaged {
            file: StateFileName::approval_state(),
            damage: SharedStateDamage::ApprovalState(error),
        }),
    }
}

/// Refuses `manifest` beside an approval state at `approval` (`None` if missing) when no sequence of writes leaves the
/// two together, naming the file that is behind.
fn refuse_partial_restore(manifest: &VaultManifest, approval: Option<(StateGeneration, StateGeneration)>) -> Result<(), VaultError> {
    check_control_generations(manifest.generations(), approval).map_err(|restore| VaultError::SharedStateDamaged {
        file: restore.file(),
        damage: SharedStateDamage::PartialRestore(restore),
    })
}

/// Why a state directory without a manifest is damaged shared state, or `None` when it holds no vault at all.
fn classify_missing_manifest(files: &[String]) -> Option<SharedStateDamage> {
    let approval = StateFileName::approval_state();
    if files.iter().any(|f| is_record_file_name(f)) {
        Some(SharedStateDamage::MissingWithRecords)
    } else if files.iter().any(|f| f == approval.as_str()) {
        Some(SharedStateDamage::MissingWithApprovalState)
    } else {
        None
    }
}

/// Every `record-*.age` name the manifest does not list. A name that is not a valid state file name is left out: the
/// service could neither have written it nor remove it.
fn unindexed_files(manifest: &VaultManifest, files: &[String]) -> BTreeSet<StateFileName> {
    let indexed: BTreeSet<StateFileName> = manifest.entries().keys().map(StateFileName::record).collect();
    let candidates = files
        .iter()
        .filter(|f| is_record_file_name(f))
        .filter_map(|f| StateFileName::new(f).ok());
    candidates.filter(|name| !indexed.contains(name)).collect()
}

/// Whether `name` has the shape of a record file name, whatever sits between the prefix and the suffix.
fn is_record_file_name(name: &str) -> bool {
    name.starts_with("record-") && name.ends_with(".age")
}

/// Logs a failed open loudly. A missing vault is not damage, so the caller decides how to report it.
fn log_vault_error(error: &VaultError) {
    match error {
        VaultError::SharedStateDamaged { file, damage } => tracing::error!(
            file = %file,
            damage = %damage,
            remediation = SHARED_STATE_REMEDIATION,
            "vault shared state is damaged; the whole vault is unavailable and recovery may be required"
        ),
        VaultError::ListStateDir { kind } => tracing::error!(
            error = %kind,
            remediation = "check that the state directory exists and that the service account can read it",
            "cannot list the state directory; the vault is unavailable"
        ),
        // A missing vault is not damage, and the write variants go to the caller of the write, which audits them.
        VaultError::NotInitialized
        | VaultError::AlreadyInitialized
        | VaultError::NameTaken(_)
        | VaultError::UnknownName(_)
        | VaultError::InvalidMaterial(_)
        | VaultError::Seal(_)
        | VaultError::NextManifest(_)
        | VaultError::Write(_)
        | VaultError::CommitUncertain(_)
        | VaultError::ReopenRequired
        | VaultError::WrongStateDir { .. } => {}
    }
}
