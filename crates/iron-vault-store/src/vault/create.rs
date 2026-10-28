//! Creating an empty vault: the manifest that every later write builds on.

use std::collections::BTreeMap;

use super::{Vault, VaultError, classify_missing_manifest, list_state_dir, write::commit_manifest};
use crate::{StateDirLock, StateFileName, StoreFs, VaultId, VaultIdentity, VaultManifest, seal_manifest};

impl Vault {
    /// Creates an empty vault in the locked state directory: a new vault ID and a manifest with no entries at the first
    /// state generation, written durably before any record file or approval state can exist.
    ///
    /// Writing the empty manifest first is what lets a crash during the first add be told apart from a lost index:
    /// record files without a manifest open as damaged shared state, never as a new vault. For the same reason this
    /// refuses a state directory that already holds a manifest or any record file, and never overwrites either.
    ///
    /// It also refuses `approval.age` without a manifest: approval counters start at zero only when a vault is created
    /// and are never reset (spec §3.9), so a new vault ID beside an earlier vault's counters would be a reset. The
    /// envelope files `identity.age`, `operational.age` and `approver.age` do not block creation, because
    /// initialization writes them around this call and a retried initialization must still create. Initialization must
    /// write `identity.age` durably before the first record is sealed (EP-24).
    ///
    /// A [`VaultError::CommitUncertain`] means the manifest may not survive power loss: open the vault to see whether
    /// it exists. The caller has already authorized initialization; this performs it.
    pub fn create(lock: &StateDirLock, fs: &impl StoreFs, identity: VaultIdentity) -> Result<Vault, VaultError> {
        refuse_existing_vault(&list_state_dir(lock, fs)?)?;
        let manifest = VaultManifest::first(VaultId::new_random()).map_err(VaultError::NextManifest)?;
        commit_manifest(lock, fs, &seal_manifest(&identity, &manifest).map_err(VaultError::Seal)?)?;
        Ok(Vault {
            dir: lock.dir().to_path_buf(),
            identity,
            manifest,
            healthy: BTreeMap::new(),
        })
    }
}

/// Refuses a state directory that holds a manifest, or record files or approval state whose manifest is gone.
fn refuse_existing_vault(files: &[String]) -> Result<(), VaultError> {
    let manifest = StateFileName::manifest();
    if files.iter().any(|f| f == manifest.as_str()) {
        return Err(VaultError::AlreadyInitialized);
    }
    classify_missing_manifest(files).map_or(Ok(()), |damage| Err(VaultError::SharedStateDamaged { file: manifest, damage }))
}
