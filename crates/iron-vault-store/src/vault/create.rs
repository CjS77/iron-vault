//! Creating an empty vault: the manifest that every later write builds on.

use std::collections::BTreeMap;

use super::{SharedStateDamage, Vault, VaultError, is_record_file_name, list_state_dir, write::commit_manifest};
use crate::{StateDirLock, StateFileName, StoreFs, VaultId, VaultIdentity, VaultManifest, seal_manifest};

impl Vault {
    /// Creates an empty vault in the locked state directory: a new vault ID and a manifest at generation 0 with no
    /// entries, written durably before any record file can exist.
    ///
    /// Writing the empty manifest first is what lets a crash during the first add be told apart from a lost index:
    /// record files without a manifest open as damaged shared state, never as a new vault. For the same reason this
    /// refuses a state directory that already holds a manifest or any record file, and never overwrites either.
    ///
    /// A [`VaultError::CommitUncertain`] means the manifest may not survive power loss: open the vault to see whether
    /// it exists. The caller has already authorized initialization; this performs it.
    pub fn create(lock: &StateDirLock, fs: &impl StoreFs, identity: VaultIdentity) -> Result<Vault, VaultError> {
        refuse_existing_vault(&list_state_dir(lock, fs)?)?;
        let manifest = VaultManifest::new(VaultId::new_random(), 0, BTreeMap::new()).map_err(VaultError::NextManifest)?;
        commit_manifest(lock, fs, &seal_manifest(&identity, &manifest).map_err(VaultError::Seal)?)?;
        Ok(Vault {
            dir: lock.dir().to_path_buf(),
            identity,
            manifest,
            healthy: BTreeMap::new(),
        })
    }
}

/// Refuses a state directory that holds a manifest, or record files whose manifest is gone.
fn refuse_existing_vault(files: &[String]) -> Result<(), VaultError> {
    let manifest = StateFileName::manifest();
    match (
        files.iter().any(|f| f == manifest.as_str()),
        files.iter().any(|f| is_record_file_name(f)),
    ) {
        (true, _) => Err(VaultError::AlreadyInitialized),
        (false, true) => Err(VaultError::SharedStateDamaged {
            file: manifest,
            damage: SharedStateDamage::MissingWithRecords,
        }),
        (false, false) => Ok(()),
    }
}
