//! The store half of `reset` (design/reset.md): what a reset would discard, read without the vault identity, and the
//! discard itself.
//!
//! The filesystem has no transaction, and a vault holds dozens of files. The discard writes `reset.unfinished` before
//! its first removal and removes it last, and removes the manifest first, so a crash at any point leaves either the
//! intact vault or an Unfinished reset, never a vault that half-opens. Only the next reset finishes an interrupted one:
//! `init`, `import`, `unlock` and startup all refuse it.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;
use std::path::Path;

use crate::durable::{StepFailure, remove_in, replace_in};
use crate::initialization::{Entry, classify, present_config_files};
use crate::store_owned::{CONFIG_FILES, in_removal_order, is_store_owned, is_vault_file};
use crate::vault::is_record_file_name;
use crate::{
    ConfigDirLock, ConfigFileName, ErrorKindLabel, InitStateError, InitializationState, MAX_MANIFEST_LEN, ManifestError, ReadError,
    StateDirLock, StateFileName, StoreFs, VaultId, WriteStep, read_state_file, unverified_vault_id,
};

/// What a reset would discard, read from the directory listings without the vault identity: the store's part of the
/// reset summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResetScope {
    /// The initialization state.
    pub state: InitializationState,
    /// Whether the state directory holds a vault file. With none there is nothing to reset, whatever the state.
    pub has_vault_file: bool,
    /// The number of `record-*.age` files, unverified: only the manifest says which records are live.
    pub record_files: usize,
    /// The config files present, which a reset removes with the vault.
    pub config_files: Vec<ConfigFileName>,
    /// The foreign files in the state directory, sorted, which a reset leaves.
    pub foreign: Vec<String>,
}

/// Reads what a reset would discard. Writes nothing.
pub fn reset_scope(state: &StateDirLock, config: &ConfigDirLock, fs: &impl StoreFs) -> Result<ResetScope, InitStateError> {
    let initialization = InitializationState::read(state, config, fs)?;
    let names = fs
        .list_dir(state.dir())
        .map_err(|e| InitStateError::ListStateDir { kind: e.kind() })?;
    Ok(ResetScope {
        state: initialization,
        has_vault_file: names.iter().any(|name| name.to_str().is_some_and(is_vault_file)),
        record_files: names.iter().filter(|name| name.to_str().is_some_and(is_record_file_name)).count(),
        config_files: present_config_files(config, fs)?,
        foreign: foreign(&names),
    })
}

/// Why the vault ID could not be read from the manifest's clear header.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UnverifiedVaultIdError {
    /// `manifest.age` could not be read.
    #[error(transparent)]
    Read(#[from] ReadError),
    /// Its header is not a manifest's.
    #[error(transparent)]
    Manifest(#[from] ManifestError),
}

/// The vault ID in `manifest.age`'s clear header, read while the vault is locked. It is unverified, since nothing checks
/// the MAC without the vault identity: enough for reset's confirmation, which only names the vault the owner means.
pub fn read_unverified_vault_id(state: &StateDirLock, fs: &impl StoreFs) -> Result<VaultId, UnverifiedVaultIdError> {
    // MAX_MANIFEST_LEN is 1 MiB, so it always fits in a u64.
    let file = read_state_file(state, fs, &StateFileName::manifest(), MAX_MANIFEST_LEN as u64)?;
    Ok(unverified_vault_id(&file)?)
}

/// The step of a discard that failed, as `vault.reset-failed` names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetStep {
    /// Writing `reset.unfinished`. The vault is intact.
    Begin,
    /// Removing a store-owned file. The next reset resumes.
    Remove,
    /// Removing `reset.unfinished`. The next reset resumes.
    Finish,
}

impl fmt::Display for ResetStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Begin => "begin",
            Self::Remove => "remove",
            Self::Finish => "finish",
        })
    }
}

/// Why a discard stopped. No variant carries file contents.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DiscardFailure {
    /// The state directory holds no vault file, so there is nothing to reset; nothing was written.
    #[error("there is no vault file to reset")]
    NothingToReset,
    /// Listing the state directory failed; nothing was written.
    #[error("cannot list the state directory: {kind}")]
    ListStateDir {
        /// The underlying error kind.
        kind: io::ErrorKind,
    },
    /// Listing the config directory failed; nothing was written.
    #[error("cannot list the config directory: {kind}")]
    ListConfigDir {
        /// The underlying error kind.
        kind: io::ErrorKind,
    },
    /// A store-owned name is a symlink, directory or other non-regular entry, which a reset never follows or descends
    /// into; nothing was written, and an administrator must inspect it.
    #[error("{file} is not a regular file, so nothing was removed; inspect it")]
    NotARegularFile {
        /// The entry's name.
        file: String,
    },
    /// Checking that a store-owned name is a regular file failed; nothing was written.
    #[error("cannot check {file}: {kind}")]
    Inspect {
        /// The entry's name.
        file: String,
        /// The underlying error kind.
        kind: io::ErrorKind,
    },
    /// A file step failed. At [`ResetStep::Begin`] the vault is intact; at any later step `reset.unfinished` stays and
    /// the next reset resumes.
    #[error("reset step {step} failed on {file} at {failed}: {kind}")]
    Io {
        /// The reset step.
        step: ResetStep,
        /// The file the step acted on.
        file: String,
        /// The file operation that failed.
        failed: WriteStep,
        /// The underlying error kind.
        kind: io::ErrorKind,
    },
}

/// Why [`discard_vault`] stopped, with the files it removed before it did, for the `vault.reset-failed` log.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{cause}")]
pub struct DiscardError {
    /// Why it stopped.
    pub cause: DiscardFailure,
    /// The files unlinked before it stopped, in removal order.
    pub removed: Vec<String>,
}

impl From<DiscardFailure> for DiscardError {
    fn from(cause: DiscardFailure) -> Self {
        Self {
            cause,
            removed: Vec::new(),
        }
    }
}

/// A finished discard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscardedVault {
    /// The store-owned files removed, in removal order, state directory first; `reset.unfinished` is not among them.
    pub removed: Vec<String>,
    /// The foreign files left in the state directory, sorted. With any, the directory reads Unrecognized.
    pub foreign: Vec<String>,
    /// Set when `reset.unfinished` was unlinked but the state directory fsync failed, so it may come back after power
    /// loss. It can only come back over a directory with no vault file, where the next reset removes it.
    pub finish_uncertain: Option<ErrorKindLabel>,
}

/// Discards every store-owned file of a vault, in the removal order of design/reset.md, and keeps every foreign file.
///
/// The caller holds the service-wide lock and both directory locks, has withdrawn the vault and has the owner's
/// confirmation. Nothing is written when the state directory holds no vault file, or when a store-owned name is not a
/// regular file. Then `reset.unfinished` is durably written, the commit point; the state files are removed in
/// [`crate::store_owned::STATE_FILES`] order, manifest first, then their stale temp files, then the config files,
/// signatures first, each unlinked and followed by the config directory's fsync, then theirs; and `reset.unfinished` is
/// removed last. Each removal skips a file already gone, so a rerun after a crash resumes where the last run stopped.
pub fn discard_vault(state: &StateDirLock, config: &ConfigDirLock, fs: &impl StoreFs) -> Result<DiscardedVault, DiscardError> {
    let (removals, foreign) = plan(state, config, fs)?;
    let marker = StateFileName::unfinished_reset();
    replace_in(fs, state.dir(), marker.as_str(), b"").map_err(failed(ResetStep::Begin, marker.as_str()))?;
    let mut removed = Vec::new();
    removals
        .iter()
        .try_for_each(|(dir, name)| {
            let (unlinked, result) = remove(fs, dir, name);
            if unlinked {
                removed.push(name.clone());
            }
            result
        })
        .map_err(|cause| DiscardError {
            cause,
            removed: removed.clone(),
        })?;
    let finish_uncertain = finish(state, fs, &marker).map_err(|cause| DiscardError {
        cause,
        removed: removed.clone(),
    })?;
    Ok(DiscardedVault {
        removed,
        foreign,
        finish_uncertain,
    })
}

/// The files a discard removes, each with its directory, in removal order; and the foreign files it keeps.
type Plan<'a> = (Vec<(&'a Path, String)>, Vec<String>);

/// Every file to remove with its directory, in order, and the foreign files to keep. Refuses a directory with no vault
/// file and a store-owned name that is not a regular file.
fn plan<'a>(state: &'a StateDirLock, config: &'a ConfigDirLock, fs: &impl StoreFs) -> Result<Plan<'a>, DiscardFailure> {
    let state_names = fs
        .list_dir(state.dir())
        .map_err(|e| DiscardFailure::ListStateDir { kind: e.kind() })?;
    if !state_names.iter().any(|name| name.to_str().is_some_and(is_vault_file)) {
        return Err(DiscardFailure::NothingToReset);
    }
    let config_names = fs
        .list_dir(config.dir())
        .map_err(|e| DiscardFailure::ListConfigDir { kind: e.kind() })?;
    let removals: Vec<_> = state_removals(&state_names)
        .into_iter()
        .map(|name| (state.dir(), name))
        .chain(config_removals(&config_names).into_iter().map(|name| (config.dir(), name)))
        .collect();
    removals.iter().try_for_each(|(dir, name)| ensure_regular(fs, dir, name))?;
    Ok((removals, foreign(&state_names)))
}

/// The store-owned state files present but `reset.unfinished`, in removal order, then their stale temp files.
fn state_removals(names: &[OsString]) -> Vec<String> {
    let files: Vec<_> = names.iter().filter_map(|name| StateFileName::new(name.to_str()?).ok()).collect();
    let temps = names
        .iter()
        .filter_map(|name| name.to_str())
        .filter(|name| StateFileName::from_temp_name(name).is_some_and(|file| is_store_owned(&file)));
    in_removal_order(&files)
        .into_iter()
        .filter(|file| *file != StateFileName::unfinished_reset())
        .map(|file| file.to_string())
        .chain(temps.map(str::to_owned))
        .collect()
}

/// The config files present, signatures first, then their stale temp files.
fn config_removals(names: &[OsString]) -> Vec<String> {
    CONFIG_FILES
        .iter()
        .map(|file| file.as_str().to_owned())
        .chain(CONFIG_FILES.iter().map(|file| file.temp_name()))
        .filter(|name| names.iter().any(|present| present.as_os_str() == OsStr::new(name)))
        .collect()
}

/// The names that are neither store-owned nor the lock file, `lost+found` or a stale temp file, in listing order.
fn foreign(names: &[OsString]) -> Vec<String> {
    names
        .iter()
        .filter(|name| classify(name) == Entry::Foreign)
        .map(|name| name.to_string_lossy().into_owned())
        .collect()
}

/// Refuses an entry that is not a regular file. `read_bounded` checks the entry without following it before opening
/// anything, and with a limit of zero reads nothing of a non-empty file.
fn ensure_regular(fs: &impl StoreFs, dir: &Path, name: &str) -> Result<(), DiscardFailure> {
    match fs.read_bounded(&dir.join(name), 0).map_err(|e| e.kind()) {
        Ok(_) | Err(io::ErrorKind::FileTooLarge | io::ErrorKind::NotFound) => Ok(()),
        Err(io::ErrorKind::InvalidInput) => Err(DiscardFailure::NotARegularFile { file: name.to_owned() }),
        Err(kind) => Err(DiscardFailure::Inspect {
            file: name.to_owned(),
            kind,
        }),
    }
}

/// Durably removes `dir/name`: whether it was unlinked, and whether that failed. A file already gone is skipped. A
/// failed directory fsync comes after the unlink, so that file counts as removed.
fn remove(fs: &impl StoreFs, dir: &Path, name: &str) -> (bool, Result<(), DiscardFailure>) {
    match remove_in(fs, dir, name) {
        Ok(()) => (true, Ok(())),
        Err(StepFailure {
            step: WriteStep::Remove,
            kind: io::ErrorKind::NotFound,
        }) => (false, Ok(())),
        Err(failure) => (failure.step == WriteStep::SyncDir, Err(failed(ResetStep::Remove, name)(failure))),
    }
}

/// Removes `reset.unfinished`. A failed directory fsync after the unlink is a success with its kind: the marker can
/// only come back over a directory with no vault file, because `init`'s and `import`'s first durable write fsyncs the
/// state directory, making the unlink durable, before either writes a vault file.
fn finish(state: &StateDirLock, fs: &impl StoreFs, marker: &StateFileName) -> Result<Option<ErrorKindLabel>, DiscardFailure> {
    match remove_in(fs, state.dir(), marker.as_str()) {
        Ok(())
        | Err(StepFailure {
            step: WriteStep::Remove,
            kind: io::ErrorKind::NotFound,
        }) => Ok(None),
        Err(StepFailure {
            step: WriteStep::SyncDir,
            kind,
        }) => Ok(Some(ErrorKindLabel::from(kind))),
        Err(failure) => Err(failed(ResetStep::Finish, marker.as_str())(failure)),
    }
}

fn failed(step: ResetStep, file: &str) -> impl Fn(StepFailure) -> DiscardFailure + '_ {
    move |failure| DiscardFailure::Io {
        step,
        file: file.to_owned(),
        failed: failure.step,
        kind: failure.kind,
    }
}

#[cfg(test)]
mod tests;
