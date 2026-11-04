//! The initialization state of the state and config directories, and the `init.unfinished` file that marks an
//! initialization in progress (design/vault-initialization.md).
//!
//! Initialization writes about nine durable files and the filesystem has no transaction. `init.unfinished` is written
//! first and removed last, so a crash between leaves a directory that reads Unfinished instead of a vault that opens
//! as damaged. The state is read from names alone, without the vault identity, so it is known while the vault is locked.

use std::ffi::OsStr;
use std::io;

use crate::config_dir::remove_config_files;
use crate::durable::{ReadFailure, ensure_dir_sync_supported, read_in};
use crate::state_dir::LOCK_FILE;
use crate::vault::is_record_file_name;
use crate::{
    ConfigDirLock, ConfigFileName, ConfigWriteError, StateDirLock, StateFileName, StoreFs, UnlockError, WriteError, WriteStep,
    durable_remove, durable_replace,
};

/// The only bytes initialization ever writes to `config.toml` and `config.toml.pending`. A config file with any other
/// bytes is the owner's and is never discarded.
const INITIAL_CONFIG: &[u8] = b"schema_version = 1\n";

/// The directory a filesystem check creates on a fresh volume; it is not a vault file, so the checks ignore it.
const LOST_FOUND: &str = "lost+found";

/// The order a discard removes config files: all signatures before any config. A signature with no config beside it
/// reads as the owner's file (Unrecognized), and `publish` can leave `config.toml` beside `config.toml.sig.staged`, so
/// removing any config while a signature remains could strand that signature after a crash.
const DISCARD_ORDER: [ConfigFileName; 4] = [
    ConfigFileName::ActiveSignature,
    ConfigFileName::StagedSignature,
    ConfigFileName::Active,
    ConfigFileName::Pending,
];

/// How many offending names an [`InitStateError::Unrecognized`] carries.
const MAX_NAMED: usize = 5;

/// What the state and config directories hold, read without the vault identity.
///
/// The checks run in this order and the first that matches decides: `init.unfinished` present (Unfinished, unless a
/// record file, a foreign file or a config file that is not the initial config is there), else `manifest.age` present
/// (Initialized, whatever else is there), else only the lock file, `lost+found` and temp files and no config file
/// (Uninitialized), else Unrecognized. `init` proceeds only on Uninitialized and Unfinished.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitializationState {
    /// Nothing of a vault or its config is there.
    Uninitialized,
    /// An initialization started and has not reached its commit point.
    Unfinished,
    /// A manifest and no `init.unfinished`.
    Initialized,
    /// Files init did not write, or a vault's files without its manifest. Nothing may be written or removed.
    Unrecognized,
}

/// Why reading or changing the initialization state failed. No variant carries file contents.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InitStateError {
    /// Listing the state directory failed.
    #[error("cannot list the state directory: {kind}")]
    ListStateDir {
        /// The underlying error kind.
        kind: io::ErrorKind,
    },
    /// Listing the config directory failed.
    #[error("cannot list the config directory: {kind}")]
    ListConfigDir {
        /// The underlying error kind.
        kind: io::ErrorKind,
    },
    /// A config file could not be read to compare it with the initial config.
    #[error("cannot read config file {file}: {kind}")]
    ReadConfig {
        /// The file that was read.
        file: ConfigFileName,
        /// The underlying error kind.
        kind: io::ErrorKind,
    },
    /// The vault is initialized, so init has nothing to do.
    #[error("the vault is already initialized")]
    AlreadyInitialized,
    /// The directories hold files init did not write; init will not write or remove anything there.
    #[error("the vault directories hold files that initialization did not write, first {files:?}; move them aside")]
    Unrecognized {
        /// The first offending names, sorted state-directory names first.
        files: Vec<String>,
    },
    /// Writing or removing a state file failed.
    #[error(transparent)]
    State(#[from] WriteError),
    /// Removing a config file failed.
    #[error(transparent)]
    Config(ConfigWriteError),
    /// `init.unfinished` was unlinked but the directory fsync failed, so the removal may not survive power loss and
    /// the vault may read Unfinished again after a reboot.
    #[error("init.unfinished is removed but the removal may not survive power loss: {kind}")]
    FinishUncertain {
        /// The underlying error kind.
        kind: io::ErrorKind,
    },
}

impl InitializationState {
    /// Reads the state from directory listings and file existence alone, plus, beside `init.unfinished`, the bytes of
    /// the config directory's own files.
    pub fn read(state: &StateDirLock, config: &ConfigDirLock, fs: &impl StoreFs) -> Result<Self, InitStateError> {
        survey(state, config, fs).map(|found| found.state)
    }
}

/// Starts an initialization: step 1 of the write order, plus the discard of an earlier unfinished one.
///
/// On Uninitialized this durably writes an empty `init.unfinished`. On Unfinished it durably removes, in an order that
/// never leaves a signature alone, every file an initialization writes, and keeps `init.unfinished`; it returns those
/// file names for the `vault.init-discarded` log. On Initialized and Unrecognized it refuses and changes nothing.
pub fn begin_initialization(state: &StateDirLock, config: &ConfigDirLock, fs: &impl StoreFs) -> Result<Vec<String>, InitStateError> {
    let found = survey(state, config, fs)?;
    match found.state {
        InitializationState::Uninitialized => durable_replace(state, fs, &StateFileName::unfinished_initialization(), b"")
            .map(|()| Vec::new())
            .map_err(InitStateError::State),
        InitializationState::Unfinished => discard(state, config, fs),
        InitializationState::Initialized => Err(InitStateError::AlreadyInitialized),
        InitializationState::Unrecognized => Err(InitStateError::Unrecognized {
            files: found.blockers.into_iter().take(MAX_NAMED).collect(),
        }),
    }
}

/// Finishes an initialization: durably removes `init.unfinished`, its commit point.
///
/// A failed directory fsync comes after the unlink, so it is [`InitStateError::FinishUncertain`] and not a plain
/// failure: the vault reads Initialized now and may read Unfinished after power loss. A platform with no directory
/// fsync is refused up front, before the unlink, as an ordinary failure.
pub fn finish_initialization(state: &StateDirLock, fs: &impl StoreFs) -> Result<(), InitStateError> {
    let marker = StateFileName::unfinished_initialization();
    ensure_dir_sync_supported(&marker)?;
    durable_remove(state, fs, &marker).map_err(|error| match error {
        WriteError::Io {
            step: WriteStep::SyncDir,
            kind,
            ..
        } => InitStateError::FinishUncertain { kind },
        other => InitStateError::State(other),
    })
}

/// Refuses an unlock that cannot succeed, before any envelope is read or scrypt runs.
pub(crate) fn ensure_unlockable(lock: &StateDirLock, fs: &impl StoreFs) -> Result<(), UnlockError> {
    let names = fs.list_dir(lock.dir()).map_err(|e| UnlockError::ListStateDir { kind: e.kind() })?;
    let has = |file: StateFileName| names.iter().any(|n| n.as_os_str() == OsStr::new(file.as_str()));
    if has(StateFileName::unfinished_initialization()) {
        return Err(UnlockError::InitializationUnfinished);
    }
    if has(StateFileName::passphrase_envelope()) || has(StateFileName::manifest()) {
        Ok(())
    } else {
        Err(UnlockError::NotInitialized)
    }
}

/// Entries of the state directory, by what they mean to the initialization state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Entry {
    /// The lock file, `lost+found` and stale temp files.
    Ignored,
    /// `init.unfinished`.
    Marker,
    /// `manifest.age`.
    Manifest,
    /// Another file an initialization writes.
    InitFile,
    /// A `record-*.age` file.
    Record,
    /// Anything else.
    Foreign,
}

struct Survey {
    state: InitializationState,
    /// The names that made the state Unrecognized, empty otherwise.
    blockers: Vec<String>,
}

impl Survey {
    fn new(clean: InitializationState, blockers: Vec<String>) -> Self {
        let state = if blockers.is_empty() {
            clean
        } else {
            InitializationState::Unrecognized
        };
        Self { state, blockers }
    }
}

/// The files an initialization writes to the state directory except the marker, in the order a discard removes them.
fn written_files() -> [StateFileName; 5] {
    [
        StateFileName::approval_state(),
        StateFileName::manifest(),
        StateFileName::approver_key(),
        StateFileName::passphrase_envelope(),
        StateFileName::identity_envelope(),
    ]
}

fn classify(name: &OsStr) -> Entry {
    let Some(text) = name.to_str() else { return Entry::Foreign };
    if text == LOCK_FILE || text == LOST_FOUND || StateFileName::from_temp_name(text).is_some() {
        return Entry::Ignored;
    }
    match StateFileName::new(text) {
        Ok(file) if file == StateFileName::unfinished_initialization() => Entry::Marker,
        Ok(file) if file == StateFileName::manifest() => Entry::Manifest,
        Ok(file) if written_files().contains(&file) => Entry::InitFile,
        Ok(file) if is_record_file_name(file.as_str()) => Entry::Record,
        _ => Entry::Foreign,
    }
}

fn survey(state: &StateDirLock, config: &ConfigDirLock, fs: &impl StoreFs) -> Result<Survey, InitStateError> {
    let listing = fs
        .list_dir(state.dir())
        .map_err(|e| InitStateError::ListStateDir { kind: e.kind() })?;
    let entries: Vec<_> = listing.iter().map(|n| (classify(n), n.to_string_lossy().into_owned())).collect();
    let has = |wanted: Entry| entries.iter().any(|(kind, _)| *kind == wanted);
    let names_where = |keep: fn(Entry) -> bool| entries.iter().filter(move |(k, _)| keep(*k)).map(|(_, n)| n.clone());
    if has(Entry::Marker) {
        let blockers = names_where(|k| matches!(k, Entry::Record | Entry::Foreign))
            .chain(config_test_failures(config, fs)?)
            .collect();
        return Ok(Survey::new(InitializationState::Unfinished, blockers));
    }
    if has(Entry::Manifest) {
        return Ok(Survey::new(InitializationState::Initialized, Vec::new()));
    }
    let config_files = present_config_files(config, fs)?.into_iter().map(|f| f.to_string());
    let blockers = names_where(|k| k != Entry::Ignored).chain(config_files).collect();
    Ok(Survey::new(InitializationState::Uninitialized, blockers))
}

fn present_config_files(config: &ConfigDirLock, fs: &impl StoreFs) -> Result<Vec<ConfigFileName>, InitStateError> {
    let names = fs
        .list_dir(config.dir())
        .map_err(|e| InitStateError::ListConfigDir { kind: e.kind() })?;
    Ok(ConfigFileName::ALL
        .into_iter()
        .filter(|file| names.iter().any(|n| n.as_os_str() == OsStr::new(file.as_str())))
        .collect())
}

/// The config files that fail the config test: a config holding other bytes than the initial config, and signatures
/// with no config beside them. Only the four config names count; everything else in the directory is ignored.
fn config_test_failures(config: &ConfigDirLock, fs: &impl StoreFs) -> Result<Vec<String>, InitStateError> {
    let (configs, signatures): (Vec<_>, Vec<_>) = present_config_files(config, fs)?
        .into_iter()
        .partition(|f| matches!(f, ConfigFileName::Active | ConfigFileName::Pending));
    let other_bytes = configs
        .iter()
        .map(|&file| is_initial_config(config, fs, file).map(|initial| (!initial).then_some(file)))
        .collect::<Result<Vec<_>, _>>()?;
    let lone_signatures = if configs.is_empty() { signatures } else { Vec::new() };
    Ok(other_bytes
        .into_iter()
        .flatten()
        .chain(lone_signatures)
        .map(|f| f.to_string())
        .collect())
}

/// Whether `file` holds exactly the initial config. The read is bounded by the initial config's length, so a larger
/// file is refused unread.
fn is_initial_config(config: &ConfigDirLock, fs: &impl StoreFs, file: ConfigFileName) -> Result<bool, InitStateError> {
    // The initial config is 19 bytes, so the length always fits in a u64.
    match read_in(fs, config.dir(), file.as_str(), INITIAL_CONFIG.len() as u64) {
        Ok(bytes) => Ok(bytes == INITIAL_CONFIG),
        Err(ReadFailure::TooLarge | ReadFailure::NotRegular) => Ok(false),
        Err(ReadFailure::Io(kind)) => Err(InitStateError::ReadConfig { file, kind }),
    }
}

/// Removes what an unfinished initialization wrote, config files first. `init.unfinished` stays, so a crash part-way
/// reads Unfinished again and the next run discards again.
fn discard(state: &StateDirLock, config: &ConfigDirLock, fs: &impl StoreFs) -> Result<Vec<String>, InitStateError> {
    let config_removed = remove_config_files(config, fs, &DISCARD_ORDER).map_err(InitStateError::Config)?;
    let state_removed = written_files()
        .into_iter()
        .filter_map(|file| match durable_remove(state, fs, &file) {
            Ok(()) => Some(Ok(file.to_string())),
            Err(WriteError::NotFound { .. }) => None,
            Err(error) => Some(Err(InitStateError::State(error))),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(config_removed.into_iter().map(|f| f.to_string()).chain(state_removed).collect())
}

#[cfg(test)]
mod tests;
