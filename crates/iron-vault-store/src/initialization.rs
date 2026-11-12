//! The initialization state: what the state and config directories hold before a vault is unlocked, and the
//! `init.unfinished` and `import.unfinished` markers that make `init` and `import` safe to interrupt
//! ([vault initialization](../../../design/vault-initialization.md#initialization-state),
//! [unfinished import](../../../design/migration-bundle.md#the-unfinished-import)).
//!
//! Initialization writes about nine durable files, an import many more, and the filesystem has no transaction. The
//! marker is written first and removed last, so a crash in between leaves a directory that reads Unfinished, not a
//! vault that opens as damaged. The next `init` or `import` discards what the unfinished run wrote and starts again.
//! `unlock` calls [`require_initialized`] first, so it never opens a half-written vault:
//!
//! ```text
//!                begin_initialization                                   finish_initialization
//!                writes init.unfinished                                 removes init.unfinished
//! Uninitialized ───────────────────────▶ Unfinished(Initialization) ───────────────────────▶ Initialized
//!       │                                    │                ▲
//!       │                                    │ crash          │ begin_initialization or begin_import:
//!       │                                    ▼                │ discard, then write its own marker
//!       │                                 Unfinished ─────────┘
//!       │        begin_import                                           finish_import
//!       │        writes import.unfinished                               removes import.unfinished
//!       └──────────────────────────────▶ Unfinished(Import) ───────────────────────────────▶ Initialized
//! ```
//!
//! The state is read from names alone, plus the bytes of the config files beside `init.unfinished`, without the vault
//! identity, so it is known while the vault is locked.

use std::ffi::OsStr;
use std::io;

use crate::config_dir::remove_config_file;
use crate::durable::{ReadFailure, ensure_dir_sync_supported, read_in};
use crate::owner_lock::remove_owner_lock;
use crate::recovery_record::remove_recovery_check;
use crate::state_dir::LOCK_FILE;
use crate::store_owned::{CONFIG_FILES, is_store_owned, is_vault_file};
use crate::vault::is_record_file_name;
use crate::{
    ConfigDirLock, ConfigFileName, ConfigWriteError, StateDirLock, StateFileName, StoreFs, UnlockError, WriteError, WriteStep,
    durable_remove, durable_replace,
};

/// The initial config: the only bytes initialization ever writes to `config.toml` and `config.toml.pending`, approved
/// as version 1.
///
/// It names no listener, caller or route, because a new vault holds no credential. A config file with any other bytes
/// is the owner's and is never discarded.
pub const INITIAL_CONFIG: &[u8] = b"schema_version = 1\n";

/// The directory `mkfs` creates at the root of a fresh ext4 volume. It is not a vault file, so the checks ignore it.
const LOST_FOUND: &str = "lost+found";

/// How many offending names an [`InitStateError::Unrecognized`] carries.
const MAX_NAMED: usize = 5;

/// What the state and config directories hold, read without the vault identity.
///
/// The checks run in this order, and the first that matches decides. A blocker turns the state it guards into
/// Unrecognized:
///
/// ```text
/// reset.unfinished present                ──▶ UnfinishedReset, whatever else is there
/// init.unfinished and import.unfinished    ──▶ Unrecognized: no run writes both
/// init.unfinished present                  ──▶ Unfinished(Initialization)
///                                              blockers: a record file, a foreign or other store-owned file, a
///                                              second approver key envelope, a config file failing the config test
/// import.unfinished present                ──▶ Unfinished(Import)
///                                              blockers: a foreign or other store-owned file, a config file other
///                                              than config.toml
/// manifest.age present                     ──▶ Initialized, whatever else is there
/// otherwise                                ──▶ Uninitialized
///                                              blockers: a vault file, a foreign file, any config file
/// ```
///
/// `init` and `import` proceed only on Uninitialized and Unfinished.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitializationState {
    /// Nothing of a vault or its config is there.
    Uninitialized,
    /// An initialization or an import started and has not reached its commit point.
    Unfinished(UnfinishedKind),
    /// A manifest and neither `init.unfinished` nor `import.unfinished`.
    Initialized,
    /// Files `init` or `import` did not write, or a vault's files without its manifest. Nothing may be written or
    /// removed.
    Unrecognized,
    /// A reset past its commit point that has not finished: `reset.unfinished` is there. Only the next `reset` finishes
    /// it, and every other command refuses it.
    UnfinishedReset,
}

/// Names the run that left an Unfinished directory: the one whose marker is there. Either command discards either kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnfinishedKind {
    /// `init.unfinished`: an initialization.
    Initialization,
    /// `import.unfinished`: an import of a migration bundle.
    Import,
}

impl UnfinishedKind {
    /// Returns the marker this kind of run writes first and removes last.
    pub fn marker(self) -> StateFileName {
        match self {
            Self::Initialization => StateFileName::unfinished_initialization(),
            Self::Import => StateFileName::unfinished_import(),
        }
    }
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
    /// The vault is initialized, so `init` and `import` have nothing to do.
    #[error("the vault is already initialized")]
    AlreadyInitialized,
    /// A reset was interrupted. Until it finishes, the directories may hold a vault that has served, so neither `init`
    /// nor `import` may discard them.
    #[error("a reset was interrupted; run `iron-vault reset` again")]
    ResetUnfinished,
    /// The directories hold files `init` and `import` did not write, so neither writes or removes anything there.
    #[error("the vault directories hold files that init or import did not write, first {files:?}; move them aside")]
    Unrecognized {
        /// The first offending names, sorted state-directory names first.
        files: Vec<String>,
    },
    /// Writing or removing a state file failed.
    #[error(transparent)]
    State(#[from] WriteError),
    /// Removing a leftover `recovery.toml` from an Uninitialized directory failed. Nothing else was written.
    #[error("cannot remove the leftover recovery check record: {0}")]
    LeftoverRecoveryCheck(WriteError),
    /// Removing a stale owner-lock file from an Uninitialized directory failed. Nothing else was written.
    #[error("cannot remove the stale owner-lock file: {0}")]
    LeftoverOwnerLock(WriteError),
    /// Removing a config file failed.
    #[error(transparent)]
    Config(ConfigWriteError),
    /// `init.unfinished` was unlinked but the directory fsync failed. The removal may not survive power loss, and the
    /// vault may read Unfinished again after a reboot.
    #[error("init.unfinished is removed but the removal may not survive power loss: {kind}")]
    FinishUncertain {
        /// The underlying error kind.
        kind: io::ErrorKind,
    },
    /// `import.unfinished` was unlinked but the directory fsync failed: [`InitStateError::FinishUncertain`] for an
    /// import.
    #[error("import.unfinished is removed but the removal may not survive power loss: {kind}")]
    ImportFinishUncertain {
        /// The underlying error kind.
        kind: io::ErrorKind,
    },
}

/// Records an unfinished run that [`begin_initialization`] or [`begin_import`] discarded, and the files the discard
/// unlinked, for the `vault.init-discarded` or `migration.import-discarded` audit event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discarded {
    /// Which run left the files.
    pub kind: UnfinishedKind,
    /// The files unlinked, config directory first, in removal order. When the other command's marker went too, it is
    /// last.
    pub files: Vec<String>,
}

/// Says why [`begin_initialization`] or [`begin_import`] stopped, with what its discard removed before it did.
///
/// A discard that fails part-way has still removed files, and the audit event must name them.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{cause}")]
pub struct BeginError {
    /// Why it stopped.
    pub cause: InitStateError,
    /// What the discard unlinked before it stopped, or `None` if no discard ran.
    pub discarded: Option<Discarded>,
}

impl From<InitStateError> for BeginError {
    fn from(cause: InitStateError) -> Self {
        Self { cause, discarded: None }
    }
}

impl InitializationState {
    /// Reads the state from directory listings and file existence alone, plus, beside `init.unfinished`, the bytes of
    /// the config directory's own files.
    pub fn read(state: &StateDirLock, config: &ConfigDirLock, fs: &impl StoreFs) -> Result<Self, InitStateError> {
        survey(state, config, fs).map(|found| found.state)
    }
}

/// Refuses the directories that [`begin_initialization`] and [`begin_import`] refuse, and writes nothing.
///
/// Initialized fails with [`InitStateError::AlreadyInitialized`], Unfinished reset with
/// [`InitStateError::ResetUnfinished`], and Unrecognized with [`InitStateError::Unrecognized`] naming its first
/// offending files. Otherwise it returns Uninitialized or Unfinished, so `init` or `import` can refuse, or warn of a
/// discard, before it prompts for anything.
pub fn ensure_initializable(
    state: &StateDirLock,
    config: &ConfigDirLock,
    fs: &impl StoreFs,
) -> Result<InitializationState, InitStateError> {
    let found = survey(state, config, fs)?;
    match found.state {
        InitializationState::Initialized => Err(InitStateError::AlreadyInitialized),
        InitializationState::UnfinishedReset => Err(InitStateError::ResetUnfinished),
        InitializationState::Unrecognized => Err(InitStateError::Unrecognized {
            files: found.blockers.into_iter().take(MAX_NAMED).collect(),
        }),
        initializable @ (InitializationState::Uninitialized | InitializationState::Unfinished(_)) => Ok(initializable),
    }
}

/// Starts an initialization: step 1 of the write order, plus the discard of an earlier unfinished run of either kind.
///
/// - On Uninitialized, it durably removes a leftover `recovery.toml`, so the new vault does not inherit the old vault's
///   `last_checked`, and a stale owner-lock file, so the new vault can host-unlock. Then it durably writes an empty
///   `init.unfinished` and returns `None`. These removals are not audit events, so they are not reported.
/// - On Unfinished, it durably removes every file the unfinished run wrote, in an order that never leaves a signature
///   alone, and returns them for the `vault.init-discarded` or `migration.import-discarded` audit event. A discard
///   that fails part-way names them on its error. An unfinished import's marker is removed last and `init.unfinished`
///   written, so the caller always holds its own marker.
/// - On Initialized, Unfinished reset and Unrecognized, it refuses and changes nothing.
pub fn begin_initialization(state: &StateDirLock, config: &ConfigDirLock, fs: &impl StoreFs) -> Result<Option<Discarded>, BeginError> {
    begin(state, config, fs, UnfinishedKind::Initialization)
}

/// Starts an import: does what [`begin_initialization`] does, but writes `import.unfinished`. It discards an unfinished
/// initialization or import alike.
pub fn begin_import(state: &StateDirLock, config: &ConfigDirLock, fs: &impl StoreFs) -> Result<Option<Discarded>, BeginError> {
    begin(state, config, fs, UnfinishedKind::Import)
}

fn begin(state: &StateDirLock, config: &ConfigDirLock, fs: &impl StoreFs, own: UnfinishedKind) -> Result<Option<Discarded>, BeginError> {
    match ensure_initializable(state, config, fs)? {
        InitializationState::Unfinished(found) => discard(state, config, fs, (found, own)).map(Some),
        // Uninitialized: `ensure_initializable` returns no other state.
        _ => remove_recovery_check(state, fs)
            .map_err(InitStateError::LeftoverRecoveryCheck)
            .and_then(|_| remove_owner_lock(state, fs).map_err(InitStateError::LeftoverOwnerLock))
            .and_then(|_| write_marker(state, fs, own))
            .map(|()| None)
            .map_err(Into::into),
    }
}

fn write_marker(state: &StateDirLock, fs: &impl StoreFs, kind: UnfinishedKind) -> Result<(), InitStateError> {
    durable_replace(state, fs, &kind.marker(), b"").map_err(InitStateError::State)
}

/// Finishes an initialization: durably removes `init.unfinished`, its commit point.
///
/// A failed directory fsync comes after the unlink, so it is [`InitStateError::FinishUncertain`] and not a plain
/// failure: the vault reads Initialized now and may read Unfinished after power loss. A platform with no directory
/// fsync is refused up front, before the unlink, as an ordinary failure.
pub fn finish_initialization(state: &StateDirLock, fs: &impl StoreFs) -> Result<(), InitStateError> {
    finish(state, fs, UnfinishedKind::Initialization)
}

/// Finishes an import: durably removes `import.unfinished`, its commit point, as [`finish_initialization`] does, with
/// [`InitStateError::ImportFinishUncertain`] for a failed directory fsync.
pub fn finish_import(state: &StateDirLock, fs: &impl StoreFs) -> Result<(), InitStateError> {
    finish(state, fs, UnfinishedKind::Import)
}

fn finish(state: &StateDirLock, fs: &impl StoreFs, kind: UnfinishedKind) -> Result<(), InitStateError> {
    let marker = kind.marker();
    ensure_dir_sync_supported(&marker)?;
    durable_remove(state, fs, &marker).map_err(|error| match (error, kind) {
        (
            WriteError::Io {
                step: WriteStep::SyncDir,
                kind,
                ..
            },
            UnfinishedKind::Initialization,
        ) => InitStateError::FinishUncertain { kind },
        (
            WriteError::Io {
                step: WriteStep::SyncDir,
                kind,
                ..
            },
            UnfinishedKind::Import,
        ) => InitStateError::ImportFinishUncertain { kind },
        (other, _) => InitStateError::State(other),
    })
}

/// Requires the Initialized state for an unlock and returns the sorted names of the foreign files beside the manifest,
/// so the caller can warn of them.
///
/// It never refuses over a foreign file there: `Vault::open` ignores names it does not know, and an editor's backup
/// must not lock the owner out of a working vault. Any other state is refused with the file names only, before a
/// passphrase is asked for: Uninitialized and Unfinished with their `iron-vault init` or `iron-vault import` text,
/// Unfinished reset with its `iron-vault reset` text, and Unrecognized naming its first offending files.
pub fn require_initialized(state: &StateDirLock, config: &ConfigDirLock, fs: &impl StoreFs) -> Result<Vec<String>, UnlockError> {
    let found = survey(state, config, fs).map_err(UnlockError::InitializationState)?;
    match found.state {
        InitializationState::Initialized => Ok(found.foreign),
        InitializationState::Uninitialized => Err(UnlockError::NotInitialized),
        InitializationState::Unfinished(UnfinishedKind::Initialization) => Err(UnlockError::InitializationUnfinished),
        InitializationState::Unfinished(UnfinishedKind::Import) => Err(UnlockError::ImportUnfinished),
        InitializationState::UnfinishedReset => Err(UnlockError::ResetUnfinished),
        InitializationState::Unrecognized => Err(UnlockError::Unrecognized {
            files: found.blockers.into_iter().take(MAX_NAMED).collect(),
        }),
    }
}

/// Refuses an unlock that cannot succeed, before any envelope is read or scrypt runs: a marker of an unfinished reset,
/// initialization or import is there, or neither `operational.age` nor `manifest.age` is.
pub(crate) fn ensure_unlockable(lock: &StateDirLock, fs: &impl StoreFs) -> Result<(), UnlockError> {
    let names = fs.list_dir(lock.dir()).map_err(|e| UnlockError::ListStateDir { kind: e.kind() })?;
    let has = |file: StateFileName| names.iter().any(|n| n.as_os_str() == OsStr::new(file.as_str()));
    if has(StateFileName::unfinished_reset()) {
        return Err(UnlockError::ResetUnfinished);
    }
    if has(StateFileName::unfinished_initialization()) {
        return Err(UnlockError::InitializationUnfinished);
    }
    if has(StateFileName::unfinished_import()) {
        return Err(UnlockError::ImportUnfinished);
    }
    if has(StateFileName::passphrase_envelope()) || has(StateFileName::manifest()) {
        Ok(())
    } else {
        Err(UnlockError::NotInitialized)
    }
}

/// Classifies an entry of the state directory by what it means to the initialization state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Entry {
    /// The lock file, `lost+found` and stale temp files.
    Ignored,
    /// `reset.unfinished`.
    ResetMarker,
    /// `init.unfinished`.
    Marker,
    /// `import.unfinished`.
    ImportMarker,
    /// `manifest.age`.
    Manifest,
    /// Another file an initialization writes.
    InitFile,
    /// An approver key envelope, `approver-<approver ID>.age`. An initialization writes one, an import any number.
    ApproverKey,
    /// `recovery.toml`: part of the vault beside a manifest, removed by a discard, and never a foreign file.
    RecoveryRecord,
    /// `locked-by-owner`: part of no vault, so it blocks nothing. Every discard removes it.
    OwnerLock,
    /// A `record-*.age` file. An import writes any number, an initialization none.
    Record,
    /// Another store-owned file that neither an initialization nor an import writes, such as `recipients.age.staged`
    /// or an approver's `.tpm` key blob. It is part of the vault beside a manifest, and a blocker beside either marker:
    /// the discard would leave it in the new vault.
    OtherOwned,
    /// A file the store does not own.
    Foreign,
}

struct Survey {
    state: InitializationState,
    /// The names that made the state Unrecognized, empty otherwise.
    blockers: Vec<String>,
    /// The sorted names of the foreign files beside a manifest, empty in every other state.
    foreign: Vec<String>,
}

impl Survey {
    fn new(clean: InitializationState, blockers: Vec<String>) -> Self {
        let state = if blockers.is_empty() {
            clean
        } else {
            InitializationState::Unrecognized
        };
        Self {
            state,
            blockers,
            foreign: Vec::new(),
        }
    }

    fn with_foreign(self, foreign: Vec<String>) -> Self {
        Self { foreign, ..self }
    }
}

/// Lists the files a discard of an unfinished initialization or import removes from the state directory, in order.
///
/// First come a recovery check record and an owner-lock file: beside the marker, an earlier vault left them. Then come
/// the files the run writes, except the marker. `variable_files` sit between `manifest.age` and `operational.age`: the
/// approver key envelopes and, for an import, the record files. Their names hold generated IDs, so they are known only
/// from the listing.
fn written_files(variable_files: impl IntoIterator<Item = StateFileName>) -> Vec<StateFileName> {
    [
        StateFileName::recovery_check_record(),
        StateFileName::owner_lock(),
        StateFileName::approval_state(),
        StateFileName::manifest(),
    ]
    .into_iter()
    .chain(variable_files)
    .chain([
        StateFileName::passphrase_envelope(),
        StateFileName::recipient_inventory(),
        StateFileName::identity_envelope(),
    ])
    .collect()
}

/// Lists the valid state file names in the state directory.
fn listed_names(state: &StateDirLock, fs: &impl StoreFs) -> Result<Vec<StateFileName>, InitStateError> {
    let listing = fs
        .list_dir(state.dir())
        .map_err(|e| InitStateError::ListStateDir { kind: e.kind() })?;
    Ok(listing.iter().filter_map(|name| StateFileName::new(name.to_str()?).ok()).collect())
}

/// Returns the names in `listing` that `is_member` accepts, sorted so a discard's audit event is deterministic.
fn family(listing: &[StateFileName], is_member: fn(&str) -> bool) -> Vec<StateFileName> {
    let mut members: Vec<_> = listing.iter().filter(|name| is_member(name.as_str())).cloned().collect();
    members.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    members
}

/// Lists the files a discard of an unfinished import removes from the state directory, in order: the leftovers of an
/// earlier vault, then what an import writes except the marker. All of them are on the store-owned list.
fn import_files(listing: &[StateFileName]) -> Vec<StateFileName> {
    let records = family(listing, is_record_file_name);
    let approver_keys = family(listing, |name| StateFileName::approver_key_id(name).is_some());
    written_files(records.into_iter().chain(approver_keys))
}

/// Classifies the state-directory entry `name`. A name not on the store-owned list is foreign, unless it is the lock
/// file, `lost+found` or a stale temporary file.
pub(crate) fn classify(name: &OsStr) -> Entry {
    let Some(text) = name.to_str() else { return Entry::Foreign };
    if text == LOCK_FILE || text == LOST_FOUND || StateFileName::from_temp_name(text).is_some() {
        return Entry::Ignored;
    }
    match StateFileName::new(text) {
        Ok(file) if !is_store_owned(&file) => Entry::Foreign,
        Ok(file) if file == StateFileName::unfinished_reset() => Entry::ResetMarker,
        Ok(file) if file == StateFileName::unfinished_initialization() => Entry::Marker,
        Ok(file) if file == StateFileName::unfinished_import() => Entry::ImportMarker,
        Ok(file) if file == StateFileName::manifest() => Entry::Manifest,
        Ok(file) if file == StateFileName::recovery_check_record() => Entry::RecoveryRecord,
        Ok(file) if file == StateFileName::owner_lock() => Entry::OwnerLock,
        Ok(file) if written_files(None).contains(&file) => Entry::InitFile,
        Ok(file) if StateFileName::approver_key_id(file.as_str()).is_some() => Entry::ApproverKey,
        Ok(file) if is_record_file_name(file.as_str()) => Entry::Record,
        Ok(_) => Entry::OtherOwned,
        Err(_) => Entry::Foreign,
    }
}

fn survey(state: &StateDirLock, config: &ConfigDirLock, fs: &impl StoreFs) -> Result<Survey, InitStateError> {
    let listing = fs
        .list_dir(state.dir())
        .map_err(|e| InitStateError::ListStateDir { kind: e.kind() })?;
    let entries: Vec<_> = listing.iter().map(|n| (classify(n), n.to_string_lossy().into_owned())).collect();
    let has = |wanted: Entry| entries.iter().any(|(kind, _)| *kind == wanted);
    let names_where = |keep: fn(Entry) -> bool| entries.iter().filter(move |(k, _)| keep(*k)).map(|(_, n)| n.clone());
    if has(Entry::ResetMarker) {
        return Ok(Survey::new(InitializationState::UnfinishedReset, Vec::new()));
    }
    if has(Entry::Marker) && has(Entry::ImportMarker) {
        // No run writes both markers, so neither is known to be the directory's own.
        let markers = names_where(|k| matches!(k, Entry::Marker | Entry::ImportMarker)).collect();
        return Ok(Survey::new(InitializationState::Unrecognized, markers));
    }
    if has(Entry::Marker) {
        return unfinished_initialization(config, fs, &entries);
    }
    if has(Entry::ImportMarker) {
        return unfinished_import(config, fs, &entries);
    }
    if has(Entry::Manifest) {
        let mut foreign: Vec<_> = names_where(|k| k == Entry::Foreign).collect();
        foreign.sort();
        return Ok(Survey::new(InitializationState::Initialized, Vec::new()).with_foreign(foreign));
    }
    let config_files = present_config_files(config, fs)?.into_iter().map(|f| f.to_string());
    let blockers = entries
        .iter()
        .filter(|(kind, name)| *kind == Entry::Foreign || is_vault_file(name))
        .map(|(_, name)| name.clone())
        .chain(config_files)
        .collect();
    Ok(Survey::new(InitializationState::Uninitialized, blockers))
}

/// Decides the state beside `init.unfinished`: Unfinished, unless a record file, a foreign or other store-owned file, a
/// second approver key envelope or a config file that fails the config test is there.
fn unfinished_initialization(config: &ConfigDirLock, fs: &impl StoreFs, entries: &[(Entry, String)]) -> Result<Survey, InitStateError> {
    // An initialization writes one approver key envelope, so beside a second neither is known to be its own.
    let several_keys = entries.iter().filter(|(kind, _)| *kind == Entry::ApproverKey).count() > 1;
    let blocks =
        |kind: Entry| matches!(kind, Entry::Record | Entry::Foreign | Entry::OtherOwned) || (several_keys && kind == Entry::ApproverKey);
    let blockers = entries
        .iter()
        .filter(|(kind, _)| blocks(*kind))
        .map(|(_, name)| name.clone())
        .chain(config_test_failures(config, fs)?)
        .collect();
    Ok(Survey::new(
        InitializationState::Unfinished(UnfinishedKind::Initialization),
        blockers,
    ))
}

/// Decides the state beside `import.unfinished`: Unfinished, unless a foreign or other store-owned file is there, or a
/// config file other than `config.toml`. An import writes any number of approver key and record files, and
/// `config.toml` with the bundle's bytes, which are not judged.
fn unfinished_import(config: &ConfigDirLock, fs: &impl StoreFs, entries: &[(Entry, String)]) -> Result<Survey, InitStateError> {
    let other_config = present_config_files(config, fs)?
        .into_iter()
        .filter(|&file| file != ConfigFileName::Active)
        .map(|file| file.to_string());
    let blockers = entries
        .iter()
        .filter(|(kind, _)| matches!(kind, Entry::Foreign | Entry::OtherOwned))
        .map(|(_, name)| name.clone())
        .chain(other_config)
        .collect();
    Ok(Survey::new(InitializationState::Unfinished(UnfinishedKind::Import), blockers))
}

pub(crate) fn present_config_files(config: &ConfigDirLock, fs: &impl StoreFs) -> Result<Vec<ConfigFileName>, InitStateError> {
    let names = fs
        .list_dir(config.dir())
        .map_err(|e| InitStateError::ListConfigDir { kind: e.kind() })?;
    Ok(ConfigFileName::ALL
        .into_iter()
        .filter(|file| names.iter().any(|n| n.as_os_str() == OsStr::new(file.as_str())))
        .collect())
}

/// Lists the config files that fail the [config test](../../../design/vault-initialization.md#the-config-test): a
/// config holding other bytes than the initial config, and signatures with no config beside them. Only the four config
/// names count; everything else in the directory is ignored.
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

/// Returns `true` if and only if `file` holds exactly the initial config.
///
/// The read is bounded by the initial config's length, so a larger file, or one that is not a regular file, gives
/// `false` unread.
fn is_initial_config(config: &ConfigDirLock, fs: &impl StoreFs, file: ConfigFileName) -> Result<bool, InitStateError> {
    // The initial config is 19 bytes, so the length always fits in a u64.
    match read_in(fs, config.dir(), file.as_str(), INITIAL_CONFIG.len() as u64) {
        Ok(bytes) => Ok(bytes == INITIAL_CONFIG),
        Err(ReadFailure::TooLarge | ReadFailure::NotRegular) => Ok(false),
        Err(ReadFailure::Io(kind)) => Err(InitStateError::ReadConfig { file, kind }),
    }
}

/// One removal of a discard: a config file or a state file.
enum Removal {
    Config(ConfigFileName),
    State(StateFileName),
}

impl Removal {
    /// Removes the file durably, and returns its name, whether it was unlinked, and whether the removal failed.
    fn run(&self, state: &StateDirLock, config: &ConfigDirLock, fs: &impl StoreFs) -> (String, bool, Result<(), InitStateError>) {
        let (name, (unlinked, result)) = match self {
            Self::Config(file) => (file.to_string(), config_removal(remove_config_file(config, fs, *file))),
            Self::State(file) => (file.to_string(), state_removal(durable_remove(state, fs, file))),
        };
        (name, unlinked, result)
    }
}

/// What a discard of an unfinished `found` removes, in order: its config files, then its state files. The marker is not
/// among them.
fn removals(state: &StateDirLock, fs: &impl StoreFs, found: UnfinishedKind) -> Result<Vec<Removal>, InitStateError> {
    let listing = listed_names(state, fs)?;
    let (configs, files) = match found {
        UnfinishedKind::Initialization => (
            CONFIG_FILES.to_vec(),
            written_files(family(&listing, |name| StateFileName::approver_key_id(name).is_some())),
        ),
        UnfinishedKind::Import => (vec![ConfigFileName::Active], import_files(&listing)),
    };
    Ok(configs
        .into_iter()
        .map(Removal::Config)
        .chain(files.into_iter().map(Removal::State))
        .collect())
}

/// Removes what an unfinished `found` wrote, config files first, and stops at the first failure.
///
/// The marker stays, so a crash part-way reads Unfinished again and the next run discards again. When `own`, the
/// command's kind, differs from `found`, the discard ends by durably removing the other command's marker, which reads
/// Uninitialized, and writing `own`'s. A crash between the two leaves Uninitialized, which either command starts from.
///
/// Every file unlinked is named, on success and on failure alike. A failed directory fsync comes after its unlink, so
/// that file is named too: it is gone now, though power loss may bring it back.
fn discard(
    state: &StateDirLock,
    config: &ConfigDirLock,
    fs: &impl StoreFs,
    (found, own): (UnfinishedKind, UnfinishedKind),
) -> Result<Discarded, BeginError> {
    let swap = (found != own).then(|| Removal::State(found.marker()));
    let plan = removals(state, fs, found)?.into_iter().chain(swap);
    let mut files = Vec::new();
    let outcome = plan
        .map(|removal| removal.run(state, config, fs))
        .try_for_each(|(name, unlinked, result)| {
            if unlinked {
                files.push(name);
            }
            result
        });
    let outcome = outcome.and_then(|()| if found == own { Ok(()) } else { write_marker(state, fs, own) });
    let discarded = Discarded { kind: found, files };
    match outcome {
        Ok(()) => Ok(discarded),
        Err(cause) => Err(BeginError {
            cause,
            discarded: Some(discarded),
        }),
    }
}

/// Splits a config file's removal result into whether it unlinked the file and whether it failed.
///
/// A failed `SyncDir` counts as unlinked because `remove_in` in `durable.rs` unlinks before its directory fsync. If
/// that order changes, so must this.
fn config_removal(removed: Result<bool, ConfigWriteError>) -> (bool, Result<(), InitStateError>) {
    match removed {
        Ok(existed) => (existed, Ok(())),
        Err(error) => {
            let unlinked = matches!(
                error,
                ConfigWriteError::Io {
                    step: WriteStep::SyncDir,
                    ..
                }
            );
            (unlinked, Err(InitStateError::Config(error)))
        }
    }
}

/// Splits a state file's removal result into whether it unlinked the file and whether it failed. An absent file is
/// skipped. A failed `SyncDir` counts as unlinked, as in [`config_removal`].
fn state_removal(removed: Result<(), WriteError>) -> (bool, Result<(), InitStateError>) {
    match removed {
        Ok(()) => (true, Ok(())),
        Err(WriteError::NotFound { .. }) => (false, Ok(())),
        Err(error) => {
            let unlinked = matches!(
                error,
                WriteError::Io {
                    step: WriteStep::SyncDir,
                    ..
                }
            );
            (unlinked, Err(InitStateError::State(error)))
        }
    }
}

#[cfg(test)]
mod tests;
