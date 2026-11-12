//! Vault import at store level: the [write order](../../../design/migration-bundle.md#write-order) that `import` runs
//! on the destination, from `import.unfinished` to its removal
//! ([spec §12](../../../design/iron-vault-specification.md#12-configuration-approval-and-reload),
//! [§13](../../../design/iron-vault-specification.md#13-vault-structure-and-durable-writes),
//! [§14](../../../design/iron-vault-specification.md#14-recipients-startup-and-memory),
//! [§16](../../../design/iron-vault-specification.md#16-administration-recovery-and-migration) steps 4 and 5).
//!
//! ```text
//!  1  discard leftovers, write import.unfinished   ← after this, a failure leaves the vault Unfinished
//!  2  record-<record ID>.age        the bundle's bytes, ascending record ID
//!  3  approver-<approver ID>.age    the envelope inside each bundled approver key
//!  4  approval.age                  the bundle's bytes
//!  5  config.toml                   the bundle's bytes
//!  6  identity.age, recipients.age  wrapped for the new recipients, each proved
//!  7  operational.age               sealed to the new vault passphrase
//!  8  manifest.age                  the bundle's bytes, last of the vault files
//!  9  read every file back and check it with the vault identity
//! 10  remove import.unfinished      ← commit
//! ```
//!
//! [`crate::begin_import`] and [`crate::finish_import`] write and remove the marker; this module runs the steps between.
//! Each step is durable before the next starts, so a failure at any step after the first leaves a directory that reads
//! Unfinished, which the next `import` or `init` discards. The manifest, the approval state and the config are the
//! bundle's bytes and are never re-sealed, so no counter or state generation changes on the way.

#[cfg(test)]
mod tests;

use std::fmt;

use thiserror::Error;

use crate::config_dir::write_imported_config;
use crate::init::{seal_operational, write_checked_identity};
use crate::{
    ApprovalVersion, BeginError, BundleCheckError, ConfigDigest, ConfigDirLock, ConfigFileName, ConfigReadError, ConfigWriteError,
    ControlFiles, Discarded, InitFailure, InitStateError, InitializationState, MAX_APPROVAL_STATE_LEN, MAX_MANIFEST_LEN,
    MAX_RECORD_FILE_LEN, OperationalIdentity, PASSPHRASE_WORK_FACTOR, Passphrase, ReadError, RecipientIdentity, RecipientRole, RecoveryKey,
    RecoveryKeySecret, StateDirLock, StateFileName, StoreFs, UtcSecond, VaultId, VerifiedBundle, WriteError, begin_import, durable_replace,
    finish_import, read_config_file, read_signer_key, read_state_file, write_signer_key,
};

/// The keys an import enrols for the destination: a new operational identity, a new recovery key and, with
/// `--host-unlock`, this machine's host unlock identity
/// ([migration bundle, "Destination recipients"](../../../design/migration-bundle.md#destination-recipients)).
///
/// The source's recipients never come across, so the destination has its own two ways in from its commit point. It has
/// no `Clone`, its `Debug` shows nothing of any key, and every key is dropped when the import returns.
pub struct ImportKeys {
    operational: RecipientIdentity,
    recovery: RecipientIdentity,
    host_unlock: Option<RecipientIdentity>,
}

impl ImportKeys {
    /// Generates the operational identity and the recovery key, and returns the recovery key's text for the service's
    /// one reveal. Generating both before the reveal means the key the owner saves is the key that is enrolled.
    pub fn generate() -> (Self, RecoveryKeySecret) {
        let (operational, _) = OperationalIdentity::generate();
        let (secret, recovery) = RecoveryKey::generate_with_identity();
        let keys = Self {
            operational,
            recovery,
            host_unlock: None,
        };
        (keys, secret)
    }

    /// Enrols `host_unlock`, the identity read from the unlock handoff, as a third recipient, as
    /// [`crate::SealingKeys::with_host_unlock`] does for `init`.
    pub fn with_host_unlock(mut self, host_unlock: RecipientIdentity) -> Self {
        self.host_unlock = Some(host_unlock);
        self
    }
}

impl fmt::Debug for ImportKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ImportKeys([REDACTED])")
    }
}

/// One step of the write order, or the discard of an unfinished vault that comes before step 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportStep {
    /// Removing the files an unfinished initialization or import wrote, or a leftover `recovery.toml` or
    /// `locked-by-owner` from an Uninitialized directory.
    Discard,
    /// Step 1: writing `import.unfinished`, or refusing a directory import must not write to.
    Begin,
    /// Step 2: writing every record file.
    Records,
    /// Step 3: writing every approver key file.
    ApproverKeys,
    /// Step 4: writing `approval.age`.
    ApprovalState,
    /// Step 5: writing `config.toml`.
    Config,
    /// Step 6: writing `identity.age`, proving each recipient unwraps it, and writing `recipients.age`.
    IdentityEnvelope,
    /// Step 7: writing `operational.age`.
    PassphraseEnvelope,
    /// Step 8: writing `manifest.age`.
    Manifest,
    /// Step 9: reading the files back and checking them with the vault identity.
    Check,
    /// Step 10: removing `import.unfinished`, the commit point.
    Finish,
}

impl ImportStep {
    /// Returns the step's number in the write order, or `None` for the discard.
    pub fn number(self) -> Option<u8> {
        match self {
            Self::Discard => None,
            Self::Begin => Some(1),
            Self::Records => Some(2),
            Self::ApproverKeys => Some(3),
            Self::ApprovalState => Some(4),
            Self::Config => Some(5),
            Self::IdentityEnvelope => Some(6),
            Self::PassphraseEnvelope => Some(7),
            Self::Manifest => Some(8),
            Self::Check => Some(9),
            Self::Finish => Some(10),
        }
    }
}

impl fmt::Display for ImportStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self {
            Self::Discard => "discarding the unfinished vault, a leftover recovery check record or a stale owner-lock file",
            Self::Begin => "writing import.unfinished",
            Self::Records => "writing the record files",
            Self::ApproverKeys => "writing the approver key files",
            Self::ApprovalState => "writing the approval state",
            Self::Config => "writing config.toml",
            Self::IdentityEnvelope => "writing and checking the identity envelope and the recipient inventory",
            Self::PassphraseEnvelope => "writing the passphrase envelope",
            Self::Manifest => "writing the manifest",
            Self::Check => "checking the files as read back",
            Self::Finish => "removing import.unfinished",
        };
        match self.number() {
            Some(n) => write!(f, "step {n}, {what}"),
            None => f.write_str(what),
        }
    }
}

/// What the write order tells its caller as it goes, so the service can send the owner progress notices and the CLI's
/// reads never wait out its socket timeout on a large vault
/// ([migration bundle, "Write order"](../../../design/migration-bundle.md#write-order)).
///
/// The methods return nothing: a notice that cannot be sent never stops the write order.
pub trait ImportProgress {
    /// Tells the caller that `step` is about to start. Step 1 is told before any discard.
    fn step(&mut self, step: ImportStep);

    /// Tells the caller that, within step 2 or step 9, `done` of the `total` record files are written or checked.
    fn records(&mut self, step: ImportStep, done: usize, total: usize);
}

/// A failed import: the step it failed at, why, and what its discard removed before the failure. It carries no key
/// material, passphrase text or file bytes, because none of its causes do.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("vault import failed at {step}: {cause}")]
pub struct ImportError {
    step: ImportStep,
    cause: ImportFailure,
    discarded: Option<Box<Discarded>>,
}

impl ImportError {
    /// Returns the step that failed.
    pub fn step(&self) -> ImportStep {
        self.step
    }

    /// Returns why it failed. [`InitStateError::ImportFinishUncertain`] at [`ImportStep::Finish`] means the outcome is
    /// unknown: the vault reads Initialized now and may read Unfinished after power loss.
    pub fn cause(&self) -> &ImportFailure {
        &self.cause
    }

    /// Returns what the discard removed, for the `vault.init-discarded` or `migration.import-discarded` log, as
    /// [`crate::InitError::discarded`] reports it.
    pub fn discarded(&self) -> Option<&Discarded> {
        self.discarded.as_deref()
    }
}

/// Why a step of the import failed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ImportFailure {
    /// Reading the initialization state, refusing it, discarding, or the marker's write or removal failed.
    #[error(transparent)]
    State(#[from] InitStateError),
    /// A state file could not be written.
    #[error(transparent)]
    Write(#[from] WriteError),
    /// `config.toml` could not be written.
    #[error(transparent)]
    ConfigWrite(#[from] ConfigWriteError),
    /// Wrapping, writing or proving the identity envelope or the recipient inventory, or sealing the passphrase
    /// envelope, failed: `init`'s steps 2 and 3, which steps 6 and 7 reuse.
    #[error(transparent)]
    Identity(#[from] InitFailure),
    /// A state file could not be read back.
    #[error(transparent)]
    Read(#[from] ReadError),
    /// `config.toml` could not be read back.
    #[error(transparent)]
    ConfigRead(#[from] ConfigReadError),
    /// A file as read back failed a bundle check with the vault identity.
    #[error(transparent)]
    Check(#[from] BundleCheckError),
}

/// A vault imported up to its commit point: what the success response and the `migration.imported` event report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedVault {
    /// The vault's ID, the source's.
    pub vault_id: VaultId,
    /// The number of record files written.
    pub records: usize,
    /// The number of approver key files written.
    pub approvers: usize,
    /// The committed approval version, the source's.
    pub committed_version: ApprovalVersion,
    /// The highest reserved approval version, the source's: the destination's first approval commits above it.
    pub highest_reserved: u64,
    /// The committed config digest, which `config.toml` matches.
    pub config_digest: ConfigDigest,
    /// The roles of the recipients enrolled, in the order `identity.age` was wrapped for them: kinds, never keys.
    pub recipients: Vec<RecipientRole>,
    /// The unfinished run discarded before step 1, for the `vault.init-discarded` or `migration.import-discarded` log.
    pub discarded: Option<Discarded>,
}

/// Imports a verified migration bundle into the locked state and config directories: discards an unfinished vault, then
/// runs the write order from `import.unfinished` to its removal.
///
/// The caller holds the service-wide lock, has revealed the recovery key and has the owner's `yes`. A refusal at step 1
/// changes nothing; a failure at any later step leaves the directories Unfinished, for the next import to discard. The
/// keys and the vault passphrase are dropped on return.
pub fn import_vault<F: StoreFs>(
    state: &StateDirLock,
    config: &ConfigDirLock,
    fs: &F,
    bundle: VerifiedBundle,
    (keys, passphrase): (ImportKeys, Passphrase),
    enrolled_at: UtcSecond,
    progress: &mut impl ImportProgress,
) -> Result<ImportedVault, ImportError> {
    let dirs = (state, config);
    import_vault_at(
        dirs,
        fs,
        (bundle, keys, passphrase),
        (enrolled_at, PASSPHRASE_WORK_FACTOR),
        progress,
    )
}

/// Runs [`import_vault`] sealing the passphrase envelope at work factor `log_n`, so tests do not spend seconds in
/// scrypt.
pub(crate) fn import_vault_at<F: StoreFs>(
    (state, config): (&StateDirLock, &ConfigDirLock),
    fs: &F,
    (bundle, keys, passphrase): (VerifiedBundle, ImportKeys, Passphrase),
    (enrolled_at, log_n): (UtcSecond, u8),
    progress: &mut impl ImportProgress,
) -> Result<ImportedVault, ImportError> {
    progress.step(ImportStep::Begin);
    let discarded = begin(state, config, fs)?;
    match write_vault((state, config), fs, &bundle, (keys, passphrase), (enrolled_at, log_n), progress) {
        Ok(recipients) => Ok(ImportedVault {
            vault_id: bundle.vault_id(),
            records: bundle.records().len(),
            approvers: bundle.approver_keys().len(),
            committed_version: bundle.committed_version(),
            highest_reserved: bundle.highest_reserved(),
            config_digest: bundle.config_digest(),
            recipients,
            discarded,
        }),
        Err(error) => Err(ImportError {
            discarded: discarded.map(Box::new),
            ..error
        }),
    }
}

/// Runs the discard and step 1. The state is read first only to name the step a failure belongs to, as `init`'s is.
fn begin(state: &StateDirLock, config: &ConfigDirLock, fs: &impl StoreFs) -> Result<Option<Discarded>, ImportError> {
    let unfinished = matches!(
        InitializationState::read(state, config, fs).map_err(at(ImportStep::Begin))?,
        InitializationState::Unfinished(_)
    );
    begin_import(state, config, fs).map_err(|BeginError { cause, discarded }| {
        // Removing a leftover recovery check record or owner-lock file is part of the discard; a failed marker write is `Begin`.
        let leftover = matches!(
            cause,
            InitStateError::LeftoverRecoveryCheck(_) | InitStateError::LeftoverOwnerLock(_)
        );
        ImportError {
            step: if unfinished || leftover {
                ImportStep::Discard
            } else {
                ImportStep::Begin
            },
            cause: cause.into(),
            discarded: discarded.map(Box::new),
        }
    })
}

/// Runs steps 2 to 10, once step 1 is durable. Returns the roles enrolled.
fn write_vault<F: StoreFs>(
    (state, config): (&StateDirLock, &ConfigDirLock),
    fs: &F,
    bundle: &VerifiedBundle,
    (keys, passphrase): (ImportKeys, Passphrase),
    (enrolled_at, log_n): (UtcSecond, u8),
    progress: &mut impl ImportProgress,
) -> Result<Vec<RecipientRole>, ImportError> {
    copy_bundle_files((state, config), fs, bundle, progress)?;
    let ImportKeys {
        operational,
        recovery,
        host_unlock,
    } = keys;
    progress.step(ImportStep::IdentityEnvelope);
    let vault = (bundle.identity(), bundle.vault_id());
    let recipients = write_checked_identity(state, fs, vault, (&operational, recovery, host_unlock), enrolled_at)
        .map_err(at(ImportStep::IdentityEnvelope))?;
    progress.step(ImportStep::PassphraseEnvelope);
    seal_operational(state, fs, operational, passphrase, log_n).map_err(at(ImportStep::PassphraseEnvelope))?;
    progress.step(ImportStep::Manifest);
    durable_replace(state, fs, &StateFileName::manifest(), bundle.manifest_file()).map_err(at(ImportStep::Manifest))?;
    progress.step(ImportStep::Check);
    check_written((state, config), fs, bundle, progress).map_err(at(ImportStep::Check))?;
    progress.step(ImportStep::Finish);
    finish_import(state, fs).map_err(at(ImportStep::Finish))?;
    Ok(recipients)
}

/// Runs steps 2 to 5: writes the files whose bytes the bundle holds, apart from the manifest, which comes last of the
/// vault files.
fn copy_bundle_files(
    (state, config): (&StateDirLock, &ConfigDirLock),
    fs: &impl StoreFs,
    bundle: &VerifiedBundle,
    progress: &mut impl ImportProgress,
) -> Result<(), ImportError> {
    progress.step(ImportStep::Records);
    write_records(state, fs, bundle, progress).map_err(at(ImportStep::Records))?;
    progress.step(ImportStep::ApproverKeys);
    bundle
        .approver_keys()
        .iter()
        .try_for_each(|(id, envelope)| write_signer_key(state, fs, *id, envelope))
        .map_err(at(ImportStep::ApproverKeys))?;
    progress.step(ImportStep::ApprovalState);
    durable_replace(state, fs, &StateFileName::approval_state(), bundle.approval_file()).map_err(at(ImportStep::ApprovalState))?;
    progress.step(ImportStep::Config);
    write_imported_config(config, fs, bundle.config()).map_err(at(ImportStep::Config))
}

/// Runs step 2: writes every record file, in ascending record ID, each with its own directory fsync.
fn write_records(
    state: &StateDirLock,
    fs: &impl StoreFs,
    bundle: &VerifiedBundle,
    progress: &mut impl ImportProgress,
) -> Result<(), WriteError> {
    let total = bundle.records().len();
    bundle.records().iter().enumerate().try_for_each(|(done, (id, file))| {
        durable_replace(state, fs, &StateFileName::record(id), file)?;
        progress.records(ImportStep::Records, done + 1, total);
        Ok(())
    })
}

/// Runs step 9: holds the files as read back to the bundle checks that `unlock`'s config check rests on. The manifest
/// and the approval state must open with the vault identity and pair, and must name the bundle's records and approvers.
/// Each record file's digest must match its manifest entry, each approver key file must have its form, and
/// `config.toml` must match the committed config digest.
fn check_written(
    (state, config): (&StateDirLock, &ConfigDirLock),
    fs: &impl StoreFs,
    bundle: &VerifiedBundle,
    progress: &mut impl ImportProgress,
) -> Result<(), ImportFailure> {
    let manifest = read_state_file(state, fs, &StateFileName::manifest(), MAX_MANIFEST_LEN as u64)?;
    let approval = read_state_file(state, fs, &StateFileName::approval_state(), MAX_APPROVAL_STATE_LEN as u64)?;
    let control = ControlFiles::open(bundle.identity(), bundle.vault_id(), &manifest, &approval)?;
    control.check_record_ids(bundle.records().keys().copied())?;
    control.check_approver_ids(bundle.approver_keys().keys().copied())?;
    let total = bundle.records().len();
    bundle.records().keys().enumerate().try_for_each(|(done, id)| {
        control.check_record(*id, &read_state_file(state, fs, &StateFileName::record(id), MAX_RECORD_FILE_LEN)?)?;
        progress.records(ImportStep::Check, done + 1, total);
        Ok::<_, ImportFailure>(())
    })?;
    bundle
        .approver_keys()
        .keys()
        .try_for_each(|id| Ok::<_, ImportFailure>(control.check_approver_key(&read_signer_key(state, fs, *id)?)?))?;
    Ok(control.check_config(&read_config_file(config, fs, ConfigFileName::Active)?)?)
}

fn at<E: Into<ImportFailure>>(step: ImportStep) -> impl FnOnce(E) -> ImportError {
    move |error| ImportError {
        step,
        cause: error.into(),
        discarded: None,
    }
}
