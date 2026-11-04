//! Vault initialization at store level: the write order of design/vault-initialization.md, from `init.unfinished` to
//! committed approval version 1 (spec §3.9, §3.10, §3.11, §3.13).
//!
//! [`crate::InitializationState`] and the `init.unfinished` marker live in `initialization`; this module runs the steps
//! between writing the marker and removing it. Each step is durable before the next starts, so a failure at any step
//! after the first leaves a directory that reads Unfinished, which the next initialization discards.

mod keys;
mod passphrases;
#[cfg(test)]
mod tests;

use std::fmt;

use thiserror::Error;

use crate::initialization::INITIAL_CONFIG;
use crate::passphrase::seal_at;
use crate::{
    AdmissionPaused, ApprovalError, ApprovalPassphrase, ApprovalState, ApprovalStorage, ApprovalVersion, ConfigDirLock, EnvelopeError,
    InitStateError, InitializationState, PASSPHRASE_WORK_FACTOR, Passphrase, PendingConfig, ReadError, RecipientIdentity, RecipientSet,
    RecipientSetError, SignError, SoftwareSigner, SoftwareSignerKey, StateDirLock, StoreFs, Vault, VaultError, VaultId, VaultIdentity,
    WriteError, approval::seal_signer_key_at, begin_initialization, finish_initialization, open_signer_key, read_identity_envelope,
    read_signer_key, unwrap_identity, wrap_identity, write_identity_envelope, write_passphrase_envelope, write_signer_key,
};

pub use keys::{NewVaultKeys, SealingKeys};
pub use passphrases::{InitPassphrases, InitPassphrasesError, MIN_PASSPHRASE_CHARS, WhichPassphrase};

/// One step of the write order, or the discard of an unfinished initialization that comes before step 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitStep {
    /// Removing the files an unfinished initialization wrote.
    Discard,
    /// Step 1: writing `init.unfinished`, or refusing a directory init must not write to.
    Begin,
    /// Step 2: writing `identity.age` and proving both recipients unwrap it.
    IdentityEnvelope,
    /// Step 3: writing `operational.age`.
    PassphraseEnvelope,
    /// Step 4: writing `approver.age`.
    ApproverKey,
    /// Step 5: creating the vault's manifest.
    Manifest,
    /// Step 6: creating the approval state and recording it in the manifest.
    ApprovalState,
    /// Step 7: opening `approver.age` as read back.
    OpenSigner,
    /// Step 8: approving the initial config as version 1.
    FirstApproval,
    /// Step 9: removing `init.unfinished`, the commit point.
    Finish,
}

impl InitStep {
    /// The step's number in the write order, or `None` for the discard.
    pub fn number(self) -> Option<u8> {
        match self {
            Self::Discard => None,
            Self::Begin => Some(1),
            Self::IdentityEnvelope => Some(2),
            Self::PassphraseEnvelope => Some(3),
            Self::ApproverKey => Some(4),
            Self::Manifest => Some(5),
            Self::ApprovalState => Some(6),
            Self::OpenSigner => Some(7),
            Self::FirstApproval => Some(8),
            Self::Finish => Some(9),
        }
    }
}

impl fmt::Display for InitStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self {
            Self::Discard => "discarding the unfinished initialization",
            Self::Begin => "writing init.unfinished",
            Self::IdentityEnvelope => "writing and checking the identity envelope",
            Self::PassphraseEnvelope => "writing the passphrase envelope",
            Self::ApproverKey => "writing the approver key envelope",
            Self::Manifest => "creating the manifest",
            Self::ApprovalState => "creating the approval state",
            Self::OpenSigner => "opening the approver key envelope",
            Self::FirstApproval => "approving the initial config",
            Self::Finish => "removing init.unfinished",
        };
        match self.number() {
            Some(n) => write!(f, "step {n}, {what}"),
            None => f.write_str(what),
        }
    }
}

/// A failed initialization: the step it failed at, and why. It carries no key material, passphrase text or config
/// bytes, because none of its causes do.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("vault initialization failed at {step}: {cause}")]
pub struct InitError {
    step: InitStep,
    cause: InitFailure,
}

impl InitError {
    /// The step that failed.
    pub fn step(&self) -> InitStep {
        self.step
    }

    /// Why it failed.
    pub fn cause(&self) -> &InitFailure {
        &self.cause
    }
}

/// Why a step of initialization failed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum InitFailure {
    /// Reading the initialization state, refusing it, discarding or the marker's write or removal failed;
    /// [`InitStateError::FinishUncertain`] at [`InitStep::Finish`] means the vault may read Unfinished after power loss.
    #[error(transparent)]
    State(#[from] InitStateError),
    /// The operational and recovery keys do not form a recipient set.
    #[error(transparent)]
    Recipients(#[from] RecipientSetError),
    /// An envelope could not be sealed or opened.
    #[error(transparent)]
    Envelope(#[from] EnvelopeError),
    /// A state file could not be written.
    #[error(transparent)]
    Write(#[from] WriteError),
    /// A state file could not be read back.
    #[error(transparent)]
    Read(#[from] ReadError),
    /// `identity.age` as read back unwraps to another identity from the one generated.
    #[error("the identity envelope as read back does not hold the generated vault identity")]
    IdentityMismatch,
    /// The approver key could not be sealed or opened.
    #[error(transparent)]
    Sign(#[from] SignError),
    /// The vault or its approval state could not be created.
    #[error(transparent)]
    Vault(#[from] VaultError),
    /// The approval transaction failed.
    #[error(transparent)]
    Approval(#[from] ApprovalError),
    /// The approval committed a version other than 1, so the counters did not start at zero (spec §3.9).
    #[error("the first approval committed version {0}, not 1")]
    UnexpectedVersion(ApprovalVersion),
}

/// A vault initialized up to its commit point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitializedVault {
    /// The new vault's ID.
    pub vault_id: VaultId,
    /// The committed approval version, always 1.
    pub version: ApprovalVersion,
    /// The files discarded from an unfinished initialization before step 1, for the `vault.init-discarded` log.
    pub discarded: Vec<String>,
}

/// Initializes a vault in the locked state and config directories: discards an unfinished initialization, then runs
/// the write order from `init.unfinished` to its removal, approving the initial config as version 1.
///
/// The caller holds the service-wide lock, has revealed the recovery key and had its saving confirmed, and passes the
/// admission pause guard the approval's commit requires. A refusal at step 1 changes nothing; a failure at any later
/// step leaves the directories Unfinished, for the next initialization to discard. Every key and both passphrases are
/// dropped on return.
pub fn initialize<F: StoreFs>(
    state: &StateDirLock,
    config: &ConfigDirLock,
    fs: &F,
    keys: SealingKeys,
    passphrases: InitPassphrases,
    paused: &impl AdmissionPaused,
) -> Result<InitializedVault, InitError> {
    initialize_at(state, config, fs, (keys, passphrases), paused, PASSPHRASE_WORK_FACTOR)
}

/// [`initialize`] sealing both passphrase envelopes at work factor `log_n`, so tests do not spend seconds in scrypt.
pub(crate) fn initialize_at<F: StoreFs>(
    state: &StateDirLock,
    config: &ConfigDirLock,
    fs: &F,
    (keys, passphrases): (SealingKeys, InitPassphrases),
    paused: &impl AdmissionPaused,
    log_n: u8,
) -> Result<InitializedVault, InitError> {
    let discarded = begin(state, config, fs)?;
    let SealingKeys {
        vault,
        operational,
        recovery,
        signer,
        approver,
    } = keys;
    let (passphrase, approval_passphrase) = passphrases.into_parts();
    write_checked_identity(state, fs, &vault, &operational, recovery).map_err(at(InitStep::IdentityEnvelope))?;
    seal_operational(state, fs, operational, passphrase, log_n).map_err(at(InitStep::PassphraseEnvelope))?;
    seal_approver(state, fs, signer, &approval_passphrase, log_n).map_err(at(InitStep::ApproverKey))?;
    let mut created = Vault::create(state, fs, vault).map_err(at(InitStep::Manifest))?;
    let (mut approval, _) = created
        .create_approval_state(state, fs, approver)
        .map_err(at(InitStep::ApprovalState))?;
    let signer = open_signer(state, fs, approval_passphrase, &approval).map_err(at(InitStep::OpenSigner))?;
    let storage = ApprovalStorage {
        state_dir: state,
        config_dir: config,
        identity: created.identity(),
        fs,
    };
    let version = approve_initial_config(&storage, &mut approval, signer, paused).map_err(at(InitStep::FirstApproval))?;
    finish_initialization(state, fs).map_err(at(InitStep::Finish))?;
    Ok(InitializedVault {
        vault_id: created.manifest().vault_id(),
        version,
        discarded,
    })
}

/// The discard and step 1. The state is read first only to name the step a failure belongs to: with the service-wide
/// lock held, nothing else changes it before `begin_initialization` reads it again.
fn begin(state: &StateDirLock, config: &ConfigDirLock, fs: &impl StoreFs) -> Result<Vec<String>, InitError> {
    let step = match InitializationState::read(state, config, fs).map_err(at(InitStep::Begin))? {
        InitializationState::Unfinished => InitStep::Discard,
        _ => InitStep::Begin,
    };
    begin_initialization(state, config, fs).map_err(at(step))
}

/// Step 2. Both recipient paths are proved on the file as read back, before anything depends on it, while the recovery
/// key the owner saved still means nothing. The recovery identity is dropped on return.
fn write_checked_identity(
    state: &StateDirLock,
    fs: &impl StoreFs,
    vault: &VaultIdentity,
    operational: &RecipientIdentity,
    recovery: RecipientIdentity,
) -> Result<(), InitFailure> {
    let recipients = RecipientSet::new([operational.recipient_key(), recovery.recipient_key()])?;
    write_identity_envelope(state, fs, &wrap_identity(vault, &recipients)?)?;
    let envelope = read_identity_envelope(state, fs)?;
    [operational, &recovery].into_iter().try_for_each(|recipient| {
        match unwrap_identity(&envelope, recipient)?.public_key() == vault.public_key() {
            true => Ok(()),
            false => Err(InitFailure::IdentityMismatch),
        }
    })
}

/// Step 3. The operational identity and the vault passphrase are dropped on return.
fn seal_operational(
    state: &StateDirLock,
    fs: &impl StoreFs,
    operational: RecipientIdentity,
    passphrase: Passphrase,
    log_n: u8,
) -> Result<(), InitFailure> {
    Ok(write_passphrase_envelope(state, fs, &seal_at(&operational, &passphrase, log_n)?)?)
}

/// Step 4. The signer key is dropped on return.
fn seal_approver(
    state: &StateDirLock,
    fs: &impl StoreFs,
    signer: SoftwareSignerKey,
    passphrase: &ApprovalPassphrase,
    log_n: u8,
) -> Result<(), InitFailure> {
    Ok(write_signer_key(state, fs, &seal_signer_key_at(&signer, passphrase, log_n)?)?)
}

/// Step 7: proves `approver.age` as written opens with the approval passphrase, which is dropped on return.
fn open_signer(
    state: &StateDirLock,
    fs: &impl StoreFs,
    passphrase: ApprovalPassphrase,
    approval: &ApprovalState,
) -> Result<SoftwareSigner, InitFailure> {
    Ok(open_signer_key(&read_signer_key(state, fs)?, &passphrase, approval.approver())?)
}

/// Step 8: the approval transaction on the initial config, which a new vault's counters must commit as version 1.
fn approve_initial_config<F: StoreFs>(
    storage: &ApprovalStorage<'_, F>,
    approval: &mut ApprovalState,
    signer: SoftwareSigner,
    paused: &impl AdmissionPaused,
) -> Result<ApprovalVersion, InitFailure> {
    let committed = PendingConfig::write(storage, INITIAL_CONFIG.to_vec())?
        .prepare(storage, approval, signer)?
        .commit(storage, paused)?;
    let version = committed.approval().version();
    match version == ApprovalVersion::FIRST {
        true => Ok(version),
        false => Err(InitFailure::UnexpectedVersion(version)),
    }
}

fn at<E: Into<InitFailure>>(step: InitStep) -> impl FnOnce(E) -> InitError {
    move |error| InitError { step, cause: error.into() }
}
