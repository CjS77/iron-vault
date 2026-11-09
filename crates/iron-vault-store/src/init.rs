//! Vault initialization at store level: the write order of design/vault-initialization.md, from `init.unfinished` to
//! committed approval version 1 (spec §12, §13, §14, §16).
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
    AdmissionPaused, ApprovalError, ApprovalPassphrase, ApprovalState, ApprovalStorage, ApprovalVersion, BeginError, ConfigDigest,
    ConfigDirLock, EnvelopeError, ErrorKindLabel, InitStateError, InitializationState, PASSPHRASE_WORK_FACTOR, Passphrase, PendingConfig,
    ReadError, RecipientIdentity, RecipientSet, RecipientSetError, SignError, SoftwareSigner, SoftwareSignerKey, StateDirLock, StoreFs,
    UtcSecond, Vault, VaultError, VaultId, VaultIdentity, WriteError, approval::seal_signer_key_at, begin_initialization,
    finish_initialization, open_signer_key, read_identity_envelope, read_signer_key, unwrap_identity, wrap_identity,
    write_identity_envelope, write_passphrase_envelope, write_signer_key,
};
use crate::{
    RecipientEntry, RecipientInventory, RecipientInventoryError, RecipientInventoryReadError, RecipientInventoryWriteError, RecipientLabel,
    RecipientLabelError, RecipientRole, envelope_digest, read_recipient_inventory, write_recipient_inventory,
};

pub use keys::{NewVaultKeys, SealingKeys};
pub use passphrases::{InitPassphrases, InitPassphrasesError, MIN_PASSPHRASE_CHARS, WhichPassphrase};

/// One step of the write order, or the discard of an unfinished initialization that comes before step 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitStep {
    /// Removing the files an unfinished initialization wrote, or a leftover `recovery.toml` from an Uninitialized directory.
    Discard,
    /// Step 1: writing `init.unfinished`, or refusing a directory init must not write to.
    Begin,
    /// Step 2: writing `identity.age`, proving each recipient unwraps it, and writing `recipients.age`.
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
            Self::Discard => "discarding the unfinished initialization or a leftover recovery check record",
            Self::Begin => "writing init.unfinished",
            Self::IdentityEnvelope => "writing and checking the identity envelope and the recipient inventory",
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

/// A failed initialization: the step it failed at, why, and what its discard removed before the failure. It carries no
/// key material, passphrase text or config bytes, because none of its causes do. When the first approval committed
/// before the failure, [`InitError::approved`] reports it.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("vault initialization failed at {step}: {cause}")]
pub struct InitError {
    step: InitStep,
    cause: InitFailure,
    discarded: Box<[String]>,
    approved: Option<Box<FirstApproval>>,
}

impl InitError {
    /// A failure at `step` for `cause`, with nothing discarded, so the binary's tests can build each message.
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_tests(step: InitStep, cause: InitFailure) -> Self {
        Self {
            step,
            cause,
            discarded: Box::default(),
            approved: None,
        }
    }

    /// The step that failed.
    pub fn step(&self) -> InitStep {
        self.step
    }

    /// Why it failed.
    pub fn cause(&self) -> &InitFailure {
        &self.cause
    }

    /// The files the discard removed, for the `vault.init-discarded` log: all of them when a later step failed, those
    /// removed before the failure when the discard itself failed part-way, and none when nothing was discarded.
    pub fn discarded(&self) -> &[String] {
        &self.discarded
    }

    /// Step 8's outcome, set only when the first approval was committed and a later step failed. Its events are the
    /// caller's to record even though initialization did not finish.
    pub fn approved(&self) -> Option<&FirstApproval> {
        self.approved.as_deref()
    }
}

/// Why a step of initialization failed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum InitFailure {
    /// Reading the initialization state, refusing it, discarding or the marker's write or removal failed;
    /// [`InitStateError::FinishUncertain`] at [`InitStep::Finish`] means the vault may read Unfinished after power loss.
    #[error(transparent)]
    State(#[from] InitStateError),
    /// The recipient keys do not form a recipient set.
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
    /// The recipient inventory could not be built from the recipients.
    #[error(transparent)]
    Inventory(#[from] RecipientInventoryError),
    /// The recipient inventory could not be written.
    #[error(transparent)]
    InventoryWrite(#[from] RecipientInventoryWriteError),
    /// The recipient inventory could not be read back.
    #[error(transparent)]
    InventoryRead(#[from] RecipientInventoryReadError),
    /// A default recipient label broke the label rule.
    #[error(transparent)]
    InventoryLabel(#[from] RecipientLabelError),
    /// The inventory as read back names a recipient set other than the one the envelope was wrapped for.
    #[error("the recipient inventory as read back does not match the identity envelope")]
    InventoryMismatch,
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
    /// The approval committed a version other than 1, so the counters did not start at zero (spec §12).
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
    /// The digest of the initial config that version 1 approves.
    pub digest: ConfigDigest,
    /// The kind of the directory fsync failure that made the first commit uncertain until it was settled, if one did.
    pub commit_uncertain: Option<ErrorKindLabel>,
    /// The files discarded from an unfinished initialization before step 1, for the `vault.init-discarded` log.
    pub discarded: Vec<String>,
    /// The roles of the recipients enrolled, in the order `identity.age` was wrapped for them: kinds, never keys.
    pub recipients: Vec<RecipientRole>,
}

impl InitializedVault {
    /// The first approval's outcome, as an [`InitError`] that failed after it reports it.
    pub fn approved(&self) -> FirstApproval {
        FirstApproval {
            version: self.version,
            digest: self.digest,
            commit_uncertain: self.commit_uncertain.clone(),
        }
    }
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
    enrolled_at: UtcSecond,
) -> Result<InitializedVault, InitError> {
    initialize_at(
        state,
        config,
        fs,
        (keys, passphrases),
        paused,
        (enrolled_at, PASSPHRASE_WORK_FACTOR),
    )
}

/// [`initialize`] sealing both passphrase envelopes at work factor `log_n`, so tests do not spend seconds in scrypt.
pub(crate) fn initialize_at<F: StoreFs>(
    state: &StateDirLock,
    config: &ConfigDirLock,
    fs: &F,
    (keys, passphrases): (SealingKeys, InitPassphrases),
    paused: &impl AdmissionPaused,
    (enrolled_at, log_n): (UtcSecond, u8),
) -> Result<InitializedVault, InitError> {
    let discarded = begin(state, config, fs)?;
    match write_vault(state, config, fs, (keys, passphrases), paused, (enrolled_at, log_n)) {
        Ok((vault_id, committed, recipients)) => Ok(InitializedVault {
            vault_id,
            recipients,
            version: committed.version,
            digest: committed.digest,
            commit_uncertain: committed.commit_uncertain,
            discarded,
        }),
        Err(error) => Err(InitError {
            discarded: discarded.into(),
            ..error
        }),
    }
}

/// Steps 2 to 9, once step 1 is durable: the vault's ID and its first approval.
fn write_vault<F: StoreFs>(
    state: &StateDirLock,
    config: &ConfigDirLock,
    fs: &F,
    (keys, passphrases): (SealingKeys, InitPassphrases),
    paused: &impl AdmissionPaused,
    (enrolled_at, log_n): (UtcSecond, u8),
) -> Result<(VaultId, FirstApproval, Vec<RecipientRole>), InitError> {
    let SealingKeys {
        vault,
        vault_id,
        operational,
        recovery,
        host_unlock,
        signer,
        approver,
    } = keys;
    let (passphrase, approval_passphrase) = passphrases.into_parts();
    let recipients = write_checked_identity(state, fs, (&vault, vault_id), (&operational, recovery, host_unlock), enrolled_at)
        .map_err(at(InitStep::IdentityEnvelope))?;
    seal_operational(state, fs, operational, passphrase, log_n).map_err(at(InitStep::PassphraseEnvelope))?;
    seal_approver(state, fs, signer, &approval_passphrase, log_n).map_err(at(InitStep::ApproverKey))?;
    let mut created = Vault::create_with_id(state, fs, vault, vault_id).map_err(at(InitStep::Manifest))?;
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
    let approved = approve_initial_config(&storage, &mut approval, signer, paused).map_err(at(InitStep::FirstApproval))?;
    finish_initialization(state, fs).map_err(|error| InitError {
        approved: Some(Box::new(approved.clone())),
        ..at(InitStep::Finish)(error)
    })?;
    Ok((created.manifest().vault_id(), approved, recipients))
}

/// The discard and step 1. The state is read first only to name the step a failure belongs to: with the service-wide
/// lock held, nothing else changes it before `begin_initialization` reads it again.
fn begin(state: &StateDirLock, config: &ConfigDirLock, fs: &impl StoreFs) -> Result<Vec<String>, InitError> {
    let unfinished = InitializationState::read(state, config, fs).map_err(at(InitStep::Begin))? == InitializationState::Unfinished;
    begin_initialization(state, config, fs).map_err(|BeginError { cause, discarded }| InitError {
        // Removing a leftover recovery check record is part of the discard; a failed marker write is `Begin`.
        step: if unfinished || matches!(cause, InitStateError::LeftoverRecoveryCheck(_)) {
            InitStep::Discard
        } else {
            InitStep::Begin
        },
        cause: cause.into(),
        discarded: discarded.into(),
        approved: None,
    })
}

/// One recipient init enrols: its identity, role and default label.
type Enrolment<'a> = (&'a RecipientIdentity, RecipientRole, &'static str);

/// Step 2. Every recipient path is proved on the file as read back, before anything depends on it, while the recovery
/// key the owner saved still means nothing: each identity must unwrap the same vault identity. Then the recipient
/// inventory is written for the same keys and read back, so `recipients.age` exists from the moment the vault does.
/// The recovery and host unlock identities are dropped on return. Returns the roles enrolled.
fn write_checked_identity(
    state: &StateDirLock,
    fs: &impl StoreFs,
    (vault, vault_id): (&VaultIdentity, VaultId),
    (operational, recovery, host_unlock): (&RecipientIdentity, RecipientIdentity, Option<RecipientIdentity>),
    enrolled_at: UtcSecond,
) -> Result<Vec<RecipientRole>, InitFailure> {
    let enrolments: Vec<Enrolment> = [
        Some((operational, RecipientRole::Operational, "vault passphrase")),
        Some((&recovery, RecipientRole::Recovery, "recovery key")),
        host_unlock.as_ref().map(|host| (host, RecipientRole::HostUnlock, "host unlock")),
    ]
    .into_iter()
    .flatten()
    .collect();
    let recipients = RecipientSet::new(enrolments.iter().map(|(identity, ..)| identity.recipient_key()))?;
    write_identity_envelope(state, fs, &wrap_identity(vault, &recipients)?)?;
    let envelope = read_identity_envelope(state, fs)?;
    enrolments.iter().try_for_each(
        |(identity, ..)| match unwrap_identity(&envelope, identity)?.public_key() == vault.public_key() {
            true => Ok(()),
            false => Err(InitFailure::IdentityMismatch),
        },
    )?;
    write_checked_inventory(state, fs, (vault, vault_id, &envelope), (&enrolments, &recipients), enrolled_at)?;
    Ok(enrolments.iter().map(|(_, role, _)| *role).collect())
}

/// The recipient inventory for `enrolments`, written and read back, so `recipients.age` exists from the moment the
/// vault does.
fn write_checked_inventory(
    state: &StateDirLock,
    fs: &impl StoreFs,
    (vault, vault_id, envelope): (&VaultIdentity, VaultId, &[u8]),
    (enrolments, recipients): (&[Enrolment], &RecipientSet),
    enrolled_at: UtcSecond,
) -> Result<(), InitFailure> {
    let entries = enrolments
        .iter()
        .map(|(identity, role, label)| {
            Ok(RecipientEntry::new(
                identity.recipient_key(),
                *role,
                RecipientLabel::new(label)?,
                enrolled_at,
            ))
        })
        .collect::<Result<Vec<_>, InitFailure>>()?;
    let inventory = RecipientInventory::new(vault_id, envelope_digest(envelope), entries)?;
    write_recipient_inventory(state, fs, vault, &inventory)?;
    let read_back = read_recipient_inventory(state, fs, vault)?;
    match read_back == inventory && read_back.recipient_set() == *recipients {
        true => Ok(()),
        false => Err(InitFailure::InventoryMismatch),
    }
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

/// What step 8 committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirstApproval {
    /// The committed version, always 1.
    pub version: ApprovalVersion,
    /// The digest of the initial config that version approves.
    pub digest: ConfigDigest,
    /// The kind of the directory fsync failure that made the commit uncertain until it was settled, if one did.
    pub commit_uncertain: Option<ErrorKindLabel>,
}

/// Step 8: the approval transaction on the initial config, which a new vault's counters must commit as version 1. The
/// service records its events from what the store returns, as for any approval.
fn approve_initial_config<F: StoreFs>(
    storage: &ApprovalStorage<'_, F>,
    approval: &mut ApprovalState,
    signer: SoftwareSigner,
    paused: &impl AdmissionPaused,
) -> Result<FirstApproval, InitFailure> {
    let committed = PendingConfig::write(storage, INITIAL_CONFIG.to_vec())?
        .prepare(storage, approval, signer)?
        .commit(storage, paused)?;
    let version = committed.approval().version();
    if version != ApprovalVersion::FIRST {
        return Err(InitFailure::UnexpectedVersion(version));
    }
    Ok(FirstApproval {
        version,
        digest: ConfigDigest::of(INITIAL_CONFIG),
        commit_uncertain: committed.commit_uncertain().cloned(),
    })
}

fn at<E: Into<InitFailure>>(step: InitStep) -> impl FnOnce(E) -> InitError {
    move |error| InitError {
        step,
        cause: error.into(),
        discarded: Box::default(),
        approved: None,
    }
}
