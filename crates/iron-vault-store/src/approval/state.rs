//! The approval state: the pinned approver and the approval version counters (spec §3.9, §3.10).
//!
//! Versioned approval stops an old `config.toml` and `config.toml.sig` pair from becoming valid again only if the
//! counters never go backwards. The state lives in `approval.age`, sealed to the vault public key and authenticated with
//! a MAC keyed from the vault identity, so only the service can write one that opens. Every change is one durable replace
//! of that file, and memory changes only after the replace returns: a version handed out here is already durable, so it
//! is never handed out twice. The byte layouts are in `design/storage-formats.md`.
//!
//! Every write also reads the manifest from disk, before touching any file, and takes the next vault-wide state
//! generation after the manifest's and its own, recording the manifest's as its peer generation. The state-directory
//! lock makes the service the only writer, so the file on disk is the current one and no two writes share a state
//! generation. Restoring the whole state directory from an older copy restores older counters too; spec §3.9 leaves
//! protection against that outside v0.

mod encoding;
mod file;
#[cfg(test)]
mod tests;

use std::io;

use ed25519_dalek::{SigningKey, VerifyingKey};
use thiserror::Error;

use super::{ApprovalDecodeError, ApprovalVersion, ConfigDigest, SignatureAlgorithm};
use crate::{
    MAX_MANIFEST_LEN, ManifestError, OpenError, ReadError, SealError, StateDirLock, StateFileName, StateGeneration, StoreFs, VaultId,
    VaultIdentity, VaultManifest, WriteError, WriteStep, durable_replace, open_manifest, read_state_file,
};

pub use file::{open_approval_state, seal_approval_state};

/// The largest approval state file accepted, in bytes on disk, checked before any other work; also the payload limit.
///
/// A payload with an Ed25519 approver is 127 bytes. `age` adds a header of at most about 400 bytes plus a 16-byte nonce
/// and a 16-byte tag, and the file adds 53 bytes of header and MAC: under 600 bytes in all. The limit leaves room for a
/// later algorithm with a longer public key while keeping a planted file cheap to refuse.
pub const MAX_APPROVAL_STATE_LEN: usize = 4096;

/// The algorithm and public key every config approval must verify against (spec §3.9).
///
/// It is kept only in the approval state, never read from the config or the signature file. The key is checked when it
/// is pinned, so a held approver always has a usable key: an unusable one is refused at enrolment, not at the next
/// reload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedApprover {
    key: ApproverKey,
}

/// A validated public key, tagged with its algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApproverKey {
    /// An Ed25519 key that is a valid, non-weak point.
    Ed25519(VerifyingKey),
}

/// Why a public key cannot be pinned as an approver. Carries no key bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidKeyReason {
    /// The bytes do not decode to a point on the curve.
    NotAPoint,
    /// The key is a small-order point, which strict verification refuses for every signature.
    WeakKey,
}

impl PinnedApprover {
    /// The approver with `public_key` for `algorithm`, refusing a key of the wrong length, a non-point or a weak key.
    pub fn new(algorithm: SignatureAlgorithm, public_key: Vec<u8>) -> Result<Self, ApprovalStateError> {
        match algorithm {
            SignatureAlgorithm::Ed25519 => {
                let bytes: [u8; 32] = public_key
                    .try_into()
                    .map_err(|key: Vec<u8>| ApprovalStateError::PublicKeyLength { algorithm, len: key.len() })?;
                let key = VerifyingKey::from_bytes(&bytes).map_err(|_| invalid(algorithm, InvalidKeyReason::NotAPoint))?;
                if key.is_weak() {
                    return Err(invalid(algorithm, InvalidKeyReason::WeakKey));
                }
                Ok(Self {
                    key: ApproverKey::Ed25519(key),
                })
            }
        }
    }

    /// The Ed25519 approver for `signing_key`.
    ///
    /// Infallible because an Ed25519 public key is a clamped scalar times the basepoint: clamping makes the scalar a
    /// multiple of the cofactor and the basepoint has prime order, so the result is never a small-order point.
    pub(crate) fn from_signing_key(signing_key: &SigningKey) -> Self {
        Self {
            key: ApproverKey::Ed25519(signing_key.verifying_key()),
        }
    }

    /// The algorithm approvals must be signed with.
    pub fn algorithm(&self) -> SignatureAlgorithm {
        match self.key {
            ApproverKey::Ed25519(_) => SignatureAlgorithm::Ed25519,
        }
    }

    /// The encoded public key approvals must verify against.
    pub fn public_key(&self) -> &[u8] {
        match &self.key {
            ApproverKey::Ed25519(key) => key.as_bytes(),
        }
    }

    /// The validated key approvals must verify against.
    pub(crate) fn key(&self) -> &ApproverKey {
        &self.key
    }
}

fn invalid(algorithm: SignatureAlgorithm, reason: InvalidKeyReason) -> ApprovalStateError {
    ApprovalStateError::InvalidApproverKey { algorithm, reason }
}

/// One vault's approval state: the pinned approver, the highest reserved version and the committed approval, at one
/// state generation.
///
/// The committed version is never above the highest reserved version, whether the state was built or decoded. The
/// highest reserved version is 0 only in a newly created state, and no operation lowers it. The peer generation is
/// always below the state generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalState {
    vault_id: VaultId,
    state_generation: StateGeneration,
    peer_generation: StateGeneration,
    approver: PinnedApprover,
    highest_reserved: u64,
    committed: Option<(ApprovalVersion, ConfigDigest)>,
}

/// The approval state cannot be built, opened or changed. No variant carries key material or MAC bytes.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ApprovalStateError {
    /// The file is larger than [`MAX_APPROVAL_STATE_LEN`]; nothing else was read.
    #[error("approval state exceeds the {limit}-byte limit")]
    TooLarge {
        /// The limit that was exceeded.
        limit: usize,
    },
    /// The file header or the payload is not a well-formed v1 encoding.
    #[error("approval state is malformed: {0}")]
    Format(#[from] ApprovalDecodeError),
    /// The MAC does not match: the file was altered, or written by someone without this vault's identity.
    #[error("approval state failed its integrity check; it is damaged or was not written by this vault, and the vault may need recovery")]
    Damaged,
    /// The MAC matched but the ciphertext did not open.
    #[error("approval state ciphertext cannot be opened: {0}")]
    Sealed(#[from] OpenError),
    /// The payload names a different vault from the file header, or the file is for a different vault from the one
    /// being opened.
    #[error("approval state belongs to a different vault")]
    VaultIdMismatch,
    /// The approver's public key has the wrong length for its algorithm.
    #[error("{algorithm:?} approver public key is {len} bytes")]
    PublicKeyLength {
        /// The approver's algorithm.
        algorithm: SignatureAlgorithm,
        /// The key's length.
        len: usize,
    },
    /// The approver's public key has the right length but is not a usable key for its algorithm.
    #[error("{algorithm:?} approver public key is unusable: {reason:?}")]
    InvalidApproverKey {
        /// The approver's algorithm.
        algorithm: SignatureAlgorithm,
        /// What is wrong with the key.
        reason: InvalidKeyReason,
    },
    /// The byte saying whether an approval is committed is neither `00` nor `01`.
    #[error("unknown committed-approval tag {0}")]
    BadCommittedTag(u8),
    /// The committed version is above the highest reserved version, which no service write produces.
    #[error("approval state commits a version that was never reserved")]
    CommittedNotReserved,
    /// The peer generation is not below the state generation. Every write takes one above both files' state
    /// generations, so no service write produces this, and the two files would share a state generation.
    #[error("approval state peer generation is not below its state generation")]
    PeerNotOlder,
    /// The manifest, whose state generation every write needs, cannot be read; a missing manifest is refused too.
    /// Nothing was written.
    #[error("cannot read the vault manifest to take the next state generation: {0}")]
    ManifestUnreadable(ReadError),
    /// The manifest was read but did not open as this vault's manifest. Nothing was written.
    #[error("the vault manifest is damaged, so the next state generation cannot be taken: {0}")]
    ManifestDamaged(ManifestError),
    /// The state generation or the peer generation is 0, which no approval state is written at.
    #[error("approval state names state generation 0")]
    ZeroStateGeneration,
    /// The approval state or the manifest is at state generation `u64::MAX`, so no later approval state can be written.
    #[error("vault state generation is exhausted; the approval state cannot be written again")]
    StateGenerationExhausted,
    /// The highest reserved version is `u64::MAX`: no version is left to reserve, and nothing may be signed.
    #[error("approval versions are exhausted; no further approval can be signed")]
    Exhausted,
    /// `commit` named a version above the highest reserved version.
    #[error("approval version {version} was never reserved; the highest reserved version is {highest_reserved}")]
    NotReserved {
        /// The version the caller tried to commit.
        version: ApprovalVersion,
        /// The highest version reserved so far.
        highest_reserved: u64,
    },
    /// `commit` named a version that is not newer than the committed one.
    #[error("approval version {version} is not newer than the committed version {committed}")]
    NotNewer {
        /// The version the caller tried to commit.
        version: ApprovalVersion,
        /// The version already committed.
        committed: ApprovalVersion,
    },
    /// `create` found an approval state file already in the state directory; creating would reset its counters.
    #[error("the approval state already exists; creating it again would reset its version counters")]
    AlreadyExists,
    /// The approval state file could not be read, or is over its size limit.
    #[error(transparent)]
    Read(ReadError),
    /// Sealing the new state failed; nothing was written.
    #[error("cannot seal the approval state: {0}")]
    Seal(SealError),
    /// A file step failed before the rename. The state on disk and in memory is unchanged.
    #[error("the approval state write failed and changed nothing: {0}")]
    Write(WriteError),
    /// The new state was renamed into place but the state directory fsync failed, so it may not survive power loss.
    /// Disk may hold the new state while memory holds the old: reload before using it.
    #[error("the approval state write may or may not have committed ({0}); reload the approval state to see which")]
    WriteUncertain(WriteError),
    /// The state on disk is not the one in memory, or cannot be read: another writer changed it, an earlier write was
    /// uncertain, or the file is gone or damaged. Nothing was written; reload the approval state.
    #[error("the approval state on disk differs from the one in memory; reload it before changing it")]
    ReloadRequired,
}

impl ApprovalState {
    /// A state from its parts, refusing a committed version above the highest reserved one and a peer generation not
    /// below the state generation.
    fn from_parts(
        vault_id: VaultId,
        state_generation: StateGeneration,
        peer_generation: StateGeneration,
        approver: PinnedApprover,
        highest_reserved: u64,
        committed: Option<(ApprovalVersion, ConfigDigest)>,
    ) -> Result<Self, ApprovalStateError> {
        if peer_generation >= state_generation {
            return Err(ApprovalStateError::PeerNotOlder);
        }
        match committed {
            Some((version, _)) if version.get() > highest_reserved => Err(ApprovalStateError::CommittedNotReserved),
            _ => Ok(Self {
                vault_id,
                state_generation,
                peer_generation,
                approver,
                highest_reserved,
                committed,
            }),
        }
    }

    /// Writes the state of the vault whose manifest is in the state directory to `approval.age` and returns it:
    /// `approver` pinned, nothing reserved and nothing committed, at the state generation after the manifest's.
    ///
    /// Refuses a missing or damaged manifest: the vault is created first, and its manifest names the vault and the
    /// state generation to follow. Refuses with [`ApprovalStateError::AlreadyExists`] if the file exists, so the
    /// counters are never reset. The caller has already authorized vault creation; this performs it.
    pub fn create(
        lock: &StateDirLock,
        fs: &impl StoreFs,
        identity: &VaultIdentity,
        approver: PinnedApprover,
    ) -> Result<Self, ApprovalStateError> {
        let manifest = read_manifest(lock, fs, identity)?;
        let state = Self {
            vault_id: manifest.vault_id(),
            state_generation: next_generation(manifest.state_generation(), None)?,
            peer_generation: manifest.state_generation(),
            approver,
            highest_reserved: 0,
            committed: None,
        };
        let bytes = seal_approval_state(identity, &state).map_err(ApprovalStateError::Seal)?;
        refuse_existing(lock, fs)?;
        replace_file(lock, fs, &bytes)?;
        Ok(state)
    }

    /// Reads `approval.age` and opens it as the approval state of vault `vault_id`.
    ///
    /// Any error is damaged shared state (spec §3.10): approvals cannot be checked, so the service must not proxy.
    pub fn load(lock: &StateDirLock, fs: &impl StoreFs, identity: &VaultIdentity, vault_id: VaultId) -> Result<Self, ApprovalStateError> {
        // MAX_APPROVAL_STATE_LEN is 4 KiB, so it always fits in a u64.
        let file =
            read_state_file(lock, fs, &StateFileName::approval_state(), MAX_APPROVAL_STATE_LEN as u64).map_err(ApprovalStateError::Read)?;
        let state = open_approval_state(identity, &file)?;
        match state.vault_id == vault_id {
            true => Ok(state),
            false => Err(ApprovalStateError::VaultIdMismatch),
        }
    }

    /// The vault this state belongs to.
    pub fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    /// The state generation this state was written at.
    pub fn state_generation(&self) -> StateGeneration {
        self.state_generation
    }

    /// The manifest's state generation when this state was written.
    pub fn peer_generation(&self) -> StateGeneration {
        self.peer_generation
    }

    /// The approver every config approval must verify against.
    pub fn approver(&self) -> &PinnedApprover {
        &self.approver
    }

    /// The highest version reserved so far; 0 before the first reservation.
    pub fn highest_reserved(&self) -> u64 {
        self.highest_reserved
    }

    /// The committed approval version and config digest, if any approval has been committed.
    pub fn committed(&self) -> Option<(ApprovalVersion, ConfigDigest)> {
        self.committed
    }

    /// Durably reserves the next approval version and returns it, before anything is signed (spec §3.9).
    ///
    /// The version is consumed whether or not signing succeeds. At `u64::MAX` this returns
    /// [`ApprovalStateError::Exhausted`] and touches no file, and the caller must not sign. Only an `Ok` version may
    /// be signed: any error means the reservation may not be durable.
    pub fn reserve(
        &mut self,
        lock: &StateDirLock,
        fs: &impl StoreFs,
        identity: &VaultIdentity,
    ) -> Result<ApprovalVersion, ApprovalStateError> {
        let version = self
            .highest_reserved
            .checked_add(1)
            .and_then(ApprovalVersion::new)
            .ok_or(ApprovalStateError::Exhausted)?;
        self.write(
            lock,
            fs,
            identity,
            Self {
                highest_reserved: version.get(),
                ..self.clone()
            },
        )?;
        Ok(version)
    }

    /// Durably makes `(version, digest)` the committed approval: the commit point of an approval (spec §3.9, step 5).
    ///
    /// `version` must be reserved and newer than the committed version; anything else is refused before any file is
    /// touched. The caller has already checked the signature over this version and digest.
    pub fn commit(
        &mut self,
        lock: &StateDirLock,
        fs: &impl StoreFs,
        identity: &VaultIdentity,
        version: ApprovalVersion,
        digest: ConfigDigest,
    ) -> Result<(), ApprovalStateError> {
        if version.get() > self.highest_reserved {
            return Err(ApprovalStateError::NotReserved {
                version,
                highest_reserved: self.highest_reserved,
            });
        }
        match self.committed {
            Some((committed, _)) if version <= committed => Err(ApprovalStateError::NotNewer { version, committed }),
            _ => self.write(
                lock,
                fs,
                identity,
                Self {
                    committed: Some((version, digest)),
                    ..self.clone()
                },
            ),
        }
    }

    /// Durably pins `approver` in place of the current one, keeping both counters (spec §3.9).
    ///
    /// The active signature stops verifying because the key changed, until the owner approves the config again at a
    /// new version. This performs an already authorized change: the caller checks administrator or existing-owner
    /// authorization.
    pub fn replace_approver(
        &mut self,
        lock: &StateDirLock,
        fs: &impl StoreFs,
        identity: &VaultIdentity,
        approver: PinnedApprover,
    ) -> Result<(), ApprovalStateError> {
        self.write(lock, fs, identity, Self { approver, ..self.clone() })
    }

    /// Replaces the file with `next` at the next state generation, then makes that the state in memory. The disk checks
    /// come first: the manifest on disk gives the peer generation, and a stale in-memory state would otherwise write
    /// lower counters over newer ones.
    fn write(&mut self, lock: &StateDirLock, fs: &impl StoreFs, identity: &VaultIdentity, next: Self) -> Result<(), ApprovalStateError> {
        let manifest_generation = self.manifest_generation(lock, fs, identity)?;
        let next = Self {
            state_generation: next_generation(manifest_generation, Some(self.state_generation))?,
            peer_generation: manifest_generation,
            ..next
        };
        let bytes = seal_approval_state(identity, &next).map_err(ApprovalStateError::Seal)?;
        self.ensure_disk_matches(lock, fs, identity)?;
        replace_file(lock, fs, &bytes)?;
        *self = next;
        Ok(())
    }

    /// The state generation of this vault's manifest on disk.
    fn manifest_generation(
        &self,
        lock: &StateDirLock,
        fs: &impl StoreFs,
        identity: &VaultIdentity,
    ) -> Result<StateGeneration, ApprovalStateError> {
        let manifest = read_manifest(lock, fs, identity)?;
        match manifest.vault_id() == self.vault_id {
            true => Ok(manifest.state_generation()),
            false => Err(ApprovalStateError::ManifestDamaged(ManifestError::VaultIdMismatch)),
        }
    }

    /// Refuses with [`ApprovalStateError::ReloadRequired`] unless the state on disk is exactly this one.
    fn ensure_disk_matches(&self, lock: &StateDirLock, fs: &impl StoreFs, identity: &VaultIdentity) -> Result<(), ApprovalStateError> {
        match Self::load(lock, fs, identity, self.vault_id) {
            Ok(on_disk) if on_disk == *self => Ok(()),
            _ => Err(ApprovalStateError::ReloadRequired),
        }
    }
}

#[cfg(test)]
impl ApprovalState {
    /// This state as if written at `state_generation`, which no service write can choose.
    pub(crate) fn with_state_generation(&self, state_generation: StateGeneration) -> Self {
        Self {
            state_generation,
            ..self.clone()
        }
    }
}

/// The state generation the next approval state write takes, given the manifest's and the approval state's current ones.
fn next_generation(manifest: StateGeneration, approval: Option<StateGeneration>) -> Result<StateGeneration, ApprovalStateError> {
    StateGeneration::next(Some(manifest), approval).ok_or(ApprovalStateError::StateGenerationExhausted)
}

/// The manifest on disk, whose state generation every approval state write follows and records.
fn read_manifest(lock: &StateDirLock, fs: &impl StoreFs, identity: &VaultIdentity) -> Result<VaultManifest, ApprovalStateError> {
    // MAX_MANIFEST_LEN is 1 MiB, so it always fits in a u64.
    let file =
        read_state_file(lock, fs, &StateFileName::manifest(), MAX_MANIFEST_LEN as u64).map_err(ApprovalStateError::ManifestUnreadable)?;
    open_manifest(identity, &file).map_err(ApprovalStateError::ManifestDamaged)
}

/// Refuses to create the approval state over an existing file, whatever it holds.
fn refuse_existing(lock: &StateDirLock, fs: &impl StoreFs) -> Result<(), ApprovalStateError> {
    match read_state_file(lock, fs, &StateFileName::approval_state(), MAX_APPROVAL_STATE_LEN as u64) {
        Err(ReadError::Io {
            kind: io::ErrorKind::NotFound,
            ..
        }) => Ok(()),
        Ok(_) | Err(ReadError::TooLarge { .. }) => Err(ApprovalStateError::AlreadyExists),
        Err(other) => Err(ApprovalStateError::Read(other)),
    }
}

/// Durably replaces `approval.age`. A failure at the directory fsync comes after the rename, so the disk may already
/// hold the new state; that is [`ApprovalStateError::WriteUncertain`], never "unchanged".
fn replace_file(lock: &StateDirLock, fs: &impl StoreFs, bytes: &[u8]) -> Result<(), ApprovalStateError> {
    durable_replace(lock, fs, &StateFileName::approval_state(), bytes).map_err(|error| match error {
        WriteError::Io {
            step: WriteStep::SyncDir, ..
        } => {
            tracing::error!(
                error = %error,
                remediation = "reload the approval state: the change took effect only if the reloaded state shows it",
                "approval state was replaced but the state directory fsync failed; the change may not survive power loss"
            );
            ApprovalStateError::WriteUncertain(error)
        }
        other => ApprovalStateError::Write(other),
    })
}
