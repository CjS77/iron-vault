//! The approval state: the pinned approvers and the approval version counters (spec §12, §13).
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
//! generation. Restoring the whole state directory from an older copy restores older counters too; spec §12 leaves
//! protection against that outside v0.

mod approver;
mod encoding;
mod file;
#[cfg(test)]
mod tests;

use std::cmp::Ordering;
use std::io;

use thiserror::Error;

use super::{ApprovalDecodeError, ApprovalVersion, ConfigDigest, SignatureAlgorithm};
use crate::{
    MAX_MANIFEST_LEN, ManifestError, OpenError, PartialRestore, ReadError, RecipientLabelError, SealError, StateDirLock, StateFileName,
    StateGeneration, StoreFs, VaultId, VaultIdentity, VaultManifest, WriteError, WriteStep, durable_replace, open_manifest,
    partial_restore::check_control_generations, read_state_file,
};

pub(crate) use approver::ApproverKey;
pub use approver::{ApproverId, ApproverLabel, ApproverPublicKey, InvalidKeyReason, MAX_APPROVERS, PinnedApprover};
pub use file::{open_approval_state, seal_approval_state};

/// The largest approval state file accepted, in bytes on disk, checked before any other work; also the payload limit.
///
/// A payload with [`MAX_APPROVERS`] approvers is at most 2,814 bytes. `age` adds a header of at most about 400 bytes plus
/// a 16-byte nonce and a 16-byte tag, and the file adds 53 bytes of header and MAC: under 3,300 bytes in all. The limit
/// keeps a planted file cheap to refuse.
pub const MAX_APPROVAL_STATE_LEN: usize = 4096;

/// One vault's approval state: the pinned approvers, the highest reserved version and the committed approval, at one
/// state generation.
///
/// The committed version is never above the highest reserved version, whether the state was built or decoded. The
/// highest reserved version is 0 only in a newly created state, and no operation lowers it. The peer generation is
/// always below the state generation. It pins from 1 to [`MAX_APPROVERS`] approvers, in strictly ascending order of
/// approver ID, no two with the same public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalState {
    vault_id: VaultId,
    state_generation: StateGeneration,
    peer_generation: StateGeneration,
    approvers: Vec<PinnedApprover>,
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
    /// The approver ID is not a random version 4 UUID, so the service did not generate it.
    #[error("approver ID is not a random version 4 UUID")]
    InvalidApproverId,
    /// The approver label is not UTF-8.
    #[error("approver label is not UTF-8")]
    ApproverLabelNotUtf8,
    /// The approver label breaks the recipient label rule.
    #[error("approver label breaks the label rule: {0}")]
    InvalidApproverLabel(RecipientLabelError),
    /// The enrolment time is outside the range a UTC second holds.
    #[error("approver enrolment time is out of range")]
    BadEnrolmentTime,
    /// The payload pins no approver, or more than [`MAX_APPROVERS`].
    #[error("approval state pins {0} approvers; it must pin from 1 to {MAX_APPROVERS}")]
    ApproverCount(u64),
    /// The approver IDs are not in strictly ascending order, which no service write produces.
    #[error("approval state approvers are not in ascending approver ID order")]
    UnsortedApprovers,
    /// Two approvers share an approver ID: in the payload, or the one being enrolled is already pinned.
    #[error("approver ID {0} is already pinned")]
    DuplicateApproverId(ApproverId),
    /// Two approvers share a public key: in the payload, or the one being enrolled is already pinned under another ID.
    #[error("the approver's public key is already pinned")]
    DuplicateApproverKey,
    /// `enroll_approver` would pin more than [`MAX_APPROVERS`]. Nothing was written.
    #[error("{MAX_APPROVERS} approvers are already pinned; remove one before enrolling another")]
    TooManyApprovers,
    /// `remove_approver` named the last pinned approver; without one no config could be approved. Nothing was written.
    #[error("the last pinned approver cannot be removed")]
    LastApprover,
    /// `remove_approver` named an approver ID that is not pinned. Nothing was written.
    #[error("no pinned approver has ID {0}")]
    UnknownApprover(ApproverId),
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
    /// The approval state and the manifest are not a pair any sequence of writes leaves: one was restored from an older
    /// copy or deleted. `load` and every write refuse such a pair, and `create` refuses a manifest that records an
    /// approval state, because creating one again would reset its counters (spec §12). Nothing was written.
    #[error(transparent)]
    PartialRestore(PartialRestore),
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
    /// A state from its parts, refusing approvers that break the state's invariant, a committed version above the
    /// highest reserved one, and a peer generation not below the state generation.
    fn from_parts(
        vault_id: VaultId,
        (state_generation, peer_generation): (StateGeneration, StateGeneration),
        approvers: Vec<PinnedApprover>,
        highest_reserved: u64,
        committed: Option<(ApprovalVersion, ConfigDigest)>,
    ) -> Result<Self, ApprovalStateError> {
        if peer_generation >= state_generation {
            return Err(ApprovalStateError::PeerNotOlder);
        }
        check_approvers(&approvers)?;
        match committed {
            Some((version, _)) if version.get() > highest_reserved => Err(ApprovalStateError::CommittedNotReserved),
            _ => Ok(Self {
                vault_id,
                state_generation,
                peer_generation,
                approvers,
                highest_reserved,
                committed,
            }),
        }
    }

    /// Writes the state of the vault whose manifest is in the state directory to `approval.age` and returns it:
    /// `approver` alone pinned, nothing reserved and nothing committed, at the state generation after the manifest's.
    ///
    /// Refuses a missing or damaged manifest: the vault is created first, and its manifest names the vault and the
    /// state generation to follow. Refuses with [`ApprovalStateError::AlreadyExists`] if the file exists, and with
    /// [`ApprovalStateError::PartialRestore`] if the manifest records an approval state that is now missing, so the
    /// counters are never reset. The caller has already authorized vault creation; this performs it.
    ///
    /// Only [`crate::Vault::create_approval_state`] calls this, so the manifest write that records the new state follows.
    pub(crate) fn create(
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
            approvers: vec![approver],
            highest_reserved: 0,
            committed: None,
        };
        let bytes = seal_approval_state(identity, &state).map_err(ApprovalStateError::Seal)?;
        refuse_existing(lock, fs)?;
        check_control_generations(manifest.generations(), None).map_err(ApprovalStateError::PartialRestore)?;
        replace_file(lock, fs, &bytes)?;
        Ok(state)
    }

    /// Reads `approval.age` and opens it as the approval state of vault `vault_id`, refusing it unless it and this
    /// vault's manifest on disk are a pair some sequence of writes leaves together.
    ///
    /// Any error is damaged shared state (spec §13): approvals cannot be checked, so the service must not proxy. A
    /// [`ApprovalStateError::PartialRestore`] means one of the two files was restored from an older copy, so the
    /// counters may have gone backwards; it is never repaired here (spec §12).
    pub fn load(lock: &StateDirLock, fs: &impl StoreFs, identity: &VaultIdentity, vault_id: VaultId) -> Result<Self, ApprovalStateError> {
        let state = Self::read(lock, fs, identity, vault_id)?;
        let manifest = read_vault_manifest(lock, fs, identity, vault_id)?;
        check_control_generations(manifest.generations(), Some(state.generations())).map_err(ApprovalStateError::PartialRestore)?;
        Ok(state)
    }

    /// Reads `approval.age` and opens it as the approval state of vault `vault_id`, without comparing it with the
    /// manifest: for a caller that holds the manifest already and runs that check itself.
    pub(crate) fn read(
        lock: &StateDirLock,
        fs: &impl StoreFs,
        identity: &VaultIdentity,
        vault_id: VaultId,
    ) -> Result<Self, ApprovalStateError> {
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

    /// The state generation and the peer generation, as the partial restore check takes them.
    pub(crate) fn generations(&self) -> (StateGeneration, StateGeneration) {
        (self.state_generation, self.peer_generation)
    }

    /// The pinned approvers, in ascending order of approver ID; a config approval must verify against one of them.
    pub fn approvers(&self) -> &[PinnedApprover] {
        &self.approvers
    }

    /// The pinned approver with ID `id`, if any.
    pub fn approver(&self, id: ApproverId) -> Option<&PinnedApprover> {
        self.approvers.iter().find(|approver| approver.id() == id)
    }

    /// The highest version reserved so far; 0 before the first reservation.
    pub fn highest_reserved(&self) -> u64 {
        self.highest_reserved
    }

    /// The committed approval version and config digest, if any approval has been committed.
    pub fn committed(&self) -> Option<(ApprovalVersion, ConfigDigest)> {
        self.committed
    }

    /// Durably reserves the next approval version and returns it, before anything is signed (spec §12).
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

    /// Durably makes `(version, digest)` the committed approval: the commit point of an approval (spec §12, step 5).
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

    /// Durably pins `approver` beside the approvers already pinned, keeping both counters (spec §12). Signing-key
    /// rotation is an enroll followed by a [`remove_approver`](Self::remove_approver).
    ///
    /// Refuses, before any file is touched, an approver ID or a public key already pinned and a seventeenth approver.
    /// This performs an already authorized change: the caller checks the owner's authorization.
    pub fn enroll_approver(
        &mut self,
        lock: &StateDirLock,
        fs: &impl StoreFs,
        identity: &VaultIdentity,
        approver: PinnedApprover,
    ) -> Result<(), ApprovalStateError> {
        let at = match self.approvers.binary_search_by_key(&approver.id(), PinnedApprover::id) {
            Ok(_) => return Err(ApprovalStateError::DuplicateApproverId(approver.id())),
            Err(at) => at,
        };
        if self.approvers.iter().any(|pinned| pinned.public_key() == approver.public_key()) {
            return Err(ApprovalStateError::DuplicateApproverKey);
        }
        if self.approvers.len() >= MAX_APPROVERS {
            return Err(ApprovalStateError::TooManyApprovers);
        }
        let mut approvers = self.approvers.clone();
        approvers.insert(at, approver);
        self.write(lock, fs, identity, Self { approvers, ..self.clone() })
    }

    /// Durably unpins the approver `id`, keeping both counters (spec §12).
    ///
    /// If that approver signed the active `config.toml.sig`, the signature stops verifying, because no pinned key
    /// matches it any more, until the owner approves the config again at a new version. Refuses, before any file is
    /// touched, an ID that is not pinned and the last approver, since without one no config could ever be approved
    /// again. This performs an already authorized change: the caller checks the owner's authorization.
    pub fn remove_approver(
        &mut self,
        lock: &StateDirLock,
        fs: &impl StoreFs,
        identity: &VaultIdentity,
        id: ApproverId,
    ) -> Result<(), ApprovalStateError> {
        let at = self
            .approvers
            .binary_search_by_key(&id, PinnedApprover::id)
            .map_err(|_| ApprovalStateError::UnknownApprover(id))?;
        if self.approvers.len() == 1 {
            return Err(ApprovalStateError::LastApprover);
        }
        let mut approvers = self.approvers.clone();
        approvers.remove(at);
        self.write(lock, fs, identity, Self { approvers, ..self.clone() })
    }

    /// Writes the state on disk again, its counters unchanged, after a commit of `expected` whose rename landed but
    /// whose directory fsync failed (design/config-approval.md, "Settling an uncertain commit").
    ///
    /// Reading the file back proves nothing, since the page cache serves it, and neither does a second fsync, which
    /// Linux can report as successful after a failed writeback. A fresh durable write is the only proof. Refuses with
    /// [`ApprovalStateError::ReloadRequired`] unless the state on disk commits `expected`. Memory takes the state on
    /// disk only once that write succeeds, so after a failure this state still refuses every write until a reload.
    pub(crate) fn settle_commit(
        &mut self,
        lock: &StateDirLock,
        fs: &impl StoreFs,
        identity: &VaultIdentity,
        expected: (ApprovalVersion, ConfigDigest),
    ) -> Result<(), ApprovalStateError> {
        let mut on_disk = Self::load(lock, fs, identity, self.vault_id)?;
        if on_disk.committed != Some(expected) {
            return Err(ApprovalStateError::ReloadRequired);
        }
        on_disk.write(lock, fs, identity, on_disk.clone())?;
        *self = on_disk;
        Ok(())
    }

    /// Replaces the file with `next` at the next state generation, then makes that the state in memory. The disk checks
    /// come first: a stale in-memory state would otherwise write lower counters over newer ones, and the manifest on
    /// disk gives the peer generation. A partial restore is refused rather than written over: recording the restored
    /// manifest as the peer would make the pair agree again and hide the restore (spec §12).
    fn write(&mut self, lock: &StateDirLock, fs: &impl StoreFs, identity: &VaultIdentity, next: Self) -> Result<(), ApprovalStateError> {
        self.ensure_disk_matches(lock, fs, identity)?;
        let manifest = read_vault_manifest(lock, fs, identity, self.vault_id)?;
        check_control_generations(manifest.generations(), Some(self.generations())).map_err(ApprovalStateError::PartialRestore)?;
        let next = Self {
            state_generation: next_generation(manifest.state_generation(), Some(self.state_generation))?,
            peer_generation: manifest.state_generation(),
            ..next
        };
        let bytes = seal_approval_state(identity, &next).map_err(ApprovalStateError::Seal)?;
        replace_file(lock, fs, &bytes)?;
        *self = next;
        Ok(())
    }

    /// Refuses with [`ApprovalStateError::ReloadRequired`] unless the state on disk is exactly this one.
    fn ensure_disk_matches(&self, lock: &StateDirLock, fs: &impl StoreFs, identity: &VaultIdentity) -> Result<(), ApprovalStateError> {
        match Self::read(lock, fs, identity, self.vault_id) {
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

    /// This state with `highest_reserved` reserved, which only a run of reservations reaches.
    pub(crate) fn with_highest_reserved(&self, highest_reserved: u64) -> Self {
        Self {
            highest_reserved,
            ..self.clone()
        }
    }
}

/// Refuses approvers no service write leaves: none or more than [`MAX_APPROVERS`], IDs not strictly ascending, or one
/// public key pinned twice. Every entry was validated when it was built.
fn check_approvers(approvers: &[PinnedApprover]) -> Result<(), ApprovalStateError> {
    if approvers.is_empty() || approvers.len() > MAX_APPROVERS {
        // At most 16 here or 0, so it always fits in a u64.
        return Err(ApprovalStateError::ApproverCount(approvers.len() as u64));
    }
    approvers.windows(2).try_for_each(|pair| match pair[0].id().cmp(&pair[1].id()) {
        Ordering::Less => Ok(()),
        Ordering::Equal => Err(ApprovalStateError::DuplicateApproverId(pair[1].id())),
        Ordering::Greater => Err(ApprovalStateError::UnsortedApprovers),
    })?;
    let pinned_twice = approvers
        .iter()
        .enumerate()
        .any(|(i, approver)| approvers[..i].iter().any(|earlier| earlier.public_key() == approver.public_key()));
    match pinned_twice {
        true => Err(ApprovalStateError::DuplicateApproverKey),
        false => Ok(()),
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

/// The manifest of vault `vault_id` on disk, refusing another vault's.
fn read_vault_manifest(
    lock: &StateDirLock,
    fs: &impl StoreFs,
    identity: &VaultIdentity,
    vault_id: VaultId,
) -> Result<VaultManifest, ApprovalStateError> {
    let manifest = read_manifest(lock, fs, identity)?;
    match manifest.vault_id() == vault_id {
        true => Ok(manifest),
        false => Err(ApprovalStateError::ManifestDamaged(ManifestError::VaultIdMismatch)),
    }
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
        } => ApprovalStateError::WriteUncertain(error),
        other => ApprovalStateError::Write(other),
    })
}
