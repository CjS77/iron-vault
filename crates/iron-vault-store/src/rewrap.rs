//! The recipient change transaction: rewrapping the vault identity for a new recipient set and writing the inventory
//! that describes it (spec §3.10, §3.11, `design/recipients.md`).
//!
//! Two files change and the filesystem has no transaction, so the inventory is written twice: staged before the
//! identity envelope and in place after it. The envelope's durable replace is the single commit point; the inventory
//! check finishes or discards an interrupted change from the staged inventory. No credential record, manifest or
//! approval file is touched, because the vault identity itself does not change.

#[cfg(test)]
mod tests;

use std::fmt;

use thiserror::Error;

use crate::{
    EnvelopeError, ReadError, RecipientChange, RecipientChangeRefusal, RecipientInventory, SealError, StateDirLock, StateFileName, StoreFs,
    VaultIdentity, WriteError, WriteStep, durable_remove, durable_replace, envelope_digest, read_identity_envelope,
    seal_recipient_inventory, wrap_identity, write_identity_envelope,
};

/// A step of the recipient change that touches the state directory, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecipientChangeStep {
    /// Writing `recipients.age.staged`.
    Stage,
    /// Writing `identity.age`, the commit point.
    Envelope,
    /// Reading `identity.age` back and comparing its digest with the staged inventory's.
    ReadBack,
    /// Writing `recipients.age` with the staged bytes.
    Inventory,
    /// Removing `recipients.age.staged`.
    Cleanup,
}

impl RecipientChangeStep {
    /// The step's label in the audit log.
    pub fn label(self) -> &'static str {
        match self {
            Self::Stage => "stage",
            Self::Envelope => "envelope",
            Self::ReadBack => "read_back",
            Self::Inventory => "inventory",
            Self::Cleanup => "cleanup",
        }
    }
}

impl fmt::Display for RecipientChangeStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Whether a recipient change that failed part-way committed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeCommitted {
    /// `identity.age` was not replaced: the change never happened.
    No,
    /// `identity.age` may have been replaced: the next inventory check settles which.
    Unknown,
    /// `identity.age` was replaced: the change stands, and the next inventory check finishes the inventory.
    Yes,
}

impl ChangeCommitted {
    /// The value's label in the audit log.
    pub fn label(self) -> &'static str {
        match self {
            Self::No => "no",
            Self::Unknown => "unknown",
            Self::Yes => "yes",
        }
    }
}

/// What went wrong at a step. It names files, never their contents.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RecipientChangeFault {
    /// A durable replace or remove failed.
    #[error(transparent)]
    Write(#[from] WriteError),
    /// `identity.age` could not be read back.
    #[error(transparent)]
    Read(#[from] ReadError),
    /// `identity.age` as read back is not the envelope just written.
    #[error("identity.age as read back is not the envelope just written")]
    EnvelopeMismatch,
}

/// A recipient change step failed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("the recipient change failed at its {step} step: {fault}")]
pub struct RecipientChangeWriteError {
    step: RecipientChangeStep,
    fault: RecipientChangeFault,
}

impl RecipientChangeWriteError {
    /// The step that failed.
    pub fn step(&self) -> RecipientChangeStep {
        self.step
    }

    /// What went wrong.
    pub fn fault(&self) -> &RecipientChangeFault {
        &self.fault
    }

    /// Whether the change committed. A failed directory fsync after the envelope's rename leaves the rename in place,
    /// though it may not survive power loss, and a failed read back cannot say what is on disk.
    pub fn committed(&self) -> ChangeCommitted {
        match (self.step, &self.fault) {
            (RecipientChangeStep::Stage, _) => ChangeCommitted::No,
            (
                RecipientChangeStep::Envelope,
                RecipientChangeFault::Write(WriteError::Io {
                    step: WriteStep::SyncDir, ..
                }),
            ) => ChangeCommitted::Unknown,
            (RecipientChangeStep::Envelope, _) => ChangeCommitted::No,
            (RecipientChangeStep::ReadBack, _) => ChangeCommitted::Unknown,
            (RecipientChangeStep::Inventory | RecipientChangeStep::Cleanup, _) => ChangeCommitted::Yes,
        }
    }
}

/// Why a recipient change did not commit, or may not have. No variant carries key material.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RecipientChangeError {
    /// The change rule refused the change; nothing was written.
    #[error(transparent)]
    Refused(#[from] RecipientChangeRefusal),
    /// The vault identity could not be wrapped for the new set; nothing was written.
    #[error(transparent)]
    Wrap(#[from] EnvelopeError),
    /// The new inventory could not be sealed; nothing was written.
    #[error("cannot seal the recipient inventory: {0}")]
    Seal(#[from] SealError),
    /// A step up to the read back failed; [`RecipientChangeWriteError::committed`] says `No` or `Unknown`.
    #[error(transparent)]
    Write(RecipientChangeWriteError),
}

/// A committed recipient change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewrappedIdentity {
    /// The inventory that describes the new `identity.age`.
    pub inventory: RecipientInventory,
    /// A failure after the commit point, at the inventory or cleanup step. The change stands; the next inventory check
    /// finishes it from the staged inventory.
    pub unfinished: Option<RecipientChangeWriteError>,
}

/// Rewraps the vault identity for the recipient set `change` leads to from `current`, and writes the inventory that
/// describes the new envelope.
///
/// The caller holds the service-wide lock and `current` is the inventory the inventory check just opened, so nothing
/// else changes either file before the write. The new envelope cannot be proved by unwrapping, because the service holds
/// no recipient's private key here; `age` wraps one file key for every stanza, so the read back proves the bytes on disk
/// are the bytes wrapped.
pub fn rewrap_identity(
    state: &StateDirLock,
    fs: &impl StoreFs,
    vault: &VaultIdentity,
    current: &RecipientInventory,
    change: &RecipientChange,
) -> Result<RewrappedIdentity, RecipientChangeError> {
    let next = change.apply(current)?;
    let envelope = wrap_identity(vault, &next.recipient_set())?;
    let inventory = next.describing(envelope_digest(&envelope));
    let staged = seal_recipient_inventory(vault, &inventory)?;
    commit(state, fs, &envelope, &staged).map_err(RecipientChangeError::Write)?;
    let unfinished = finish(state, fs, &staged).err();
    Ok(RewrappedIdentity { inventory, unfinished })
}

/// The stage, envelope and read back steps: up to and including the commit point.
fn commit(state: &StateDirLock, fs: &impl StoreFs, envelope: &[u8], staged: &[u8]) -> Result<(), RecipientChangeWriteError> {
    durable_replace(state, fs, &StateFileName::staged_recipient_inventory(), staged).map_err(at(RecipientChangeStep::Stage))?;
    write_identity_envelope(state, fs, envelope).map_err(at(RecipientChangeStep::Envelope))?;
    let read_back = read_identity_envelope(state, fs).map_err(at(RecipientChangeStep::ReadBack))?;
    match read_back == envelope {
        true => Ok(()),
        false => Err(at(RecipientChangeStep::ReadBack)(RecipientChangeFault::EnvelopeMismatch)),
    }
}

/// The inventory and cleanup steps, after the commit point.
fn finish(state: &StateDirLock, fs: &impl StoreFs, staged: &[u8]) -> Result<(), RecipientChangeWriteError> {
    durable_replace(state, fs, &StateFileName::recipient_inventory(), staged).map_err(at(RecipientChangeStep::Inventory))?;
    durable_remove(state, fs, &StateFileName::staged_recipient_inventory()).map_err(at(RecipientChangeStep::Cleanup))
}

fn at<E: Into<RecipientChangeFault>>(step: RecipientChangeStep) -> impl FnOnce(E) -> RecipientChangeWriteError {
    move |fault| RecipientChangeWriteError { step, fault: fault.into() }
}
