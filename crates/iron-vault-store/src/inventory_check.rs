//! The inventory check: how every recipient command opens the recipient inventory, bound to the identity envelope on
//! disk (spec §3.10, §3.12, `design/recipients.md`).
//!
//! An inventory describes only the envelope whose digest it carries, and must list as many recipients as the envelope
//! has X25519 stanzas. A staged inventory that matches the envelope is a recipient change that committed and was not
//! finished, so it is finished; one that does not is discarded once `recipients.age` matches. Anything else is damaged
//! shared state, reported and never repaired: the inventory is the only record of the recipient keys, and a rebuilt one
//! could silently drop a real recipient at the next rewrap.

#[cfg(test)]
mod tests;

use std::io;

use thiserror::Error;

use crate::{
    MAX_RECIPIENT_INVENTORY_LEN, ReadError, RecipientInventory, RecipientInventoryError, StanzaKind, StateDirLock, StateFileName, StoreFs,
    VaultId, VaultIdentity, WriteError, durable_remove, durable_replace, envelope_digest, open_recipient_inventory, read_identity_envelope,
    read_state_file, stanza_kinds,
};

/// What is wrong with the recipient inventory, in the order the check decides it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum InventoryDamage {
    /// `identity.age` cannot be read, or holds a stanza other than X25519 and grease.
    #[error("identity.age cannot be read")]
    EnvelopeUnreadable,
    /// There is no `recipients.age`.
    #[error("recipients.age is missing")]
    Missing,
    /// `recipients.age` cannot be read, or is over its size limit.
    #[error("recipients.age cannot be read")]
    Unreadable,
    /// Its MAC does not verify: it was altered, or it is not this vault's.
    #[error("recipients.age failed its integrity check")]
    Mac,
    /// The frame or the decoder refuses it for another reason.
    #[error("recipients.age is malformed")]
    Malformed,
    /// It holds a recipient role this release does not know.
    #[error("recipients.age holds a recipient role this release does not know")]
    UnknownRole,
    /// It names another vault.
    #[error("recipients.age belongs to another vault")]
    OtherVault,
    /// It describes another `identity.age`.
    #[error("recipients.age describes another identity.age")]
    EnvelopeMismatch,
    /// It describes this `identity.age` but lists a different number of recipients from its X25519 stanzas.
    #[error("recipients.age lists a different number of recipients from identity.age")]
    CountMismatch,
}

impl InventoryDamage {
    /// The damage's label in the audit log.
    pub fn label(self) -> &'static str {
        match self {
            Self::EnvelopeUnreadable => "envelope_unreadable",
            Self::Missing => "missing",
            Self::Unreadable => "unreadable",
            Self::Mac => "mac",
            Self::Malformed => "malformed",
            Self::UnknownRole => "unknown_role",
            Self::OtherVault => "other_vault",
            Self::EnvelopeMismatch => "envelope_mismatch",
            Self::CountMismatch => "count_mismatch",
        }
    }
}

/// How the check settled a staged inventory it found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeRecovery {
    /// The staged change had committed: `recipients.age` now holds it, or already did.
    Completed,
    /// The staged change never committed and was removed.
    Discarded,
}

impl ChangeRecovery {
    /// The value's label in the audit log.
    pub fn label(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Discarded => "discarded",
        }
    }
}

/// The inventory that matches `identity.age`, and what was done with a staged inventory on the way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedInventory {
    /// The current inventory.
    pub inventory: RecipientInventory,
    /// Set when a staged inventory was finished or discarded.
    pub recovered: Option<ChangeRecovery>,
}

/// Why the inventory check failed. No variant carries file contents or key material.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum InventoryCheckError {
    /// The inventory is damaged shared state; nothing was written.
    #[error("the recipient inventory is damaged: {0}")]
    Damaged(InventoryDamage),
    /// Finishing or discarding a staged inventory failed.
    #[error("cannot settle the staged recipient inventory: {0}")]
    Write(#[from] WriteError),
}

/// What the inventory is checked against: the digest of `identity.age` and its number of X25519 stanzas.
struct Envelope {
    digest: [u8; 32],
    recipients: usize,
}

/// One inventory file as read and opened.
struct Opened {
    bytes: Vec<u8>,
    inventory: RecipientInventory,
}

/// Opens the recipient inventory that matches `identity.age`, finishing or discarding a staged recipient change first.
///
/// The caller holds the service-wide lock, the vault identity and the vault ID from the manifest it opened. Only a
/// staged inventory is ever written or removed here, and only when one of the two files matches the envelope on disk.
pub fn check_recipient_inventory(
    lock: &StateDirLock,
    fs: &impl StoreFs,
    identity: &VaultIdentity,
    vault_id: VaultId,
) -> Result<CheckedInventory, InventoryCheckError> {
    let envelope = read_envelope(lock, fs).map_err(InventoryCheckError::Damaged)?;
    let open = |name| open_bound(lock, fs, identity, vault_id, &name, &envelope);
    let staged = open(StateFileName::staged_recipient_inventory());
    match open(StateFileName::recipient_inventory()) {
        Ok(current) => Ok(CheckedInventory {
            recovered: settle_staged(lock, fs, &staged)?,
            inventory: current.inventory,
        }),
        Err(damage) => match staged {
            Ok(staged) => complete_staged(lock, fs, staged),
            Err(_) => Err(InventoryCheckError::Damaged(damage)),
        },
    }
}

/// The inventory matches: a staged file beside it is removed, as `Completed` when it matches too and `Discarded` when
/// it does not.
fn settle_staged(
    lock: &StateDirLock,
    fs: &impl StoreFs,
    staged: &Result<Opened, InventoryDamage>,
) -> Result<Option<ChangeRecovery>, InventoryCheckError> {
    let recovery = match staged {
        Err(InventoryDamage::Missing) => return Ok(None),
        Ok(_) => ChangeRecovery::Completed,
        Err(_) => ChangeRecovery::Discarded,
    };
    durable_remove(lock, fs, &StateFileName::staged_recipient_inventory())?;
    Ok(Some(recovery))
}

/// Only the staged inventory matches: the change committed, so `recipients.age` takes its bytes.
fn complete_staged(lock: &StateDirLock, fs: &impl StoreFs, staged: Opened) -> Result<CheckedInventory, InventoryCheckError> {
    durable_replace(lock, fs, &StateFileName::recipient_inventory(), &staged.bytes)?;
    durable_remove(lock, fs, &StateFileName::staged_recipient_inventory())?;
    Ok(CheckedInventory {
        inventory: staged.inventory,
        recovered: Some(ChangeRecovery::Completed),
    })
}

fn read_envelope(lock: &StateDirLock, fs: &impl StoreFs) -> Result<Envelope, InventoryDamage> {
    let bytes = read_identity_envelope(lock, fs).map_err(|_| InventoryDamage::EnvelopeUnreadable)?;
    let kinds = stanza_kinds(&bytes).map_err(|_| InventoryDamage::EnvelopeUnreadable)?;
    if !kinds.iter().all(StanzaKind::is_x25519_or_grease) {
        return Err(InventoryDamage::EnvelopeUnreadable);
    }
    Ok(Envelope {
        digest: envelope_digest(&bytes),
        recipients: kinds.iter().filter(|kind| **kind == StanzaKind::X25519).count(),
    })
}

/// Reads and opens the inventory file `name` and checks it describes `envelope`.
fn open_bound(
    lock: &StateDirLock,
    fs: &impl StoreFs,
    identity: &VaultIdentity,
    vault_id: VaultId,
    name: &StateFileName,
    envelope: &Envelope,
) -> Result<Opened, InventoryDamage> {
    let bytes = read_state_file(lock, fs, name, MAX_RECIPIENT_INVENTORY_LEN as u64).map_err(read_damage)?;
    let inventory = open_recipient_inventory(identity, &bytes).map_err(open_damage)?;
    match inventory {
        _ if inventory.vault_id() != vault_id => Err(InventoryDamage::OtherVault),
        _ if *inventory.envelope_digest() != envelope.digest => Err(InventoryDamage::EnvelopeMismatch),
        _ if inventory.entries().len() != envelope.recipients => Err(InventoryDamage::CountMismatch),
        _ => Ok(Opened { bytes, inventory }),
    }
}

fn read_damage(error: ReadError) -> InventoryDamage {
    match error {
        ReadError::Io {
            kind: io::ErrorKind::NotFound,
            ..
        } => InventoryDamage::Missing,
        _ => InventoryDamage::Unreadable,
    }
}

fn open_damage(error: RecipientInventoryError) -> InventoryDamage {
    match error {
        RecipientInventoryError::TooLarge { .. } => InventoryDamage::Unreadable,
        RecipientInventoryError::Damaged => InventoryDamage::Mac,
        RecipientInventoryError::UnknownRole(_) => InventoryDamage::UnknownRole,
        _ => InventoryDamage::Malformed,
    }
}
