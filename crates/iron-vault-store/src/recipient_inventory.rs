//! The recipient inventory: the service's own record of which recipient keys `identity.age` is wrapped for (spec §13,
//! §14, `design/recipients.md`).
//!
//! An X25519 stanza does not name its recipient, so without this file the service could not rewrap the vault identity for
//! the recipients it keeps. Anyone holding the vault public key could seal a list of their own choosing, so the
//! inventory is a MAC'd file: only the holder of the vault identity writes one that opens. It carries the digest of the
//! `identity.age` it describes, which is how a restore of either file alone is noticed.

mod change;
mod encoding;
#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::fmt;

use blake2::{Blake2b256, Digest};
use thiserror::Error;

pub use change::{RecipientChange, RecipientChangeRefusal};

use crate::mac_file::MacFileKind;
use crate::sealed::{OpenError, SealError};
use crate::vault_id::{VaultId, VaultIdError};
use crate::vault_identity::VaultIdentity;
use crate::{
    MAX_RECIPIENTS, ReadError, RecipientKey, RecipientSet, StateDirLock, StateFileName, StoreFs, UtcSecond, WriteError, durable_replace,
    read_state_file,
};

/// The largest inventory file accepted, in bytes on disk, checked before any other work. A full inventory is under
/// 10,300 bytes (`design/storage-formats.md`).
pub const MAX_RECIPIENT_INVENTORY_LEN: usize = 16 * 1024;

/// The longest recipient label, in bytes of UTF-8.
const MAX_LABEL_LEN: usize = 64;

/// The inventory's MAC'd file frame: magic `IVRF`, version 1, its own key persona and domain tag, so a MAC from the
/// manifest or the approval state never verifies here.
const KIND: MacFileKind<RecipientInventoryError> = MacFileKind {
    magic: *b"IVRF",
    version: 1,
    persona: b"iv-recipients-v1",
    domain_tag: b"iron-vault recipients file v1 mac\0",
    max_len: MAX_RECIPIENT_INVENTORY_LEN,
    too_large: RecipientInventoryError::TooLarge {
        limit: MAX_RECIPIENT_INVENTORY_LEN,
    },
    truncated: RecipientInventoryError::Truncated,
    bad_magic: RecipientInventoryError::BadMagic,
    unknown_version: RecipientInventoryError::UnknownVersion,
    damaged: RecipientInventoryError::Damaged,
    invalid_vault_id: RecipientInventoryError::InvalidVaultId,
};

/// What reaches the vault through a recipient. The role decides how the recipient counts toward the independence rule.
///
/// Codes 4 and 5 (`tpm`, `hardware`) are reserved for later epics and are refused on reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RecipientRole {
    /// The operational identity, opened by the vault passphrase through `operational.age`.
    Operational,
    /// An offline recovery key the service generated and showed once.
    Recovery,
    /// A recipient key the owner supplied.
    Added,
    /// The intermediate identity of the host unlock adapter, which a container-profile service reads from the unlock
    /// handoff. It is in the unlock class and never counts as recovery: its secret lives on the host.
    HostUnlock,
}

impl RecipientRole {
    /// The role's code in the inventory payload.
    pub fn code(self) -> u8 {
        match self {
            Self::Operational => 1,
            Self::Recovery => 2,
            Self::Added => 3,
            Self::HostUnlock => 6,
        }
    }

    /// The role with `code`, or `None` for a reserved or unknown code.
    pub fn from_code(code: u8) -> Option<Self> {
        [Self::Operational, Self::Recovery, Self::Added, Self::HostUnlock]
            .into_iter()
            .find(|role| role.code() == code)
    }

    /// The name the CLI prints and the audit log records.
    pub fn name(self) -> &'static str {
        match self {
            Self::Operational => "operational",
            Self::Recovery => "recovery",
            Self::Added => "added",
            Self::HostUnlock => "host-unlock",
        }
    }
}

/// Owner text saying which device or copy a recipient key is, valid on construction: 1 to 64 bytes of UTF-8, no control
/// or format character, no leading or trailing whitespace. A label can then neither start a log line nor reorder a
/// summary with a bidirectional control. It is never interpreted and need not be unique.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientLabel(String);

/// Why a string is not a recipient label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RecipientLabelError {
    /// The label is empty.
    #[error("recipient label is empty")]
    Empty,
    /// The label is longer than 64 bytes.
    #[error("recipient label is longer than {MAX_LABEL_LEN} bytes")]
    TooLong,
    /// The label has a control or format character.
    #[error("recipient label has a control or format character")]
    ControlOrFormat,
    /// The label starts or ends with whitespace.
    #[error("recipient label has leading or trailing whitespace")]
    SurroundingWhitespace,
}

impl RecipientLabel {
    /// Validates `text` as a label.
    pub fn new(text: &str) -> Result<Self, RecipientLabelError> {
        match text {
            "" => Err(RecipientLabelError::Empty),
            _ if text.len() > MAX_LABEL_LEN => Err(RecipientLabelError::TooLong),
            _ if text.chars().any(|c| c.is_control() || is_format_char(c)) => Err(RecipientLabelError::ControlOrFormat),
            _ if text.trim() != text => Err(RecipientLabelError::SurroundingWhitespace),
            _ => Ok(Self(text.to_owned())),
        }
    }

    /// The label text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RecipientLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Whether `c` is in Unicode general category Cf. `std` knows Cc but not Cf. `icu_properties` knows it but is only a
/// transitive dependency here, and adding it directly would pull a large Unicode data crate into the store's audited
/// surface for one check, so the ranges are listed by hand (Unicode 16). A character added to Cf later is accepted
/// until the list is updated.
fn is_format_char(c: char) -> bool {
    const CF: [(u32, u32); 21] = [
        (0xAD, 0xAD),
        (0x600, 0x605),
        (0x61C, 0x61C),
        (0x6DD, 0x6DD),
        (0x70F, 0x70F),
        (0x890, 0x891),
        (0x8E2, 0x8E2),
        (0x180E, 0x180E),
        (0x200B, 0x200F),
        (0x202A, 0x202E),
        (0x2060, 0x2064),
        (0x2066, 0x206F),
        (0xFEFF, 0xFEFF),
        (0xFFF9, 0xFFFB),
        (0x110BD, 0x110BD),
        (0x110CD, 0x110CD),
        (0x13430, 0x1343F),
        (0x1BCA0, 0x1BCA3),
        (0x1D173, 0x1D17A),
        (0xE0001, 0xE0001),
        (0xE0020, 0xE007F),
    ];
    CF.iter().any(|&(lo, hi)| (lo..=hi).contains(&u32::from(c)))
}

/// One enrolled recipient: its key, role, label and the UTC second it was enrolled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientEntry {
    key: RecipientKey,
    role: RecipientRole,
    label: RecipientLabel,
    enrolled_at: UtcSecond,
}

impl RecipientEntry {
    /// An entry for `key`, enrolled at `enrolled_at`. The caller reads the clock; the store never does.
    pub fn new(key: RecipientKey, role: RecipientRole, label: RecipientLabel, enrolled_at: UtcSecond) -> Self {
        Self {
            key,
            role,
            label,
            enrolled_at,
        }
    }

    /// The recipient key; entries are identified by it.
    pub fn key(&self) -> &RecipientKey {
        &self.key
    }

    /// The recipient's role.
    pub fn role(&self) -> RecipientRole {
        self.role
    }

    /// The recipient's label.
    pub fn label(&self) -> &RecipientLabel {
        &self.label
    }

    /// When the recipient was enrolled.
    pub fn enrolled_at(&self) -> UtcSecond {
        self.enrolled_at
    }
}

/// The recipients of one identity envelope: from 2 to [`MAX_RECIPIENTS`] entries, no key twice, in the canonical order
/// of [`RecipientKey`], so an inventory has one encoding whatever order its entries were added in. It names the
/// `identity.age` it describes by that file's [`envelope_digest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientInventory {
    vault_id: VaultId,
    envelope_digest: [u8; 32],
    entries: BTreeMap<RecipientKey, RecipientEntry>,
}

impl RecipientInventory {
    /// An inventory of `entries` describing the envelope with digest `envelope_digest`.
    pub fn new(
        vault_id: VaultId,
        envelope_digest: [u8; 32],
        entries: impl IntoIterator<Item = RecipientEntry>,
    ) -> Result<Self, RecipientInventoryError> {
        let entries = entries
            .into_iter()
            .try_fold(BTreeMap::new(), |mut map, entry| match map.insert(entry.key.clone(), entry) {
                None => Ok(map),
                Some(_) => Err(RecipientInventoryError::DuplicateKey),
            })?;
        match entries.len() {
            count @ 0..2 => Err(RecipientInventoryError::TooFew { count }),
            count if count > MAX_RECIPIENTS => Err(RecipientInventoryError::TooMany { limit: MAX_RECIPIENTS }),
            _ => Ok(Self {
                vault_id,
                envelope_digest,
                entries,
            }),
        }
    }

    /// The vault this inventory belongs to.
    pub fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    /// The digest of the `identity.age` this inventory describes.
    pub fn envelope_digest(&self) -> &[u8; 32] {
        &self.envelope_digest
    }

    /// The entries in canonical key order.
    pub fn entries(&self) -> impl ExactSizeIterator<Item = &RecipientEntry> {
        self.entries.values()
    }

    /// The entry for `key`, if it is enrolled.
    pub fn get(&self, key: &RecipientKey) -> Option<&RecipientEntry> {
        self.entries.get(key)
    }

    /// The set of keys the identity envelope is wrapped for.
    pub fn recipient_set(&self) -> RecipientSet {
        RecipientSet::from_validated(self.entries.keys().cloned().collect())
    }

    /// This inventory describing the envelope with digest `envelope_digest` instead.
    pub(crate) fn describing(self, envelope_digest: [u8; 32]) -> Self {
        Self { envelope_digest, ..self }
    }
}

/// The digest of an `identity.age` file's bytes exactly as they sit on disk: BLAKE2b-256, unkeyed.
pub fn envelope_digest(envelope: &[u8]) -> [u8; 32] {
    Blake2b256::digest(envelope).into()
}

/// An inventory cannot be built or opened. No variant carries file bytes, key material or MAC bytes.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RecipientInventoryError {
    /// The file is larger than [`MAX_RECIPIENT_INVENTORY_LEN`]; nothing else was read.
    #[error("recipient inventory exceeds the {limit}-byte limit")]
    TooLarge {
        /// The limit that was exceeded.
        limit: usize,
    },
    /// The file or payload ends inside a fixed-width field.
    #[error("recipient inventory is truncated")]
    Truncated,
    /// The file or payload does not start with the inventory magic.
    #[error("not a recipient inventory")]
    BadMagic,
    /// The file or payload has a version this build cannot read.
    #[error("unknown recipient inventory version {0}")]
    UnknownVersion(u8),
    /// The MAC does not match: the inventory was altered, or written by someone without this vault's identity.
    #[error("recipient inventory failed its integrity check; it is damaged or was not written by this vault")]
    Damaged,
    /// The MAC matched but the ciphertext did not open.
    #[error("recipient inventory ciphertext cannot be opened: {0}")]
    Sealed(#[from] OpenError),
    /// The payload names a different vault from the authenticated header.
    #[error("recipient inventory payload belongs to a different vault from its header")]
    VaultIdMismatch,
    /// A length prefix reaches past the end of the payload.
    #[error("recipient inventory field length runs past the end of the payload")]
    LengthPastEnd,
    /// Bytes follow the last entry.
    #[error("recipient inventory payload has trailing bytes")]
    TrailingBytes,
    /// The vault ID is not a random version 4 UUID.
    #[error(transparent)]
    InvalidVaultId(#[from] VaultIdError),
    /// Fewer than two entries.
    #[error("recipient inventory has {count} entries, fewer than 2")]
    TooFew {
        /// The number of entries.
        count: usize,
    },
    /// More than [`MAX_RECIPIENTS`] entries.
    #[error("recipient inventory has more than {limit} entries")]
    TooMany {
        /// The limit that was exceeded.
        limit: usize,
    },
    /// A recipient key is not the canonical text of an X25519 recipient key.
    #[error("recipient inventory holds a key that is not a canonical X25519 recipient key")]
    InvalidKey,
    /// Two entries have the same recipient key.
    #[error("recipient inventory lists a recipient key twice")]
    DuplicateKey,
    /// The entries are not in ascending key order, so the payload is not the one encoding of its inventory.
    #[error("recipient inventory entries are not in ascending key order")]
    UnsortedEntries,
    /// A role code this release does not know, whether reserved or unassigned.
    #[error("recipient inventory holds role code {0}, which this release does not know")]
    UnknownRole(u8),
    /// A label is not UTF-8.
    #[error("recipient inventory label is not UTF-8")]
    LabelNotUtf8,
    /// A label breaks the label rule.
    #[error(transparent)]
    InvalidLabel(#[from] RecipientLabelError),
    /// An enrolment time is outside the UTC second range.
    #[error("recipient inventory enrolment time is outside the UTC second range")]
    BadTime,
}

/// The inventory file's bytes: header, the payload sealed to the vault public key, then the MAC.
pub fn seal_recipient_inventory(identity: &VaultIdentity, inventory: &RecipientInventory) -> Result<Vec<u8>, SealError> {
    KIND.seal(identity, inventory.vault_id, &encoding::encode(inventory))
}

/// `inventory` sealed with its first entry's role code replaced by `code`, so a test can plant a role this build does
/// not know behind a valid MAC.
#[cfg(test)]
pub(crate) fn seal_with_role_code(identity: &VaultIdentity, inventory: &RecipientInventory, code: u8) -> Vec<u8> {
    KIND.seal(identity, inventory.vault_id, &encoding::encode_with_role_code(inventory, code))
        .unwrap()
}

/// The inventory a file holds. Size, header and MAC are checked before anything is decrypted.
pub fn open_recipient_inventory(identity: &VaultIdentity, file: &[u8]) -> Result<RecipientInventory, RecipientInventoryError> {
    let (vault_id, payload) = KIND.open(identity, file)?;
    let inventory = encoding::decode(&payload)?;
    match inventory.vault_id == vault_id {
        true => Ok(inventory),
        false => Err(RecipientInventoryError::VaultIdMismatch),
    }
}

/// Why the inventory could not be written.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RecipientInventoryWriteError {
    /// Sealing to the vault public key failed.
    #[error("cannot seal the recipient inventory: {0}")]
    Seal(#[from] SealError),
    /// The durable replace failed.
    #[error(transparent)]
    Write(#[from] WriteError),
}

/// Why the inventory could not be read.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RecipientInventoryReadError {
    /// The file could not be read; `ReadError::Io` with `NotFound` means there is no inventory.
    #[error(transparent)]
    Read(#[from] ReadError),
    /// The file was read but is not this vault's inventory.
    #[error(transparent)]
    Open(#[from] RecipientInventoryError),
}

/// Seals `inventory` and durably replaces `recipients.age` with it.
pub fn write_recipient_inventory(
    lock: &StateDirLock,
    fs: &impl StoreFs,
    identity: &VaultIdentity,
    inventory: &RecipientInventory,
) -> Result<(), RecipientInventoryWriteError> {
    let bytes = seal_recipient_inventory(identity, inventory)?;
    Ok(durable_replace(lock, fs, &StateFileName::recipient_inventory(), &bytes)?)
}

/// Reads and opens `recipients.age`, refusing a file longer than [`MAX_RECIPIENT_INVENTORY_LEN`].
pub fn read_recipient_inventory(
    lock: &StateDirLock,
    fs: &impl StoreFs,
    identity: &VaultIdentity,
) -> Result<RecipientInventory, RecipientInventoryReadError> {
    let file = read_state_file(lock, fs, &StateFileName::recipient_inventory(), MAX_RECIPIENT_INVENTORY_LEN as u64)?;
    Ok(open_recipient_inventory(identity, &file)?)
}
