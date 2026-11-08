//! The recipient inventory payload v1 encoding: the plaintext an inventory file seals (`design/storage-formats.md`).

use super::{MAX_RECIPIENTS, RecipientEntry, RecipientInventory, RecipientInventoryError, RecipientLabel, RecipientRole};
use crate::vault_id::VaultId;
use crate::wire::{Reader, WireError};
use crate::{RecipientKey, UtcSecond};

/// The first bytes of every inventory payload, distinct from the file magic so neither is read as the other.
const MAGIC: [u8; 4] = *b"IVRP";
/// The payload version this code writes and the only one it reads.
const VERSION: u8 = 1;
/// The length of a canonical `age1…` X25519 recipient key.
const KEY_TEXT_LEN: usize = 62;

/// The inventory's v1 payload. Entries are written in ascending key order, so an inventory has one encoding.
pub(super) fn encode(inventory: &RecipientInventory) -> Vec<u8> {
    let mut out = [&MAGIC[..], &[VERSION], inventory.vault_id.as_bytes(), &inventory.envelope_digest].concat();
    put_len(&mut out, inventory.entries.len());
    inventory.entries.values().for_each(|entry| {
        put_field(&mut out, entry.key.to_string().as_bytes());
        out.push(entry.role.code());
        put_field(&mut out, entry.label.as_str().as_bytes());
        out.extend_from_slice(&entry.enrolled_at.unix_seconds().to_be_bytes());
    });
    out
}

/// The inventory a v1 payload holds, accepted only if it is that inventory's one encoding.
pub(super) fn decode(payload: &[u8]) -> Result<RecipientInventory, RecipientInventoryError> {
    let mut reader = Reader::new(payload);
    if reader.take(MAGIC.len())? != MAGIC {
        return Err(RecipientInventoryError::BadMagic);
    }
    match reader.u8()? {
        VERSION => decode_v1(&mut reader),
        version => Err(RecipientInventoryError::UnknownVersion(version)),
    }
}

/// The payload of `inventory` with its first entry's role code replaced by `code`, as a build that knows more roles
/// could write it.
#[cfg(test)]
pub(super) fn encode_with_role_code(inventory: &RecipientInventory, code: u8) -> Vec<u8> {
    let first_role = MAGIC.len() + 1 + 16 + 32 + 8 + 8 + KEY_TEXT_LEN;
    let mut payload = encode(inventory);
    payload[first_role] = code;
    payload
}

fn decode_v1(reader: &mut Reader<'_>) -> Result<RecipientInventory, RecipientInventoryError> {
    let vault_id = VaultId::from_bytes(reader.array()?)?;
    let envelope_digest = reader.array()?;
    let entries = read_entries(reader)?;
    reader.finish()?;
    RecipientInventory::new(vault_id, envelope_digest, entries)
}

/// Writes a length as a `u64`. `usize` is at most 64 bits on every Rust target, so the widening cast is lossless.
fn put_len(out: &mut Vec<u8>, len: usize) {
    out.extend_from_slice(&(len as u64).to_be_bytes());
}

fn put_field(out: &mut Vec<u8>, bytes: &[u8]) {
    put_len(out, bytes.len());
    out.extend_from_slice(bytes);
}

/// Reads the entries, requiring keys strictly ascending. The count is checked against the limits before any entry is
/// read, so a huge count never drives a long loop.
fn read_entries(reader: &mut Reader<'_>) -> Result<Vec<RecipientEntry>, RecipientInventoryError> {
    let count = usize::try_from(reader.u64()?)
        .ok()
        .filter(|count| *count <= MAX_RECIPIENTS)
        .ok_or(RecipientInventoryError::TooMany { limit: MAX_RECIPIENTS })?;
    (0..count).try_fold(Vec::<RecipientEntry>::with_capacity(count), |mut entries, _| {
        let entry = read_entry(reader)?;
        match entries.last().map(|last| last.key.cmp(&entry.key)) {
            Some(std::cmp::Ordering::Equal) => return Err(RecipientInventoryError::DuplicateKey),
            Some(std::cmp::Ordering::Greater) => return Err(RecipientInventoryError::UnsortedEntries),
            _ => entries.push(entry),
        }
        Ok(entries)
    })
}

fn read_entry(reader: &mut Reader<'_>) -> Result<RecipientEntry, RecipientInventoryError> {
    let key = read_key(reader.field()?)?;
    let code = reader.u8()?;
    let role = RecipientRole::from_code(code).ok_or(RecipientInventoryError::UnknownRole(code))?;
    let label = std::str::from_utf8(reader.field()?).map_err(|_| RecipientInventoryError::LabelNotUtf8)?;
    let enrolled_at = UtcSecond::from_unix_seconds(reader.u64()?).map_err(|_| RecipientInventoryError::BadTime)?;
    Ok(RecipientEntry::new(key, role, RecipientLabel::new(label)?, enrolled_at))
}

/// The key whose canonical text is `text`. Bech32 also accepts an all-uppercase spelling; refusing it keeps one
/// encoding per inventory.
fn read_key(text: &[u8]) -> Result<RecipientKey, RecipientInventoryError> {
    let key: RecipientKey = std::str::from_utf8(text)
        .ok()
        .filter(|text| text.len() == KEY_TEXT_LEN)
        .and_then(|text| text.parse().ok())
        .ok_or(RecipientInventoryError::InvalidKey)?;
    match key.to_string().as_bytes() == text {
        true => Ok(key),
        false => Err(RecipientInventoryError::InvalidKey),
    }
}

impl From<WireError> for RecipientInventoryError {
    fn from(error: WireError) -> Self {
        match error {
            WireError::Truncated => Self::Truncated,
            WireError::LengthPastEnd => Self::LengthPastEnd,
            WireError::TrailingBytes => Self::TrailingBytes,
        }
    }
}
