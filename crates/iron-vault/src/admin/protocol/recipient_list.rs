//! The `recipient list` result: one entry per enrolled recipient, in inventory order
//! ([recipients: Admin protocol](../../../../../design/recipients.md#admin-protocol)). Public keys, roles, labels and times only: no type
//! here can hold a secret.

use iron_vault_store::{RecipientEntry, RecipientLabel, RecipientRole, UtcSecond};

use super::fields::{self, Field, exact};
use super::status::{take_in, take_name_in};
use super::{AdminResponse, FrameError};

const TAG_COMMAND: u16 = super::body::TAG_COMMAND;
const TAG_ENTRIES: u16 = 2;

const INVALID_ENTRIES: FrameError = FrameError::InvalidValue(TAG_ENTRIES);

/// Encodes the success body: the command it answers, then the entries as one byte value. An entry whose key or label is longer
/// than its one-byte length counts is refused, never truncated; the store's own bounds make that unreachable.
pub(super) fn encode_result(command: u16, entries: &[RecipientEntry]) -> Result<Vec<u8>, FrameError> {
    let entries = entries.iter().try_fold(Vec::new(), |mut out, entry| {
        put_text(&mut out, &entry.key().to_string())?;
        out.push(entry.role().code());
        put_text(&mut out, entry.label().as_str())?;
        out.extend_from_slice(&entry.enrolled_at().unix_seconds().to_be_bytes());
        Ok::<_, FrameError>(out)
    })?;
    let mut out = Vec::new();
    fields::put(&mut out, TAG_COMMAND, &command.to_be_bytes());
    fields::put(&mut out, TAG_ENTRIES, &entries);
    Ok(out)
}

pub(super) fn decode_result(fields: &[Field<'_>]) -> Result<AdminResponse, FrameError> {
    let [_, mut rest] = exact(fields, [TAG_COMMAND, TAG_ENTRIES])?;
    let entries = std::iter::from_fn(|| (!rest.is_empty()).then(|| take_entry(&mut rest))).collect::<Result<_, _>>()?;
    Ok(AdminResponse::RecipientList { entries })
}

fn put_text(out: &mut Vec<u8>, text: &str) -> Result<(), FrameError> {
    out.push(u8::try_from(text.len()).map_err(|_| INVALID_ENTRIES)?);
    out.extend_from_slice(text.as_bytes());
    Ok(())
}

fn take_entry(rest: &mut &[u8]) -> Result<RecipientEntry, FrameError> {
    let key = take_name_in(TAG_ENTRIES, rest)?;
    let role = RecipientRole::from_code(take_in(TAG_ENTRIES, rest, 1)?[0]).ok_or(INVALID_ENTRIES)?;
    let label = RecipientLabel::new(&take_name_in::<String>(TAG_ENTRIES, rest)?).map_err(|_| INVALID_ENTRIES)?;
    let seconds = <[u8; 8]>::try_from(take_in(TAG_ENTRIES, rest, 8)?).map_err(|_| INVALID_ENTRIES)?;
    let enrolled_at = UtcSecond::from_unix_seconds(u64::from_be_bytes(seconds)).map_err(|_| INVALID_ENTRIES)?;
    Ok(RecipientEntry::new(key, role, label, enrolled_at))
}

#[cfg(test)]
mod tests;
