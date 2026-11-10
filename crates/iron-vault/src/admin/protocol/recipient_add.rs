//! `recipient add`'s arguments and success result (`design/recipients.md`, "Admin protocol"). Only the bounds are checked
//! here: the key and the label stay text, and the service parses and validates them, so a bad one is `recipient-invalid`.

use iron_vault_store::RecipientKey;

use super::fields::{self, Field, exact, read_text};
use super::{AdminRequest, AdminResponse, FrameError};

const TAG_COMMAND: u16 = super::body::TAG_COMMAND;
const TAG_SOURCE: u16 = 2;
const TAG_RECIPIENT: u16 = 3;
const TAG_LABEL: u16 = 4;
const TAG_RESULT_RECIPIENT: u16 = 2;
const TAG_RECIPIENTS: u16 = 3;

/// The source of a key the owner gives.
const SOURCE_OWNER_KEY: u8 = 1;
/// The source of a recovery key the service generates; it carries no key.
const SOURCE_NEW_RECOVERY: u8 = 2;
/// The source of a host unlock identity's key the owner gives, enrolled with the `host-unlock` role.
const SOURCE_HOST_UNLOCK_KEY: u8 = 3;

/// The request for a key the owner gives: `host_unlock` picks source `3` over source `1`.
pub(super) fn encode_request(command: u16, recipient: &str, label: &str, host_unlock: bool) -> Vec<u8> {
    let source = if host_unlock { SOURCE_HOST_UNLOCK_KEY } else { SOURCE_OWNER_KEY };
    let mut out = Vec::new();
    fields::put(&mut out, TAG_COMMAND, &command.to_be_bytes());
    fields::put(&mut out, TAG_SOURCE, &[source]);
    fields::put(&mut out, TAG_RECIPIENT, recipient.as_bytes());
    fields::put(&mut out, TAG_LABEL, label.as_bytes());
    out
}

pub(super) fn encode_recovery_request(command: u16, label: &str) -> Vec<u8> {
    let mut out = Vec::new();
    fields::put(&mut out, TAG_COMMAND, &command.to_be_bytes());
    fields::put(&mut out, TAG_SOURCE, &[SOURCE_NEW_RECOVERY]);
    fields::put(&mut out, TAG_RECIPIENT, b"");
    fields::put(&mut out, TAG_LABEL, label.as_bytes());
    out
}

/// An owner key needs source `1` or `3` and a key, and a new recovery key source `2` and none: a mismatch is a malformed
/// frame, not a rule the service judges.
pub(super) fn decode_request(fields: &[Field<'_>]) -> Result<AdminRequest, FrameError> {
    let [_, source, recipient, label] = exact(fields, [TAG_COMMAND, TAG_SOURCE, TAG_RECIPIENT, TAG_LABEL])?;
    let (recipient, label) = (read_text(TAG_RECIPIENT, recipient)?, read_text(TAG_LABEL, label)?);
    match (source, recipient.is_empty()) {
        ([SOURCE_OWNER_KEY], false) => Ok(AdminRequest::RecipientAdd { recipient, label }),
        ([SOURCE_HOST_UNLOCK_KEY], false) => Ok(AdminRequest::RecipientAddHostUnlock { recipient, label }),
        ([SOURCE_OWNER_KEY | SOURCE_HOST_UNLOCK_KEY], true) => Err(FrameError::InvalidValue(TAG_RECIPIENT)),
        ([SOURCE_NEW_RECOVERY], true) => Ok(AdminRequest::RecipientAddRecovery { label }),
        ([SOURCE_NEW_RECOVERY], false) => Err(FrameError::InvalidValue(TAG_RECIPIENT)),
        _ => Err(FrameError::InvalidValue(TAG_SOURCE)),
    }
}

/// The success body: the command it answers, the enrolled key as text, then the recipient count.
pub(super) fn encode_result(command: u16, recipient: &RecipientKey, recipients: u8) -> Vec<u8> {
    let mut out = Vec::new();
    fields::put(&mut out, TAG_COMMAND, &command.to_be_bytes());
    fields::put(&mut out, TAG_RESULT_RECIPIENT, recipient.to_string().as_bytes());
    fields::put(&mut out, TAG_RECIPIENTS, &[recipients]);
    out
}

pub(super) fn decode_result(fields: &[Field<'_>]) -> Result<AdminResponse, FrameError> {
    let [_, recipient, recipients] = exact(fields, [TAG_COMMAND, TAG_RESULT_RECIPIENT, TAG_RECIPIENTS])?;
    let recipient = read_text(TAG_RESULT_RECIPIENT, recipient)?
        .parse()
        .map_err(|_| FrameError::InvalidValue(TAG_RESULT_RECIPIENT))?;
    let [recipients] = *recipients else {
        return Err(FrameError::InvalidValue(TAG_RECIPIENTS));
    };
    Ok(AdminResponse::RecipientAdd { recipient, recipients })
}

#[cfg(test)]
mod tests;
