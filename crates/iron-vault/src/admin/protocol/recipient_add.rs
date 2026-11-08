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

/// The source of a key the owner gives. Source `2`, a recovery key the service generates, is not served yet.
const SOURCE_OWNER_KEY: u8 = 1;

pub(super) fn encode_request(command: u16, recipient: &str, label: &str) -> Vec<u8> {
    let mut out = Vec::new();
    fields::put(&mut out, TAG_COMMAND, &command.to_be_bytes());
    fields::put(&mut out, TAG_SOURCE, &[SOURCE_OWNER_KEY]);
    fields::put(&mut out, TAG_RECIPIENT, recipient.as_bytes());
    fields::put(&mut out, TAG_LABEL, label.as_bytes());
    out
}

/// An owner key needs source `1` and a key: an empty one is a malformed frame, not a rule the service judges.
pub(super) fn decode_request(fields: &[Field<'_>]) -> Result<AdminRequest, FrameError> {
    let [_, source, recipient, label] = exact(fields, [TAG_COMMAND, TAG_SOURCE, TAG_RECIPIENT, TAG_LABEL])?;
    if source != [SOURCE_OWNER_KEY] {
        return Err(FrameError::InvalidValue(TAG_SOURCE));
    }
    match read_text(TAG_RECIPIENT, recipient)? {
        key if key.is_empty() => Err(FrameError::InvalidValue(TAG_RECIPIENT)),
        recipient => Ok(AdminRequest::RecipientAdd {
            recipient,
            label: read_text(TAG_LABEL, label)?,
        }),
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
