//! `reset`'s success result ([reset: Result](../../../../../design/reset.md#result)). The request has no arguments.

use iron_vault_store::VaultId;

use super::fields::{self, Field, exact, read_flag, read_text, read_u64};
use super::{AdminResponse, FrameError};

const TAG_COMMAND: u16 = super::body::TAG_COMMAND;
const TAG_VAULT_ID: u16 = 2;
const TAG_REMOVED: u16 = 3;
const TAG_FOREIGN: u16 = 4;
const TAG_CLEARED: u16 = 5;
const TAG_FINISH_UNCERTAIN: u16 = 6;

/// Encodes the success body: the command it answers, the confirmed vault ID (empty when the confirmation was the state directory's
/// path), the number of files removed, the foreign files left (escaped names, one per line), a flag set if and only if
/// the lock drain cleared the vault identity, and a flag set if and only if the removal of `reset.unfinished` is
/// uncertain.
pub(super) fn encode_result(
    command: u16,
    vault_id: Option<VaultId>,
    removed: u64,
    foreign: &[String],
    cleared: bool,
    finish_uncertain: bool,
) -> Vec<u8> {
    let mut out = Vec::new();
    fields::put(&mut out, TAG_COMMAND, &command.to_be_bytes());
    fields::put(&mut out, TAG_VAULT_ID, vault_id.as_ref().map_or(&[][..], |id| id.as_bytes()));
    fields::put(&mut out, TAG_REMOVED, &removed.to_be_bytes());
    fields::put(&mut out, TAG_FOREIGN, foreign.join("\n").as_bytes());
    fields::put(&mut out, TAG_CLEARED, &[u8::from(cleared)]);
    fields::put(&mut out, TAG_FINISH_UNCERTAIN, &[u8::from(finish_uncertain)]);
    out
}

pub(super) fn decode_result(fields: &[Field<'_>]) -> Result<AdminResponse, FrameError> {
    let [_, vault_id, removed, foreign, cleared, finish_uncertain] = exact(
        fields,
        [
            TAG_COMMAND,
            TAG_VAULT_ID,
            TAG_REMOVED,
            TAG_FOREIGN,
            TAG_CLEARED,
            TAG_FINISH_UNCERTAIN,
        ],
    )?;
    let vault_id = match vault_id {
        [] => None,
        bytes => <[u8; 16]>::try_from(bytes)
            .ok()
            .and_then(|bytes| VaultId::from_bytes(bytes).ok())
            .map(Some)
            .ok_or(FrameError::InvalidValue(TAG_VAULT_ID))?,
    };
    let foreign = read_text(TAG_FOREIGN, foreign)?;
    Ok(AdminResponse::Reset {
        vault_id,
        removed: read_u64(TAG_REMOVED, removed)?,
        foreign: foreign.lines().map(str::to_owned).collect(),
        cleared: read_flag(TAG_CLEARED, cleared)?,
        finish_uncertain: read_flag(TAG_FINISH_UNCERTAIN, finish_uncertain)?,
    })
}
