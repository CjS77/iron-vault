//! The `forget-machine` result ([admin protocol: forget-machine](../../../../../design/admin-protocol.md#forget-machine)): the
//! independence rule's failure, if any, and the recovery check state in `status`'s encoding. The request is
//! `recipient remove`'s: one key, as text.

use super::fields::{self, Field, exact, read_text};
use super::recovery_status::{self, RecoveryStatus};
use super::{AdminResponse, FrameError};

const TAG_COMMAND: u16 = super::body::TAG_COMMAND;
const TAG_INDEPENDENCE: u16 = 2;

/// Encodes the success body: the command it answers, the failed part's sentence (empty when the rule holds), then tags 13 to 17.
pub(super) fn encode_result(command: u16, independence: Option<&str>, recovery: &RecoveryStatus) -> Vec<u8> {
    let mut out = Vec::new();
    fields::put(&mut out, TAG_COMMAND, &command.to_be_bytes());
    fields::put(&mut out, TAG_INDEPENDENCE, independence.unwrap_or_default().as_bytes());
    recovery_status::encode(&mut out, recovery);
    out
}

pub(super) fn decode_result(fields: &[Field<'_>]) -> Result<AdminResponse, FrameError> {
    use recovery_status::{TAG_DAYS, TAG_DETAIL, TAG_DUE, TAG_RECORD, TAG_TIME};
    let [_, independence, record, time, days, due, detail] = exact(
        fields,
        [TAG_COMMAND, TAG_INDEPENDENCE, TAG_RECORD, TAG_TIME, TAG_DAYS, TAG_DUE, TAG_DETAIL],
    )?;
    let independence = read_text(TAG_INDEPENDENCE, independence)?;
    Ok(AdminResponse::ForgetMachine {
        independence: (!independence.is_empty()).then_some(independence),
        recovery: recovery_status::decode(recovery_status::Raw {
            record,
            time,
            days,
            due,
            detail,
        })?,
    })
}
