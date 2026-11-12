//! `approver remove`'s argument and success result
//! ([approval signers: Admin protocol](../../../../../design/approval-signers.md#admin-protocol)). The ID travels as 16 raw bytes and stays
//! raw in the request: the service, not the codec, checks that it is a version 4 UUID (`approver-invalid`), so only a
//! length other than 16 is a malformed frame.

use super::fields::{self, Field, exact};
use super::{AdminRequest, AdminResponse, FrameError};

const TAG_COMMAND: u16 = super::body::TAG_COMMAND;
const TAG_APPROVER: u16 = 2;
const TAG_APPROVERS: u16 = 2;

pub(super) fn encode_request(command: u16, approver: &[u8; 16]) -> Vec<u8> {
    let mut out = Vec::new();
    fields::put(&mut out, TAG_COMMAND, &command.to_be_bytes());
    fields::put(&mut out, TAG_APPROVER, approver);
    out
}

pub(super) fn decode_request(fields: &[Field<'_>]) -> Result<AdminRequest, FrameError> {
    let [_, approver] = exact(fields, [TAG_COMMAND, TAG_APPROVER])?;
    let approver = <[u8; 16]>::try_from(approver).map_err(|_| FrameError::InvalidValue(TAG_APPROVER))?;
    Ok(AdminRequest::ApproverRemove { approver })
}

/// Encodes the success body: the command it answers, then the approver count.
pub(super) fn encode_result(command: u16, approvers: u8) -> Vec<u8> {
    let mut out = Vec::new();
    fields::put(&mut out, TAG_COMMAND, &command.to_be_bytes());
    fields::put(&mut out, TAG_APPROVERS, &[approvers]);
    out
}

pub(super) fn decode_result(fields: &[Field<'_>]) -> Result<AdminResponse, FrameError> {
    let [_, approvers] = exact(fields, [TAG_COMMAND, TAG_APPROVERS])?;
    match approvers {
        &[approvers] => Ok(AdminResponse::ApproverRemove { approvers }),
        _ => Err(FrameError::InvalidValue(TAG_APPROVERS)),
    }
}
