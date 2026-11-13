// SPDX-License-Identifier: MPL-2.0
//! `approver add`'s arguments and success result
//! ([approval signers: Admin protocol](../../../../../design/approval-signers.md#admin-protocol)). Only the
//! bounds are checked here: the label stays text, and the service validates it, so a bad one is `approver-invalid`. A
//! kind code outside 1 to 3 is a malformed frame; a kind this install does not offer is the service's
//! `approver-kind-unavailable`.

use iron_vault_store::ApproverId;

use super::fields::{self, Field, exact, read_text};
use super::{AdminRequest, AdminResponse, FrameError};

const TAG_COMMAND: u16 = super::body::TAG_COMMAND;
const TAG_KIND: u16 = 2;
const TAG_LABEL: u16 = 3;
const TAG_APPROVER: u16 = 2;
const TAG_APPROVERS: u16 = 3;

/// A signer kind as `approver add` names it on the wire. Every kind the protocol defines is here, including those this
/// install does not offer yet, so the service, not the codec, decides which kinds it enrolls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestedSignerKind {
    /// `software`: an Ed25519 key sealed to its own approval passphrase.
    Software = 1,
    /// `tpm`: a TPM approval key with a PIN ([TPM approval signer](../../../../../design/tpm-approval-signer.md)).
    Tpm = 2,
    /// `hardware`: a hardware key with PIN and touch, planned for a later phase.
    Hardware = 3,
}

impl RequestedSignerKind {
    /// Returns the kind's name, as `--kind` takes it and the summary shows it: `software`, `tpm` or `hardware`.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Software => "software",
            Self::Tpm => "tpm",
            Self::Hardware => "hardware",
        }
    }

    fn from_code(code: &[u8]) -> Result<Self, FrameError> {
        match code {
            [1] => Ok(Self::Software),
            [2] => Ok(Self::Tpm),
            [3] => Ok(Self::Hardware),
            _ => Err(FrameError::InvalidValue(TAG_KIND)),
        }
    }
}

pub(super) fn encode_request(command: u16, kind: RequestedSignerKind, label: &str) -> Vec<u8> {
    let mut out = Vec::new();
    fields::put(&mut out, TAG_COMMAND, &command.to_be_bytes());
    fields::put(&mut out, TAG_KIND, &[kind as u8]);
    fields::put(&mut out, TAG_LABEL, label.as_bytes());
    out
}

pub(super) fn decode_request(fields: &[Field<'_>]) -> Result<AdminRequest, FrameError> {
    let [_, kind, label] = exact(fields, [TAG_COMMAND, TAG_KIND, TAG_LABEL])?;
    Ok(AdminRequest::ApproverAdd {
        kind: RequestedSignerKind::from_code(kind)?,
        label: read_text(TAG_LABEL, label)?,
    })
}

/// Encodes the success body: the command it answers, the new approver ID's 16 bytes, then the approver count.
pub(super) fn encode_result(command: u16, approver: ApproverId, approvers: u8) -> Vec<u8> {
    let mut out = Vec::new();
    fields::put(&mut out, TAG_COMMAND, &command.to_be_bytes());
    fields::put(&mut out, TAG_APPROVER, approver.as_bytes());
    fields::put(&mut out, TAG_APPROVERS, &[approvers]);
    out
}

pub(super) fn decode_result(fields: &[Field<'_>]) -> Result<AdminResponse, FrameError> {
    let [_, approver, approvers] = exact(fields, [TAG_COMMAND, TAG_APPROVER, TAG_APPROVERS])?;
    let approver = <[u8; 16]>::try_from(approver)
        .ok()
        .and_then(|bytes| ApproverId::from_bytes(bytes).ok())
        .ok_or(FrameError::InvalidValue(TAG_APPROVER))?;
    let [approvers] = *approvers else {
        return Err(FrameError::InvalidValue(TAG_APPROVERS));
    };
    Ok(AdminResponse::ApproverAdd { approver, approvers })
}
