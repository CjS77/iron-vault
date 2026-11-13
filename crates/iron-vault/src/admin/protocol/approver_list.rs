// SPDX-License-Identifier: MPL-2.0
//! The `approver list` result: one entry per pinned approver, in approver order
//! ([approval signers: Admin protocol](../../../../../design/approval-signers.md#admin-protocol)). Approver IDs, kinds, labels and times
//! only: no type here can hold a key or a secret.

use iron_vault_store::{ApproverId, ApproverLabel, SignerKind, UtcSecond};

use super::fields::{self, Field, exact};
use super::status::{take_in, take_name_in};
use super::{AdminResponse, FrameError};

const TAG_COMMAND: u16 = super::body::TAG_COMMAND;
const TAG_ENTRIES: u16 = 2;

const INVALID_ENTRIES: FrameError = FrameError::InvalidValue(TAG_ENTRIES);

/// One pinned approver as `approver list` shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApproverEntry {
    /// The approver's ID.
    pub id: ApproverId,
    /// What signs for the approver.
    pub kind: SignerKind,
    /// `true` if and only if this approver signed the active approval.
    pub active: bool,
    /// The owner's label.
    pub label: ApproverLabel,
    /// When the approver was enrolled.
    pub enrolled_at: UtcSecond,
}

/// Encodes the success body: the command it answers, then the entries as one byte value. Each entry is laid out as:
///
/// ```text
/// bytes  field
/// 16     approver ID
/// 1      signer kind code: 1 software, 2 tpm
/// 1      active flag: 1 if and only if this approver signed the active approval
/// 1      label length
/// n      label, UTF-8
/// 8      enrolment time, Unix seconds, big-endian u64
/// ```
pub(super) fn encode_result(command: u16, entries: &[ApproverEntry]) -> Result<Vec<u8>, FrameError> {
    let entries = entries.iter().try_fold(Vec::new(), |mut out, entry| {
        out.extend_from_slice(entry.id.as_bytes());
        out.push(entry.kind.code());
        out.push(u8::from(entry.active));
        let label = entry.label.as_str();
        out.push(u8::try_from(label.len()).map_err(|_| INVALID_ENTRIES)?);
        out.extend_from_slice(label.as_bytes());
        out.extend_from_slice(&entry.enrolled_at.unix_seconds().to_be_bytes());
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
    Ok(AdminResponse::ApproverList { entries })
}

fn take_entry(rest: &mut &[u8]) -> Result<ApproverEntry, FrameError> {
    let id = <[u8; 16]>::try_from(take_in(TAG_ENTRIES, rest, 16)?).map_err(|_| INVALID_ENTRIES)?;
    let id = ApproverId::from_bytes(id).map_err(|_| INVALID_ENTRIES)?;
    let kind = SignerKind::from_code(take_in(TAG_ENTRIES, rest, 1)?[0]).map_err(|_| INVALID_ENTRIES)?;
    let active = match take_in(TAG_ENTRIES, rest, 1)?[0] {
        0 => false,
        1 => true,
        _ => return Err(INVALID_ENTRIES),
    };
    let label = ApproverLabel::new(&take_name_in::<String>(TAG_ENTRIES, rest)?).map_err(|_| INVALID_ENTRIES)?;
    let seconds = <[u8; 8]>::try_from(take_in(TAG_ENTRIES, rest, 8)?).map_err(|_| INVALID_ENTRIES)?;
    let enrolled_at = UtcSecond::from_unix_seconds(u64::from_be_bytes(seconds)).map_err(|_| INVALID_ENTRIES)?;
    Ok(ApproverEntry {
        id,
        kind,
        active,
        label,
        enrolled_at,
    })
}

#[cfg(test)]
mod tests;
