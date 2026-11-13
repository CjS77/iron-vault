// SPDX-License-Identifier: MPL-2.0
//! The answers `approver add` and `approver remove` share: the error response for each refusal an approver command can
//! end with.

use iron_vault_store::MayHaveCommitted;

use super::protocol::{AdminResponse, ErrorCode};
use super::unlock::state_name;
use crate::service_context::ApproverRefusal;
use crate::service_state::ServiceState;

/// Returns the error answer for an approver command (`command`) that ended without changing the approvers.
pub(super) fn refused(command: &str, refusal: ApproverRefusal) -> AdminResponse {
    match refusal {
        ApproverRefusal::Busy => error(ErrorCode::Busy, "another operation is running; try again shortly".to_owned()),
        ApproverRefusal::WrongState(state) => wrong_state(command, state),
        ApproverRefusal::SetInvalid(rule) => error(ErrorCode::ApproverSetInvalid, format!("{rule}; nothing was changed")),
        ApproverRefusal::UnknownApprover => error(
            ErrorCode::UnknownApprover,
            "no pinned approver has this ID; nothing was changed".to_owned(),
        ),
        ApproverRefusal::InUse => error(
            ErrorCode::ApproverInUse,
            "this approver signed the active approval; approve the config with another approver first; nothing was changed".to_owned(),
        ),
        ApproverRefusal::KindUnavailable(cause) => error(ErrorCode::ApproverKindUnavailable, cause),
        ApproverRefusal::TpmLockedOut(cause) => error(ErrorCode::TpmLockedOut, cause),
        ApproverRefusal::Failed { committed, cause } => error(ErrorCode::VaultWriteFailed, failed_message(committed, &cause)),
    }
}

/// Returns the failure message for `cause`, adding how to check whether the change committed if and only if it may
/// have.
fn failed_message(committed: MayHaveCommitted, cause: &str) -> String {
    match committed {
        MayHaveCommitted::No => cause.to_owned(),
        MayHaveCommitted::Unknown => format!("{cause}; the change may have committed: `iron-vault approver list` settles it"),
    }
}

pub(super) fn wrong_state(command: &str, state: ServiceState) -> AdminResponse {
    error(
        ErrorCode::WrongState,
        format!(
            "`{command}` is allowed only while the service is Ready; it is {}",
            state_name(state)
        ),
    )
}

pub(super) fn error(code: ErrorCode, message: String) -> AdminResponse {
    AdminResponse::Error { code, message }
}
