//! The startup host unlock outcome in the status report and its field encoding (`design/admin-protocol.md#status`, tag 18).
//!
//! An empty value means the profile tried no host unlock. Otherwise the first byte is the outcome, and a refusal adds a
//! second byte naming why, so the report round-trips as the service's own type.

use super::FrameError;
use crate::service_context::{HostUnlockOutcome, HostUnlockRefusal};

pub(super) const TAG_OUTCOME: u16 = 18;

/// The value of tag 18.
pub(super) fn encode(outcome: Option<HostUnlockOutcome>) -> Vec<u8> {
    match outcome {
        None => Vec::new(),
        Some(HostUnlockOutcome::Unlocked) => vec![1],
        Some(HostUnlockOutcome::Absent) => vec![2],
        Some(HostUnlockOutcome::UnsealFailed) => vec![3],
        Some(HostUnlockOutcome::OwnerLocked) => vec![4],
        Some(HostUnlockOutcome::Refused(refusal)) => vec![5, refusal_code(refusal)],
    }
}

/// A refusal's code. Exhaustive, so a new refusal cannot reach the wire under another's code.
const fn refusal_code(refusal: HostUnlockRefusal) -> u8 {
    match refusal {
        HostUnlockRefusal::MemoryUnprotected => 0,
        HostUnlockRefusal::Untrusted => 1,
        HostUnlockRefusal::Unreadable => 2,
        HostUnlockRefusal::NotAnIdentity => 3,
        HostUnlockRefusal::NotInitialized => 4,
        HostUnlockRefusal::NotARecipient => 5,
    }
}

/// The refusal a code names.
const fn refusal_of(code: u8) -> Option<HostUnlockRefusal> {
    match code {
        0 => Some(HostUnlockRefusal::MemoryUnprotected),
        1 => Some(HostUnlockRefusal::Untrusted),
        2 => Some(HostUnlockRefusal::Unreadable),
        3 => Some(HostUnlockRefusal::NotAnIdentity),
        4 => Some(HostUnlockRefusal::NotInitialized),
        5 => Some(HostUnlockRefusal::NotARecipient),
        _ => None,
    }
}

/// Reads tag 18's value.
pub(super) fn decode(value: &[u8]) -> Result<Option<HostUnlockOutcome>, FrameError> {
    match value {
        [] => Ok(None),
        [1] => Ok(Some(HostUnlockOutcome::Unlocked)),
        [2] => Ok(Some(HostUnlockOutcome::Absent)),
        [3] => Ok(Some(HostUnlockOutcome::UnsealFailed)),
        [4] => Ok(Some(HostUnlockOutcome::OwnerLocked)),
        [5, code] => refusal_of(*code)
            .map(|refusal| Some(HostUnlockOutcome::Refused(refusal)))
            .ok_or(FrameError::InvalidValue(TAG_OUTCOME)),
        _ => Err(FrameError::InvalidValue(TAG_OUTCOME)),
    }
}
