//! The startup host unlock outcome in the status report and its field encoding (`design/admin-protocol.md#status`, tag 18).
//!
//! An empty value means the profile tried no host unlock. Otherwise the first byte is the outcome, and a refusal adds a
//! second byte naming why, so the report round-trips as the service's own type.

use super::FrameError;
use crate::service_context::{HostUnlockOutcome, HostUnlockRefusal};

pub(super) const TAG_OUTCOME: u16 = 18;

const REFUSALS: [HostUnlockRefusal; 6] = [
    HostUnlockRefusal::MemoryUnprotected,
    HostUnlockRefusal::Untrusted,
    HostUnlockRefusal::Unreadable,
    HostUnlockRefusal::NotAnIdentity,
    HostUnlockRefusal::NotInitialized,
    HostUnlockRefusal::NotARecipient,
];

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

/// A refusal's position in [`REFUSALS`], which is its code.
fn refusal_code(refusal: HostUnlockRefusal) -> u8 {
    REFUSALS
        .iter()
        .position(|r| *r == refusal)
        .and_then(|i| u8::try_from(i).ok())
        .unwrap_or(0)
}

/// Reads tag 18's value.
pub(super) fn decode(value: &[u8]) -> Result<Option<HostUnlockOutcome>, FrameError> {
    match value {
        [] => Ok(None),
        [1] => Ok(Some(HostUnlockOutcome::Unlocked)),
        [2] => Ok(Some(HostUnlockOutcome::Absent)),
        [3] => Ok(Some(HostUnlockOutcome::UnsealFailed)),
        [4] => Ok(Some(HostUnlockOutcome::OwnerLocked)),
        [5, code] => REFUSALS
            .get(usize::from(*code))
            .map(|refusal| Some(HostUnlockOutcome::Refused(*refusal)))
            .ok_or(FrameError::InvalidValue(TAG_OUTCOME)),
        _ => Err(FrameError::InvalidValue(TAG_OUTCOME)),
    }
}
