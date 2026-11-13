// SPDX-License-Identifier: MPL-2.0
//! The recovery check part of the status report and its field encoding
//! ([admin protocol: status](../../../../../design/admin-protocol.md#status), tags 13 to 17).
//!
//! The service computes the days and the due flag with its own clock, so the CLI prints the same line even when its own
//! clock is wrong.

use iron_vault_store::UtcSecond;

use super::FrameError;
use super::fields::{self, read_flag, read_text, read_u64};

pub(super) const TAG_RECORD: u16 = 13;
pub(super) const TAG_TIME: u16 = 14;
pub(super) const TAG_DAYS: u16 = 15;
pub(super) const TAG_DUE: u16 = 16;
pub(super) const TAG_DETAIL: u16 = 17;

/// What the recovery check record says, as a fact for the owner. It is not proof that the key works.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryStatus {
    /// There is no usable record. `detail` is one of the design's fixed phrases saying why; `due` is set only for an
    /// unusable record, which counts as a reminder due.
    Unknown {
        /// Why the record is unknown.
        detail: String,
        /// `true` if and only if a recovery reminder is due.
        due: bool,
    },
    /// The vault has a record but no check has run since the schedule started counting at `since`.
    NeverChecked {
        /// When the reminder schedule started counting.
        since: UtcSecond,
        /// Whole days from `since` to the service's clock; zero for a time in the future.
        days: u64,
        /// `true` if and only if a recovery reminder is due.
        due: bool,
    },
    /// A recovery check has run.
    Checked {
        /// The time of the last successful check.
        last_checked: UtcSecond,
        /// Whole days from `last_checked` to the service's clock; zero for a time in the future.
        days: u64,
        /// `true` if and only if a recovery reminder is due.
        due: bool,
    },
}

impl RecoveryStatus {
    /// Returns `true` if and only if a recovery check has run and no reminder is due: the only status `forget-machine`
    /// accepts as proof that another recovery path exists. A vault that was never checked, or whose record is unusable,
    /// has not shown one.
    pub const fn verified(&self) -> bool {
        matches!(self, Self::Checked { due: false, .. })
    }
}

/// Appends tags 13 to 17.
pub(super) fn encode(out: &mut Vec<u8>, status: &RecoveryStatus) {
    let (record, time, days, due, detail) = match status {
        RecoveryStatus::Unknown { detail, due } => (0, 0, 0, *due, detail.as_str()),
        RecoveryStatus::NeverChecked { since, days, due } => (1, since.unix_seconds(), *days, *due, ""),
        RecoveryStatus::Checked { last_checked, days, due } => (2, last_checked.unix_seconds(), *days, *due, ""),
    };
    fields::put(out, TAG_RECORD, &[record]);
    fields::put(out, TAG_TIME, &time.to_be_bytes());
    fields::put(out, TAG_DAYS, &days.to_be_bytes());
    fields::put(out, TAG_DUE, &[u8::from(due)]);
    fields::put(out, TAG_DETAIL, detail.as_bytes());
}

/// Returns the encoded values of tags 13 to 17, in tag order.
pub(super) struct Raw<'a> {
    pub(super) record: &'a [u8],
    pub(super) time: &'a [u8],
    pub(super) days: &'a [u8],
    pub(super) due: &'a [u8],
    pub(super) detail: &'a [u8],
}

/// Reads the report part. Tag 14 and 15 are zero and the detail is set exactly when the record is unknown.
pub(super) fn decode(raw: Raw<'_>) -> Result<RecoveryStatus, FrameError> {
    let (time, days) = (read_u64(TAG_TIME, raw.time)?, read_u64(TAG_DAYS, raw.days)?);
    let due = read_flag(TAG_DUE, raw.due)?;
    let detail = read_text(TAG_DETAIL, raw.detail)?;
    let at = || UtcSecond::from_unix_seconds(time).map_err(|_| FrameError::InvalidValue(TAG_TIME));
    match raw.record {
        [0] if time == 0 && days == 0 && !detail.is_empty() => Ok(RecoveryStatus::Unknown { detail, due }),
        [1] if detail.is_empty() => Ok(RecoveryStatus::NeverChecked { since: at()?, days, due }),
        [2] if detail.is_empty() => Ok(RecoveryStatus::Checked {
            last_checked: at()?,
            days,
            due,
        }),
        _ => Err(FrameError::InvalidValue(TAG_RECORD)),
    }
}
