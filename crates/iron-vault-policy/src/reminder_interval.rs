//! The `[recovery] reminder_days` setting: how often the service reminds the owner to run a recovery check
//! (spec §3.13, `design/recovery.md`).

use serde::Deserialize;
use thiserror::Error;

/// Fewest days a reminder interval may be, so a misconfigured value cannot flood the log.
const MIN_DAYS: i64 = 7;
/// Most days a reminder interval may be, so a reminder cannot be pushed out of sight for years.
const MAX_DAYS: i64 = 365;
/// The interval when the `[recovery]` table or its key is absent: every few months.
const DEFAULT_DAYS: u16 = 90;

/// Why a `[recovery] reminder_days` was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("recovery.reminder_days must be a whole number of days from {MIN_DAYS} to {MAX_DAYS}, not {value}")]
pub struct ReminderIntervalError {
    /// The rejected value.
    pub value: i64,
}

/// The days between recovery reminders: a whole number from 7 to 365, valid on construction.
///
/// It is part of the approved config, so a change that silences reminders needs the approval passphrase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "i64")]
pub struct ReminderInterval(u16);

impl ReminderInterval {
    /// The interval in whole days.
    pub fn days(self) -> u16 {
        self.0
    }
}

impl Default for ReminderInterval {
    fn default() -> Self {
        Self(DEFAULT_DAYS)
    }
}

impl TryFrom<i64> for ReminderInterval {
    type Error = ReminderIntervalError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        u16::try_from(value)
            .ok()
            .filter(|_| (MIN_DAYS..=MAX_DAYS).contains(&value))
            .map(Self)
            .ok_or(ReminderIntervalError { value })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_edges_are_accepted() {
        assert_eq!(ReminderInterval::try_from(7).map(ReminderInterval::days), Ok(7));
        assert_eq!(ReminderInterval::try_from(365).map(ReminderInterval::days), Ok(365));
    }

    #[test]
    fn values_outside_the_range_are_refused() {
        [6, 366, 0, -1, i64::MIN, i64::MAX].into_iter().for_each(|v| {
            let err = ReminderInterval::try_from(v).unwrap_err();
            assert_eq!(
                err.to_string(),
                format!("recovery.reminder_days must be a whole number of days from 7 to 365, not {v}")
            );
        });
    }

    #[test]
    fn default_is_ninety_days() {
        assert_eq!(ReminderInterval::default().days(), 90);
    }
}
