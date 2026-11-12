//! The `[recovery] reminder_days` setting: how often the service reminds the owner to run a recovery check
//! ([spec §16](../../../design/iron-vault-specification.md#16-administration-recovery-and-migration),
//! [recovery design](../../../design/recovery.md#reminders)).

use std::fmt;

use serde::de::{self, Deserialize, Deserializer, Visitor};
use thiserror::Error;

/// The fewest days a reminder interval may be, so a misconfigured value cannot flood the log.
const MIN_DAYS: u16 = 7;
/// The most days a reminder interval may be, so a reminder cannot be pushed out of sight for years.
const MAX_DAYS: u16 = 365;
/// The interval when the `[recovery]` table or its `reminder_days` key is absent.
const DEFAULT_DAYS: u16 = 90;

/// Why a `[recovery] reminder_days` was rejected.
///
/// Every wrong value, of any type, gets this one message, so the rule is always named.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("recovery.reminder_days must be a whole number of days from {MIN_DAYS} to {MAX_DAYS}, not {found}")]
pub struct ReminderIntervalError {
    /// The rejected value as written, such as `366`, `30.5` or `"soon"`.
    pub found: String,
}

impl ReminderIntervalError {
    fn new(found: impl fmt::Display) -> Self {
        Self { found: found.to_string() }
    }
}

/// The days between recovery reminders: a whole number from 7 to 365, valid on construction.
///
/// It is part of the approved config, so a change that silences reminders needs the approval passphrase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
            .filter(|days| (MIN_DAYS..=MAX_DAYS).contains(days))
            .map(Self)
            .ok_or_else(|| ReminderIntervalError::new(value))
    }
}

/// Accepts any TOML value, so every wrong type gets the fixed message instead of serde's generic type error.
///
/// That covers integers (including ones outside the `i64`/`u64` range), floats, booleans, strings, arrays, and tables
/// or date-times (the toml deserializer presents a date-time as a map).
struct IntervalVisitor;

impl<'de> Visitor<'de> for IntervalVisitor {
    type Value = ReminderInterval;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a whole number of days")
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
        ReminderInterval::try_from(v).map_err(E::custom)
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
        i64::try_from(v)
            .map_err(|_| E::custom(ReminderIntervalError::new(v)))
            .and_then(|v| self.visit_i64(v))
    }

    fn visit_i128<E: de::Error>(self, v: i128) -> Result<Self::Value, E> {
        i64::try_from(v)
            .map_err(|_| E::custom(ReminderIntervalError::new(v)))
            .and_then(|v| self.visit_i64(v))
    }

    fn visit_u128<E: de::Error>(self, v: u128) -> Result<Self::Value, E> {
        i64::try_from(v)
            .map_err(|_| E::custom(ReminderIntervalError::new(v)))
            .and_then(|v| self.visit_i64(v))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> {
        // Debug formatting keeps the fraction, so `30.0` is shown as written rather than as `30`.
        Err(E::custom(ReminderIntervalError::new(format!("{v:?}"))))
    }

    fn visit_seq<A: de::SeqAccess<'de>>(self, _seq: A) -> Result<Self::Value, A::Error> {
        Err(de::Error::custom(ReminderIntervalError::new("an array")))
    }

    fn visit_map<A: de::MapAccess<'de>>(self, _map: A) -> Result<Self::Value, A::Error> {
        Err(de::Error::custom(ReminderIntervalError::new("a table or date-time")))
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
        Err(E::custom(ReminderIntervalError::new(v)))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        Err(E::custom(ReminderIntervalError::new(format!("{v:?}"))))
    }
}

impl<'de> Deserialize<'de> for ReminderInterval {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(IntervalVisitor)
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
