//! The recovery check record: state file `recovery.toml` (design/recovery.md, design/storage-formats.md).
//!
//! It is plaintext, so reminders work while the vault is locked. The store reads no clock: every time here is an
//! argument or a decoded value.

use std::fmt;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use toml::value::{Datetime, Offset};

use crate::{
    ErrorKindLabel, ReadError, StateDirLock, StateFileName, StoreFs, WriteError, durable_remove, durable_replace, read_state_file,
};

/// The longest `recovery.toml` a reader accepts. The record is two lines of under 50 bytes; a larger file is not one.
pub const MAX_RECOVERY_CHECK_RECORD_LEN: u64 = 1024;

/// The last second of year 9999, the latest time RFC 3339 can write with four year digits.
const MAX_UNIX_SECONDS: u64 = 253_402_300_799;
const SECONDS_PER_DAY: u64 = 86_400;

/// A UTC time to whole seconds, from 1970-01-01T00:00:00Z to 9999-12-31T23:59:59Z, valid on construction.
///
/// It prints as RFC 3339 with `Z`, which is also a TOML offset date-time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UtcSecond(u64);

/// A time outside the range a [`UtcSecond`] holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("time is outside 1970-01-01T00:00:00Z to 9999-12-31T23:59:59Z")]
pub struct UtcSecondError;

impl UtcSecond {
    /// The time `seconds` after the Unix epoch.
    pub fn from_unix_seconds(seconds: u64) -> Result<Self, UtcSecondError> {
        (seconds <= MAX_UNIX_SECONDS).then_some(Self(seconds)).ok_or(UtcSecondError)
    }

    /// `time` truncated to whole seconds. The caller reads the clock; the store never does.
    pub fn from_system_time(time: SystemTime) -> Result<Self, UtcSecondError> {
        let elapsed = time.duration_since(UNIX_EPOCH).map_err(|_| UtcSecondError)?;
        Self::from_unix_seconds(elapsed.as_secs())
    }

    /// Whole seconds since the Unix epoch.
    pub fn unix_seconds(self) -> u64 {
        self.0
    }

    /// Builds the time from a TOML date-time, which must be UTC (`Z`) with whole seconds and no leap second.
    fn from_toml(value: &Datetime) -> Option<Self> {
        let (date, time) = (value.date?, value.time?);
        let valid = value.offset == Some(Offset::Z) && time.nanosecond.is_none() && time.second.is_some_and(|s| s <= 59);
        if !valid {
            return None;
        }
        let days = u64::try_from(days_from_civil(i64::from(date.year), i64::from(date.month), i64::from(date.day))).ok()?;
        let seconds = u64::from(time.hour) * 3600 + u64::from(time.minute) * 60 + u64::from(time.second?);
        Self::from_unix_seconds(days * SECONDS_PER_DAY + seconds).ok()
    }
}

impl fmt::Display for UtcSecond {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (days, rest) = (self.0 / SECONDS_PER_DAY, self.0 % SECONDS_PER_DAY);
        // `days` is at most 2_932_896, so it fits an i64.
        let (year, month, day) = civil_from_days(days as i64);
        let (hour, minute, second) = (rest / 3600, rest % 3600 / 60, rest % 60);
        write!(f, "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's `days_from_civil`).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The `(year, month, day)` of a day count since 1970-01-01 (Hinnant's `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(month <= 2), month, day)
}

/// The recovery check record: when the reminder schedule started counting, and when the last successful recovery check
/// ran, absent when there has been none. Valid on construction: a check never precedes the start of the schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryCheckRecord {
    since: UtcSecond,
    last_checked: Option<UtcSecond>,
}

/// Why bytes are not a recovery check record. Every message is fixed: the file's text is never copied into an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RecoveryCheckRecordError {
    /// The bytes are longer than [`MAX_RECOVERY_CHECK_RECORD_LEN`].
    #[error("recovery check record is longer than {MAX_RECOVERY_CHECK_RECORD_LEN} bytes")]
    TooLarge,
    /// The bytes are not UTF-8 text.
    #[error("recovery check record is not UTF-8")]
    NotUtf8,
    /// The text is not a TOML document.
    #[error("recovery check record is not valid TOML")]
    NotToml,
    /// The document has a key other than `since` and `last_checked`. A key a later release adds makes the record
    /// unusable to this one, since this one cannot know what the key means.
    #[error("recovery check record has an unknown key")]
    UnknownKey,
    /// The document has no `since`.
    #[error("recovery check record has no `since`")]
    MissingSince,
    /// A value is not a UTC date-time with whole seconds.
    #[error("recovery check record has a time that is not a UTC date-time to whole seconds")]
    BadTime,
    /// `last_checked` is earlier than `since`.
    #[error("recovery check record has `last_checked` before `since`")]
    CheckedBeforeSince,
}

impl RecoveryCheckRecord {
    /// A record, refused when `last_checked` is before `since`.
    pub fn new(since: UtcSecond, last_checked: Option<UtcSecond>) -> Result<Self, RecoveryCheckRecordError> {
        match last_checked {
            Some(checked) if checked < since => Err(RecoveryCheckRecordError::CheckedBeforeSince),
            _ => Ok(Self { since, last_checked }),
        }
    }

    /// When the reminder schedule started counting.
    pub fn since(&self) -> UtcSecond {
        self.since
    }

    /// When the last successful recovery check ran, if there has been one.
    pub fn last_checked(&self) -> Option<UtcSecond> {
        self.last_checked
    }

    /// The file's bytes: `since`, then `last_checked` when present, one per line, always in that order.
    pub fn encode(&self) -> Vec<u8> {
        let checked = self.last_checked.map(|t| format!("last_checked = {t}\n")).unwrap_or_default();
        format!("since = {}\n{checked}", self.since).into_bytes()
    }

    /// Reads a record from `bytes`, refusing anything but a `since` and at most a `last_checked`. TOML ignores key order
    /// and whitespace, so they are not checked; [`RecoveryCheckRecord::encode`] always writes the one form.
    pub fn decode(bytes: &[u8]) -> Result<Self, RecoveryCheckRecordError> {
        use RecoveryCheckRecordError as E;
        if bytes.len() as u64 > MAX_RECOVERY_CHECK_RECORD_LEN {
            return Err(E::TooLarge);
        }
        let text = std::str::from_utf8(bytes).map_err(|_| E::NotUtf8)?;
        let table: toml::Table = text.parse().map_err(|_| E::NotToml)?;
        if table.keys().any(|k| k != "since" && k != "last_checked") {
            return Err(E::UnknownKey);
        }
        let time = |key: &str| {
            table
                .get(key)
                .map(|v| v.as_datetime().and_then(UtcSecond::from_toml).ok_or(E::BadTime))
        };
        let since = time("since").ok_or(E::MissingSince)??;
        Self::new(since, time("last_checked").transpose()?)
    }
}

/// Why the record could not be read: the file is unusable. An absent file is not an error; it reads as `None`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecoveryCheckReadError {
    /// The file could not be read, is not a regular file or is larger than the limit.
    #[error(transparent)]
    Read(#[from] ReadError),
    /// The file was read and is not a record.
    #[error(transparent)]
    Decode(#[from] RecoveryCheckRecordError),
}

impl RecoveryCheckReadError {
    /// The error as a label that holds no file name, path or file text, for a log record.
    pub fn error_kind_label(&self) -> ErrorKindLabel {
        match self {
            Self::Read(ReadError::Io { kind, .. }) => ErrorKindLabel::from(*kind),
            Self::Read(ReadError::TooLarge { .. }) | Self::Decode(RecoveryCheckRecordError::TooLarge) => ErrorKindLabel::fixed("too_large"),
            Self::Read(ReadError::NotARegularFile { .. }) => ErrorKindLabel::fixed("not_a_regular_file"),
            Self::Decode(decode) => ErrorKindLabel::fixed(decode.label()),
        }
    }
}

impl RecoveryCheckRecordError {
    /// A fixed snake_case name for the reason, for `error_kind_label`.
    fn label(self) -> &'static str {
        match self {
            Self::TooLarge => "too_large",
            Self::NotUtf8 => "not_utf8",
            Self::NotToml => "not_toml",
            Self::UnknownKey => "unknown_key",
            Self::MissingSince => "missing_since",
            Self::BadTime => "bad_time",
            Self::CheckedBeforeSince => "checked_before_since",
        }
    }
}

/// The state file `recovery.toml`.
fn file() -> StateFileName {
    StateFileName::recovery_check_record()
}

/// Reads `recovery.toml`: `None` when it is absent, and an error when it is there and unusable, so the caller can tell a
/// missing record (create it) from a damaged one (leave it for the owner, count a reminder as due).
pub fn read_recovery_check(lock: &StateDirLock, fs: &impl StoreFs) -> Result<Option<RecoveryCheckRecord>, RecoveryCheckReadError> {
    match read_state_file(lock, fs, &file(), MAX_RECOVERY_CHECK_RECORD_LEN) {
        Ok(bytes) => Ok(Some(RecoveryCheckRecord::decode(&bytes)?)),
        Err(ReadError::Io {
            kind: io::ErrorKind::NotFound,
            ..
        }) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Replaces `recovery.toml` with `record`, durably: a temp file, its fsync, the rename and the directory fsync.
pub fn write_recovery_check(lock: &StateDirLock, fs: &impl StoreFs, record: &RecoveryCheckRecord) -> Result<(), WriteError> {
    durable_replace(lock, fs, &file(), &record.encode())
}

/// Removes `recovery.toml` durably and says whether it was there. `begin_initialization` calls this on an Uninitialized
/// directory, so a new vault never starts with the `last_checked` of a vault that is gone.
pub(crate) fn remove_recovery_check(lock: &StateDirLock, fs: &impl StoreFs) -> Result<bool, WriteError> {
    match durable_remove(lock, fs, &file()) {
        Ok(()) => Ok(true),
        Err(WriteError::NotFound { .. }) => Ok(false),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests;
