//! When a recovery reminder is due (`design/recovery.md`, "Reminders"). Every rule of the schedule is in
//! [`reminder_due`], which reads no clock and no file: the service passes in the record, the interval, how long ago it
//! last reminded and the time.

use std::time::Duration;

use iron_vault_policy::ReminderInterval;
use iron_vault_store::{ErrorKindLabel, RecoveryCheckRecord, UtcSecond};

/// The least time between two reminders, so a service that stays overdue writes one a week, not one a day.
pub const REMINDER_SPACING: Duration = Duration::from_secs(7 * SECONDS_PER_DAY);

const SECONDS_PER_DAY: u64 = 86_400;

/// What the service knows of the recovery check record when it decides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordState {
    /// A recovery check has run; this is the time of the last one.
    Checked(UtcSecond),
    /// No check has run since the schedule started counting at this time.
    NeverChecked(UtcSecond),
    /// The record could not be read or is damaged. The owner is reminded at once, since nothing shows a check was done.
    Unusable(ErrorKindLabel),
}

impl RecordState {
    /// The state of a readable record.
    pub fn of(record: &RecoveryCheckRecord) -> Self {
        record.last_checked().map_or(Self::NeverChecked(record.since()), Self::Checked)
    }

    /// The time the interval counts from; `None` for an unusable record, which has none.
    fn reference(&self) -> Option<UtcSecond> {
        match self {
            Self::Checked(time) | Self::NeverChecked(time) => Some(*time),
            Self::Unusable(_) => None,
        }
    }
}

/// A reminder that is due now: what the `recovery.reminder` event reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Due {
    /// The record's state, which says which fields the event carries.
    pub record: RecordState,
    /// The interval in force, in days.
    pub reminder_days: u16,
}

/// Decides whether a recovery reminder is due.
///
/// It is due once the whole days elapsed since the record's reference time (`last_checked`, else `since`) reach the
/// interval, or while the record is unusable, unless a reminder was written `since_last_reminder` ago and that is under
/// [`REMINDER_SPACING`]. A clock behind the reference time counts as zero days, so a clock fault delays a reminder and
/// never raises one early.
pub fn reminder_due(
    record: &RecordState,
    interval: ReminderInterval,
    since_last_reminder: Option<Duration>,
    now: UtcSecond,
) -> Option<Due> {
    let spaced = since_last_reminder.is_none_or(|elapsed| elapsed >= REMINDER_SPACING);
    let overdue = record
        .reference()
        .is_none_or(|reference| whole_days_between(reference, now) >= u64::from(interval.days()));
    (spaced && overdue).then(|| Due {
        record: record.clone(),
        reminder_days: interval.days(),
    })
}

/// Whole days from `earlier` to `later`; zero when `later` is the earlier time.
pub fn whole_days_between(earlier: UtcSecond, later: UtcSecond) -> u64 {
    later.unix_seconds().saturating_sub(earlier.unix_seconds()) / SECONDS_PER_DAY
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = SECONDS_PER_DAY;
    const START: u64 = 1_800_000_000;

    fn at(offset_seconds: u64) -> UtcSecond {
        UtcSecond::from_unix_seconds(START + offset_seconds).unwrap()
    }

    fn interval(days: i64) -> ReminderInterval {
        ReminderInterval::try_from(days).unwrap()
    }

    fn days_ago(days: u64) -> Option<Duration> {
        Some(Duration::from_secs(days * DAY))
    }

    fn due(record: &RecordState, days: i64, reminded: Option<Duration>, now: UtcSecond) -> bool {
        reminder_due(record, interval(days), reminded, now).is_some()
    }

    #[test]
    fn a_vault_never_checked_is_due_once_the_interval_has_passed_since_the_schedule_started() {
        let never = RecordState::NeverChecked(at(0));
        assert!(!due(&never, 90, None, at(90 * DAY - 1)));
        assert!(due(&never, 90, None, at(90 * DAY)));
        assert!(due(&never, 90, None, at(400 * DAY)));
    }

    #[test]
    fn a_checked_vault_counts_from_its_last_check() {
        let checked = RecordState::Checked(at(10 * DAY));
        assert!(!due(&checked, 30, None, at(40 * DAY - 1)));
        assert!(due(&checked, 30, None, at(40 * DAY)));
        assert!(due(&checked, 30, None, at(41 * DAY)));
    }

    #[test]
    fn the_interval_boundary_is_inclusive_at_both_ends_of_the_range() {
        let never = RecordState::NeverChecked(at(0));
        assert!(due(&never, 7, None, at(7 * DAY)));
        assert!(!due(&never, 7, None, at(7 * DAY - 1)));
        assert!(due(&never, 365, None, at(365 * DAY)));
        assert!(!due(&never, 365, None, at(365 * DAY - 1)));
    }

    #[test]
    fn a_reminder_in_the_last_seven_days_holds_the_next_one_back() {
        let overdue = RecordState::NeverChecked(at(0));
        let now = at(100 * DAY);
        assert!(!due(&overdue, 90, days_ago(6), now));
        assert!(!due(&overdue, 90, Some(REMINDER_SPACING - Duration::from_secs(1)), now));
        assert!(due(&overdue, 90, days_ago(7), now));
        assert!(due(&overdue, 90, days_ago(30), now));
    }

    #[test]
    fn an_unusable_record_is_always_due_but_still_spaced() {
        let unusable = RecordState::Unusable(ErrorKindLabel::fixed("not_toml"));
        assert!(due(&unusable, 365, None, at(0)));
        assert!(!due(&unusable, 365, days_ago(1), at(0)));
        assert!(due(&unusable, 365, days_ago(7), at(0)));
    }

    #[test]
    fn a_clock_behind_the_reference_time_counts_as_zero_days() {
        let checked = RecordState::Checked(at(100 * DAY));
        assert!(!due(&checked, 7, None, at(0)));
        assert!(!due(&checked, 7, None, at(100 * DAY)));
    }

    #[test]
    fn the_reminder_carries_the_record_and_the_interval() {
        let record = RecordState::Checked(at(0));
        let found = reminder_due(&record, interval(30), None, at(30 * DAY)).unwrap();
        assert_eq!(found, Due { record, reminder_days: 30 });
    }

    #[test]
    fn a_readable_record_is_checked_or_never_checked() {
        let (since, checked) = (at(0), at(DAY));
        assert_eq!(
            RecordState::of(&RecoveryCheckRecord::new(since, None).unwrap()),
            RecordState::NeverChecked(since)
        );
        assert_eq!(
            RecordState::of(&RecoveryCheckRecord::new(since, Some(checked)).unwrap()),
            RecordState::Checked(checked)
        );
    }
}
