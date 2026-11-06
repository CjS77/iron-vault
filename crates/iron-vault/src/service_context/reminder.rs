//! The recovery reminder schedule's side of the service context (`design/recovery.md`, "Reminders").
//!
//! An evaluation runs at startup, after each unlock and every 24 hours, in every state. It reads the recovery check
//! record without the service-wide lock, since the record is replaced by rename and a read sees the old bytes or the
//! new whole. Only a missing record takes the lock, to write the first one. What the schedule remembers, the interval
//! in force and when it last reminded, lives in memory: a restart forgets the spacing and starts at the default
//! interval until a config is activated, and `lock` keeps both.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use iron_vault_policy::ReminderInterval;
use iron_vault_store::{InitializationState, RecoveryCheckRecord, StoreFs, UtcSecond, read_recovery_check, write_recovery_check};
use tokio::time::Instant;

use super::recovery::synced_late;
use super::{ServiceContext, ServiceLocks};
use crate::audit::AuditEvent;
use crate::audit::recovery::RecoveryReminder;
use crate::recovery_reminder::{Due, RecordState, reminder_due};

/// How often the service evaluates the schedule, on the monotonic clock, counted from startup.
const EVALUATION_PERIOD: Duration = Duration::from_secs(24 * 60 * 60);

/// What the schedule keeps in memory.
#[derive(Debug, Default)]
pub(super) struct ReminderSchedule {
    /// The interval of the last activated config; 90 days until the first activation.
    interval: ReminderInterval,
    /// When the last reminder was written. Monotonic, so a wall-clock jump cannot lengthen or shorten the spacing.
    last_reminded: Option<Instant>,
}

impl ReminderSchedule {
    pub(super) fn set_interval(&mut self, interval: ReminderInterval) {
        self.interval = interval;
    }

    /// A successful recovery check starts a new interval, so its next reminder is never held back by one for the last.
    pub(super) fn clear_spacing(&mut self) {
        self.last_reminded = None;
    }

    /// Decides, and when a reminder is due remembers that it is being written.
    fn due(&mut self, record: &RecordState, now: UtcSecond) -> Option<Due> {
        let since_last_reminder = self.last_reminded.map(|at| at.elapsed());
        let due = reminder_due(record, self.interval, since_last_reminder, now)?;
        self.last_reminded = Some(Instant::now());
        Some(due)
    }
}

/// The schedule shared with the tasks that change it: activation sets the interval, a recovery check clears the spacing.
pub(super) type SharedSchedule = Arc<Mutex<ReminderSchedule>>;

/// Runs `change` on the schedule. Nothing a panic could leave half-changed is kept in it, so a poisoned lock is used.
pub(super) fn with_schedule<T>(schedule: &Mutex<ReminderSchedule>, change: impl FnOnce(&mut ReminderSchedule) -> T) -> T {
    change(&mut schedule.lock().unwrap_or_else(PoisonError::into_inner))
}

/// What the state directory holds, as far as the schedule is concerned.
enum Loaded {
    /// There is no vault, so there is no key to check.
    NotInitialized,
    /// The vault has no recovery check record yet.
    Missing,
    Record(RecordState),
}

impl<F: StoreFs + Send + Sync + 'static> ServiceContext<F> {
    /// Evaluates the schedule once and writes `recovery.reminder` when a reminder is due. Never fails the service: a
    /// record that cannot be read or written makes the reminder due instead, and a task that ends without a result
    /// skips this evaluation.
    pub async fn evaluate_recovery_reminder(&self) {
        let Ok(now) = self.clock.now() else {
            tracing::warn!("the system clock is outside the years 1970 to 9999, so no recovery reminder was evaluated");
            return;
        };
        let Some(record) = self.schedule_record(now).await else { return };
        if let Some(due) = with_schedule(&self.reminders, |schedule| schedule.due(&record, now)) {
            RecoveryReminder(&due).emit();
        }
    }

    /// Evaluates the schedule every 24 hours of the monotonic clock from now, until the runtime ends.
    pub async fn remind_daily(&self) {
        let mut ticks = tokio::time::interval_at(Instant::now() + EVALUATION_PERIOD, EVALUATION_PERIOD);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticks.tick().await;
            self.evaluate_recovery_reminder().await;
        }
    }

    /// The record's state, creating the first record when the vault has none. `None` when there is no vault or the
    /// read did not finish.
    async fn schedule_record(&self, now: UtcSecond) -> Option<RecordState> {
        let loaded = match self.on_pool(|locks, fs| load(locks, fs)).await? {
            Loaded::Missing => self.create_first_record(now).await?,
            loaded => loaded,
        };
        match loaded {
            Loaded::Record(state) => Some(state),
            Loaded::NotInitialized | Loaded::Missing => None,
        }
    }

    /// Waits for the service-wide lock, reads again, since a recovery check may have written a record while this
    /// waited, and writes `since = now` if there is still none. The task owns the guard, so a dropped caller cannot
    /// release it while the write runs.
    async fn create_first_record(&self, now: UtcSecond) -> Option<Loaded> {
        let service_wide = Arc::clone(&self.service_wide).lock_owned().await;
        self.on_pool(move |locks, fs| {
            let _held = service_wide;
            match load(locks, fs) {
                Loaded::Missing => Loaded::Record(write_first(locks, fs, now)),
                loaded => loaded,
            }
        })
        .await
    }

    /// Runs `work` on the blocking pool; `None` when the task ended without a result.
    async fn on_pool<T: Send + 'static>(&self, work: impl FnOnce(&ServiceLocks, &F) -> T + Send + 'static) -> Option<T> {
        let (locks, setup) = (Arc::clone(&self.locks), Arc::clone(&self.setup));
        tokio::task::spawn_blocking(move || work(&locks, &setup.fs)).await.ok()
    }
}

fn load(locks: &ServiceLocks, fs: &impl StoreFs) -> Loaded {
    if !matches!(
        InitializationState::read(&locks.state, &locks.config, fs),
        Ok(InitializationState::Initialized)
    ) {
        return Loaded::NotInitialized;
    }
    match read_recovery_check(&locks.state, fs) {
        Ok(Some(record)) => Loaded::Record(RecordState::of(&record)),
        Ok(None) => Loaded::Missing,
        Err(error) => Loaded::Record(RecordState::Unusable(error.error_kind_label())),
    }
}

/// Writes the first record, `since = now`. A record that cannot be written is unusable for this evaluation, and the
/// next evaluation tries again.
fn write_first(locks: &ServiceLocks, fs: &impl StoreFs, now: UtcSecond) -> RecordState {
    let written = RecoveryCheckRecord::new(now, None)
        .map_err(|_| iron_vault_store::ErrorKindLabel::fixed("invalid_record"))
        .and_then(|record| {
            write_recovery_check(&locks.state, fs, &record)
                .or_else(synced_late)
                .map_err(|error| error.error_kind_label())
        });
    written.map_or_else(RecordState::Unusable, |()| RecordState::NeverChecked(now))
}
