//! The recovery reminder schedule against a running service context (specification §16, §18; design/recovery.md,
//! "Reminders"), with a test clock for the wall time and a paused tokio clock for the 7-day spacing.
//!
//! The log buffer is shared by every test of this binary and a reminder names no vault, so each test starts its clock at
//! a time of its own and finds its records by the times they report.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::fs;
use std::sync::Arc;
use std::time::Duration;

use common::approval_harness::{Fixture, captured_logs, identity};
use iron_vault::clock::TestClock;
use iron_vault::service_context::ServiceContext;
use iron_vault::service_state::ServiceState;
use iron_vault_store::{
    OsFs, RecipientSet, RecoveryCheckRecord, RecoveryKey, RecoveryKeySecret, StateDirLock, UtcSecond, wrap_identity,
    write_identity_envelope,
};
use secrecy::{ExposeSecret, SecretString};

const DAY: u64 = 86_400;

fn time(unix_seconds: u64) -> String {
    UtcSecond::from_unix_seconds(unix_seconds).unwrap().to_string()
}

fn write_record(fixture: &Fixture, since: u64, last_checked: Option<u64>) {
    let at = |seconds| UtcSecond::from_unix_seconds(seconds).unwrap();
    let record = RecoveryCheckRecord::new(at(since), last_checked.map(at)).unwrap();
    fs::write(fixture.path("state/recovery.toml"), record.encode()).unwrap();
}

fn record(fixture: &Fixture) -> Option<RecoveryCheckRecord> {
    fs::read(fixture.path("state/recovery.toml"))
        .ok()
        .map(|bytes| RecoveryCheckRecord::decode(&bytes).unwrap())
}

/// The reminders whose `field` reads `value`.
fn reminders(field: &str, value: &str) -> Vec<serde_json::Value> {
    captured_logs()
        .events("recovery.reminder")
        .into_iter()
        .filter(|event| event[field] == value)
        .collect()
}

fn started(base: u64) -> (Arc<TestClock>, String) {
    captured_logs();
    (Arc::new(TestClock::at(base)), time(base))
}

#[tokio::test]
async fn an_overdue_vault_logs_one_reminder_and_the_next_waits_seven_days() {
    let (clock, _) = started(1_900_000_000);
    let since = time(1_900_000_000 - 100 * DAY);
    let fixture = Fixture::new().await;
    write_record(&fixture, 1_900_000_000 - 100 * DAY, None);
    let service = fixture.ready_at(clock).await;
    tokio::time::pause();

    service.evaluate_recovery_reminder().await;
    service.evaluate_recovery_reminder().await;

    let first = reminders("reminders_since", &since);
    assert_eq!(first.len(), 1);
    let event = &first[0];
    assert_eq!(
        (event["level"].as_str(), event["recovery_record"].as_str()),
        (Some("INFO"), Some("never_checked"))
    );
    assert_eq!(event["reminder_days"], 90);
    assert!(event["remediation"].as_str().unwrap().contains("recovery check"));
    assert!(event.get("last_checked").is_none() && event.get("error_kind").is_none());

    tokio::time::advance(Duration::from_secs(6 * DAY)).await;
    service.evaluate_recovery_reminder().await;
    assert_eq!(reminders("reminders_since", &since).len(), 1);

    tokio::time::advance(Duration::from_secs(DAY)).await;
    service.evaluate_recovery_reminder().await;
    assert_eq!(reminders("reminders_since", &since).len(), 2);
}

#[tokio::test]
async fn a_missing_record_is_created_with_since_and_no_reminder_until_the_interval_passes() {
    let base = 1_910_000_000;
    let (clock, since) = started(base);
    let fixture = Fixture::new().await;
    assert_eq!(record(&fixture), None);
    let service = fixture.ready_at(Arc::clone(&clock)).await;

    service.evaluate_recovery_reminder().await;

    let created = record(&fixture).unwrap();
    assert_eq!((created.since().unix_seconds(), created.last_checked()), (base, None));
    assert!(reminders("reminders_since", &since).is_empty());
    clock.set(base + 90 * DAY - 1);
    service.evaluate_recovery_reminder().await;
    assert!(reminders("reminders_since", &since).is_empty());
    clock.set(base + 90 * DAY);
    service.evaluate_recovery_reminder().await;
    assert_eq!(reminders("reminders_since", &since).len(), 1);
}

#[tokio::test]
async fn a_locked_service_still_reminds() {
    let base = 1_920_000_000;
    let (clock, _) = started(base);
    let since = time(base - 91 * DAY);
    let fixture = Fixture::new().await;
    write_record(&fixture, base - 91 * DAY, None);
    let service = fixture.ready_at(clock).await;
    service.lock(Duration::from_secs(5)).await.unwrap();
    assert_eq!(service.state().await, ServiceState::Locked);

    service.evaluate_recovery_reminder().await;

    assert_eq!(reminders("reminders_since", &since).len(), 1);
}

#[tokio::test]
async fn a_successful_recovery_check_clears_the_spacing() {
    let base = 1_930_000_000;
    let (clock, _) = started(base);
    let (key, recovery) = RecoveryKey::generate();
    let (_, other) = RecoveryKey::generate();
    let fixture = Fixture::new().await;
    let lock = StateDirLock::acquire(&fixture.path("state")).unwrap();
    let envelope = wrap_identity(&identity(), &RecipientSet::new([recovery, other]).unwrap()).unwrap();
    write_identity_envelope(&lock, &OsFs, &envelope).unwrap();
    drop(lock);
    write_record(&fixture, base - 200 * DAY, None);
    let service: Arc<ServiceContext> = fixture.ready_at(Arc::clone(&clock)).await;
    tokio::time::pause();

    service.evaluate_recovery_reminder().await;
    assert_eq!(reminders("reminders_since", &time(base - 200 * DAY)).len(), 1);
    let recipient = RecoveryKeySecret::parse(SecretString::from(key.expose_secret().to_owned())).unwrap();
    service.check_recovery(recipient).await.unwrap();
    assert_eq!(record(&fixture).unwrap().last_checked().unwrap().unix_seconds(), base);

    // A day of spacing has passed, not seven, and the check has made the schedule start over.
    clock.set(base + 90 * DAY);
    tokio::time::advance(Duration::from_secs(DAY)).await;
    service.evaluate_recovery_reminder().await;

    let checked = reminders("last_checked", &time(base));
    assert_eq!(checked.len(), 1);
    assert_eq!(checked[0]["recovery_record"], "checked");
}

#[tokio::test]
async fn a_damaged_record_is_reported_as_unusable_and_the_service_keeps_serving() {
    let (clock, _) = started(1_940_000_000);
    let fixture = Fixture::new().await;
    fs::write(fixture.path("state/recovery.toml"), b"since = [\n").unwrap();
    let service = fixture.ready_at(clock).await;

    service.evaluate_recovery_reminder().await;

    let unusable = reminders("error_kind", "not_toml");
    assert_eq!(unusable.len(), 1);
    assert_eq!(
        (unusable[0]["level"].as_str(), unusable[0]["recovery_record"].as_str()),
        (Some("INFO"), Some("unusable"))
    );
    assert_eq!(fs::read(fixture.path("state/recovery.toml")).unwrap(), b"since = [\n");
    assert_eq!(service.state().await, ServiceState::Ready);
    assert_eq!(common::approval_harness::get(&fixture, "fx").await.status, 200);
}

#[tokio::test]
async fn an_unreadable_record_is_reported_as_unusable_and_left_in_place() {
    let (clock, _) = started(1_950_000_000);
    let fixture = Fixture::new().await;
    fs::create_dir(fixture.path("state/recovery.toml")).unwrap();
    let service = fixture.ready_at(clock).await;

    service.evaluate_recovery_reminder().await;

    assert_eq!(reminders("error_kind", "not_a_regular_file").len(), 1);
    assert!(fixture.path("state/recovery.toml").is_dir());
    assert_eq!(service.state().await, ServiceState::Ready);
}

#[tokio::test]
async fn the_daily_task_evaluates_every_24_hours_from_its_start() {
    let base = 1_960_000_000;
    let (clock, _) = started(base);
    let since = time(base - 100 * DAY);
    let fixture = Fixture::new().await;
    write_record(&fixture, base - 100 * DAY, None);
    let service = fixture.ready_at(clock).await;
    tokio::time::pause();
    let daily = Arc::clone(&service);
    let task = tokio::spawn(async move { daily.remind_daily().await });
    // The task fixes its first deadline when it first runs.
    tokio::task::yield_now().await;

    tokio::time::advance(Duration::from_secs(DAY - 1)).await;
    tokio::task::yield_now().await;
    assert!(reminders("reminders_since", &since).is_empty());
    tokio::time::advance(Duration::from_secs(1)).await;
    // The evaluation reads the record on the blocking pool, which a paused clock does not wait for.
    for _ in 0..200 {
        if !reminders("reminders_since", &since).is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    assert_eq!(reminders("reminders_since", &since).len(), 1);
    task.abort();
}
