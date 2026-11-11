//! `status` reports the recovery check record in every form (design/recovery.md, "Status"), read from disk on each call
//! with the service's own clock.

#![cfg(target_os = "linux")]

use crate::common;

use std::fs;
use std::sync::Arc;

use common::approval_harness::Fixture;
use iron_vault::admin::protocol::RecoveryStatus;
use iron_vault::clock::TestClock;
use iron_vault::service_state::ServiceState;
use iron_vault_store::{RecoveryCheckRecord, UtcSecond};

const DAY: u64 = 86_400;
const BASE: u64 = 1_900_000_000;

fn at(seconds: u64) -> UtcSecond {
    UtcSecond::from_unix_seconds(seconds).unwrap()
}

fn write_record(fixture: &Fixture, since: u64, last_checked: Option<u64>) {
    let record = RecoveryCheckRecord::new(at(since), last_checked.map(at)).unwrap();
    fs::write(fixture.path("state/recovery.toml"), record.encode()).unwrap();
}

async fn recovery_at(fixture: &Fixture, now: u64) -> RecoveryStatus {
    let service = fixture.ready_at(Arc::new(TestClock::at(now))).await;
    let report = service.status().await;
    assert_eq!(report.state, ServiceState::Ready);
    report.recovery
}

fn unknown(detail: &str, due: bool) -> RecoveryStatus {
    RecoveryStatus::Unknown {
        detail: detail.to_owned(),
        due,
    }
}

#[tokio::test]
async fn a_checked_record_reports_whole_days_and_the_due_flag_from_the_interval() {
    let fixture = Fixture::new().await;
    write_record(&fixture, BASE - 200 * DAY, Some(BASE - 37 * DAY - 5));
    assert_eq!(
        recovery_at(&fixture, BASE).await,
        RecoveryStatus::Checked {
            last_checked: at(BASE - 37 * DAY - 5),
            days: 37,
            due: false
        }
    );
    write_record(&fixture, BASE - 200 * DAY, Some(BASE - 90 * DAY));
    assert_eq!(
        recovery_at(&fixture, BASE).await,
        RecoveryStatus::Checked {
            last_checked: at(BASE - 90 * DAY),
            days: 90,
            due: true
        }
    );
}

#[tokio::test]
async fn a_never_checked_record_counts_from_since() {
    let fixture = Fixture::new().await;
    write_record(&fixture, BASE - 12 * DAY, None);
    assert_eq!(
        recovery_at(&fixture, BASE).await,
        RecoveryStatus::NeverChecked {
            since: at(BASE - 12 * DAY),
            days: 12,
            due: false
        }
    );
    write_record(&fixture, BASE - 91 * DAY, None);
    assert!(matches!(
        recovery_at(&fixture, BASE).await,
        RecoveryStatus::NeverChecked { days: 91, due: true, .. }
    ));
}

#[tokio::test]
async fn a_time_in_the_future_is_zero_days() {
    let fixture = Fixture::new().await;
    write_record(&fixture, BASE - DAY, Some(BASE + 10 * DAY));
    assert!(matches!(
        recovery_at(&fixture, BASE).await,
        RecoveryStatus::Checked { days: 0, due: false, .. }
    ));
}

#[tokio::test]
async fn a_missing_record_is_unknown_and_status_does_not_create_it() {
    let fixture = Fixture::new().await;
    assert_eq!(recovery_at(&fixture, BASE).await, unknown("no check record yet", false));
    assert!(!fixture.path("state/recovery.toml").exists());
}

#[tokio::test]
async fn a_damaged_record_is_unknown_and_due_and_status_still_succeeds() {
    let fixture = Fixture::new().await;
    fs::write(fixture.path("state/recovery.toml"), b"since = [\n").unwrap();
    assert_eq!(
        recovery_at(&fixture, BASE).await,
        unknown("the check record is unusable (not_toml)", true)
    );
}

#[tokio::test]
async fn a_record_that_is_a_directory_is_unknown_and_due_and_status_still_succeeds() {
    let fixture = Fixture::new().await;
    fs::create_dir(fixture.path("state/recovery.toml")).unwrap();
    assert_eq!(
        recovery_at(&fixture, BASE).await,
        unknown("the check record is unusable (not_a_regular_file)", true)
    );
}
