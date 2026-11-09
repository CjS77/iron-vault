//! An approved config's `[logging] destination` moves the log at activation (specification §18, §15;
//! `design/audit-logging.md`, "Switching at activation").
//!
//! The service logs through a `LogSwitch` installed as the process-wide subscriber, so records written on the blocking
//! pool (the config check's) reach the files too. A global default can be installed once per process, so one test runs
//! the whole sequence: a move to a usable directory, an approval the pre-check refuses, one whose destination fails at
//! activation, and a config that removes the setting. Directories are checked by their leaf only, since a temp
//! directory's ancestors pass no log directory rule.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use common::approval_harness::{
    APPROVAL_PASSPHRASE, Exchanged, Fixture, approve, approve_request, converse, error_code, read_frame, send, spawn_admin, versions,
};
use iron_vault::admin::protocol::{AdminResponse, ApprovalResult, ErrorCode, Frame, OwnerInput};
use iron_vault::deployment::DeploymentProfile;
use iron_vault::logging::{LOG_FILE_NAME, LogDestination, LogFailure, LogOpener, LogSwitch, subscriber};
use iron_vault::path_metadata::invoking_user;
use iron_vault::service_context::ServiceContext;
use iron_vault::service_state::{FailureReason, ServiceState};
use iron_vault_store::OsFs;
use tokio::net::UnixStream;
use zeroize::Zeroizing;

const APPROVE: [&str; 2] = ["yes", APPROVAL_PASSPHRASE];

/// A log directory at `mode`.
fn log_dir(fixture: &Fixture, name: &str, mode: u32) -> PathBuf {
    let dir = fixture.path(name);
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(mode)).unwrap();
    dir
}

fn records(dir: &Path) -> Vec<serde_json::Value> {
    fs::read_to_string(dir.join(LOG_FILE_NAME))
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn events<'a>(records: &'a [serde_json::Value], event: &str) -> Vec<&'a serde_json::Value> {
    records.iter().filter(|record| record["event"] == event).collect()
}

fn has_message(dir: &Path, message: &str) -> bool {
    records(dir).iter().any(|record| record["message"] == message)
}

fn with_destination(fixture: &Fixture, dir: &Path) -> String {
    format!("{}\n[logging]\ndestination = \"{}\"\n", fixture.config("fx"), dir.display())
}

/// The one `service.log-destination-changed` in `dir`, checked to name both destinations.
fn assert_changed(dir: &Path, to: &Path, from: &Path, version: u64) {
    let records = records(dir);
    let changed = events(&records, "service.log-destination-changed");
    assert_eq!(changed.len(), 1, "{records:?}");
    assert_eq!(changed[0]["log_destination"], to.display().to_string());
    assert_eq!(changed[0]["previous_log_destination"], from.display().to_string());
    assert_eq!(changed[0]["version"], version);
}

/// `config approve` for `config`, running `change` while the confirmation prompt is open: after the pre-check, before
/// the commit and the check at activation.
async fn approve_changing(service: &Arc<ServiceContext>, config: &str, change: impl FnOnce()) -> Exchanged {
    let (path, stop, task) = spawn_admin(service);
    let mut stream = UnixStream::connect(path).await.unwrap();
    send(&mut stream, &approve_request(config)).await;
    while !matches!(read_frame(&mut stream).await, Frame::Prompt(_)) {}
    change();
    send(&mut stream, &Frame::OwnerInput(OwnerInput::new(Zeroizing::new(b"yes".to_vec())))).await;
    let exchanged = converse(&mut stream, &[APPROVAL_PASSPHRASE]).await;
    let _ = stop.send(());
    let _ = task.await;
    exchanged
}

#[tokio::test]
async fn an_approved_destination_moves_the_log_and_an_unusable_one_leaves_it_where_it_is() {
    let fixture = Fixture::new().await;
    let bootstrap = log_dir(&fixture, "log-bootstrap", 0o750);
    let opener = LogOpener::new(
        DeploymentProfile::Development,
        Ok(invoking_user().unwrap()),
        None,
        LogFailure::default(),
    )
    .leaf_only();
    let log = LogSwitch::open(LogDestination::Directory(bootstrap.clone()), opener).unwrap();
    tracing::subscriber::set_global_default(subscriber(log.clone(), DeploymentProfile::Development)).unwrap();
    let service = fixture.start_logging(OsFs, log.clone()).await;
    assert_eq!(service.state().await, ServiceState::Ready);

    // A usable directory: the change event is the old destination's last record and the new one's first.
    let moved = log_dir(&fixture, "log-moved", 0o750);
    let approved = approve(&service, &with_destination(&fixture, &moved), &APPROVE).await;
    assert!(matches!(
        approved.response,
        AdminResponse::ConfigApprove(ApprovalResult { version: 2, .. })
    ));
    tracing::info!("after the move");
    let old = records(&bootstrap);
    assert_eq!(old.last().unwrap()["event"], "service.log-destination-changed", "{old:?}");
    assert_eq!(events(&old, "config.approval-completed").len(), 1, "{old:?}");
    assert_changed(&bootstrap, &moved, &bootstrap, 2);
    assert_eq!(records(&moved)[0]["event"], "service.log-destination-changed");
    assert_changed(&moved, &moved, &bootstrap, 2);
    assert!(has_message(&moved, "after the move") && !has_message(&bootstrap, "after the move"));

    // A directory others can write: the pre-check refuses it, reserves nothing and creates nothing.
    let open_to_all = log_dir(&fixture, "log-open", 0o757);
    let refused = approve(&service, &with_destination(&fixture, &open_to_all), &APPROVE).await;
    assert_eq!(error_code(&refused.response), ErrorCode::ConfigInvalid);
    assert_eq!(versions(&service).await, (Some(2), 2));
    assert!(fs::read_dir(&open_to_all).unwrap().next().is_none());

    // A directory that passes the pre-check, which creates nothing, and that others can write by the time the approval
    // commits fails the check at activation; the log stays where it is.
    let changed = log_dir(&fixture, "log-changed", 0o750);
    let failed = approve_changing(&service, &with_destination(&fixture, &changed), || {
        fs::set_permissions(&changed, fs::Permissions::from_mode(0o757)).unwrap();
    })
    .await;
    assert_eq!(error_code(&failed.response), ErrorCode::CommittedNotActive, "{:?}", failed.response);
    assert_eq!(service.state().await, ServiceState::Unavailable(FailureReason::PolicyInvalid));
    tracing::info!("after the failed move");
    let current = records(&moved);
    let check_failed = events(&current, "config.check-failed");
    assert_eq!(check_failed.len(), 1, "{current:?}");
    assert_eq!(check_failed[0]["unavailable_reason"], "policy_invalid");
    assert_eq!(check_failed[0]["failure"], "log_destination_unusable");
    assert_eq!(check_failed[0]["detail"], "the log directory's mode is too open");
    assert_eq!(check_failed[0]["log_destination"], changed.display().to_string());
    assert!(has_message(&moved, "after the failed move"));
    assert!(!changed.join(LOG_FILE_NAME).exists());
    assert_eq!(log.current(), LogDestination::Directory(moved.clone()));

    // Removing the setting returns to the bootstrap destination.
    let back = approve(&service, &fixture.config("fx"), &APPROVE).await;
    assert!(matches!(
        back.response,
        AdminResponse::ConfigApprove(ApprovalResult { version: 4, .. })
    ));
    assert_eq!(service.state().await, ServiceState::Ready);
    tracing::info!("back at the bootstrap destination");
    assert!(has_message(&bootstrap, "back at the bootstrap destination") && !has_message(&moved, "back at the bootstrap destination"));
    let returned = records(&bootstrap);
    let changes = events(&returned, "service.log-destination-changed");
    assert_eq!(changes.len(), 2, "{returned:?}");
    assert_eq!(changes[1]["previous_log_destination"], moved.display().to_string());
    assert_eq!(events(&records(&moved), "service.log-destination-changed").len(), 2);
    assert!(!log.failure().is_tripped());
}
