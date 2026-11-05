//! An approval-state write whose directory fsync fails is recorded through the JSON layer, in order (specification §3.9,
//! §3.15; `design/audit-logging.md`, "Config approvals and checks"): a settled commit, a reservation, and init's first
//! approval and approval state.
//!
//! A filesystem fails the state-directory fsync after the Nth rename of `approval.age` since it was armed. Every test
//! logs into one captured buffer, so the tests take turns and each reads only the records written during its own run.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};

use common::approval_harness::{APPROVAL_PASSPHRASE, Fixture, approve, assert_audit_record, captured_logs, mkdir};
use common::proxy_harness::TempDir;
use iron_vault::admin::protocol::{AdminResponse, ApprovalResult};
use iron_vault::config_check::UpstreamSettings;
use iron_vault::deployment::{Accounts, DeploymentProfile, PasswdDirectory};
use iron_vault::hardening::{CoreDumps, HardeningReport, MemoryProtection};
use iron_vault::path_metadata::invoking_user;
use iron_vault::service_context::{InitRefusal, ServiceContext, ServiceLocks, ServiceSetup};
use iron_vault::socket_activation::PassedSockets;
use iron_vault::trusted_path_report::ServicePaths;
use iron_vault::upstream::client::TransportLimits;
use iron_vault_policy::Capabilities;
use iron_vault_store::{ApprovalPassphrase, ConfigDigest, INITIAL_CONFIG, InitPassphrases, NewVaultKeys, OsFs, Passphrase, StoreFs};
use secrecy::SecretString;
use serde_json::Value;

/// The tests take turns: they share one log buffer.
static TURN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The real filesystem, except that the directory fsync after the Nth rename of `approval.age` since [`arm`](Self::arm)
/// fails once.
#[derive(Clone, Default)]
struct UncertainFs(Arc<Mutex<Armed>>);

#[derive(Default)]
struct Armed {
    renames_left: Option<usize>,
    fail_next_sync: bool,
    /// Fail the directory fsync after `init.unfinished` is removed, which is init's last step.
    fail_finish: bool,
}

impl UncertainFs {
    fn arm_finish(&self) {
        self.0.lock().unwrap().fail_finish = true;
    }

    fn arm(&self, nth_rename: usize) {
        self.0.lock().unwrap().renames_left = Some(nth_rename);
    }
}

impl StoreFs for UncertainFs {
    type File = fs::File;

    fn create_private(&self, path: &Path) -> io::Result<fs::File> {
        OsFs.create_private(path)
    }

    fn write_all(&self, file: &mut fs::File, bytes: &[u8]) -> io::Result<()> {
        OsFs.write_all(file, bytes)
    }

    fn sync_file(&self, file: &fs::File) -> io::Result<()> {
        OsFs.sync_file(file)
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        OsFs.rename(from, to)?;
        let mut armed = self.0.lock().unwrap();
        if to.file_name().is_some_and(|name| name == "approval.age") {
            armed.renames_left = armed.renames_left.and_then(|left| left.checked_sub(1));
            armed.fail_next_sync |= armed.renames_left == Some(0);
        }
        Ok(())
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        OsFs.remove_file(path)?;
        let mut armed = self.0.lock().unwrap();
        if path.file_name().is_some_and(|name| name == "init.unfinished") {
            armed.fail_next_sync |= armed.fail_finish;
        }
        Ok(())
    }

    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        let mut armed = self.0.lock().unwrap();
        match std::mem::take(&mut armed.fail_next_sync) {
            true => {
                armed.renames_left = None;
                Err(io::Error::from(io::ErrorKind::StorageFull))
            }
            false => OsFs.sync_dir(dir),
        }
    }

    fn list_dir(&self, dir: &Path) -> io::Result<Vec<OsString>> {
        OsFs.list_dir(dir)
    }

    fn read_bounded(&self, path: &Path, max_len: u64) -> io::Result<Vec<u8>> {
        OsFs.read_bounded(path, max_len)
    }
}

/// The records written after byte `from` of the log whose event is one of `events`, in order.
fn records_since(from: usize, events: &[&str]) -> Vec<Value> {
    captured_logs()
        .text()
        .get(from..)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|record| events.iter().any(|event| record["event"] == *event))
        .collect()
}

fn names(records: &[Value]) -> Vec<&str> {
    records.iter().map(|record| record["event"].as_str().unwrap()).collect()
}

fn assert_uncertain_state_record(record: &Value) {
    assert_audit_record(record, "ERROR", &["file", "error_kind"]);
    assert_eq!(
        (record["file"].as_str(), record["error_kind"].as_str()),
        (Some("approval.age"), Some("storage_full"))
    );
}

const APPROVAL_EVENTS: [&str; 5] = [
    "config.version-reserved",
    "config.commit-uncertain",
    "vault.commit-uncertain",
    "config.approval-completed",
    "config.approval-failed",
];

#[tokio::test]
async fn a_settled_commit_logs_the_reservation_the_uncertain_commit_and_the_completion_in_order() {
    let _turn = TURN.lock().await;
    let fixture = Fixture::new().await;
    let fs = UncertainFs::default();
    let service = fixture.ready_on(fs.clone()).await;
    let from = captured_logs().text().len();
    // Version 2's reservation is the first rename of `approval.age`, its commit the second.
    fs.arm(2);

    let approved = approve(&service, &fixture.config("rates"), &["yes", APPROVAL_PASSPHRASE]).await;

    assert!(
        matches!(approved.response, AdminResponse::ConfigApprove(ApprovalResult { version: 2, .. })),
        "{approved:?}"
    );
    let records = records_since(from, &APPROVAL_EVENTS);
    assert_eq!(
        names(&records),
        [
            "config.version-reserved",
            "config.commit-uncertain",
            "vault.commit-uncertain",
            "config.approval-completed"
        ],
        "{records:?}"
    );
    assert_audit_record(&records[1], "WARN", &["version", "error_kind"]);
    assert_eq!(
        (records[1]["version"].as_u64(), records[1]["error_kind"].as_str()),
        (Some(2), Some("storage_full"))
    );
    assert_uncertain_state_record(&records[2]);
}

#[tokio::test]
async fn a_reservation_whose_fsync_fails_logs_the_uncertain_write_and_no_reserved_version() {
    let _turn = TURN.lock().await;
    let fixture = Fixture::new().await;
    let fs = UncertainFs::default();
    let service = fixture.ready_on(fs.clone()).await;
    let from = captured_logs().text().len();
    fs.arm(1);

    let failed = approve(&service, &fixture.config("rates"), &["yes", APPROVAL_PASSPHRASE]).await;

    assert!(matches!(failed.response, AdminResponse::Error { .. }), "{failed:?}");
    let records = records_since(from, &APPROVAL_EVENTS);
    assert_eq!(names(&records), ["vault.commit-uncertain", "config.approval-failed"], "{records:?}");
    assert_uncertain_state_record(&records[0]);
}

/// Empty state and config directories and a service over `fs`, Locked and waiting for an init.
struct InitFixture {
    dir: TempDir,
}

impl InitFixture {
    fn new() -> Self {
        let dir = TempDir::new();
        mkdir(&dir.path().join("state"));
        mkdir(&dir.path().join("etc"));
        Self { dir }
    }

    fn start(&self, fs: UncertainFs) -> ServiceContext<UncertainFs> {
        let paths = ServicePaths {
            profile: DeploymentProfile::Development,
            owner: invoking_user().unwrap(),
            config: self.dir.path().join("etc/config.toml"),
            state_dir: self.dir.path().join("state"),
            runtime_dir: Some(self.dir.path().to_path_buf()),
        };
        let locks = ServiceLocks::acquire(&paths).unwrap();
        let provisional = locks.unverified_listeners(&fs);
        let setup = ServiceSetup {
            accounts: PasswdDirectory::new(Accounts::parse(""), &paths, Path::new("/nonexistent")).unwrap(),
            paths,
            fs,
            capabilities: Capabilities::default(),
            upstream: UpstreamSettings::new(DeploymentProfile::Development, invoking_user().unwrap(), TransportLimits::default()),
            hardening: HardeningReport {
                core_dumps: CoreDumps::Disabled,
                memory: MemoryProtection::Unsupported,
            },
            log: iron_vault::logging::LogSwitch::stdout_for_tests(invoking_user().unwrap()).unwrap(),
        };
        ServiceContext::start(locks, setup, &provisional, PassedSockets::default()).unwrap()
    }
}

const INIT_EVENTS: [&str; 6] = [
    "config.version-reserved",
    "config.commit-uncertain",
    "vault.commit-uncertain",
    "config.approval-completed",
    "vault.initialized",
    "vault.init-failed",
];

async fn init_with_fault(nth_rename: usize, fail_finish: bool) -> (Result<(), InitRefusal>, Vec<Value>) {
    let fixture = InitFixture::new();
    let fs = UncertainFs::default();
    let service = fixture.start(fs.clone());
    let from = captured_logs().text().len();
    fs.arm(nth_rename);
    if fail_finish {
        fs.arm_finish();
    }
    let vault = Passphrase::new(SecretString::from("INIT-vault-passphrase-41c7")).unwrap();
    let approval = ApprovalPassphrase::new(SecretString::from(APPROVAL_PASSPHRASE)).unwrap();
    let keys = NewVaultKeys::generate().unwrap().into_sealing();
    let result = service
        .initialize(keys, InitPassphrases::new(vault, approval).unwrap())
        .await
        .map(drop);
    (result, records_since(from, &INIT_EVENTS))
}

#[tokio::test]
async fn an_uncertain_commit_at_init_step_8_logs_the_pair_before_the_vault_is_initialized() {
    let _turn = TURN.lock().await;
    // `approval.age` is created (1), version 1 reserved (2) and committed (3).
    let (result, records) = init_with_fault(3, false).await;

    assert!(result.is_ok(), "{result:?}");
    assert_eq!(
        names(&records),
        [
            "config.version-reserved",
            "config.commit-uncertain",
            "vault.commit-uncertain",
            "config.approval-completed",
            "vault.initialized"
        ],
        "{records:?}"
    );
    assert_eq!(
        (records[1]["version"].as_u64(), records[1]["error_kind"].as_str()),
        (Some(1), Some("storage_full"))
    );
    assert_uncertain_state_record(&records[2]);
}

#[tokio::test]
async fn an_uncertain_approval_state_creation_at_init_step_6_logs_the_write_before_the_failed_step() {
    let _turn = TURN.lock().await;

    let (result, records) = init_with_fault(1, false).await;

    assert!(matches!(result, Err(InitRefusal::Failed(_))), "{result:?}");
    assert_eq!(names(&records), ["vault.commit-uncertain", "vault.init-failed"], "{records:?}");
    assert_uncertain_state_record(&records[0]);
    assert_eq!(records[1]["step"], "6");
}

#[tokio::test]
async fn a_failure_at_init_step_9_still_logs_the_committed_first_approval_before_the_failed_step() {
    let _turn = TURN.lock().await;
    // Step 8's commit is uncertain, then the fsync after the removal of `init.unfinished` fails.
    let (result, records) = init_with_fault(3, true).await;

    assert!(matches!(result, Err(InitRefusal::Failed(_))), "{result:?}");
    assert_eq!(
        names(&records),
        [
            "config.version-reserved",
            "config.commit-uncertain",
            "vault.commit-uncertain",
            "config.approval-completed",
            "vault.init-failed"
        ],
        "{records:?}"
    );
    assert_uncertain_state_record(&records[2]);
    assert_eq!(records[0]["version"].as_u64(), Some(1));
    assert_eq!(records[0]["config_digest"], ConfigDigest::of(INITIAL_CONFIG).to_string().as_str());
    assert_eq!(records[4]["step"], "9");
}
