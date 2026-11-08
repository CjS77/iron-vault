//! `recipient remove` end to end over a real admin socket against a running service context on an initialized vault
//! (`design/recipients.md`, "`recipient remove <age1…>`"): the removal of an enrolled recipient, the refusals that come
//! before any prompt, the owner presence that must follow the summary, and the sentence about old copies.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use common::approval_harness::{Exchanged, captured_logs, converse, error_code, mkdir, read_frame, send, spawn_admin};
use common::proxy_harness::TempDir;
use iron_vault::admin::protocol::{AdminRequest, AdminResponse, ErrorCode, Frame, OwnerInput};
use iron_vault::deployment::{Accounts, DeploymentProfile, PasswdDirectory};
use iron_vault::hardening::{CoreDumps, HardeningReport, MemoryProtection};
use iron_vault::path_metadata::invoking_user;
use iron_vault::service_context::{ServiceContext, ServiceLocks, ServiceSetup};
use iron_vault::socket_activation::PassedSockets;
use iron_vault::trusted_path_report::ServicePaths;
use iron_vault::upstream::client::TransportLimits;
use iron_vault_policy::Capabilities;
use iron_vault_store::{
    OsFs, RecipientEntry, RecipientIdentity, RecipientInventory, RecipientKey, RecipientLabel, RecipientRole, RecipientSet, RecoveryKey,
    StateFileName, UtcSecond, envelope_digest, open_recipient_inventory, seal_recipient_inventory, unwrap_identity, wrap_identity,
};
use secrecy::{ExposeSecret, SecretString};
use tokio::net::UnixStream;
use zeroize::Zeroizing;

const VAULT_PASSPHRASE: &str = "REMOVE-vault-passphrase-41c7";
const APPROVAL_PASSPHRASE: &str = "REMOVE-approval-passphrase-9d2e";

/// Empty state and config directories in a temporary directory that is also the runtime directory.
struct Fixture {
    dir: TempDir,
}

impl Fixture {
    fn new() -> Self {
        let dir = TempDir::new();
        mkdir(&dir.path().join("state"));
        mkdir(&dir.path().join("etc"));
        Self { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// Starts the service as `serve` does, without systemd sockets: Locked, waiting for an unlock or an init.
    fn start(&self) -> Arc<ServiceContext> {
        let paths = ServicePaths {
            profile: DeploymentProfile::Development,
            owner: invoking_user().unwrap(),
            config: self.path("etc/config.toml"),
            state_dir: self.path("state"),
            runtime_dir: Some(self.dir.path().to_path_buf()),
        };
        let locks = ServiceLocks::acquire(&paths).unwrap();
        let provisional = locks.unverified_listeners(&OsFs);
        let setup = ServiceSetup {
            accounts: PasswdDirectory::new(Accounts::parse(""), &paths, Path::new("/nonexistent")).unwrap(),
            paths,
            fs: OsFs,
            capabilities: Capabilities::default(),
            upstream: iron_vault::config_check::UpstreamSettings::new(
                DeploymentProfile::Development,
                invoking_user().unwrap(),
                TransportLimits::default(),
            ),
            hardening: HardeningReport {
                core_dumps: CoreDumps::Disabled,
                memory: MemoryProtection::Unsupported,
            },
            log: iron_vault::logging::LogSwitch::stdout_for_tests(invoking_user().unwrap()).unwrap(),
        };
        Arc::new(ServiceContext::start(locks, setup, &provisional, PassedSockets::default()).unwrap())
    }

    /// Every file of the state directory with its bytes.
    fn state_files(&self) -> BTreeMap<String, Vec<u8>> {
        fs::read_dir(self.path("state"))
            .unwrap()
            .map(|entry| entry.unwrap())
            .filter(|entry| entry.file_type().unwrap().is_file())
            .map(|entry| (entry.file_name().to_string_lossy().into_owned(), fs::read(entry.path()).unwrap()))
            .collect()
    }
}

/// Sends `request` and answers the prompts in turn with `answers`; the notices and reveals are not needed here, except
/// that the recovery key shown by `init` is returned.
async fn exchange(service: &Arc<ServiceContext>, request: AdminRequest, answers: &[&[u8]]) -> (AdminResponse, Vec<String>) {
    let (path, stop, task) = spawn_admin(service);
    let mut stream = UnixStream::connect(path).await.unwrap();
    send(&mut stream, &Frame::Request(request)).await;
    let (mut answers, mut reveals) = (answers.iter(), Vec::new());
    let response = loop {
        match read_frame(&mut stream).await {
            Frame::Response(response) => break response,
            Frame::Notice(_) => {}
            Frame::Reveal(secret) => reveals.push(String::from_utf8(secret.expose_secret().to_vec()).unwrap()),
            Frame::Prompt(_) => {
                let answer = answers.next().expect("a prompt beyond the answers given");
                send(&mut stream, &Frame::OwnerInput(OwnerInput::new(Zeroizing::new(answer.to_vec())))).await;
            }
            other => panic!("unexpected frame {other:?}"),
        }
    };
    let _ = stop.send(());
    task.await.unwrap();
    (response, reveals)
}

/// Initializes the vault and returns the recovery key shown.
async fn init(service: &Arc<ServiceContext>) -> String {
    let (vault, approval) = (VAULT_PASSPHRASE.as_bytes(), APPROVAL_PASSPHRASE.as_bytes());
    let (response, reveals) = exchange(
        service,
        AdminRequest::Init { host_unlock: false },
        &[vault, vault, approval, approval, b"yes"],
    )
    .await;
    assert!(matches!(response, AdminResponse::Init { .. }), "{response:?}");
    reveals.into_iter().next().unwrap()
}

async fn unlock(service: &Arc<ServiceContext>) {
    let (response, _) = exchange(service, AdminRequest::Unlock, &[VAULT_PASSPHRASE.as_bytes()]).await;
    assert!(matches!(response, AdminResponse::Success), "{response:?}");
}

/// Sends `request` over a new connection and answers its prompts with `answers`.
async fn run(service: &Arc<ServiceContext>, request: AdminRequest, answers: &[&str]) -> Exchanged {
    let (path, stop, task) = spawn_admin(service);
    let mut stream = UnixStream::connect(path).await.unwrap();
    send(&mut stream, &Frame::Request(request)).await;
    let exchanged = converse(&mut stream, answers).await;
    let _ = stop.send(());
    task.await.unwrap();
    exchanged
}

async fn remove(service: &Arc<ServiceContext>, key: &RecipientKey, answers: &[&str]) -> Exchanged {
    run(
        service,
        AdminRequest::RecipientRemove {
            recipient: key.to_string(),
        },
        answers,
    )
    .await
}

async fn entries(service: &Arc<ServiceContext>) -> Vec<RecipientEntry> {
    match run(service, AdminRequest::RecipientList, &[]).await.response {
        AdminResponse::RecipientList { entries } => entries,
        other => panic!("expected the recipient list, got {other:?}"),
    }
}

async fn key_of(service: &Arc<ServiceContext>, role: RecipientRole) -> RecipientKey {
    entries(service)
        .await
        .iter()
        .find(|entry| entry.role() == role)
        .unwrap()
        .key()
        .clone()
}

/// An initialized, unlocked service, and the recovery key `init` showed.
async fn ready(fixture: &Fixture) -> (Arc<ServiceContext>, String) {
    let service = fixture.start();
    let recovery_key = init(&service).await;
    unlock(&service).await;
    (service, recovery_key)
}

async fn run_on(stream: &mut UnixStream, request: AdminRequest, answers: &[&str]) -> Exchanged {
    send(stream, &Frame::Request(request)).await;
    converse(stream, answers).await
}

/// Enrolls a fresh key under `role` the way `recipient add` will: rewraps the vault identity for the larger set and writes
/// both files, with the service idle. Returns the new key's identity.
fn enrol(fixture: &Fixture, recovery_key: &str, role: RecipientRole) -> RecipientIdentity {
    let recovery = RecipientIdentity::parse(&SecretString::from(recovery_key.to_owned())).unwrap();
    let vault = unwrap_identity(&fs::read(fixture.path("state/identity.age")).unwrap(), &recovery).unwrap();
    let current = open_recipient_inventory(&vault, &fs::read(fixture.path("state/recipients.age")).unwrap()).unwrap();
    let (secret, key) = RecoveryKey::generate();
    let added = RecipientEntry::new(
        key,
        role,
        RecipientLabel::new("old laptop").unwrap(),
        UtcSecond::from_unix_seconds(1_700_000_000).unwrap(),
    );
    let entries = current.entries().cloned().chain([added]).collect::<Vec<_>>();
    let keys = entries.iter().map(|entry| entry.key().clone());
    let envelope = wrap_identity(&vault, &RecipientSet::new(keys).unwrap()).unwrap();
    let inventory = RecipientInventory::new(current.vault_id(), envelope_digest(&envelope), entries).unwrap();
    fs::write(fixture.path("state/identity.age"), envelope).unwrap();
    fs::write(
        fixture.path("state/recipients.age"),
        seal_recipient_inventory(&vault, &inventory).unwrap(),
    )
    .unwrap();
    RecipientIdentity::parse(&SecretString::from(secret.expose_secret().to_owned())).unwrap()
}

fn opens_identity(fixture: &Fixture, who: &RecipientIdentity) -> bool {
    unwrap_identity(&fs::read(fixture.path("state/identity.age")).unwrap(), who).is_ok()
}

fn added_key(who: &RecipientIdentity) -> RecipientKey {
    who.recipient_key()
}

const OLD_COPIES: &str = "Old copies of identity.age, and backups, still open with a removed key.";

#[tokio::test]
async fn removing_an_added_recipient_rewraps_the_envelope_and_says_old_copies_still_open() {
    let logs = captured_logs();
    let fixture = Fixture::new();
    let (service, recovery_key) = ready(&fixture).await;
    let laptop = enrol(&fixture, &recovery_key, RecipientRole::Added);
    let recovery = RecipientIdentity::parse(&SecretString::from(recovery_key)).unwrap();
    assert!(opens_identity(&fixture, &laptop));

    let done = remove(&service, &added_key(&laptop), &[APPROVAL_PASSPHRASE]).await;

    assert!(
        matches!(done.response, AdminResponse::RecipientRemove { recipients: 2 }),
        "{done:?}"
    );
    assert_eq!(done.prompts.len(), 1);
    assert_eq!(done.prompts[0].label, "Approval passphrase");
    assert!(
        done.notices.contains("role: added") && done.notices.contains("label: old laptop"),
        "{}",
        done.notices
    );
    assert!(
        done.notices.contains("recipients after the change: 2 (operational 1, recovery 1)"),
        "{}",
        done.notices
    );
    assert!(
        done.notices.contains("authorize with: the approval passphrase\nremoved "),
        "{}",
        done.notices
    );
    assert!(done.notices.ends_with('\n'), "{}", done.notices);
    assert!(done.notices.contains(OLD_COPIES), "{}", done.notices);
    assert!(!opens_identity(&fixture, &laptop), "the removed key must not open the new envelope");
    assert!(opens_identity(&fixture, &recovery));
    let shown = entries(&service).await;
    assert!(shown.iter().all(|entry| entry.key() != &added_key(&laptop)));
    assert_eq!(shown.len(), 2);
    assert!(
        !fixture
            .path("state")
            .join(StateFileName::staged_recipient_inventory().to_string())
            .exists()
    );
    assert!(logs.has_field("recipient.removed", "recipient", &added_key(&laptop).to_string()));
    assert!(logs.has_field("recipient.removed", "recipient_role", "added"));
}

#[tokio::test]
async fn removing_a_recovery_recipient_also_tells_the_owner_to_check_the_key_they_keep() {
    let fixture = Fixture::new();
    let (service, recovery_key) = ready(&fixture).await;
    let second = enrol(&fixture, &recovery_key, RecipientRole::Recovery);

    let done = remove(&service, &added_key(&second), &[APPROVAL_PASSPHRASE]).await;

    assert!(
        matches!(done.response, AdminResponse::RecipientRemove { recipients: 2 }),
        "{done:?}"
    );
    assert!(
        done.notices.contains(OLD_COPIES) && done.notices.contains("recovery check"),
        "{}",
        done.notices
    );
}

#[tokio::test]
async fn the_operational_and_the_last_recovery_recipient_are_refused_before_any_prompt() {
    let logs = captured_logs();
    let fixture = Fixture::new();
    let (service, _) = ready(&fixture).await;
    let before = fixture.state_files();

    for (role, rule) in [(RecipientRole::Operational, "operational"), (RecipientRole::Recovery, "recovery")] {
        let key = key_of(&service, role).await;
        let refused = remove(&service, &key, &[]).await;

        assert_eq!(error_code(&refused.response), ErrorCode::RecipientSetInvalid, "{refused:?}");
        assert!(refused.prompts.is_empty() && refused.notices.is_empty(), "{refused:?}");
        assert!(
            matches!(&refused.response, AdminResponse::Error { message, .. } if message.contains(rule)),
            "{refused:?}"
        );
        assert!(logs.has_field("recipient.change-failed", "recipient", &key.to_string()));
        assert_eq!(fixture.state_files(), before);
    }
    assert!(logs.has_field("recipient.change-failed", "failure", "set_invalid"));
}

#[tokio::test]
async fn an_unknown_or_malformed_key_is_refused_before_any_prompt() {
    let fixture = Fixture::new();
    let (service, _) = ready(&fixture).await;
    let before = fixture.state_files();
    let (_, stranger) = RecoveryKey::generate();

    let unknown = remove(&service, &stranger, &[]).await;
    let malformed = run(
        &service,
        AdminRequest::RecipientRemove {
            recipient: "not a key".to_owned(),
        },
        &[],
    )
    .await;

    assert_eq!(error_code(&unknown.response), ErrorCode::UnknownRecipient);
    assert_eq!(error_code(&malformed.response), ErrorCode::RecipientInvalid);
    [unknown, malformed]
        .iter()
        .for_each(|refused| assert!(refused.prompts.is_empty() && refused.notices.is_empty(), "{refused:?}"));
    assert_eq!(fixture.state_files(), before);
}

#[tokio::test]
async fn a_wrong_approval_passphrase_changes_nothing() {
    let fixture = Fixture::new();
    let (service, recovery_key) = ready(&fixture).await;
    let laptop = enrol(&fixture, &recovery_key, RecipientRole::Added);
    let before = fixture.state_files();

    let denied = remove(&service, &added_key(&laptop), &["wrong-passphrase"]).await;

    assert_eq!(error_code(&denied.response), ErrorCode::ApprovalDenied);
    assert!(!denied.notices.contains(OLD_COPIES));
    assert_eq!(fixture.state_files(), before);
    assert!(opens_identity(&fixture, &laptop));
}

#[tokio::test]
async fn a_cancel_at_the_prompt_changes_nothing_and_releases_the_lock() {
    let fixture = Fixture::new();
    let (service, recovery_key) = ready(&fixture).await;
    let laptop = enrol(&fixture, &recovery_key, RecipientRole::Added);
    let before = fixture.state_files();
    let (path, stop, task) = spawn_admin(&service);
    let mut stream = UnixStream::connect(&path).await.unwrap();
    let request = AdminRequest::RecipientRemove {
        recipient: added_key(&laptop).to_string(),
    };
    send(&mut stream, &Frame::Request(request)).await;
    while !matches!(read_frame(&mut stream).await, Frame::Prompt(_)) {}

    drop(stream);
    let next = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let again = run_on_new(&path).await;
            if !matches!(again.response, AdminResponse::Error { code: ErrorCode::Busy, .. }) {
                break again;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();

    assert!(matches!(next.response, AdminResponse::RecipientList { .. }), "{next:?}");
    assert_eq!(fixture.state_files(), before);
    let _ = stop.send(());
    let _ = task.await;
}

async fn run_on_new(path: &Path) -> Exchanged {
    let mut stream = UnixStream::connect(path).await.unwrap();
    run_on(&mut stream, AdminRequest::RecipientList, &[]).await
}

#[tokio::test]
async fn a_lock_at_the_prompt_cancels_the_removal() {
    let fixture = Fixture::new();
    let (service, recovery_key) = ready(&fixture).await;
    let laptop = enrol(&fixture, &recovery_key, RecipientRole::Added);
    let before = fixture.state_files();
    let (path, stop, task) = spawn_admin(&service);
    let mut stream = UnixStream::connect(&path).await.unwrap();
    let request = AdminRequest::RecipientRemove {
        recipient: added_key(&laptop).to_string(),
    };
    send(&mut stream, &Frame::Request(request)).await;
    while !matches!(read_frame(&mut stream).await, Frame::Prompt(_)) {}

    let locking = tokio::spawn({
        let service = Arc::clone(&service);
        async move { service.lock(std::time::Duration::from_secs(5)).await }
    });
    let cancelled = converse(&mut stream, &[]).await;

    locking.await.unwrap().unwrap();
    assert_eq!(error_code(&cancelled.response), ErrorCode::ApprovalUnavailable);
    assert_eq!(fixture.state_files(), before);
    let _ = stop.send(());
    let _ = task.await;
}

#[tokio::test]
async fn a_removal_is_refused_while_the_service_is_locked() {
    let fixture = Fixture::new();
    let (service, _) = ready(&fixture).await;
    let key = key_of(&service, RecipientRole::Recovery).await;
    service.lock(std::time::Duration::from_secs(5)).await.unwrap();

    let refused = remove(&service, &key, &[]).await;

    assert_eq!(error_code(&refused.response), ErrorCode::WrongState);
    assert!(refused.prompts.is_empty());
}
