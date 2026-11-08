//! `recipient list` end to end over a real admin socket against a running service context on an initialized vault
//! (`design/recipients.md`, "`recipient list`"): the two entries `init` enrols, the refusal outside Ready, and a damaged
//! inventory, which is reported by its code and label and leaves every file as it was.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use common::approval_harness::{captured_logs, mkdir, read_frame, send, spawn_admin};
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
use iron_vault_store::{OsFs, RecipientEntry, RecipientRole, RecipientSet, RecoveryKeySecret, unwrap_identity, wrap_identity};
use secrecy::SecretString;
use tokio::net::UnixStream;
use zeroize::Zeroizing;

const VAULT_PASSPHRASE: &str = "LIST-vault-passphrase-41c7";
const APPROVAL_PASSPHRASE: &str = "LIST-approval-passphrase-9d2e";

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
    let (response, reveals) = exchange(service, AdminRequest::Init, &[vault, vault, approval, approval, b"yes"]).await;
    assert!(matches!(response, AdminResponse::Init { .. }), "{response:?}");
    reveals.into_iter().next().unwrap()
}

async fn unlock(service: &Arc<ServiceContext>) {
    let (response, _) = exchange(service, AdminRequest::Unlock, &[VAULT_PASSPHRASE.as_bytes()]).await;
    assert!(matches!(response, AdminResponse::Success), "{response:?}");
}

async fn list(service: &Arc<ServiceContext>) -> AdminResponse {
    exchange(service, AdminRequest::RecipientList, &[]).await.0
}

fn listed(response: AdminResponse) -> Vec<RecipientEntry> {
    match response {
        AdminResponse::RecipientList { entries } => entries,
        other => panic!("expected the recipient list, got {other:?}"),
    }
}

fn refusal(response: AdminResponse) -> (ErrorCode, String) {
    match response {
        AdminResponse::Error { code, message } => (code, message),
        other => panic!("expected an error, got {other:?}"),
    }
}

/// An initialized, unlocked service.
async fn ready(fixture: &Fixture) -> (Arc<ServiceContext>, String) {
    let service = fixture.start();
    let recovery_key = init(&service).await;
    unlock(&service).await;
    (service, recovery_key)
}

#[tokio::test]
async fn after_init_and_unlock_the_operational_and_recovery_entries_are_listed() {
    let fixture = Fixture::new();
    let (service, _) = ready(&fixture).await;
    let before = fixture.state_files();

    let entries = listed(list(&service).await);

    let shown: Vec<_> = entries
        .iter()
        .map(|entry| (entry.role(), entry.label().as_str().to_owned()))
        .collect();
    assert_eq!(
        shown,
        [
            (RecipientRole::Recovery, "recovery key".to_owned()),
            (RecipientRole::Operational, "vault passphrase".to_owned())
        ]
    );
    assert!(entries.iter().all(|entry| entry.key().to_string().starts_with("age1")));
    assert_eq!(fixture.state_files(), before, "a healthy list writes nothing");
}

#[tokio::test]
async fn the_list_is_refused_in_locked_and_before_init() {
    let fixture = Fixture::new();
    let service = fixture.start();
    assert_eq!(refusal(list(&service).await).0, ErrorCode::WrongState);

    init(&service).await;
    assert_eq!(refusal(list(&service).await).0, ErrorCode::WrongState);

    unlock(&service).await;
    assert!(!listed(list(&service).await).is_empty());
}

#[tokio::test]
async fn a_flipped_byte_in_the_inventory_is_damage_and_changes_nothing() {
    let logs = captured_logs();
    let fixture = Fixture::new();
    let (service, _) = ready(&fixture).await;
    let path = fixture.path("state/recipients.age");
    let mut bytes = fs::read(&path).unwrap();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 1;
    fs::write(&path, bytes).unwrap();
    let before = fixture.state_files();

    let (code, message) = refusal(list(&service).await);

    assert_eq!(code, ErrorCode::RecipientInventoryDamaged);
    assert!(message.contains("nothing was changed"), "{message}");
    assert_eq!(fixture.state_files(), before);
    assert!(logs.has_field("recipient.inventory-damaged", "inventory_damage", &damage_label(&message)));
}

/// The label the message names, in its first parentheses.
fn damage_label(message: &str) -> String {
    message.split(['(', ')']).nth(1).unwrap().to_owned()
}

#[tokio::test]
async fn a_missing_inventory_says_an_older_vault_has_none() {
    let fixture = Fixture::new();
    let (service, _) = ready(&fixture).await;
    fs::remove_file(fixture.path("state/recipients.age")).unwrap();

    let (code, message) = refusal(list(&service).await);

    assert_eq!(code, ErrorCode::RecipientInventoryDamaged);
    assert!(
        message.contains("(missing)") && message.contains("initialized before recipient commands"),
        "{message}"
    );
}

#[tokio::test]
async fn an_identity_envelope_the_inventory_does_not_describe_is_damage() {
    let fixture = Fixture::new();
    let (service, recovery_key) = ready(&fixture).await;
    let keys = listed(list(&service).await)
        .iter()
        .map(|entry| entry.key().clone())
        .collect::<Vec<_>>();
    // The same vault identity wrapped again for the same recipients: a different file, so a different digest.
    let recovery = RecoveryKeySecret::parse(SecretString::from(recovery_key)).unwrap();
    let identity = unwrap_identity(&fs::read(fixture.path("state/identity.age")).unwrap(), &recovery).unwrap();
    fs::write(
        fixture.path("state/identity.age"),
        wrap_identity(&identity, &RecipientSet::new(keys).unwrap()).unwrap(),
    )
    .unwrap();
    let before = fixture.state_files();

    let (code, message) = refusal(list(&service).await);

    assert_eq!(code, ErrorCode::RecipientInventoryDamaged);
    assert!(message.contains("(envelope_mismatch)"), "{message}");
    assert_eq!(fixture.state_files(), before);
}
