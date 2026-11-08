//! A real service on an empty state directory, driven over the admin socket by the recipient command tests: `init`,
//! `unlock`, and a snapshot of every state file's bytes.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::approval_harness::{mkdir, read_frame, send, spawn_admin};
use super::proxy_harness::TempDir;
use iron_vault::admin::protocol::{AdminRequest, AdminResponse, ErrorCode, Frame, OwnerInput};
use iron_vault::deployment::{Accounts, DeploymentProfile, PasswdDirectory};
use iron_vault::hardening::{CoreDumps, HardeningReport, MemoryProtection};
use iron_vault::path_metadata::invoking_user;
use iron_vault::service_context::{ServiceContext, ServiceLocks, ServiceSetup};
use iron_vault::socket_activation::PassedSockets;
use iron_vault::trusted_path_report::ServicePaths;
use iron_vault::upstream::client::TransportLimits;
use iron_vault_policy::Capabilities;
use iron_vault_store::{OsFs, RecipientEntry};
use tokio::net::UnixStream;
use zeroize::Zeroizing;

pub const VAULT_PASSPHRASE: &str = "LIST-vault-passphrase-41c7";
pub const APPROVAL_PASSPHRASE: &str = "LIST-approval-passphrase-9d2e";

/// Empty state and config directories in a temporary directory that is also the runtime directory.
pub struct Fixture {
    dir: TempDir,
}

impl Fixture {
    pub fn new() -> Self {
        let dir = TempDir::new();
        mkdir(&dir.path().join("state"));
        mkdir(&dir.path().join("etc"));
        Self { dir }
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// Starts the service as `serve` does, without systemd sockets: Locked, waiting for an unlock or an init.
    pub fn start(&self) -> Arc<ServiceContext> {
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
    pub fn state_files(&self) -> BTreeMap<String, Vec<u8>> {
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
pub async fn exchange(service: &Arc<ServiceContext>, request: AdminRequest, answers: &[&[u8]]) -> (AdminResponse, Vec<String>) {
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
pub async fn init(service: &Arc<ServiceContext>) -> String {
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

pub async fn unlock(service: &Arc<ServiceContext>) {
    let (response, _) = exchange(service, AdminRequest::Unlock, &[VAULT_PASSPHRASE.as_bytes()]).await;
    assert!(matches!(response, AdminResponse::Success), "{response:?}");
}

pub async fn list(service: &Arc<ServiceContext>) -> AdminResponse {
    exchange(service, AdminRequest::RecipientList, &[]).await.0
}

pub fn listed(response: AdminResponse) -> Vec<RecipientEntry> {
    match response {
        AdminResponse::RecipientList { entries } => entries,
        other => panic!("expected the recipient list, got {other:?}"),
    }
}

pub fn refusal(response: AdminResponse) -> (ErrorCode, String) {
    match response {
        AdminResponse::Error { code, message } => (code, message),
        other => panic!("expected an error, got {other:?}"),
    }
}

/// An initialized, unlocked service.
pub async fn ready(fixture: &Fixture) -> (Arc<ServiceContext>, String) {
    let service = fixture.start();
    let recovery_key = init(&service).await;
    unlock(&service).await;
    (service, recovery_key)
}
