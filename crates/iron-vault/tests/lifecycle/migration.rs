//! The migration release checks ([§19](../../../design/iron-vault-specification.md); design/migration-bundle.md,
//! "Release checks"): one test per part of "Export/import preserves records, counters, recovery access, and the service
//! boundary without writing plaintext secret artifacts". Each moves a vault from a source service to a destination
//! service with state and config directories of its own.
//!
//! A test that routes through the destination exports a source of its own, because the bundled config's listener is a
//! socket in the source's directory and its route forwards to the source's test upstream. Each import runs scrypt at
//! 256 MiB twice, so one test runs at a time.

#![cfg(target_os = "linux")]

use crate::common;

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::export::one_at_a_time;
use common::approval_harness::{
    APPROVAL_PASSPHRASE, Captured, Exchanged, Fixture, IDENTITY, approve, captured_logs, converse, converse_revealing, error_code, get,
    identity, mkdir, send, service_locks, shutdown, spawn_admin, spawn_owner_admin, versions,
};
use common::cli_import::{CliImport, CliRan};
use common::handoff_dir::HandoffDir;
use common::migration_source::{EXPORT_PASSPHRASE, SOURCE_PASSPHRASE, Source, fresh_source, send_bundle, source, write_ignoring_errors};
use common::proxy_harness::TempDir;
use common::shared_fs::SharedFs;
use flate2::Compression;
use iron_vault::admin::protocol::{self, AdminRequest, AdminResponse, ApprovalResult, ErrorCode, Frame, ImportResult, VaultStatus};
use iron_vault::config_check::UpstreamSettings;
use iron_vault::deployment::{Accounts, DeploymentProfile, PasswdDirectory};
use iron_vault::hardening::{CoreDumps, HardeningReport, MemoryProtection};
use iron_vault::logging::LogSwitch;
use iron_vault::path_metadata::invoking_user;
use iron_vault::service_context::{ServiceContext, ServiceSetup};
use iron_vault::service_state::{FailureReason, ServiceState};
use iron_vault::socket_activation::PassedSockets;
use iron_vault::trusted_path_report::ServicePaths;
use iron_vault::upstream::client::TransportLimits;
use iron_vault_policy::Capabilities;
use iron_vault_store::fault_fs::FsCall;
use iron_vault_store::migration_bundle::{BundleDecoder, EntryName, MAX_BUNDLE_LEN};
use iron_vault_store::{OsFs, RecipientRole, RecoveryKey, RecoveryKeySecret, StoreFs, VaultIdentity, open_manifest, unwrap_identity};
use secrecy::{ExposeSecret, SecretString};
use tokio::net::UnixStream;

const DEST_PASSPHRASE: &str = "DEST-vault-passphrase-6e0d";
/// The source's one credential's secret.
const FX_SECRET: &str = "fx-secret";
/// The answers of an owner who knows the export passphrase, chooses a vault passphrase and confirms the recovery key.
const COMPLETE: [&str; 4] = [EXPORT_PASSPHRASE, DEST_PASSPHRASE, DEST_PASSPHRASE, "yes"];

/// The destination: empty state and config directories in a temporary directory that is also the runtime directory.
struct Dest {
    dir: TempDir,
}

impl Dest {
    fn new() -> Self {
        let dir = TempDir::new();
        mkdir(&dir.path().join("state"));
        mkdir(&dir.path().join("etc"));
        Self { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn start(&self, source: &Source) -> Arc<ServiceContext> {
        self.start_on(source, OsFs)
    }

    /// The development service on this destination's directories through `fs`.
    fn start_on<F: StoreFs + Send + Sync + 'static>(&self, source: &Source, fs: F) -> Arc<ServiceContext<F>> {
        Arc::new(self.context_as(source, DeploymentProfile::Development, MemoryProtection::Unsupported, fs))
    }

    /// The service of `profile` on this destination's directories through `fs`, trusting the source's test upstream.
    fn context_as<F: StoreFs + Send + Sync + 'static>(
        &self,
        source: &Source,
        profile: DeploymentProfile,
        memory: MemoryProtection,
        fs: F,
    ) -> ServiceContext<F> {
        let paths = ServicePaths {
            profile,
            owner: invoking_user().unwrap(),
            config: self.path("etc/config.toml"),
            state_dir: self.path("state"),
            runtime_dir: Some(self.dir.path().to_path_buf()),
        };
        let locks = service_locks(&paths);
        let provisional = locks.unverified_listeners(&fs);
        let setup = ServiceSetup {
            accounts: PasswdDirectory::new(Accounts::parse(""), &paths, Path::new("/nonexistent")).unwrap(),
            paths,
            fs,
            capabilities: Capabilities::default(),
            upstream: UpstreamSettings::new(DeploymentProfile::Development, invoking_user().unwrap(), TransportLimits::default())
                .with_pinned_trust(source.fixture.ca().trust()),
            hardening: HardeningReport {
                core_dumps: CoreDumps::Disabled,
                memory,
            },
            log: LogSwitch::stdout_for_tests(invoking_user().unwrap()).unwrap(),
        };
        ServiceContext::start(locks, setup, &provisional, PassedSockets::default()).unwrap()
    }

    /// Every file in the state and config directories with its bytes, the lock files included.
    fn files(&self) -> Vec<(PathBuf, Vec<u8>)> {
        [regular_files(&self.path("state")), regular_files(&self.path("etc"))].concat()
    }

    /// The config directory's file names, without its lock file.
    fn config_files(&self) -> Vec<String> {
        let mut names: Vec<_> = fs::read_dir(self.path("etc"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name != "config.toml.lock")
            .collect();
        names.sort();
        names
    }
}

/// Every regular file under `dir`, recursively and sorted, with its bytes; sockets are left out.
fn regular_files(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut paths: Vec<_> = fs::read_dir(dir).unwrap().map(|entry| entry.unwrap().path()).collect();
    paths.sort();
    paths
        .into_iter()
        .flat_map(|path| match (path.is_dir(), path.is_file()) {
            (true, _) => regular_files(&path),
            (false, true) => vec![(path.clone(), fs::read(&path).unwrap())],
            (false, false) => Vec::new(),
        })
        .collect()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

/// Sends `import` with `bundle` and answers the prompts with `answers`; returns the exchange and the secrets revealed.
async fn import<F: StoreFs + Send + Sync + 'static>(
    service: &Arc<ServiceContext<F>>,
    bundle: &[u8],
    answers: &[&str],
) -> (Exchanged, Vec<String>) {
    import_with(service, false, bundle, answers).await
}

/// [`import`] with the host unlock flag as `host_unlock` says.
async fn import_with<F: StoreFs + Send + Sync + 'static>(
    service: &Arc<ServiceContext<F>>,
    host_unlock: bool,
    bundle: &[u8],
    answers: &[&str],
) -> (Exchanged, Vec<String>) {
    let (path, stop, task) = spawn_owner_admin(service);
    let mut stream = UnixStream::connect(path).await.unwrap();
    send(&mut stream, &Frame::Request(AdminRequest::Import { host_unlock })).await;
    send_bundle(&mut stream, bundle).await;
    let (exchanged, revealed) = converse_revealing(&mut stream, answers).await;
    let _ = stop.send(());
    task.await.unwrap();
    let revealed = revealed
        .iter()
        .map(|secret| String::from_utf8(secret.expose_secret().to_vec()).unwrap())
        .collect();
    (exchanged, revealed)
}

/// Sends `request` and answers the prompts with `answers`.
async fn request<F: StoreFs + Send + Sync + 'static>(
    service: &Arc<ServiceContext<F>>,
    request: AdminRequest,
    answers: &[&str],
) -> Exchanged {
    let (path, stop, task) = spawn_admin(service);
    let mut stream = UnixStream::connect(path).await.unwrap();
    send(&mut stream, &Frame::Request(request)).await;
    let exchanged = converse(&mut stream, answers).await;
    let _ = stop.send(());
    task.await.unwrap();
    exchanged
}

/// Stops the destination and starts it again, which binds the bundled config's listener in place of the source's.
async fn restart(dest: &Dest, source: &Source, service: Arc<ServiceContext>) -> Arc<ServiceContext> {
    shutdown(service).await;
    let _ = fs::remove_file(source.fixture.socket());
    dest.start(source)
}

/// What a complete import into a new destination left: the destination, its service restarted and Locked, the import's
/// result and the recovery key it revealed.
struct Imported {
    dest: Dest,
    service: Arc<ServiceContext>,
    result: ImportResult,
    recovery_key: String,
}

async fn imported(source: &Source) -> Imported {
    let dest = Dest::new();
    let service = dest.start(source);
    let (shown, mut revealed) = import(&service, &source.bytes, &COMPLETE).await;
    let AdminResponse::Import(result) = shown.response else {
        panic!("expected an import, got {shown:?}")
    };
    let service = restart(&dest, source, service).await;
    Imported {
        dest,
        service,
        result,
        recovery_key: revealed.remove(0),
    }
}

/// Unlocks the destination, which ends Unavailable for want of a signature, and approves the source's config on it.
async fn unlock_and_approve(source: &Source, service: &Arc<ServiceContext>) -> u64 {
    request(service, AdminRequest::Unlock, &[DEST_PASSPHRASE]).await;
    assert_eq!(service.state().await, ServiceState::Unavailable(FailureReason::PolicyInvalid));
    let (_, version) = approve_config(service, &source_config(source)).await;
    version
}

fn source_config(source: &Source) -> String {
    fs::read_to_string(source.fixture.path("etc/config.toml")).unwrap()
}

/// Approves `config` on `service` with the source's approver and returns the version committed.
async fn approve_config(service: &Arc<ServiceContext>, config: &str) -> (Exchanged, u64) {
    let approved = approve(service, config, &["yes", APPROVAL_PASSPHRASE]).await;
    match &approved.response {
        AdminResponse::ConfigApprove(ApprovalResult { version, .. }) => {
            let version = *version;
            (approved, version)
        }
        other => panic!("expected an approval, got {other:?}"),
    }
}

/// The record IDs and names a vault's manifest lists.
fn manifest_entries(state_dir: &Path) -> Vec<(String, String)> {
    let manifest = open_manifest(&identity(), &fs::read(state_dir.join("manifest.age")).unwrap()).unwrap();
    manifest
        .entries()
        .iter()
        .map(|(id, entry)| (id.to_string(), entry.name().to_string()))
        .collect()
}

/// The record files under `state_dir`, by name, with their bytes.
fn record_files(state_dir: &Path) -> Vec<(String, Vec<u8>)> {
    regular_files(state_dir)
        .into_iter()
        .map(|(path, bytes)| (path.file_name().unwrap().to_string_lossy().into_owned(), bytes))
        .filter(|(name, _)| name.starts_with("record-"))
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn export_import_preserves_records() {
    let _one = one_at_a_time().await;
    let source = fresh_source(false).await;
    let source_state = source.fixture.path("state");

    let Imported { dest, service, .. } = imported(&source).await;

    assert_eq!(manifest_entries(&dest.path("state")), manifest_entries(&source_state));
    assert_eq!(record_files(&dest.path("state")), record_files(&source_state));
    assert_eq!(record_files(&source_state).len() as u64, source.records);
    unlock_and_approve(&source, &service).await;
    assert_eq!(get(&source.fixture, "fx").await.status, 200);
    let sent = source.fixture.upstream().requests().pop().unwrap();
    let key = sent.headers().into_iter().find(|(name, _)| name.eq_ignore_ascii_case("x-api-key"));
    assert_eq!(key.map(|(_, value)| value).as_deref(), Some(FX_SECRET));
}

#[tokio::test(flavor = "multi_thread")]
async fn export_import_preserves_counters() {
    let _one = one_at_a_time().await;
    let logs = captured_logs();
    let source = fresh_source(true).await;
    assert_eq!((source.committed, source.highest_reserved), (1, 2));
    let old_pair = source.fixture.published_pair();

    let Imported { dest, service, result, .. } = imported(&source).await;

    assert_eq!((result.version, result.highest_reserved), (1, 2));
    let stored = |dir: &Path| fs::read(dir.join("approval.age")).unwrap();
    assert_eq!(
        stored(&dest.path("state")),
        stored(&source.fixture.path("state")),
        "import copies approval.age unchanged"
    );
    let version = unlock_and_approve(&source, &service).await;
    assert_eq!(version, 3, "the first approval commits the highest reserved version plus one");
    assert_eq!(versions(&service).await, (Some(3), 3));
    ["config.toml", "config.toml.sig"]
        .iter()
        .zip(&old_pair)
        .for_each(|(file, bytes)| fs::write(dest.path(&format!("etc/{file}")), bytes).unwrap());
    let superseded = || superseded_refusals(&logs);
    let before = superseded();
    assert_eq!(service.reload().await, Ok(ServiceState::Unavailable(FailureReason::PolicyInvalid)));
    assert_eq!(superseded(), before + 1, "the old pair was not refused as superseded");
}

/// The `config.check-failed` records that refuse an approval of version 1 as superseded by a committed version 3.
fn superseded_refusals(logs: &Captured) -> usize {
    let superseded = "the config approval is for version 1, but version 3 is committed";
    logs.events("config.check-failed")
        .iter()
        .filter(|record| record["detail"].as_str().is_some_and(|detail| detail.contains(superseded)))
        .count()
}

/// Runs `iron-vault import <bundle>` against `service` as an owner who completes it, in the bundle's directory.
async fn cli_import(service: &Arc<ServiceContext>, bundle: &Path) -> CliRan {
    let (socket, stop, task) = spawn_admin(service);
    let (cwd, bundle) = (bundle.parent().unwrap().to_path_buf(), bundle.to_path_buf());
    let ran = tokio::task::spawn_blocking(move || {
        let answers = COMPLETE.map(str::as_bytes);
        CliImport::start(&socket, &bundle, &cwd).finish(&answers)
    })
    .await
    .unwrap();
    let _ = stop.send(());
    task.await.unwrap();
    ran
}

fn config_copy(bundle: &Path) -> PathBuf {
    PathBuf::from(format!("{}.config.toml", bundle.display()))
}

#[tokio::test(flavor = "multi_thread")]
async fn import_routes_only_after_new_approval() {
    let _one = one_at_a_time().await;
    let source = fresh_source(false).await;
    let carried = TempDir::new();
    let bundle = carried.path().join("vault.bundle");
    fs::write(&bundle, &source.bytes).unwrap();
    let dest = Dest::new();
    let service = dest.start(&source);

    let ran = cli_import(&service, &bundle).await;

    assert_eq!(ran.code, Some(0), "{ran:?}");
    assert_eq!(dest.config_files(), ["config.toml"]);
    assert_eq!(fs::read_to_string(dest.path("etc/config.toml")).unwrap(), source_config(&source));
    let service = restart(&dest, &source, service).await;
    request(&service, AdminRequest::Unlock, &[DEST_PASSPHRASE]).await;
    assert_eq!(service.state().await, ServiceState::Unavailable(FailureReason::PolicyInvalid));
    assert_eq!(get(&source.fixture, "fx").await.status, 503);
    let copy = fs::read_to_string(config_copy(&bundle)).unwrap();
    assert_eq!(copy, source_config(&source));

    let (approved, _) = approve_config(&service, &copy).await;

    assert!(approved.notices.contains("no active config"), "{}", approved.notices);
    ["+ local", "+ agent", "+ fx"]
        .iter()
        .for_each(|added| assert!(approved.notices.contains(added), "{added} not in {}", approved.notices));
    assert_eq!(service.state().await, ServiceState::Ready);
    assert_eq!(get(&source.fixture, "fx").await.status, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn import_recovery_key_opens_destination() {
    let _one = one_at_a_time().await;
    let source = fresh_source(false).await;

    let Imported {
        dest: _dest,
        service,
        recovery_key,
        ..
    } = imported(&source).await;

    let checked = request(&service, AdminRequest::RecoveryCheck, &[&recovery_key]).await;
    assert!(
        matches!(checked.response, AdminResponse::RecoveryCheck { vault_id, .. } if vault_id == source.vault_id),
        "{checked:?}"
    );
    let old_key = request(&service, AdminRequest::RecoveryCheck, &[&source.recovery_key]).await;
    assert_eq!(error_code(&old_key.response), ErrorCode::RecoveryCheckFailed);
}

#[tokio::test(flavor = "multi_thread")]
async fn export_bundle_holds_no_plaintext_secret() {
    let _one = one_at_a_time().await;
    let source = fresh_source(false).await;
    let carried = TempDir::new();
    let bundle = carried.path().join("vault.bundle");
    let exporting = source.fixture.ready().await;
    let (socket, stop, task) = spawn_admin(&exporting);
    let input = format!("{SOURCE_PASSPHRASE}\n{EXPORT_PASSPHRASE}\n{EXPORT_PASSPHRASE}\n");
    let exported = super::export::run_export(&socket, &bundle, &input).await;
    let _ = stop.send(());
    task.await.unwrap();
    shutdown(exporting).await;
    assert_eq!(exported.code, Some(0), "{exported:?}");
    let dest = Dest::new();

    let ran = cli_import(&dest.start(&source), &bundle).await;

    assert_eq!(ran.code, Some(0), "{ran:?}");
    let output = [exported.stdout, exported.stderr, ran.stdout, ran.stderr].concat();
    let bytes = fs::read(&bundle).unwrap();
    let files = [
        regular_files(carried.path()),
        regular_files(&source.fixture.path("")),
        regular_files(&dest.path("")),
    ]
    .concat();
    let secrets = [FX_SECRET.to_owned(), IDENTITY.to_owned(), IDENTITY.to_lowercase()];
    secrets.iter().for_each(|secret| {
        assert!(!output.contains(secret), "a secret reached the CLI's output");
        files
            .iter()
            .for_each(|(path, held)| assert!(!contains(held, secret.as_bytes()), "a secret reached {}", path.display()));
    });
    assert_no_approver_key_in_the_clear(&source, &bytes);
    let dest_identity = fs::read(dest.path("state/identity.age")).unwrap();
    assert!(
        !contains(&dest_identity, b"scrypt"),
        "the destination's identity.age has a scrypt stanza"
    );
}

/// No entry of the bundle's archive holds a source approver key envelope's bytes. The gzip-compressed bundle itself is
/// not searched: compression would hide an envelope from a byte search anyway.
fn assert_no_approver_key_in_the_clear(source: &Source, bundle: &[u8]) {
    let mut decoder = BundleDecoder::new();
    decoder.push(bundle).unwrap();
    let decoded = decoder.finish().unwrap();
    let envelopes: Vec<_> = regular_files(&source.fixture.path("state"))
        .into_iter()
        .filter(|(path, _)| path.file_name().unwrap().to_string_lossy().starts_with("approver-"))
        .map(|(_, bytes)| bytes)
        .collect();
    assert!(!envelopes.is_empty());
    envelopes.iter().for_each(|envelope| {
        decoded
            .entries()
            .for_each(|(name, bytes)| assert!(!contains(bytes, envelope), "{name} holds an approver key envelope in the clear"));
    });
}

#[tokio::test(flavor = "multi_thread")]
async fn import_requires_export_passphrase() {
    let _one = one_at_a_time().await;
    let source = source().await;
    let dest = Dest::new();
    let service = dest.start(source);
    let before = dest.files();

    let (shown, revealed) = import(&service, &source.bytes, &["EXPORT-wrong-guess-1f0c"]).await;

    assert_eq!(error_code(&shown.response), ErrorCode::ImportDenied);
    assert!(revealed.is_empty());
    assert_eq!(dest.files(), before);
}

#[tokio::test(flavor = "multi_thread")]
async fn import_refuses_initialized_vault() {
    let _one = one_at_a_time().await;
    let source = source().await;
    let initialized = Fixture::new().await;
    let service = initialized.ready().await;
    service.lock(std::time::Duration::from_secs(5)).await.unwrap();
    let initialized_files = || [regular_files(&initialized.path("state")), regular_files(&initialized.path("etc"))].concat();
    let before = initialized_files();

    let (shown, _) = import(&service, &source.bytes, &COMPLETE).await;

    assert_eq!(error_code(&shown.response), ErrorCode::AlreadyInitialized);
    assert_eq!(initialized_files(), before);

    let unrecognized = Dest::new();
    fs::write(unrecognized.path("state/foreign-notes.txt"), b"mine").unwrap();
    let service = unrecognized.start(source);
    let before = unrecognized.files();

    let (shown, _) = import(&service, &source.bytes, &COMPLETE).await;

    assert_eq!(error_code(&shown.response), ErrorCode::AlreadyInitialized);
    assert_eq!(unrecognized.files(), before);
}

/// A destination of `profile` with locked memory whose unlock handoff is `handoff`, Locked after startup.
async fn host_unlock_dest(dest: &Dest, source: &Source, profile: DeploymentProfile, handoff: &Path) -> Arc<ServiceContext> {
    let service = dest
        .context_as(source, profile, MemoryProtection::Locked, OsFs)
        .with_handoff_path(handoff.to_path_buf());
    assert_eq!(service.unlock_at_start(&dest.path("no-handoff")).await, ServiceState::Locked);
    Arc::new(service)
}

/// The vault identity in `dest`'s `identity.age`, opened with the age secret key `secret`.
fn open_identity_with(dest: &Dest, secret: &str) -> VaultIdentity {
    let key = RecoveryKeySecret::parse(SecretString::from(secret.to_owned())).unwrap();
    unwrap_identity(&fs::read(dest.path("state/identity.age")).unwrap(), &key).unwrap()
}

/// The `migration.imported` records that name the host unlock recipient. Only this test writes one into the shared log,
/// so each profile's pass proves its own import by adding exactly one.
fn host_unlock_imports(logs: &Captured) -> usize {
    logs.events("migration.imported")
        .iter()
        .filter(|record| record["recipients"] == "operational,recovery,host-unlock")
        .count()
}

#[tokio::test(flavor = "multi_thread")]
async fn import_host_unlock_enrolls_recipient() {
    let _one = one_at_a_time().await;
    let logs = captured_logs();
    let source = source().await;
    for profile in [DeploymentProfile::Protected, DeploymentProfile::Container] {
        enrols_the_handoffs_identity(source, profile, &logs).await;
        refuses_an_absent_handoff(source, profile).await;
    }
}

/// `import --host-unlock` wraps the vault identity for the handoff's identity beside the operational and recovery
/// recipients, each opens `identity.age`, and a restart reaches the config check from the handoff alone.
async fn enrols_the_handoffs_identity(source: &Source, profile: DeploymentProfile, logs: &Captured) {
    let dest = Dest::new();
    let host_secret = RecoveryKey::generate().0.expose_secret().to_owned();
    let handoff = HandoffDir::new();
    let handoff_path = handoff.write(&host_secret);
    let service = host_unlock_dest(&dest, source, profile, &handoff_path).await;
    let before = host_unlock_imports(logs);

    let (shown, revealed) = import_with(&service, true, &source.bytes, &COMPLETE).await;

    let AdminResponse::Import(result) = &shown.response else {
        panic!("{profile:?}: expected an import, got {shown:?}")
    };
    assert_eq!(
        result.recipients,
        [RecipientRole::Operational, RecipientRole::Recovery, RecipientRole::HostUnlock]
    );
    assert!(
        shown.notices.contains("host unlock: enrolled from this machine's unlock handoff"),
        "{}",
        shown.notices
    );
    assert_eq!(host_unlock_imports(logs), before + 1, "{profile:?}");
    let vault_key = open_identity_with(&dest, &host_secret).public_key();
    assert_eq!(open_identity_with(&dest, &revealed[0]).public_key(), vault_key);
    shutdown(service).await;

    // A restart opens the vault from the handoff alone and runs the config check, which fails: nothing is approved.
    let restarted = dest
        .context_as(source, profile, MemoryProtection::Locked, OsFs)
        .with_handoff_path(handoff_path.clone());
    let reached = restarted.unlock_at_start(&handoff_path).await;
    assert_eq!(reached, ServiceState::Unavailable(FailureReason::PolicyInvalid), "{profile:?}");
    let text = logs.text();
    [&host_secret, &revealed[0]]
        .iter()
        .flat_map(|secret| [secret.to_string(), secret.to_lowercase()])
        .for_each(|secret| assert!(!text.contains(&secret), "a secret reached the log"));
}

/// With no handoff to read, `import --host-unlock` ends with `import-failed` before any prompt and writes nothing.
async fn refuses_an_absent_handoff(source: &Source, profile: DeploymentProfile) {
    let handoff = HandoffDir::new();
    let dest = Dest::new();
    let service = host_unlock_dest(&dest, source, profile, &handoff.path()).await;
    let before = dest.files();

    let (shown, revealed) = import_with(&service, true, &source.bytes, &COMPLETE).await;

    let AdminResponse::Error { code, message } = &shown.response else {
        panic!("{profile:?}: expected import-failed, got {shown:?}")
    };
    assert_eq!(*code, ErrorCode::ImportFailed, "{message}");
    assert!(
        message.contains("there is no unlock handoff") && message.contains("nothing was written"),
        "{message}"
    );
    assert!(shown.prompts.is_empty() && revealed.is_empty(), "{profile:?}");
    assert_eq!(dest.files(), before, "{profile:?}");
}

/// The ustar header fields the hostile bundles change.
const BLOCK: usize = 512;
const SIZE: std::ops::Range<usize> = 124..135;
const CHECKSUM: std::ops::Range<usize> = 148..156;
const TYPE_FLAG: usize = 156;
const MAGIC: std::ops::Range<usize> = 257..265;

fn gunzip(bundle: &[u8]) -> Vec<u8> {
    let mut archive = Vec::new();
    io::Read::read_to_end(&mut flate2::read::GzDecoder::new(bundle), &mut archive).unwrap();
    archive
}

fn gzip(archive: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), Compression::default());
    io::Write::write_all(&mut encoder, archive).unwrap();
    encoder.finish().unwrap()
}

/// `archive` with its first entry's header changed by `edit` and its checksum recomputed.
fn first_header(archive: &[u8], edit: impl FnOnce(&mut [u8])) -> Vec<u8> {
    let mut archive = archive.to_vec();
    let header = &mut archive[..BLOCK];
    edit(header);
    header[CHECKSUM].fill(b' ');
    let sum: u32 = header.iter().map(|&byte| u32::from(byte)).sum();
    header[CHECKSUM].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    archive
}

fn named(name: &'static str) -> impl FnOnce(&mut [u8]) {
    move |header: &mut [u8]| {
        header[..100].fill(0);
        header[..name.len()].copy_from_slice(name.as_bytes());
    }
}

fn typed(flag: u8) -> impl FnOnce(&mut [u8]) {
    move |header: &mut [u8]| header[TYPE_FLAG] = flag
}

/// The bundle's archive with its first entry, the bundle header, written twice.
fn duplicated(archive: &[u8]) -> Vec<u8> {
    let first = BLOCK + iron_vault_store::migration_bundle::BUNDLE_HEADER_LEN.div_ceil(BLOCK) * BLOCK;
    [&archive[..first], archive].concat()
}

/// A change to an archive entry's header block.
type HeaderEdit = Box<dyn FnOnce(&mut [u8])>;

/// Each hostile bundle, with the rule its refusal names.
fn hostile_bundles(bundle: &[u8]) -> Vec<(&'static str, Vec<u8>, &'static str)> {
    let archive = gunzip(bundle);
    let oversized = (EntryName::BundleHeader.size_limit() + 1).to_string();
    let oversized = format!("{:011o}", oversized.parse::<u64>().unwrap());
    let edits: Vec<(&'static str, HeaderEdit, &'static str)> = vec![
        ("absolute name", Box::new(named("/bundle-header")), "entry_name"),
        ("dot-dot", Box::new(named("../bundle-header")), "entry_name"),
        ("link", Box::new(typed(b'2')), "entry_header"),
        ("directory", Box::new(typed(b'5')), "entry_header"),
        ("device", Box::new(typed(b'3')), "entry_header"),
        ("unknown name", Box::new(named("notes.txt")), "entry_name"),
        ("pax header", Box::new(typed(b'x')), "entry_header"),
        (
            "GNU header",
            Box::new(|header: &mut [u8]| header[MAGIC].copy_from_slice(b"ustar  \0")),
            "entry_header",
        ),
        (
            "oversized entry",
            Box::new(move |header: &mut [u8]| header[SIZE].copy_from_slice(oversized.as_bytes())),
            "entry_size",
        ),
    ];
    edits
        .into_iter()
        .map(|(case, edit, rule)| (case, gzip(&first_header(&archive, edit)), rule))
        .chain([
            ("duplicate", gzip(&duplicated(&archive)), "entry_order"),
            (
                "trailing bytes",
                gzip(&[archive.as_slice(), b"trailing"].concat()),
                "archive_trailing",
            ),
        ])
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn import_refuses_unsafe_bundles() {
    let _one = one_at_a_time().await;
    let source = source().await;
    let dest = Dest::new();
    let service = dest.start(source);
    let before = dest.files();

    for (case, bundle, rule) in hostile_bundles(&source.bytes) {
        let (shown, _) = import(&service, &bundle, &[]).await;

        assert_bundle_invalid(&shown, case, rule);
        assert_eq!(dest.files(), before, "{case}");
    }

    let shown = import_past_the_bound(&service, &source.bytes[..10]).await;

    assert_bundle_invalid(&shown, "too large", "too_large");
    assert_eq!(dest.files(), before);
}

fn assert_bundle_invalid(shown: &Exchanged, case: &str, rule: &str) {
    match &shown.response {
        AdminResponse::Error { code, message } => {
            assert_eq!(*code, ErrorCode::BundleInvalid, "{case}: {message}");
            assert!(message.contains(rule), "{case}: {message}");
        }
        other => panic!("{case}: expected bundle-invalid, got {other:?}"),
    }
    assert!(shown.prompts.is_empty(), "{case}");
}

/// Sends a gzip member that is valid as far as it goes and longer than [`MAX_BUNDLE_LEN`]: `gzip_header`, then empty,
/// non-final stored deflate blocks, which inflate to nothing.
async fn import_past_the_bound(service: &Arc<ServiceContext>, gzip_header: &[u8]) -> Exchanged {
    const EMPTY_STORED_BLOCK: [u8; 5] = [0x00, 0x00, 0x00, 0xff, 0xff];
    let encode = |bytes: &[u8]| {
        let mut frame = Vec::new();
        protocol::encode_bundle_data(bytes, &mut frame).unwrap();
        frame
    };
    let blocks = EMPTY_STORED_BLOCK.repeat(protocol::MAX_BODY_LEN / EMPTY_STORED_BLOCK.len());
    let frames = usize::try_from(MAX_BUNDLE_LEN).unwrap() / blocks.len() + 1;
    let (header, body) = (encode(gzip_header), encode(&blocks));
    let (path, stop, task) = spawn_admin(service);
    let mut stream = UnixStream::connect(path).await.unwrap();
    send(&mut stream, &Frame::Request(AdminRequest::Import { host_unlock: false })).await;
    write_ignoring_errors(&mut stream, &header).await;
    for _ in 0..frames {
        write_ignoring_errors(&mut stream, &body).await;
    }
    write_ignoring_errors(&mut stream, &encode(&[])).await;
    let exchanged = converse(&mut stream, &[]).await;
    let _ = stop.send(());
    task.await.unwrap();
    exchanged
}

/// The step a write fault is injected at, and the call of a complete import's trace that the fault fails: the directory
/// fsync after the marker for step 1, so the marker is in place; the rename that lands each step's first file for
/// steps 2 to 8; step 9's first read; and the marker's removal for step 10.
fn fault_points(calls: &[FsCall]) -> Vec<(u8, usize)> {
    let named = |path: &Path, name: &str| path.file_name().is_some_and(|file| file.to_string_lossy().starts_with(name));
    let renamed = |name: &str| {
        calls
            .iter()
            .position(|call| matches!(call, FsCall::Rename { to, .. } if named(to, name)))
            .unwrap()
    };
    let marker = renamed("import.unfinished");
    let manifest = renamed("manifest.age");
    let first_read = manifest
        + calls[manifest..]
            .iter()
            .position(|call| matches!(call, FsCall::ReadBounded(_)))
            .unwrap();
    let removed = calls
        .iter()
        .rposition(|call| matches!(call, FsCall::RemoveFile(path) if named(path, "import.unfinished")));
    assert!(matches!(calls[marker + 1], FsCall::SyncDir(_)), "{calls:?}");
    let files = [
        "record-",
        "approver-",
        "approval.age",
        "config.toml",
        "identity.age",
        "operational.age",
        "manifest.age",
    ];
    std::iter::once((1, marker + 1))
        .chain((2..).zip(files.map(renamed)))
        .chain([(9, first_read), (10, removed.unwrap())])
        .collect()
}

/// The calls a complete import makes on a fresh destination, from its request on.
async fn import_calls(source: &Source) -> Vec<FsCall> {
    let (dest, fs) = (Dest::new(), SharedFs::default());
    let service = dest.start_on(source, fs.clone());
    let base = fs.with(|fs| fs.trace().len());
    let (shown, _) = import(&service, &source.bytes, &COMPLETE).await;
    assert!(matches!(shown.response, AdminResponse::Import(_)), "{shown:?}");
    fs.with(|fs| fs.trace().split_off(base))
}

#[tokio::test(flavor = "multi_thread")]
async fn import_crash_is_discarded() {
    let _one = one_at_a_time().await;
    let source = source().await;
    let points = fault_points(&import_calls(source).await);

    for (step, call) in points {
        let (dest, fs) = (Dest::new(), SharedFs::default());
        let service = dest.start_on(source, fs.clone());
        fs.with(|fs| fs.fail_call(fs.trace().len() + call, io::ErrorKind::Other));

        let (failed, _) = import(&service, &source.bytes, &COMPLETE).await;

        match &failed.response {
            AdminResponse::Error { code, message } => {
                assert_eq!(*code, ErrorCode::ImportFailed, "step {step}: {message}");
                assert!(message.contains(&format!("step {step},")), "step {step}: {message}");
            }
            other => panic!("step {step}: expected import-failed, got {other:?}"),
        }
        assert_eq!(service.status().await.vault, VaultStatus::ImportUnfinished, "step {step}");
        let unlock = request(&service, AdminRequest::Unlock, &[DEST_PASSPHRASE]).await;
        assert_eq!(error_code(&unlock.response), ErrorCode::UnlockFailed, "step {step}");
        let (again, _) = import(&service, &source.bytes, &COMPLETE).await;
        assert!(
            again.notices.starts_with("An unfinished import is here"),
            "step {step}: {}",
            again.notices
        );
        assert!(matches!(again.response, AdminResponse::Import(_)), "step {step}: {again:?}");
        assert_eq!(service.status().await.vault, VaultStatus::Locked, "step {step}");
    }
}
