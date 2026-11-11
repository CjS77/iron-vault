//! `export` end to end against a running service on a vault whose envelopes open with a vault passphrase
//! (`design/migration-bundle.md`, "Export" and "Transfer"). A bundle leaves only after the vault passphrase, sealed to an
//! export passphrase; every other ending leaves no bundle and no partial file, and no secret reaches a file, the output
//! or the log.

#![cfg(target_os = "linux")]

use crate::common;

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use common::approval_harness::{Captured, Fixture, assert_audit_record, captured_logs, converse, identity, mkdir, send};
use iron_vault::admin::ADMIN_SOCKET_NAME;
use iron_vault::admin::dispatch::Handlers;
use iron_vault::admin::principal::AdminPrincipals;
use iron_vault::admin::protocol::{self, AdminRequest, AdminResponse, Decoded, ErrorCode, Frame, OwnerInput};
use iron_vault::admin::server::{AdminServer, Limits};
use iron_vault::admin::socket::AdminSocket;
use iron_vault::service_context::ServiceContext;
use iron_vault_kinds::CredentialMaterial;
use iron_vault_store::migration_bundle::{BundleDecoder, DecodedBundle, EntryName};
use iron_vault_store::{
    ExportPassphrase, OperationalIdentity, OsFs, Passphrase, PermittedOrigins, RecipientSet, Vault, open_exported_identity,
    seal_passphrase_envelope_for_tests, wrap_identity, write_identity_envelope, write_passphrase_envelope,
};
use secrecy::SecretString;
use tokio::io::AsyncReadExt;
use tokio::net::UnixStream;
use tokio::sync::{Mutex, MutexGuard, oneshot};
use zeroize::Zeroizing;

const PASSPHRASE: &str = "VAULT-correct-5d1a";
const EXPORT_PASSPHRASE: &str = "EXPORT-chosen-7c2e";
/// The fixture's one credential's secret.
const FX_SECRET: &str = "fx-secret";
/// A large credential's secret, repeated to its length: records of it make a bundle larger than the socket's buffers.
const BIG_SECRET: &str = "BIG-record-secret-";
const BIG_RECORDS: usize = 16;
const BIG_LEN: usize = 48_000;

/// Each export runs scrypt at 256 MiB, twice when it seals; one test at a time keeps the binary's memory bounded, and lets
/// a test count the audit records it added to the log every test shares.
static ONE_AT_A_TIME: Mutex<()> = Mutex::const_new(());

/// A Ready service whose envelopes open with [`PASSPHRASE`], with the service's handlers on its admin socket.
struct Served {
    fixture: Fixture,
    path: PathBuf,
    logs: Captured,
    stop: Option<oneshot::Sender<()>>,
    _one: MutexGuard<'static, ()>,
}

impl Served {
    async fn new() -> Self {
        Self::with(false, Limits::default()).await
    }

    /// With `big`, [`BIG_RECORDS`] more credentials of [`BIG_LEN`] bytes each.
    async fn with(big: bool, limits: Limits) -> Self {
        Self::pinning(big, limits, |_| ()).await
    }

    /// A service whose vault `pin` has changed before it starts.
    async fn pinning(big: bool, limits: Limits, pin: impl FnOnce(&Fixture)) -> Self {
        let one = ONE_AT_A_TIME.lock().await;
        let logs = captured_logs();
        let fixture = Fixture::new().await;
        pin(&fixture);
        write_envelopes(&fixture);
        if big {
            add_big_records(&fixture);
        }
        mkdir(&fixture.path("out"));
        let service = fixture.ready().await;
        let (path, stop) = serve(&service, limits);
        Self {
            fixture,
            path,
            logs,
            stop: Some(stop),
            _one: one,
        }
    }

    async fn connect(&self, request: AdminRequest) -> UnixStream {
        let mut stream = UnixStream::connect(&self.path).await.unwrap();
        send(&mut stream, &Frame::Request(request)).await;
        stream
    }

    /// `lock` on a connection of its own, in a task, since it waits for the export to release the service-wide lock.
    fn lock(&self) -> tokio::task::JoinHandle<AdminResponse> {
        let path = self.path.clone();
        tokio::spawn(async move {
            let mut stream = UnixStream::connect(path).await.unwrap();
            send(&mut stream, &Frame::Request(AdminRequest::Lock)).await;
            converse(&mut stream, &[]).await.response
        })
    }

    /// The vault's record files with their bytes, by name.
    fn record_files(&self) -> BTreeMap<String, Vec<u8>> {
        fs::read_dir(self.fixture.path("state"))
            .unwrap()
            .map(|entry| entry.unwrap())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with("record-"))
            .map(|name| {
                let bytes = fs::read(self.fixture.path(&format!("state/{name}"))).unwrap();
                (name, bytes)
            })
            .collect()
    }

    fn bundle_path(&self) -> PathBuf {
        self.fixture.path("out/vault.bundle")
    }

    fn partial_path(&self) -> PathBuf {
        self.fixture.path("out/.vault.bundle.partial")
    }

    fn assert_no_bundle(&self) {
        assert!(!self.bundle_path().exists(), "a failed export left the bundle");
        assert!(!self.partial_path().exists(), "a failed export left the partial file");
    }

    /// The records of `event` added since `before` of them were in the log.
    fn events_since(&self, event: &str, before: usize) -> Vec<serde_json::Value> {
        self.logs.events(event).into_iter().skip(before).collect()
    }

    fn count(&self, event: &str) -> usize {
        self.logs.events(event).len()
    }
}

impl Drop for Served {
    fn drop(&mut self) {
        self.stop.take().into_iter().for_each(|stop| {
            let _ = stop.send(());
        });
    }
}

/// The admin server with the service's handlers and `limits`, until the sender is dropped or sent.
fn serve(service: &Arc<ServiceContext>, limits: Limits) -> (PathBuf, oneshot::Sender<()>) {
    let paths = service.paths().clone();
    let runtime_dir = paths.runtime_dir.clone().unwrap();
    let socket = AdminSocket::bind(&runtime_dir, paths.owner).unwrap();
    let server = AdminServer::new(
        AdminPrincipals::new(paths.profile, paths.owner.uid),
        Handlers::for_service(service),
        limits,
    );
    let (stop, stopped) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let _ = server
            .serve(socket, async {
                let _ = stopped.await;
            })
            .await;
    });
    (runtime_dir.join(ADMIN_SOCKET_NAME), stop)
}

/// `identity.age` and `operational.age` sealed to [`PASSPHRASE`], as initialization writes them.
fn write_envelopes(fixture: &Fixture) {
    let lock = common::approval_harness::state_dir_lock(&fixture.path("state"));
    let (operational, operational_key) = OperationalIdentity::generate();
    let recipients = RecipientSet::new([operational_key, OperationalIdentity::generate().1]).unwrap();
    write_identity_envelope(&lock, &OsFs, &wrap_identity(&identity(), &recipients).unwrap()).unwrap();
    let passphrase = Passphrase::new(SecretString::from(PASSPHRASE)).unwrap();
    let envelope = seal_passphrase_envelope_for_tests(&operational, &passphrase).unwrap();
    write_passphrase_envelope(&lock, &OsFs, &envelope).unwrap();
}

/// Adds [`BIG_RECORDS`] credentials through the store, before the service takes the state directory's lock.
fn add_big_records(fixture: &Fixture) {
    let lock = common::approval_harness::state_dir_lock(&fixture.path("state"));
    let (mut vault, _) = Vault::open(&lock, &OsFs, identity()).unwrap();
    (0..BIG_RECORDS).for_each(|n| {
        let origins = PermittedOrigins::new([("localhost".parse().unwrap(), "443".parse().unwrap())].into()).unwrap();
        let key = BIG_SECRET.repeat(BIG_LEN / BIG_SECRET.len());
        let material = CredentialMaterial::Static { key: key.into() };
        vault
            .add(&lock, &OsFs, format!("big_{n}").parse().unwrap(), material, origins)
            .unwrap();
    });
}

/// The next frame, or `None` once the service has closed. Reads whole frames, since a bundle has many.
async fn next_frame(stream: &mut UnixStream) -> Option<Frame> {
    let mut bytes = Vec::new();
    loop {
        let needed = match protocol::decode(&bytes).unwrap() {
            Decoded::Frame { frame, .. } => return Some(frame),
            Decoded::NeedMore(needed) => needed,
        };
        let start = bytes.len();
        bytes.resize(start + needed, 0);
        let read = tokio::time::timeout(common::WAIT, stream.read(&mut bytes[start..])).await.unwrap();
        match read {
            Ok(0) | Err(_) => return None,
            Ok(read) => bytes.truncate(start + read),
        }
    }
}

async fn answer(stream: &mut UnixStream, text: &str) {
    send(
        stream,
        &Frame::OwnerInput(OwnerInput::new(Zeroizing::new(text.as_bytes().to_vec()))),
    )
    .await;
}

/// What an export exchange showed the owner and sent, up to its response or its close.
#[derive(Debug, Default)]
struct Seen {
    prompts: Vec<String>,
    bundle: Vec<u8>,
    ended: bool,
    response: Option<AdminResponse>,
}

impl Seen {
    fn error(&self) -> (ErrorCode, &str) {
        match &self.response {
            Some(AdminResponse::Error { code, message }) => (*code, message),
            other => panic!("expected an error response, got {other:?}"),
        }
    }
}

/// Reads frames, answering each prompt with the next of `answers`, until the response, the close, or the first bundle
/// data frame when `stop_at_bundle`.
async fn follow(stream: &mut UnixStream, answers: &[&str], seen: &mut Seen, stop_at_bundle: bool) {
    let mut answers = answers.iter();
    while let Some(frame) = next_frame(stream).await {
        match frame {
            Frame::Notice(_) => {}
            Frame::Prompt(prompt) => {
                seen.prompts.push(prompt.label);
                answer(stream, answers.next().expect("a prompt beyond the answers given")).await;
            }
            Frame::BundleData(chunk) => {
                seen.ended = chunk.is_end();
                seen.bundle.extend_from_slice(chunk.bytes());
                if stop_at_bundle {
                    return;
                }
            }
            Frame::Response(response) => {
                seen.response = Some(response);
                return;
            }
            other => panic!("unexpected frame {other:?}"),
        }
    }
}

async fn export(served: &Served, answers: &[&str]) -> Seen {
    let mut stream = served.connect(AdminRequest::Export).await;
    let mut seen = Seen::default();
    follow(&mut stream, answers, &mut seen, false).await;
    seen
}

/// The output of one run of the binary.
#[derive(Debug)]
struct Ran {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// Runs `iron-vault export <bundle> --admin-socket <socket>` with `input` on stdin, off the runtime thread, so the
/// in-process service keeps serving while the binary waits for it.
async fn run_export(socket: &Path, bundle: &Path, input: &str) -> Ran {
    let (socket, bundle, input) = (socket.to_path_buf(), bundle.to_path_buf(), input.to_owned());
    let running = tokio::task::spawn_blocking(move || {
        let mut child = Command::new(env!("CARGO_BIN_EXE_iron-vault"))
            .arg("export")
            .arg(&bundle)
            .arg("--admin-socket")
            .arg(&socket)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // A command refused before it reads closes the pipe, so a failed write is not the test's failure.
        let _ = child.stdin.take().unwrap().write_all(input.as_bytes());
        let output = child.wait_with_output().unwrap();
        Ran {
            code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    });
    tokio::time::timeout(Duration::from_secs(60), running).await.unwrap().unwrap()
}

fn decoded(bytes: &[u8]) -> DecodedBundle {
    let mut decoder = BundleDecoder::new();
    decoder.push(bytes).unwrap();
    decoder.finish().unwrap()
}

fn export_passphrase(text: &str) -> ExportPassphrase {
    ExportPassphrase::new(SecretString::from(text)).unwrap()
}

/// Every file under `dir`, recursively, with its bytes.
fn files_under(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .flat_map(|path| match path.is_dir() {
            true => files_under(&path),
            false => vec![(path.clone(), fs::read(&path).unwrap())],
        })
        .collect()
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle.as_bytes())
}

#[tokio::test(flavor = "multi_thread")]
async fn an_export_writes_a_bundle_that_holds_the_vault_and_opens_only_with_the_export_passphrase() {
    let served = Served::new().await;
    let exported_before = served.count("migration.exported");
    let input = format!("{PASSPHRASE}\n{EXPORT_PASSPHRASE}\n{EXPORT_PASSPHRASE}\n");
    let ran = run_export(&served.path, &served.bundle_path(), &input).await;
    assert_eq!(ran.code, Some(0), "{ran:?}");
    assert!(!served.partial_path().exists(), "the partial file outlived the export");

    let bytes = fs::read(served.bundle_path()).unwrap();
    let mode = fs::metadata(served.bundle_path()).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let bundle = decoded(&bytes);
    let records = served.record_files();
    assert_eq!(
        (bundle.header().record_count(), bundle.header().approver_count()),
        (records.len(), 1)
    );
    let bundled: BTreeMap<String, Vec<u8>> = bundle
        .entries()
        .filter(|(name, _)| matches!(name, EntryName::Record(_)))
        .map(|(name, bytes)| (name.to_string(), bytes.to_vec()))
        .collect();
    assert_eq!(
        bundled, records,
        "the bundle's records are not the vault's record files byte for byte"
    );
    let sealed = bundle.entry(&EntryName::ExportedIdentity).unwrap();
    let opened = open_exported_identity(sealed, &export_passphrase(EXPORT_PASSPHRASE)).unwrap();
    assert_eq!(opened.public_key(), identity().public_key());
    assert!(open_exported_identity(sealed, &export_passphrase(PASSPHRASE)).is_err());

    let vault_id = bundle.header().vault_id().to_string();
    assert!(ran.stdout.contains(&vault_id), "{ran:?}");
    assert!(ran.stdout.contains(&format!("1 credentials, {} bytes", bytes.len())), "{ran:?}");
    assert!(ran.stdout.contains("opens only with the export passphrase"), "{ran:?}");
    let exported = served.events_since("migration.exported", exported_before);
    assert_eq!(exported.len(), 1, "{exported:?}");
    assert_audit_record(
        &exported[0],
        "INFO",
        &["vault_id", "records", "approvers", "committed_version", "highest_reserved"],
    );
    assert_eq!(exported[0]["vault_id"], vault_id.as_str());
    assert_eq!(
        (exported[0]["records"].as_u64(), exported[0]["approvers"].as_u64()),
        (Some(1), Some(1))
    );
    assert_eq!(exported[0]["committed_version"].as_u64(), Some(1));

    let log = served.logs.text();
    let files = [files_under(&served.fixture.path("state")), files_under(&served.fixture.path("out"))].concat();
    [FX_SECRET, PASSPHRASE, EXPORT_PASSPHRASE].iter().for_each(|secret| {
        assert!(!log.contains(secret), "{secret} reached the log");
        assert!(
            !ran.stdout.contains(secret) && !ran.stderr.contains(secret),
            "{secret} reached the output"
        );
        files
            .iter()
            .for_each(|(path, bytes)| assert!(!contains(bytes, secret), "{secret} reached {}", path.display()));
    });
}

#[tokio::test(flavor = "multi_thread")]
async fn the_export_passphrase_is_asked_only_after_authorization_and_a_broken_rule_is_rejected() {
    let served = Served::new().await;
    let (exported, failed) = (served.count("migration.exported"), served.count("migration.export-failed"));
    let denied = export(&served, &["VAULT-wrong-0b77"]).await;
    assert_eq!(denied.prompts, ["Vault passphrase"]);
    assert_eq!(denied.error().0, ErrorCode::MigrationDenied);

    let both = ["Vault passphrase", "Export passphrase", "Repeat the export passphrase"];
    let short = export(&served, &[PASSPHRASE, "short", "short"]).await;
    assert_eq!(short.prompts, both);
    let (code, message) = short.error();
    assert_eq!(code, ErrorCode::PassphraseRejected);
    assert!(message.contains("shorter than 12"), "{message}");

    let differ = export(&served, &[PASSPHRASE, "EXPORT-one-aaaaaaa", "EXPORT-two-bbbbbbb"]).await;
    assert_eq!(differ.prompts, both);
    let (code, message) = differ.error();
    assert_eq!(code, ErrorCode::PassphraseRejected);
    assert!(message.contains("differ"), "{message}");
    assert!([&denied, &short, &differ].iter().all(|seen| seen.bundle.is_empty()));
    // The authorization dropped unused at step 8 adds no record of the export's own.
    assert_eq!(served.count("migration.exported"), exported);
    assert_eq!(served.count("migration.export-failed"), failed);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_damaged_record_fails_the_check_before_any_prompt() {
    let served = Served::new().await;
    let failed = served.count("migration.export-failed");
    let (name, mut bytes) = served.record_files().into_iter().next().unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    fs::write(served.fixture.path(&format!("state/{name}")), &bytes).unwrap();

    let seen = export(&served, &[]).await;
    assert!(seen.prompts.is_empty(), "{seen:?}");
    let (code, message) = seen.error();
    assert_eq!(code, ErrorCode::ExportFailed);
    assert!(message.contains("check step") && message.contains(&name), "{message}");
    let records = served.events_since("migration.export-failed", failed);
    assert_eq!(records.len(), 1, "{records:?}");
    assert_audit_record(&records[0], "WARN", &["step", "error_kind", "file"]);
    assert_eq!(
        (
            records[0]["step"].as_str(),
            records[0]["file"].as_str(),
            records[0]["error_kind"].as_str()
        ),
        (Some("check"), Some(name.as_str()), Some("damaged"))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_lock_at_the_export_passphrase_prompt_ends_the_export_unavailable() {
    let served = Served::new().await;
    let mut stream = served.connect(AdminRequest::Export).await;
    let mut seen = Seen::default();
    // Answer the vault passphrase, then stop at the export passphrase prompt.
    while seen.prompts.len() < 2 {
        match next_frame(&mut stream).await.unwrap() {
            Frame::Prompt(prompt) => {
                seen.prompts.push(prompt.label);
                if seen.prompts.len() == 1 {
                    answer(&mut stream, PASSPHRASE).await;
                }
            }
            Frame::Notice(_) => {}
            other => panic!("unexpected frame {other:?}"),
        }
    }
    assert_eq!(seen.prompts, ["Vault passphrase", "Export passphrase"]);
    let locked = served.lock();
    follow(&mut stream, &[], &mut seen, false).await;
    let (code, message) = seen.error();
    assert_eq!(code, ErrorCode::MigrationUnavailable);
    assert!(message.contains("export passphrase"), "{message}");
    assert!(matches!(locked.await.unwrap(), AdminResponse::Lock { .. }));
    served.assert_no_bundle();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_lock_between_frames_cancels_the_export_and_then_takes_the_lock() {
    let served = Served::with(true, Limits::default()).await;
    let failed = served.count("migration.export-failed");
    let mut stream = served.connect(AdminRequest::Export).await;
    let mut seen = Seen::default();
    follow(&mut stream, &[PASSPHRASE, EXPORT_PASSPHRASE, EXPORT_PASSPHRASE], &mut seen, true).await;
    assert!(!seen.bundle.is_empty() && !seen.ended);
    let locked = served.lock();
    // The service waits on a full socket buffer, so the lock request is seen before the bundle can end.
    tokio::time::sleep(Duration::from_millis(300)).await;
    follow(&mut stream, &[], &mut seen, false).await;
    assert!(!seen.ended, "the bundle ended despite the lock");
    let (code, message) = seen.error();
    assert_eq!(code, ErrorCode::ExportFailed);
    assert!(message.contains("cancelled by lock"), "{message}");
    assert!(matches!(locked.await.unwrap(), AdminResponse::Lock { .. }));
    let records = served.events_since("migration.export-failed", failed);
    assert_eq!(records.len(), 1, "{records:?}");
    assert_audit_record(&records[0], "WARN", &["step", "error_kind"]);
    assert_eq!(
        (records[0]["step"].as_str(), records[0]["error_kind"].as_str()),
        (Some("transfer"), Some("locked"))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stalled_cli_ends_the_export_at_its_deadline_and_never_holds_off_a_lock_past_it() {
    let limits = Limits {
        request_deadline: Duration::from_secs(1),
        transfer_deadline: Duration::from_secs(3),
        ..Limits::default()
    };
    let served = Served::with(true, limits).await;
    let failed = served.count("migration.export-failed");
    let mut stream = served.connect(AdminRequest::Export).await;
    let mut seen = Seen::default();
    follow(&mut stream, &[PASSPHRASE, EXPORT_PASSPHRASE, EXPORT_PASSPHRASE], &mut seen, true).await;
    // The CLI stops reading; the socket buffer fills and the service's next frame write waits on it.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let asked = tokio::time::Instant::now();
    let locked = served.lock();
    assert!(matches!(locked.await.unwrap(), AdminResponse::Lock { .. }));
    assert!(asked.elapsed() < Duration::from_secs(5), "the lock waited {:?}", asked.elapsed());
    // Whatever reached the socket, the bundle never ended.
    follow(&mut stream, &[], &mut seen, false).await;
    assert!(!seen.ended, "a stalled export ended its bundle");
    let records = served.events_since("migration.export-failed", failed);
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(
        (records[0]["step"].as_str(), records[0]["error_kind"].as_str()),
        (Some("transfer"), Some("deadline"))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_export_leaves_neither_a_bundle_nor_a_partial_file() {
    let served = Served::new().await;
    let input = format!("{PASSPHRASE}\nEXPORT-one-aaaaaaa\nEXPORT-two-bbbbbbb\n");
    let ran = run_export(&served.path, &served.bundle_path(), &input).await;
    assert_eq!(ran.code, Some(1), "{ran:?}");
    assert!(ran.stderr.contains("passphrase-rejected"), "{ran:?}");
    served.assert_no_bundle();
}

#[tokio::test]
async fn an_existing_bundle_or_a_leftover_partial_file_is_refused_before_connecting() {
    let dir = common::proxy_harness::TempDir::new();
    let socket = dir.path().join("no-service.sock");
    let bundle = dir.path().join("vault.bundle");
    fs::write(&bundle, b"an earlier bundle").unwrap();
    let ran = run_export(&socket, &bundle, "").await;
    assert_eq!(ran.code, Some(2), "{ran:?}");
    assert!(ran.stderr.contains("vault.bundle already exists"), "{ran:?}");
    assert_eq!(fs::read(&bundle).unwrap(), b"an earlier bundle");

    fs::remove_file(&bundle).unwrap();
    let partial = dir.path().join(".vault.bundle.partial");
    fs::write(&partial, b"a crashed export").unwrap();
    let ran = run_export(&socket, &bundle, "").await;
    assert_eq!(ran.code, Some(2), "{ran:?}");
    assert!(
        ran.stderr.contains(".vault.bundle.partial is left from an earlier export"),
        "{ran:?}"
    );
    assert_eq!(fs::read(&partial).unwrap(), b"a crashed export");
    assert!(!bundle.exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tpm_approver_is_pinned_in_the_bundle_but_its_key_blob_is_not() {
    let software = std::cell::Cell::new(None);
    let served = Served::pinning(false, Limits::default(), |fixture| {
        software.set(Some(fixture.approver_id()));
        fixture.enroll_tpm_approver("laptop TPM");
    })
    .await;
    let software = software.get().unwrap();
    let input = format!("{PASSPHRASE}\n{EXPORT_PASSPHRASE}\n{EXPORT_PASSPHRASE}\n");
    let ran = run_export(&served.path, &served.bundle_path(), &input).await;
    assert_eq!(ran.code, Some(0), "{ran:?}");

    let bundle = decoded(&fs::read(served.bundle_path()).unwrap());
    let approvers: Vec<_> = bundle
        .entries()
        .filter(|(name, _)| matches!(name, EntryName::Approver(_)))
        .collect();
    assert_eq!(bundle.header().approver_count(), 1);
    assert_eq!(
        approvers.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
        [EntryName::Approver(software)]
    );
    assert!(bundle.entries().all(|(name, _)| !name.to_string().ends_with(".tpm")));
}
