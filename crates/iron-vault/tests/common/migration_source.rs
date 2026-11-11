//! A migration bundle exported from a real source vault, for the tests of `import`: one source service exports once per
//! test binary, and the bundle's bytes are read back through the store, so a test compares the destination with what the
//! source held. The source fixture stays alive, because the bundled config names a listener socket inside its directory.

use std::path::PathBuf;
use std::sync::Arc;

use tokio::io::AsyncReadExt;
use tokio::net::UnixStream;
use tokio::sync::OnceCell;

use super::approval_harness::{Fixture, identity, mkdir, send, versions};
use iron_vault::admin::dispatch::Handlers;
use iron_vault::admin::principal::AdminPrincipals;
use iron_vault::admin::protocol::{self, AdminRequest, AdminResponse, Decoded, Frame, OwnerInput};
use iron_vault::admin::server::{AdminServer, Limits};
use iron_vault::admin::socket::AdminSocket;
use iron_vault::service_context::ServiceContext;
use iron_vault_store::migration_bundle::BundleDecoder;
use iron_vault_store::{
    ApproverId, ExportPassphrase, OperationalIdentity, OsFs, Passphrase, PinnedApprover, RecipientSet, SignerKind, VaultId,
    open_bundle, seal_passphrase_envelope_for_tests, verify_bundle, wrap_identity, write_identity_envelope, write_passphrase_envelope,
};
use secrecy::SecretString;
use zeroize::Zeroizing;

/// The source vault's passphrase, which authorizes the export.
pub const SOURCE_PASSPHRASE: &str = "SOURCE-vault-5d1a-correct";
/// The export passphrase the bundle is sealed to.
pub const EXPORT_PASSPHRASE: &str = "EXPORT-chosen-7c2e-correct";

/// What the source held when it exported, and the bundle.
pub struct Source {
    /// The bundle file's bytes.
    pub bytes: Vec<u8>,
    pub vault_id: VaultId,
    pub records: u64,
    pub committed: u64,
    pub highest_reserved: u64,
    pub digest: [u8; 32],
    /// The `tpm` approver the source pins, if any.
    pub tpm_approver: Option<ApproverId>,
    /// The source fixture, kept so that the config's listener socket path stays in a live directory.
    pub fixture: Fixture,
}

static SOURCE: OnceCell<Source> = OnceCell::const_new();
static TPM_SOURCE: OnceCell<Source> = OnceCell::const_new();

/// The one source, exported on first use.
pub async fn source() -> &'static Source {
    SOURCE.get_or_init(|| export(|_| ())).await
}

/// A source that pins a `tpm` approver beside its software one, exported on first use.
pub async fn source_with_tpm_approver() -> &'static Source {
    TPM_SOURCE
        .get_or_init(|| {
            export(|fixture| {
                fixture.enroll_tpm_approver("laptop TPM");
            })
        })
        .await
}

async fn export(pin: impl FnOnce(&Fixture)) -> Source {
    let fixture = Fixture::new().await;
    pin(&fixture);
    write_envelopes(&fixture);
    mkdir(&fixture.path("out"));
    let service = fixture.ready().await;
    let held = versions(&service).await;
    let (socket, stop) = serve(&service);
    let bytes = run_export(&socket).await;
    let _ = stop.send(());
    let decoded = {
        let mut decoder = BundleDecoder::new();
        decoder.push(&bytes).unwrap();
        decoder.finish().unwrap()
    };
    let opened = open_bundle(decoded, &ExportPassphrase::new(SecretString::from(EXPORT_PASSPHRASE)).unwrap()).unwrap();
    let verified = verify_bundle(opened).unwrap();
    assert_eq!(
        (Some(verified.committed_version().get()), verified.highest_reserved()),
        (held.0, held.1)
    );
    Source {
        bytes,
        vault_id: verified.vault_id(),
        records: u64::try_from(verified.record_count()).unwrap(),
        committed: verified.committed_version().get(),
        highest_reserved: verified.highest_reserved(),
        digest: *verified.config_digest().as_bytes(),
        tpm_approver: verified
            .approvers()
            .iter()
            .find(|a| a.kind() == SignerKind::Tpm)
            .map(PinnedApprover::id),
        fixture,
    }
}

/// `identity.age` and `operational.age` sealed to [`SOURCE_PASSPHRASE`], as initialization writes them.
fn write_envelopes(fixture: &Fixture) {
    let lock = super::approval_harness::state_dir_lock(&fixture.path("state"));
    let (operational, operational_key) = OperationalIdentity::generate();
    let recipients = RecipientSet::new([operational_key, OperationalIdentity::generate().1]).unwrap();
    write_identity_envelope(&lock, &OsFs, &wrap_identity(&identity(), &recipients).unwrap()).unwrap();
    let passphrase = Passphrase::new(SecretString::from(SOURCE_PASSPHRASE)).unwrap();
    write_passphrase_envelope(
        &lock,
        &OsFs,
        &seal_passphrase_envelope_for_tests(&operational, &passphrase).unwrap(),
    )
    .unwrap();
}

fn serve(service: &Arc<ServiceContext>) -> (PathBuf, tokio::sync::oneshot::Sender<()>) {
    let paths = service.paths().clone();
    let runtime_dir = paths.runtime_dir.clone().unwrap();
    let socket = AdminSocket::bind(&runtime_dir, paths.owner).unwrap();
    let principals = AdminPrincipals::new(paths.profile, paths.owner.uid);
    let server = AdminServer::new(principals, Handlers::for_service(service), Limits::default());
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let _ = server
            .serve(socket, async {
                let _ = stopped.await;
            })
            .await;
    });
    (runtime_dir.join(iron_vault::admin::ADMIN_SOCKET_NAME), stop)
}

/// Exports over the admin socket: the vault passphrase, then the export passphrase twice.
async fn run_export(socket: &std::path::Path) -> Vec<u8> {
    let mut stream = UnixStream::connect(socket).await.unwrap();
    send(&mut stream, &Frame::Request(AdminRequest::Export)).await;
    let mut answers = [SOURCE_PASSPHRASE, EXPORT_PASSPHRASE, EXPORT_PASSPHRASE].into_iter();
    let mut bundle = Vec::new();
    loop {
        match next_frame(&mut stream).await {
            Frame::Notice(_) => {}
            Frame::Prompt(_) => {
                let answer = answers.next().unwrap();
                send(
                    &mut stream,
                    &Frame::OwnerInput(OwnerInput::new(Zeroizing::new(answer.as_bytes().to_vec()))),
                )
                .await;
            }
            Frame::BundleData(chunk) => bundle.extend_from_slice(chunk.bytes()),
            Frame::Response(AdminResponse::Export { .. }) => return bundle,
            other => panic!("unexpected frame {other:?}"),
        }
    }
}

/// The bundle as bundle data frames, ending with the empty one.
pub fn bundle_frames(bundle: &[u8]) -> Vec<Vec<u8>> {
    let frame = |bytes: &[u8]| {
        let mut out = Vec::new();
        protocol::encode_bundle_data(bytes, &mut out).unwrap();
        out
    };
    bundle
        .chunks(protocol::MAX_BODY_LEN)
        .map(frame)
        .chain(std::iter::once(frame(&[])))
        .collect()
}

/// Writes `bytes`, ignoring a failed write: a service that refuses at its first check closes while the bundle is still
/// going out.
pub async fn write_ignoring_errors(stream: &mut UnixStream, bytes: &[u8]) {
    tokio::io::AsyncWriteExt::write_all(stream, bytes).await.ok();
}

/// Sends the bundle after the request, as the CLI does.
pub async fn send_bundle(stream: &mut UnixStream, bundle: &[u8]) {
    for frame in bundle_frames(bundle) {
        write_ignoring_errors(stream, &frame).await;
    }
}

/// The next whole frame, read in as large pieces as the decoder asks for, since a bundle has many.
pub async fn next_frame(stream: &mut UnixStream) -> Frame {
    read_frame(stream).await.expect("the service closed before a frame")
}

/// The next whole frame, or `None` once the service has closed.
pub async fn read_frame(stream: &mut UnixStream) -> Option<Frame> {
    let mut bytes = Vec::new();
    loop {
        let needed = match protocol::decode(&bytes).unwrap() {
            Decoded::Frame { frame, .. } => return Some(frame),
            Decoded::NeedMore(needed) => needed,
        };
        let start = bytes.len();
        bytes.resize(start + needed, 0);
        let read = tokio::time::timeout(super::WAIT, stream.read(&mut bytes[start..])).await.unwrap();
        match read {
            Ok(0) | Err(_) => return None,
            Ok(read) => bytes.truncate(start + read),
        }
    }
}
