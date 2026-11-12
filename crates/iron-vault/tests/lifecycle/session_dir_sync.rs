//! Release check 9 over a whole session (specification §19): "Durable-write fault injection succeeds for each write
//! boundary, and every durable rename includes its directory fsync."
//!
//! The store's own fault tests check the directory-fsync rule on the writers they call. This test checks it on every
//! durable writer a session reaches, through the in-process service and the CLI's bundle writer, all on one
//! [`SharedFs`]: `init`, `unlock`, `add`, `replace`, `rm`, `config approve`, `lock`, `approver add` and `remove`,
//! `recipient add` and `remove`, `recovery check`, `export` with its bundle file, `import` into a second vault, and
//! `reset`, and each service's start.
//!
//! Each step's own calls are held to [`assert_trace_properties`] once it has reported success, so a rename whose
//! directory only a later command happens to fsync still fails.

#![cfg(target_os = "linux")]

use crate::common;

use std::cell::Cell;
use std::path::Path;
use std::sync::Arc;

use common::approval_harness::{read_frame, send, spawn_admin};
use common::migration_source::{EXPORT_PASSPHRASE, send_bundle};
use common::mock_upstream::{MockUpstream, Reply, TestCa};
use common::proxy_harness::{TOKEN_BYTES, TOKEN_HEADER, token_hash};
use common::recipient_harness::{APPROVAL_PASSPHRASE, Fixture, VAULT_PASSPHRASE};
use common::shared_fs::SharedFs;
use iron_vault::admin::protocol::{
    AdminRequest, AdminResponse, ApproverEntry, Frame, OwnerInput, ProposedConfig, RequestedOrigin, RequestedSignerKind,
};
use iron_vault::bundle_file::PartialBundle;
use iron_vault::config_check::UpstreamSettings;
use iron_vault::deployment::DeploymentProfile;
use iron_vault::path_metadata::invoking_user;
use iron_vault::service_context::ServiceContext;
use iron_vault::upstream::client::TransportLimits;
use iron_vault_policy::CredentialKind;
use iron_vault_store::RecoveryKey;
use iron_vault_store::fault_fs::{FsCall, assert_trace_properties};
use tokio::net::UnixStream;
use zeroize::Zeroizing;

type Service = Arc<ServiceContext<SharedFs>>;

const SECOND_APPROVAL: &str = "SESSION-second-approver-2c7d";
const DEST_PASSPHRASE: &str = "SESSION-dest-vault-passphrase-8a41";

/// The traced filesystem and where the step being run began in its trace.
struct Steps {
    fs: SharedFs,
    mark: Cell<usize>,
}

impl Steps {
    fn new() -> Self {
        Self {
            fs: SharedFs::default(),
            mark: Cell::new(0),
        }
    }

    /// Holds the calls since the last check that succeeded to the durable-write rules, and starts the next step.
    fn checked(&self, what: &str) {
        let (calls, end) = self.fs.with(|fs| (fs.succeeded_since(self.mark.get()), fs.trace().len()));
        eprintln!("checking the durable-write rules on {what}");
        assert_trace_properties(&calls);
        self.mark.set(end);
    }
}

/// What one admin exchange returned: the response, the secrets revealed, and the bundle bytes received.
struct Talked {
    response: AdminResponse,
    reveals: Vec<String>,
    bundle: Vec<u8>,
}

/// Sends `request` on a fresh admin socket, then `bundle` if given, and answers the prompts in turn with `answers`.
async fn talk(service: &Service, request: AdminRequest, bundle: Option<&[u8]>, answers: &[&str]) -> Talked {
    let (path, stop, task) = spawn_admin(service);
    let mut stream = UnixStream::connect(path).await.unwrap();
    send(&mut stream, &Frame::Request(request)).await;
    if let Some(bytes) = bundle {
        send_bundle(&mut stream, bytes).await;
    }
    let talked = converse(&mut stream, answers).await;
    let _ = stop.send(());
    task.await.unwrap();
    talked
}

async fn converse(stream: &mut UnixStream, answers: &[&str]) -> Talked {
    let mut answers = answers.iter();
    let (mut reveals, mut bundle) = (Vec::new(), Vec::new());
    loop {
        match read_frame(stream).await {
            Frame::Response(response) => return Talked { response, reveals, bundle },
            Frame::Notice(_) => {}
            Frame::Reveal(secret) => reveals.push(String::from_utf8(secret.expose_secret().to_vec()).unwrap()),
            Frame::BundleData(chunk) => bundle.extend_from_slice(chunk.bytes()),
            Frame::Prompt(prompt) => {
                let answer = answers
                    .next()
                    .unwrap_or_else(|| panic!("a prompt beyond the answers given: {prompt:?}"));
                let input = OwnerInput::new(Zeroizing::new(answer.as_bytes().to_vec()));
                send(stream, &Frame::OwnerInput(input)).await;
            }
            other => panic!("unexpected frame {other:?}"),
        }
    }
}

/// Runs `request`, checks the response is the one `expected` names, and checks the step's calls.
async fn step(steps: &Steps, service: &Service, request: AdminRequest, answers: &[&str], expected: fn(&AdminResponse) -> bool) -> Talked {
    let what = format!("{request:?}");
    let talked = talk(service, request, None, answers).await;
    assert!(expected(&talked.response), "{:?}", talked.response);
    steps.checked(&what);
    talked
}

fn origin(upstream: &MockUpstream) -> Vec<RequestedOrigin> {
    vec![RequestedOrigin {
        host: "localhost".to_owned(),
        port: upstream.port().try_into().unwrap(),
    }]
}

fn add(name: &str, upstream: &MockUpstream) -> AdminRequest {
    AdminRequest::Add {
        name: name.to_owned(),
        kind: CredentialKind::Static,
        origins: origin(upstream),
    }
}

fn config(fixture: &Fixture, upstream: &MockUpstream) -> AdminRequest {
    let config = format!(
        r#"schema_version = 1

[listeners.local]
unix_socket = "{socket}"
token_header = "{TOKEN_HEADER}"

[callers.agent]
listener = "local"
token_hash = "{hash}"
routes = ["fx"]

[routes.fx]
prefix = "/fx"
upstream = "https://localhost:{port}/v1"
ca_file = "/etc/iron-vault/ca/test.pem"
credential = "fx_key"
slot = {{ header = "X-Api-Key" }}
methods = ["GET"]
paths = ["/**"]
rate_limit = {{ requests = 100000, per_seconds = 1, burst = 100000 }}
"#,
        socket = fixture.path("proxy.sock").display(),
        hash = token_hash(TOKEN_BYTES),
        port = upstream.port(),
    );
    AdminRequest::ConfigApprove(ProposedConfig::new(config.into_bytes()).unwrap())
}

async fn approvers(service: &Service) -> Vec<ApproverEntry> {
    match talk(service, AdminRequest::ApproverList, None, &[]).await.response {
        AdminResponse::ApproverList { entries } => entries,
        other => panic!("expected the approver list, got {other:?}"),
    }
}

/// `init` and `unlock`; then the credential, approver, recipient and recovery commands, each of which writes the vault.
async fn change_the_vault(steps: &Steps, fixture: &Fixture, service: &Service, upstream: &MockUpstream) {
    let init = AdminRequest::Init { host_unlock: false };
    let (vault, approval) = (VAULT_PASSPHRASE, APPROVAL_PASSPHRASE);
    let recovery_key = step(steps, service, init, &[vault, vault, approval, approval, "yes"], |r| {
        matches!(r, AdminResponse::Init { .. })
    })
    .await
    .reveals
    .remove(0);
    step(steps, service, AdminRequest::Unlock, &[vault], |r| {
        matches!(r, AdminResponse::Unlock { .. })
    })
    .await;
    step(steps, service, add("fx_key", upstream), &["fx-secret"], |r| {
        matches!(r, AdminResponse::Add { .. })
    })
    .await;
    step(steps, service, add("old_key", upstream), &["old-secret"], |r| {
        matches!(r, AdminResponse::Add { .. })
    })
    .await;
    let replace = AdminRequest::Replace {
        name: "fx_key".to_owned(),
        kind: CredentialKind::Static,
        origins: origin(upstream),
    };
    step(steps, service, replace, &[approval, "fx-secret-2"], |r| {
        matches!(r, AdminResponse::Replace { .. })
    })
    .await;
    let rm = AdminRequest::Rm {
        name: "old_key".to_owned(),
    };
    step(steps, service, rm, &[approval], |r| matches!(r, AdminResponse::Success)).await;
    step(steps, service, config(fixture, upstream), &["yes", approval], |r| {
        matches!(r, AdminResponse::ConfigApprove(_))
    })
    .await;
    step(steps, service, AdminRequest::Lock, &[], |r| matches!(r, AdminResponse::Lock { .. })).await;
    step(steps, service, AdminRequest::Unlock, &[vault], |r| {
        matches!(r, AdminResponse::Unlock { .. })
    })
    .await;
    change_signers(steps, service, &recovery_key).await;
}

async fn change_signers(steps: &Steps, service: &Service, recovery_key: &str) {
    let add_approver = AdminRequest::ApproverAdd {
        kind: RequestedSignerKind::Software,
        label: "backup".to_owned(),
    };
    let added = [APPROVAL_PASSPHRASE, SECOND_APPROVAL, SECOND_APPROVAL];
    step(steps, service, add_approver, &added, |r| {
        matches!(r, AdminResponse::ApproverAdd { .. })
    })
    .await;
    let second = approvers(service).await.into_iter().find(|entry| !entry.active).unwrap().id;
    let remove_approver = AdminRequest::ApproverRemove {
        approver: *second.as_bytes(),
    };
    step(steps, service, remove_approver, &[APPROVAL_PASSPHRASE], |r| {
        matches!(r, AdminResponse::ApproverRemove { .. })
    })
    .await;
    let (_, key) = RecoveryKey::generate();
    let add_recipient = AdminRequest::RecipientAdd {
        recipient: key.to_string(),
        label: "session key".to_owned(),
    };
    step(steps, service, add_recipient, &[VAULT_PASSPHRASE], |r| {
        matches!(r, AdminResponse::RecipientAdd { .. })
    })
    .await;
    let remove_recipient = AdminRequest::RecipientRemove {
        recipient: key.to_string(),
    };
    step(steps, service, remove_recipient, &[APPROVAL_PASSPHRASE], |r| {
        matches!(r, AdminResponse::RecipientRemove { .. })
    })
    .await;
    step(steps, service, AdminRequest::RecoveryCheck, &[recovery_key], |r| {
        matches!(r, AdminResponse::RecoveryCheck { .. })
    })
    .await;
}

/// `export`, with the bundle written as the CLI writes it, through `fs`; returns the bundle as `fs` holds it, and the
/// vault ID that `reset` confirms.
async fn export(steps: &Steps, service: &Service, bundle: &Path) -> (Vec<u8>, String) {
    let fs = &steps.fs;
    let mut partial = PartialBundle::create(fs, bundle).unwrap();
    let answers = [VAULT_PASSPHRASE, EXPORT_PASSPHRASE, EXPORT_PASSPHRASE];
    let talked = talk(service, AdminRequest::Export, None, &answers).await;
    let AdminResponse::Export { vault_id, .. } = talked.response else {
        panic!("expected an export, got {:?}", talked.response)
    };
    std::io::Write::write_all(&mut partial, &talked.bundle).unwrap();
    assert_eq!(partial.keep().unwrap().map(|e| e.to_string()), None);
    drop(partial);
    steps.checked("export");
    (fs.contents(bundle).unwrap(), vault_id.to_string())
}

#[tokio::test]
async fn every_rename_and_unlink_in_a_whole_session_syncs_its_directory() {
    let _one = super::export::ONE_AT_A_TIME.lock().await;
    let ca = TestCa::new("session dir sync CA");
    let upstream = MockUpstream::start(&ca, Reply::ok("ok")).await;
    let settings = || {
        UpstreamSettings::new(DeploymentProfile::Development, invoking_user().unwrap(), TransportLimits::default())
            .with_pinned_trust(ca.trust())
    };
    let steps = Steps::new();
    let (source, dest) = (Fixture::new(), Fixture::new());
    let service = source.start_on(settings(), steps.fs.clone());
    steps.checked("the source's start");
    change_the_vault(&steps, &source, &service, &upstream).await;

    let bundle_path = source.path("vault.bundle");
    let (bundle, vault_id) = export(&steps, &service, &bundle_path).await;
    let imported = dest.start_on(settings(), steps.fs.clone());
    steps.checked("the destination's start");
    let answers = [EXPORT_PASSPHRASE, DEST_PASSPHRASE, DEST_PASSPHRASE, "yes"];
    let import = talk(&imported, AdminRequest::Import { host_unlock: false }, Some(&bundle), &answers).await;
    assert!(matches!(import.response, AdminResponse::Import(_)), "{:?}", import.response);
    steps.checked("import");
    step(&steps, &service, AdminRequest::Reset, &[&vault_id], |r| {
        matches!(r, AdminResponse::Reset { .. })
    })
    .await;

    let trace = steps.fs.with(|fs| fs.trace());
    let renamed_into = |dir: &Path| {
        trace
            .iter()
            .any(|call| matches!(call, FsCall::Rename { to, .. } if to.starts_with(dir)))
    };
    assert!(
        renamed_into(&dest.path("state")) && renamed_into(&dest.path("etc")),
        "the import bypassed the traced fs"
    );
    let linked = |call: &FsCall| matches!(call, FsCall::HardLink { to, .. } if *to == bundle_path);
    assert!(trace.iter().any(linked), "the bundle bypassed the traced fs");
}
