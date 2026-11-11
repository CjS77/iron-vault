//! The approver release checks (`design/approval-signers.md`, "Release checks"): what holds across `approver add`,
//! `approver remove` and `config approve` together, driven through a real service on a vault made by `init`. Every
//! approver passphrase and key file comes from `init` or `approver add`. Each command's own tests cover its exchange and
//! refusals.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use common::approval_harness::{Answer, Exchanged, WRONG_PASSPHRASE, captured_logs, converse_switching, error_code, send, spawn_admin};
use common::mock_upstream::{MockUpstream, Reply, TestCa};
use common::proxy_harness::{CallerRequest, Response, TOKEN_BYTES, TOKEN_HEADER, Via, WAIT, token_hash};
use common::recipient_harness::{APPROVAL_PASSPHRASE, Fixture, VAULT_PASSPHRASE, exchange, unlock};
use iron_vault::admin::protocol::{
    AdminRequest, AdminResponse, ApproverEntry, ErrorCode, Frame, ProposedConfig, RequestedOrigin, RequestedSignerKind,
};
use iron_vault::config_check::UpstreamSettings;
use iron_vault::deployment::DeploymentProfile;
use iron_vault::path_metadata::invoking_user;
use iron_vault::service_context::ServiceContext;
use iron_vault::upstream::client::TransportLimits;
use iron_vault_policy::CredentialKind;
use iron_vault_store::{ApprovalEnvelope, ApproverId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// Typed at `add`'s prompt; distinctive, so a search of the log cannot match anything else.
const CREDENTIAL_SECRET: &str = "APPROVERS-E2E-credential-7a3c";
const NEW_PASSPHRASE: &str = "ROTATED-approver-passphrase-5b19";
const SECOND_PASSPHRASE: &str = "SECOND-approver-passphrase-c04e";

/// A service on an `init`-made vault holding one credential, with the config `fx` approved by the `init` approver and
/// served through the service's own listener.
struct Session {
    fixture: Fixture,
    service: Arc<ServiceContext>,
    upstream: MockUpstream,
    recovery_key: String,
    first: ApproverId,
}

impl Session {
    async fn new() -> Self {
        let ca = TestCa::new("approvers e2e CA");
        let upstream = MockUpstream::start(&ca, Reply::ok("ok")).await;
        let fixture = Fixture::new();
        let settings = UpstreamSettings::new(DeploymentProfile::Development, invoking_user().unwrap(), TransportLimits::default());
        let service = fixture.start_with(settings.with_pinned_trust(ca.trust()));
        let recovery_key = common::recipient_harness::init(&service).await;
        unlock(&service).await;
        let (listed, _) = exchange(&service, AdminRequest::ApproverList, &[]).await;
        let first = match listed {
            AdminResponse::ApproverList { entries } => entries[0].id,
            other => panic!("expected the approver list, got {other:?}"),
        };
        let session = Self {
            fixture,
            service,
            upstream,
            recovery_key,
            first,
        };
        session.add_credential().await;
        let approved = session.approve(&["fx"], &[Answer::Input(APPROVAL_PASSPHRASE)]).await;
        assert!(is_approved(&approved), "{approved:?}");
        assert_eq!(session.get("fx").await.status, 200);
        session
    }

    /// Sends `request`, answering the prompts in turn with `answers`, on an admin socket of its own.
    async fn request(&self, request: AdminRequest, answers: &[Answer<'_>]) -> Exchanged {
        let (path, stop, task) = spawn_admin(&self.service);
        let mut stream = UnixStream::connect(path).await.unwrap();
        send(&mut stream, &Frame::Request(request)).await;
        let exchanged = converse_switching(&mut stream, answers).await;
        let _ = stop.send(());
        task.await.unwrap();
        exchanged
    }

    async fn add_credential(&self) {
        let origin = RequestedOrigin {
            host: "localhost".to_owned(),
            port: self.upstream.port().try_into().unwrap(),
        };
        let request = AdminRequest::Add {
            name: "fx_key".to_owned(),
            kind: CredentialKind::Static,
            origins: vec![origin],
        };
        let (response, _) = exchange(&self.service, request, &[CREDENTIAL_SECRET.as_bytes()]).await;
        assert!(matches!(response, AdminResponse::Add { .. }), "{response:?}");
    }

    /// `config approve` for a config granting `routes`, confirmed with `yes` and then answered with `answers`.
    async fn approve(&self, routes: &[&str], answers: &[Answer<'_>]) -> Exchanged {
        let config = ProposedConfig::new(self.config(routes).into_bytes()).unwrap();
        let answers = [&[Answer::Input("yes")], answers].concat();
        self.request(AdminRequest::ConfigApprove(config), &answers).await
    }

    fn config(&self, routes: &[&str]) -> String {
        let tables: String = routes
            .iter()
            .map(|route| {
                format!(
                    r#"
[routes.{route}]
prefix = "/{route}"
upstream = "https://localhost:{port}/v1"
ca_file = "/etc/iron-vault/ca/test.pem"
credential = "fx_key"
slot = {{ header = "X-Api-Key" }}
methods = ["GET"]
paths = ["/**"]
rate_limit = {{ requests = 100000, per_seconds = 1, burst = 100000 }}
"#,
                    port = self.upstream.port()
                )
            })
            .collect();
        let granted = routes.iter().map(|route| format!("\"{route}\"")).collect::<Vec<_>>().join(", ");
        format!(
            r#"schema_version = 1

[listeners.local]
unix_socket = "{socket}"
token_header = "{TOKEN_HEADER}"

[callers.agent]
listener = "local"
token_hash = "{hash}"
routes = [{granted}]
{tables}"#,
            socket = self.fixture.path("proxy.sock").display(),
            hash = token_hash(TOKEN_BYTES),
        )
    }

    /// The caller's `GET /<route>/latest`, over the service's own listener.
    async fn get(&self, route: &str) -> Response {
        let request = CallerRequest::get(&format!("/{route}/latest")).signed(Via::Unix);
        let mut stream = UnixStream::connect(self.fixture.path("proxy.sock")).await.unwrap();
        stream.write_all(&request.to_bytes()).await.unwrap();
        let mut raw = Vec::new();
        tokio::time::timeout(WAIT, stream.read_to_end(&mut raw)).await.unwrap().unwrap();
        Response::parse(&String::from_utf8(raw).unwrap())
    }

    /// A software `approver add` labelled `backup`, authorized by `presence` and choosing `new` twice.
    async fn add(&self, presence: &str, new: &str) -> Exchanged {
        let answers = [Answer::Input(presence), Answer::Input(new), Answer::Input(new)];
        let add = AdminRequest::ApproverAdd {
            kind: RequestedSignerKind::Software,
            label: "backup".to_owned(),
        };
        self.request(add, &answers).await
    }

    async fn remove(&self, id: ApproverId, answers: &[Answer<'_>]) -> Exchanged {
        self.request(AdminRequest::ApproverRemove { approver: *id.as_bytes() }, answers)
            .await
    }

    async fn approvers(&self) -> Vec<ApproverEntry> {
        match self.request(AdminRequest::ApproverList, &[]).await.response {
            AdminResponse::ApproverList { entries } => entries,
            other => panic!("expected the approver list, got {other:?}"),
        }
    }

    async fn active(&self) -> ApproverId {
        self.approvers().await.iter().find(|entry| entry.active).unwrap().id
    }

    async fn lock_and_unlock(&self) {
        let locked = self.request(AdminRequest::Lock, &[]).await;
        assert!(matches!(locked.response, AdminResponse::Lock { cleared: true }), "{locked:?}");
        unlock(&self.service).await;
    }

    fn key_file(&self, id: ApproverId) -> Option<Vec<u8>> {
        fs::read(self.fixture.path(&format!("state/approver-{id}.age"))).ok()
    }

    fn signer_of_published(&self) -> ApproverId {
        ApprovalEnvelope::decode(&fs::read(self.fixture.path("etc/config.toml.sig")).unwrap())
            .unwrap()
            .approver_id()
    }

    fn state_files(&self) -> BTreeMap<String, Vec<u8>> {
        self.fixture.state_files()
    }
}

fn enrolled(exchanged: &Exchanged) -> ApproverId {
    match exchanged.response {
        AdminResponse::ApproverAdd { approver, .. } => approver,
        ref other => panic!("expected an enrolled approver, got {other:?}"),
    }
}

fn is_approved(exchanged: &Exchanged) -> bool {
    matches!(exchanged.response, AdminResponse::ConfigApprove(_))
}

fn is_removed(exchanged: &Exchanged) -> bool {
    matches!(exchanged.response, AdminResponse::ApproverRemove { approvers: 1 })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A typed secret as the log could carry it: as typed, in base64 (padded or not) and in lowercase hex.
fn encodings_of_text(secret: &str) -> Vec<String> {
    vec![
        secret.to_owned(),
        STANDARD.encode(secret),
        STANDARD_NO_PAD.encode(secret),
        hex(secret.as_bytes()),
    ]
}

/// A key file as the log could carry it: its scrypt stanza line, its binary body in base64, and the whole file in
/// base64 and lowercase hex.
fn encodings_of_key_file(file: &[u8]) -> Vec<String> {
    let header_end = file.windows(5).position(|window| window == b"\n--- ").unwrap();
    let body_start = file[header_end + 1..].iter().position(|&byte| byte == b'\n').unwrap() + header_end + 2;
    let stanza = String::from_utf8_lossy(file)
        .lines()
        .find(|line| line.starts_with("-> scrypt "))
        .unwrap()
        .to_owned();
    vec![
        stanza,
        STANDARD.encode(&file[body_start..]),
        STANDARD_NO_PAD.encode(&file[body_start..]),
        STANDARD.encode(file),
        hex(file),
    ]
}

#[tokio::test]
async fn an_enrolled_approver_approves_and_the_envelope_names_it() {
    let session = Session::new().await;
    assert_eq!(session.signer_of_published(), session.first);

    let id = enrolled(&session.add(APPROVAL_PASSPHRASE, SECOND_PASSPHRASE).await);
    let approved = session
        .approve(&["fx", "rates"], &[Answer::Switch, Answer::Input(SECOND_PASSPHRASE)])
        .await;

    assert!(is_approved(&approved), "{approved:?}");
    assert_eq!(session.signer_of_published(), id);
    assert_eq!(session.active().await, id);
    assert_eq!(session.get("rates").await.status, 200);
}

#[tokio::test]
async fn rotating_the_approver_keeps_routes_serving() {
    let session = Session::new().await;
    let second = enrolled(&session.add(APPROVAL_PASSPHRASE, NEW_PASSPHRASE).await);
    // Between the add and the reapproval the first approver's approval is still the active one.
    assert_eq!(session.get("fx").await.status, 200);
    let approved = session
        .approve(&["fx", "rates"], &[Answer::Switch, Answer::Input(NEW_PASSPHRASE)])
        .await;
    assert!(is_approved(&approved), "{approved:?}");

    // The new approver signs the active approval, so it is asked first.
    let removed = session.remove(session.first, &[Answer::Input(NEW_PASSPHRASE)]).await;

    assert!(is_removed(&removed), "{removed:?}");
    assert!(session.key_file(session.first).is_none() && session.key_file(second).is_some());
    assert_eq!(session.get("fx").await.status, 200);
    // The next config check must still verify the active approval after a restart of the vault's state.
    session.lock_and_unlock().await;
    assert_eq!(session.get("fx").await.status, 200);
    assert_eq!(session.get("rates").await.status, 200);
    let again = session.approve(&["fx"], &[Answer::Input(NEW_PASSPHRASE)]).await;
    assert!(is_approved(&again), "{again:?}");
    assert_eq!(session.get("fx").await.status, 200);
}

#[tokio::test]
async fn the_last_and_the_active_approver_cannot_be_removed() {
    let session = Session::new().await;

    let last = session.remove(session.first, &[]).await;
    let second = enrolled(&session.add(APPROVAL_PASSPHRASE, NEW_PASSPHRASE).await);
    let before = session.state_files();
    let active = session.remove(session.first, &[]).await;

    assert_eq!((error_code(&last.response), last.prompts.len()), (ErrorCode::ApproverSetInvalid, 0));
    assert_eq!((error_code(&active.response), active.prompts.len()), (ErrorCode::ApproverInUse, 0));
    assert_eq!(session.state_files(), before);
    assert!(session.key_file(session.first).is_some() && session.key_file(second).is_some());
    assert_eq!(session.get("fx").await.status, 200);
}

#[tokio::test]
async fn a_wrong_answer_never_falls_through_to_another_approver() {
    let session = Session::new().await;
    let second = enrolled(&session.add(APPROVAL_PASSPHRASE, SECOND_PASSPHRASE).await);
    let before = session.state_files();

    // The active approver is asked first. The second approver's correct passphrase opens the second key, so it would
    // pass if the answer were tried against every approver; no further prompt follows the denial.
    let approval = session.approve(&["fx", "rates"], &[Answer::Input(SECOND_PASSPHRASE)]).await;
    let removal = session.remove(second, &[Answer::Input(SECOND_PASSPHRASE)]).await;

    assert_eq!(
        (error_code(&approval.response), approval.prompts.len()),
        (ErrorCode::ApprovalDenied, 2)
    );
    assert_eq!(
        (error_code(&removal.response), removal.prompts.len()),
        (ErrorCode::ApprovalDenied, 1)
    );
    assert_eq!(session.state_files(), before);
    assert_eq!(session.approvers().await.len(), 2);
}

#[tokio::test]
async fn only_a_pinned_approver_authorizes_an_approver_change() {
    let session = Session::new().await;
    let request = AdminRequest::RecipientAddRecovery {
        label: "second recovery".to_owned(),
    };
    let (added, reveals) = exchange(&session.service, request, &[b"yes", VAULT_PASSPHRASE.as_bytes()]).await;
    assert!(matches!(added, AdminResponse::RecipientAdd { .. }), "{added:?}");
    let fresh_key = reveals.into_iter().next().unwrap();
    // The fresh key opens the vault: it is a working key, only not an approver.
    let (checked, _) = exchange(&session.service, AdminRequest::RecoveryCheck, &[fresh_key.as_bytes()]).await;
    assert!(matches!(checked, AdminResponse::RecoveryCheck { .. }), "{checked:?}");
    let before = session.state_files();

    for presence in [VAULT_PASSPHRASE, fresh_key.as_str(), session.recovery_key.as_str()] {
        let denied = session.add(presence, NEW_PASSPHRASE).await;
        assert_eq!(error_code(&denied.response), ErrorCode::ApprovalDenied);
        assert_eq!(denied.prompts.len(), 1);
    }

    assert_eq!(session.state_files(), before);
    assert_eq!(before.keys().filter(|name| name.starts_with("approver-")).count(), 1);
    assert_eq!(session.approvers().await.len(), 1);
}

#[tokio::test]
async fn a_removed_approver_gives_no_presence_and_leaves_no_key_file() {
    let session = Session::new().await;
    let second = enrolled(&session.add(APPROVAL_PASSPHRASE, SECOND_PASSPHRASE).await);
    let removed = session.remove(second, &[Answer::Switch, Answer::Input(SECOND_PASSPHRASE)]).await;
    assert!(is_removed(&removed), "{removed:?}");
    assert!(session.key_file(second).is_none());
    let before = session.state_files();

    let by_add = session.add(SECOND_PASSPHRASE, NEW_PASSPHRASE).await;
    let by_approval = session.approve(&["fx"], &[Answer::Input(SECOND_PASSPHRASE)]).await;

    assert_eq!((error_code(&by_add.response), by_add.prompts.len()), (ErrorCode::ApprovalDenied, 1));
    assert_eq!(error_code(&by_approval.response), ErrorCode::ApprovalDenied);
    assert_eq!(session.state_files(), before);
}

#[tokio::test]
async fn no_typed_secret_reaches_the_log_through_approver_commands() {
    let logs = captured_logs();
    let session = Session::new().await;
    let request = AdminRequest::RecipientAddRecovery {
        label: "second recovery".to_owned(),
    };
    let (added, reveals) = exchange(&session.service, request, &[b"yes", VAULT_PASSPHRASE.as_bytes()]).await;
    assert!(matches!(added, AdminResponse::RecipientAdd { .. }), "{added:?}");
    let fresh_key = reveals.into_iter().next().unwrap();
    let first_file = session.key_file(session.first).unwrap();

    for presence in [VAULT_PASSPHRASE, fresh_key.as_str(), WRONG_PASSPHRASE] {
        let denied = session.add(presence, NEW_PASSPHRASE).await;
        assert_eq!(error_code(&denied.response), ErrorCode::ApprovalDenied);
    }
    let second = enrolled(&session.add(APPROVAL_PASSPHRASE, SECOND_PASSPHRASE).await);
    let second_file = session.key_file(second).unwrap();
    let approved = session
        .approve(&["fx", "rates"], &[Answer::Switch, Answer::Input(SECOND_PASSPHRASE)])
        .await;
    assert!(is_approved(&approved), "{approved:?}");
    let denied = session.remove(session.first, &[Answer::Input(WRONG_PASSPHRASE)]).await;
    assert_eq!(error_code(&denied.response), ErrorCode::ApprovalDenied);
    let removed = session.remove(session.first, &[Answer::Input(SECOND_PASSPHRASE)]).await;
    assert!(is_removed(&removed), "{removed:?}");

    let own = |event: &str, id: ApproverId| {
        logs.events(event)
            .iter()
            .filter(|record| record["approver_id"] == id.to_string().as_str())
            .count()
    };
    assert_eq!((own("approver.enrolled", second), own("approver.removed", session.first)), (1, 1));
    let text = logs.text();
    let typed = [
        VAULT_PASSPHRASE,
        APPROVAL_PASSPHRASE,
        CREDENTIAL_SECRET,
        WRONG_PASSPHRASE,
        NEW_PASSPHRASE,
        SECOND_PASSPHRASE,
        "AGE-SECRET-KEY-1",
        &fresh_key,
        &session.recovery_key,
    ];
    typed
        .iter()
        .flat_map(|secret| encodings_of_text(secret))
        .chain(encodings_of_key_file(&first_file))
        .chain(encodings_of_key_file(&second_file))
        .for_each(|needle| assert!(!text.contains(&needle), "a secret or key file encoding reached the log: {needle}"));
}
