//! The recipient epic's promises end to end through a real service on a vault made by `init` (`design/recipients.md`,
//! "Release checks"): a rewrap never loses the vault and never touches a credential, a removal reaches only future
//! envelopes, adding a key needs the vault passphrase even while Ready, and no secret reaches the log. The per-command
//! suites (`recipient_*_linux.rs`) cover each command's exchange; these tests cover the promises that need them together.

#![cfg(target_os = "linux")]

use crate::common;

use std::collections::BTreeMap;
use std::fs;
use std::sync::Arc;

use common::approval_harness::{Captured, captured_logs};
use common::mock_upstream::{MockUpstream, Reply, TestCa};
use common::proxy_harness::{CallerRequest, Response, TOKEN_BYTES, TOKEN_HEADER, Via, WAIT, token_hash};
use common::recipient_harness::{APPROVAL_PASSPHRASE, Fixture, VAULT_PASSPHRASE, exchange, list, listed, ready, refusal, unlock};
use iron_vault::admin::protocol::{AdminRequest, AdminResponse, ErrorCode, ProposedConfig, RequestedOrigin};
use iron_vault::config_check::UpstreamSettings;
use iron_vault::deployment::DeploymentProfile;
use iron_vault::path_metadata::invoking_user;
use iron_vault::service_context::ServiceContext;
use iron_vault::service_state::ServiceState;
use iron_vault::upstream::client::TransportLimits;
use iron_vault_policy::CredentialKind;
use iron_vault_store::{RecipientIdentity, RecipientKey, RecipientRole, RecoveryKey, open_manifest, unwrap_identity};
use secrecy::{ExposeSecret, SecretString};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// Typed at `add`'s prompt; distinctive, so a search of the log cannot match anything else.
const CREDENTIAL_SECRET: &str = "RECIPIENTS-E2E-credential-5b1d";

fn fresh_key() -> (RecipientKey, RecipientIdentity) {
    let (secret, key) = RecoveryKey::generate();
    (
        key,
        RecipientIdentity::parse(&SecretString::from(secret.expose_secret().to_owned())).unwrap(),
    )
}

/// A service on an `init`-made vault holding one credential, routed to a mock upstream by an approved config, with its
/// log captured.
struct Session {
    fixture: Fixture,
    service: Arc<ServiceContext>,
    upstream: MockUpstream,
    recovery_key: String,
    logs: Captured,
}

impl Session {
    async fn new() -> Self {
        let logs = captured_logs();
        let ca = TestCa::new("recipients e2e CA");
        let upstream = MockUpstream::start(&ca, Reply::ok("ok")).await;
        let fixture = Fixture::new();
        let settings = UpstreamSettings::new(DeploymentProfile::Development, invoking_user().unwrap(), TransportLimits::default());
        let service = fixture.start_with(settings.with_pinned_trust(ca.trust()));
        let recovery_key = common::recipient_harness::init(&service).await;
        unlock(&service).await;
        let session = Self {
            fixture,
            service,
            upstream,
            recovery_key,
            logs,
        };
        session.add_credential().await;
        session.approve_config().await;
        assert_eq!(session.get().await.status, 200);
        session
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

    async fn approve_config(&self) {
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
            socket = self.fixture.path("proxy.sock").display(),
            hash = token_hash(TOKEN_BYTES),
            port = self.upstream.port(),
        );
        let request = AdminRequest::ConfigApprove(ProposedConfig::new(config.into_bytes()).unwrap());
        let (response, _) = exchange(&self.service, request, &[b"yes", APPROVAL_PASSPHRASE.as_bytes()]).await;
        assert!(matches!(response, AdminResponse::ConfigApprove { .. }), "{response:?}");
    }

    /// The caller's `GET /fx/latest` through the route, over the service's own listener.
    async fn get(&self) -> Response {
        let request = CallerRequest::get("/fx/latest").signed(Via::Unix);
        let mut stream = UnixStream::connect(self.fixture.path("proxy.sock")).await.unwrap();
        stream.write_all(&request.to_bytes()).await.unwrap();
        let mut raw = Vec::new();
        tokio::time::timeout(WAIT, stream.read_to_end(&mut raw)).await.unwrap().unwrap();
        Response::parse(&String::from_utf8(raw).unwrap())
    }

    /// Every state file but the envelope and the inventory: the manifest, the credential records, the approval state.
    fn untouched_files(&self) -> BTreeMap<String, Vec<u8>> {
        let mut files = self.fixture.state_files();
        files.retain(|name, _| name != "identity.age" && name != "recipients.age");
        files
    }

    fn envelope(&self) -> Vec<u8> {
        fs::read(self.fixture.path("state/identity.age")).unwrap()
    }

    async fn add_key(&self, key: &RecipientKey, typed: &str) -> AdminResponse {
        let request = AdminRequest::RecipientAdd {
            recipient: key.to_string(),
            label: "e2e key".to_owned(),
        };
        exchange(&self.service, request, &[typed.as_bytes()]).await.0
    }

    async fn remove_key(&self, key: &RecipientKey) -> AdminResponse {
        let request = AdminRequest::RecipientRemove {
            recipient: key.to_string(),
        };
        exchange(&self.service, request, &[APPROVAL_PASSPHRASE.as_bytes()]).await.0
    }

    async fn key_of(&self, role: RecipientRole) -> RecipientKey {
        let entries = listed(list(&self.service).await);
        entries.iter().find(|entry| entry.role() == role).unwrap().key().clone()
    }
}

#[tokio::test]
async fn an_added_recipient_opens_the_vault_after_a_restart() {
    let fixture = Fixture::new();
    let (service, _) = ready(&fixture).await;
    let (key, identity) = fresh_key();
    let request = AdminRequest::RecipientAdd {
        recipient: key.to_string(),
        label: "restart key".to_owned(),
    };
    let (added, _) = exchange(&service, request, &[VAULT_PASSPHRASE.as_bytes()]).await;
    assert!(matches!(added, AdminResponse::RecipientAdd { recipients: 3, .. }), "{added:?}");

    drop(service);
    let service = fixture.start();
    unlock(&service).await;

    assert_eq!(service.state().await, ServiceState::Ready);
    let vault = unwrap_identity(&fs::read(fixture.path("state/identity.age")).unwrap(), &identity).unwrap();
    open_manifest(&vault, &fs::read(fixture.path("state/manifest.age")).unwrap()).expect("the manifest MAC must verify under the new key");
}

#[tokio::test]
async fn a_rewrap_leaves_every_credential_file_byte_identical_and_the_route_working() {
    let session = Session::new().await;
    let before = session.untouched_files();
    assert!(before.keys().any(|name| name.starts_with("record-")), "{:?}", before.keys());
    let (key, _) = fresh_key();

    let added = session.add_key(&key, VAULT_PASSPHRASE).await;
    assert!(matches!(added, AdminResponse::RecipientAdd { recipients: 3, .. }), "{added:?}");
    assert_eq!(session.untouched_files(), before);
    assert_eq!(session.get().await.status, 200);
    let removed = session.remove_key(&key).await;

    assert!(matches!(removed, AdminResponse::RecipientRemove { recipients: 2 }), "{removed:?}");
    assert_eq!(session.untouched_files(), before);
    assert_eq!(session.get().await.status, 200);
    let requests = session.upstream.requests();
    assert_eq!(requests.len(), 3);
    for request in &requests {
        let key = request
            .headers()
            .into_iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("x-api-key"));
        assert_eq!(
            key.map(|(_, value)| value).as_deref(),
            Some(CREDENTIAL_SECRET),
            "the credential was not injected"
        );
    }
}

#[tokio::test]
async fn a_change_that_leaves_fewer_than_two_independent_paths_is_refused_and_changes_nothing() {
    let session = Session::new().await;
    let (key, _) = fresh_key();
    let added = session.add_key(&key, VAULT_PASSPHRASE).await;
    assert!(matches!(added, AdminResponse::RecipientAdd { recipients: 3, .. }), "{added:?}");
    let before = session.fixture.state_files();

    // An added key is no independent path: with it enrolled, the recovery key is still the last one.
    for role in [RecipientRole::Recovery, RecipientRole::Operational] {
        let refused = session.remove_key(&session.key_of(role).await).await;
        assert_eq!(refusal(refused).0, ErrorCode::RecipientSetInvalid, "{role:?}");
    }

    assert_eq!(session.fixture.state_files(), before);
    assert_eq!(session.get().await.status, 200);
}

#[tokio::test]
async fn a_removed_key_still_opens_a_copy_of_the_envelope_taken_before_the_removal() {
    let session = Session::new().await;
    let (key, identity) = fresh_key();
    session.add_key(&key, VAULT_PASSPHRASE).await;
    let old_copy = session.envelope();

    let removed = session.remove_key(&key).await;

    assert!(matches!(removed, AdminResponse::RecipientRemove { .. }), "{removed:?}");
    assert!(
        unwrap_identity(&session.envelope(), &identity).is_err(),
        "the removed key opens the new envelope"
    );
    let vault = unwrap_identity(&old_copy, &identity).expect("§16: an old copy still opens with the removed key");
    open_manifest(&vault, &session.fixture.state_files()["manifest.age"]).expect("the old copy yields the live vault identity");
}

#[tokio::test]
async fn adding_a_recipient_needs_the_vault_passphrase_even_while_ready() {
    let session = Session::new().await;
    let (key, identity) = fresh_key();
    let before = session.fixture.state_files();
    assert_eq!(session.service.state().await, ServiceState::Ready);

    // Being unlocked proves nothing, and the approval passphrase is not the source factor.
    let refused = session.add_key(&key, APPROVAL_PASSPHRASE).await;

    assert_eq!(refusal(refused).0, ErrorCode::MigrationDenied);
    assert_eq!(session.fixture.state_files(), before);
    assert!(unwrap_identity(&session.envelope(), &identity).is_err());
    let accepted = session.add_key(&key, VAULT_PASSPHRASE).await;
    assert!(matches!(accepted, AdminResponse::RecipientAdd { .. }), "{accepted:?}");
    assert!(unwrap_identity(&session.envelope(), &identity).is_ok());
}

#[tokio::test]
async fn after_rotating_the_recovery_key_the_new_key_passes_recovery_check_and_the_old_fails() {
    let session = Session::new().await;
    let old_key = session.key_of(RecipientRole::Recovery).await;
    let request = AdminRequest::RecipientAddRecovery {
        label: "rotated".to_owned(),
    };
    let (_, reveals) = exchange(&session.service, request, &[b"yes", VAULT_PASSPHRASE.as_bytes()]).await;
    let new_secret = reveals.into_iter().next().unwrap();
    let removed = session.remove_key(&old_key).await;
    assert!(matches!(removed, AdminResponse::RecipientRemove { recipients: 2 }), "{removed:?}");

    let (new_check, _) = exchange(&session.service, AdminRequest::RecoveryCheck, &[new_secret.as_bytes()]).await;
    let (old_check, _) = exchange(&session.service, AdminRequest::RecoveryCheck, &[session.recovery_key.as_bytes()]).await;

    assert!(matches!(new_check, AdminResponse::RecoveryCheck { .. }), "{new_check:?}");
    assert_eq!(refusal(old_check).0, ErrorCode::RecoveryCheckFailed);
}

#[tokio::test]
async fn no_typed_secret_or_secret_key_reaches_the_log_through_a_full_session() {
    const WRONG: &str = "wrong vault passphrase E2E-3f9a";
    let session = Session::new().await;
    let (key, _) = fresh_key();
    let old_recovery = session.key_of(RecipientRole::Recovery).await;
    let denied = session.add_key(&key, WRONG).await;
    assert_eq!(refusal(denied).0, ErrorCode::MigrationDenied);
    let added = session.add_key(&key, VAULT_PASSPHRASE).await;
    assert!(matches!(added, AdminResponse::RecipientAdd { .. }), "{added:?}");
    let removed = session.remove_key(&key).await;
    assert!(matches!(removed, AdminResponse::RecipientRemove { .. }), "{removed:?}");
    let request = AdminRequest::RecipientAddRecovery {
        label: "rotated".to_owned(),
    };
    let (rotated, reveals) = exchange(&session.service, request, &[b"yes", VAULT_PASSPHRASE.as_bytes()]).await;
    assert!(matches!(rotated, AdminResponse::RecipientAdd { .. }), "{rotated:?}");
    let new_secret = reveals.into_iter().next().unwrap();
    let removed = session.remove_key(&old_recovery).await;
    assert!(matches!(removed, AdminResponse::RecipientRemove { .. }), "{removed:?}");
    let (new_check, _) = exchange(&session.service, AdminRequest::RecoveryCheck, &[new_secret.as_bytes()]).await;
    assert!(matches!(new_check, AdminResponse::RecoveryCheck { .. }), "{new_check:?}");
    let (old_check, _) = exchange(&session.service, AdminRequest::RecoveryCheck, &[session.recovery_key.as_bytes()]).await;
    assert_eq!(refusal(old_check).0, ErrorCode::RecoveryCheckFailed);

    assert!(!session.logs.events("recipient.added").is_empty() && !session.logs.events("recipient.removed").is_empty());
    let text = session.logs.text();
    [
        VAULT_PASSPHRASE,
        APPROVAL_PASSPHRASE,
        CREDENTIAL_SECRET,
        WRONG,
        "AGE-SECRET-KEY-1",
        &new_secret,
        &session.recovery_key,
    ]
    .iter()
    .for_each(|secret| assert!(!text.contains(secret), "a secret reached the log"));
}
