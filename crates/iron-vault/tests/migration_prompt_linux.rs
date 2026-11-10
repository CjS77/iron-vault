//! The migration authorization step of an admin exchange (design/migration-authorization.md, "Admin exchange", steps 5 to
//! 7), driven over the admin socket by a stand-in command that runs only that step: the right vault passphrase gives an
//! authorization, and every refusal gets its error code, retires the challenge, records one closing audit event, and
//! counts against the passphrase attempt limit only when it shows a wrong guess.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::fs;
use std::sync::Arc;
use std::time::Duration;

use common::approval_harness::{Captured, Fixture, assert_audit_record, captured_logs, converse, identity, read_frame, send};
use iron_vault::admin::ADMIN_SOCKET_NAME;
use iron_vault::admin::dispatch::{AdminHandler, HandlerFuture, Handlers};
use iron_vault::admin::migration_authorization::{NoAuthorization, no_authorization, require_migration_authorization};
use iron_vault::admin::principal::{AdminPrincipal, AdminPrincipals};
use iron_vault::admin::protocol::{AdminCommand, AdminRequest, AdminResponse, ErrorCode, Frame, Prompt};
use iron_vault::admin::server::{AdminServer, Exchange, Limits};
use iron_vault::admin::socket::AdminSocket;
use iron_vault::attempt_limit::{AttemptsCoolingDown, FAILURE_THRESHOLD};
use iron_vault::migration_authorization::{MigrationOperation, MigrationRefusal, OwnerRefusal};
use iron_vault::service_context::ServiceContext;
use iron_vault::service_state::ServiceState;
use iron_vault_store::{
    OperationalIdentity, OsFs, Passphrase, RecipientKey, RecipientSet, StateDirLock, seal_passphrase_envelope_for_tests, wrap_identity,
    write_identity_envelope, write_passphrase_envelope,
};
use secrecy::SecretString;
use tokio::net::UnixStream;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::Instant;

const PASSPHRASE: &str = "VAULT-correct-5d1a";
const WRONG_PASSPHRASE: &str = "VAULT-wrong-0b77";
/// The name the stand-in command answers to in its messages. It is registered as `ping`, whose request reaches it; its
/// success answer is `cleared`.
const COMMAND: &str = "export";

/// A command that begins a migration session and runs the migration authorization step and nothing else. Its success
/// answer is `cleared: true` when the authorization it got is valid for `operation`.
struct Authorizing {
    service: Arc<ServiceContext>,
    operation: MigrationOperation,
}

impl AdminHandler for Authorizing {
    fn handle<'a>(&'a self, _principal: AdminPrincipal, _request: AdminRequest, exchange: &'a mut Exchange) -> HandlerFuture<'a> {
        Box::pin(async move {
            let session = match self.service.begin_migration().await {
                Ok(session) => session,
                Err(refusal) => return Ok(no_authorization(COMMAND, NoAuthorization(refusal))),
            };
            let authorization = require_migration_authorization(exchange, &session, self.operation.clone()).await?;
            Ok(match authorization {
                Ok(authorization) => {
                    let vault = vault_id(&self.service).await;
                    AdminResponse::Lock {
                        cleared: authorization.authorize(vault, &self.operation, Instant::now()).is_ok(),
                    }
                }
                Err(none) => no_authorization(COMMAND, none),
            })
        })
    }
}

async fn vault_id(service: &ServiceContext) -> iron_vault_store::VaultId {
    match service.status().await.vault {
        iron_vault::admin::protocol::VaultStatus::Unlocked(vault) => vault.id,
        other => panic!("expected an unlocked vault, got {other:?}"),
    }
}

/// A fresh public key to be the destination, so one test's audit records tell apart from another's in the shared log.
fn recipient() -> RecipientKey {
    OperationalIdentity::generate().1
}

/// `identity.age` and `operational.age` sealed to [`PASSPHRASE`], as initialization writes them.
fn write_envelopes(fixture: &Fixture) {
    let lock = StateDirLock::acquire(&fixture.path("state")).unwrap();
    let (operational, operational_key) = OperationalIdentity::generate();
    let recipients = RecipientSet::new([operational_key, OperationalIdentity::generate().1]).unwrap();
    write_identity_envelope(&lock, &OsFs, &wrap_identity(&identity(), &recipients).unwrap()).unwrap();
    let passphrase = Passphrase::new(SecretString::from(PASSPHRASE)).unwrap();
    write_passphrase_envelope(
        &lock,
        &OsFs,
        &seal_passphrase_envelope_for_tests(&operational, &passphrase).unwrap(),
    )
    .unwrap();
}

/// A Ready service whose envelopes open with [`PASSPHRASE`], and the stand-in command served on its admin socket.
struct Served {
    fixture: Fixture,
    service: Arc<ServiceContext>,
    operation: MigrationOperation,
    logs: Captured,
    stop: Option<oneshot::Sender<()>>,
    server: Option<JoinHandle<()>>,
}

impl Served {
    async fn new() -> Self {
        Self::with_limits(Limits::default()).await
    }

    async fn with_limits(limits: Limits) -> Self {
        let logs = captured_logs();
        let fixture = Fixture::new().await;
        write_envelopes(&fixture);
        let service = fixture.ready().await;
        let operation = MigrationOperation::AddRecipient(recipient());
        let paths = service.paths().clone();
        let runtime_dir = paths.runtime_dir.clone().unwrap();
        let socket = AdminSocket::bind(&runtime_dir, paths.owner).unwrap();
        // The real handlers, so a `lock` request is the service's own, with the stand-in command beside them.
        let handlers = Handlers::for_service(&service).with(
            AdminCommand::Ping,
            Authorizing {
                service: Arc::clone(&service),
                operation: operation.clone(),
            },
        );
        let server = AdminServer::new(AdminPrincipals::new(paths.profile, paths.owner.uid), handlers, limits);
        let (stop, stopped) = oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            let _ = server
                .serve(socket, async {
                    let _ = stopped.await;
                })
                .await;
        });
        Self {
            fixture,
            service,
            operation,
            logs,
            stop: Some(stop),
            server: Some(server),
        }
    }

    /// A connection that has sent the stand-in command's request.
    async fn connect(&self) -> UnixStream {
        self.connect_with(AdminRequest::Ping).await
    }

    async fn connect_with(&self, request: AdminRequest) -> UnixStream {
        let runtime_dir = self.service.paths().runtime_dir.clone().unwrap();
        let mut stream = UnixStream::connect(runtime_dir.join(ADMIN_SOCKET_NAME)).await.unwrap();
        send(&mut stream, &Frame::Request(request)).await;
        stream
    }

    /// Runs the stand-in command, answering the prompt with `typed`.
    async fn run(&self, typed: &str) -> (Vec<Prompt>, AdminResponse) {
        let mut stream = self.connect().await;
        let exchanged = converse(&mut stream, &[typed]).await;
        (exchanged.prompts, exchanged.response)
    }

    /// The destination's records of `event`.
    fn events(&self, event: &str) -> Vec<serde_json::Value> {
        let destination = self.operation.destination().unwrap().to_string();
        self.logs
            .events(event)
            .into_iter()
            .filter(|record| record["destination_recipient"] == destination.as_str())
            .collect()
    }

    fn assert_challenge_issued_once(&self) {
        let issued = self.events("migration.challenge-issued");
        assert_eq!(issued.len(), 1, "{issued:?}");
        assert_audit_record(&issued[0], "INFO", &["operation", "method", "destination_recipient"]);
        assert_eq!(
            (issued[0]["operation"].as_str(), issued[0]["method"].as_str()),
            (Some("add_recipient"), Some("vault_passphrase"))
        );
    }

    /// The one refusal record, and that nothing else closed the challenge.
    fn the_refusal(&self, extra_fields: &[&str]) -> serde_json::Value {
        self.assert_challenge_issued_once();
        assert!(self.events("migration.authorized").is_empty());
        let refused = self.events("migration.authorization-refused");
        assert_eq!(refused.len(), 1, "{refused:?}");
        let own = ["operation", "method", "refusal", "destination_recipient"];
        assert_audit_record(&refused[0], "WARN", &[&own[..], extra_fields].concat());
        refused[0].clone()
    }

    async fn assert_retired(&self) {
        assert!(
            !self.service.pending_migration().await.is_pending(),
            "the challenge is still pending"
        );
    }

    /// Fails the attempt limit down to one failure short of its threshold, so any further counted failure limits.
    async fn fail_to_the_brink(&self) {
        let mut limiter = self.service.attempt_limiter().await;
        (1..FAILURE_THRESHOLD).for_each(|_| limiter.record_failure(Instant::now()));
    }

    /// Whether one more failure now limits, i.e. nothing since `fail_to_the_brink` counted.
    async fn assert_still_at_the_brink(&self) {
        let mut limiter = self.service.attempt_limiter().await;
        assert!(
            limiter.check(Instant::now()).is_ok(),
            "an outcome that shows no wrong guess counted as a failure"
        );
        limiter.record_failure(Instant::now());
        assert!(limiter.check(Instant::now()).is_err(), "the count fell short of the brink");
    }

    async fn wait_until_retired(&self) {
        tokio::time::timeout(common::WAIT, async {
            while self.service.pending_migration().await.is_pending() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the challenge was never retired");
    }
}

impl Served {
    /// Stops the server and waits until it has ended, abandoning any exchange still open after the grace.
    async fn shutdown(&mut self) {
        self.stop.take().into_iter().for_each(|stop| {
            let _ = stop.send(());
        });
        if let Some(server) = self.server.take() {
            server.await.unwrap();
        }
    }
}

impl Drop for Served {
    fn drop(&mut self) {
        self.stop.take().into_iter().for_each(|stop| {
            let _ = stop.send(());
        });
    }
}

fn denied_prompt() -> Prompt {
    Prompt {
        label: "Vault passphrase".to_owned(),
        secret: true,
        switchable: false,
    }
}

fn error_of(response: &AdminResponse) -> (ErrorCode, &str) {
    match response {
        AdminResponse::Error { code, message } => (*code, message),
        other => panic!("expected an error, got {other:?}"),
    }
}

#[tokio::test]
async fn the_right_passphrase_gives_an_authorization_for_the_operation() {
    let served = Served::new().await;

    let (prompts, response) = served.run(PASSPHRASE).await;

    assert_eq!(prompts, [denied_prompt()]);
    assert!(matches!(response, AdminResponse::Lock { cleared: true }), "{response:?}");
    served.assert_challenge_issued_once();
    let authorized = served.events("migration.authorized");
    assert_eq!(authorized.len(), 1, "{authorized:?}");
    assert_audit_record(&authorized[0], "INFO", &["operation", "method", "destination_recipient"]);
    assert!(served.events("migration.authorization-refused").is_empty());
    served.assert_retired().await;
}

#[tokio::test]
async fn a_wrong_passphrase_is_denied_with_one_refusal_event() {
    let served = Served::new().await;

    let (_, response) = served.run(WRONG_PASSPHRASE).await;

    let (code, message) = error_of(&response);
    assert_eq!((code as u16, code.name()), (28, "migration-denied"));
    assert!(!message.contains(WRONG_PASSPHRASE), "{message}");
    assert_eq!(served.the_refusal(&[])["refusal"], "wrong_passphrase");
    served.assert_retired().await;
}

#[tokio::test]
async fn input_that_cannot_be_a_passphrase_is_denied_as_a_wrong_one() {
    let served = Served::new().await;

    let (_, response) = served.run("").await;

    assert_eq!(error_of(&response).0, ErrorCode::MigrationDenied);
    assert_eq!(served.the_refusal(&[])["refusal"], "wrong_passphrase");
}

#[tokio::test]
async fn no_owner_input_cancels_with_no_authorization_and_retires_the_challenge() {
    let served = Served::new().await;
    served.fail_to_the_brink().await;
    let mut stream = served.connect().await;
    assert!(matches!(read_frame(&mut stream).await, Frame::Prompt(_)));
    assert!(served.service.pending_migration().await.is_pending());

    drop(stream);

    served.wait_until_retired().await;
    assert_eq!(served.the_refusal(&[])["refusal"], "cancelled");
    served.assert_still_at_the_brink().await;
}

#[tokio::test]
async fn a_lock_at_the_prompt_is_unavailable_and_records_no_failure() {
    let served = Served::new().await;
    served.fail_to_the_brink().await;
    let mut stream = served.connect().await;

    // The prompt is always written. A real `lock` then waits for the service-wide lock the session holds, which ends the
    // wait for the answer, so none is sent.
    assert!(matches!(read_frame(&mut stream).await, Frame::Prompt(_)));
    let mut lock = served.connect_with(AdminRequest::Lock).await;
    let Frame::Response(response) = read_frame(&mut stream).await else {
        panic!("expected the response after the prompt");
    };
    assert!(matches!(
        read_frame(&mut lock).await,
        Frame::Response(AdminResponse::Lock { cleared: true })
    ));

    let (code, message) = error_of(&response);
    assert_eq!((code as u16, code.name()), (29, "migration-unavailable"));
    assert!(message.contains("`lock`"), "{message}");
    assert_eq!(served.the_refusal(&[])["refusal"], "locked");
    served.assert_retired().await;
    served.assert_still_at_the_brink().await;
}

#[tokio::test]
async fn the_attempt_limit_answers_before_any_prompt_and_retires_the_challenge() {
    let served = Served::new().await;
    {
        let mut limiter = served.service.attempt_limiter().await;
        (0..FAILURE_THRESHOLD).for_each(|_| limiter.record_failure(Instant::now()));
    }
    let mut stream = served.connect().await;

    let exchanged = converse(&mut stream, &[]).await;

    assert!(exchanged.prompts.is_empty(), "a limited owner was asked to type");
    let (code, message) = error_of(&exchanged.response);
    assert_eq!((code as u16, code.name()), (33, "migration-rate-limited"));
    assert!(message.contains("30 seconds") || message.contains("29 seconds"), "{message}");
    let refused = served.the_refusal(&["retry_after"]);
    assert_eq!(refused["refusal"], "rate_limited");
    assert!(
        refused["retry_after"].as_u64().is_some_and(|seconds| (29..=30).contains(&seconds)),
        "{refused}"
    );
    served.assert_retired().await;
}

#[tokio::test]
async fn an_unavailable_check_is_unavailable_and_records_no_failure() {
    let served = Served::new().await;
    served.fail_to_the_brink().await;
    fs::remove_file(served.fixture.path("state/operational.age")).unwrap();

    let (_, response) = served.run(PASSPHRASE).await;

    assert_eq!(error_of(&response).0, ErrorCode::MigrationUnavailable);
    assert_eq!(served.the_refusal(&[])["refusal"], "unavailable");
    served.assert_retired().await;
    served.assert_still_at_the_brink().await;
}

#[tokio::test]
async fn the_log_holds_no_typed_bytes() {
    let served = Served::new().await;
    served.run(WRONG_PASSPHRASE).await;
    served.run(PASSPHRASE).await;

    let text = served.logs.text();
    [PASSPHRASE, WRONG_PASSPHRASE]
        .iter()
        .for_each(|typed| assert!(!text.contains(typed), "a passphrase reached the log:\n{text}"));
}

#[test]
fn each_refusal_maps_to_its_code_with_a_fixed_message() {
    let cooling = MigrationRefusal::AttemptsCoolingDown(AttemptsCoolingDown { retry_after: 45 });
    let table = [
        (MigrationRefusal::Denied(OwnerRefusal::WrongSecret), ErrorCode::MigrationDenied),
        (MigrationRefusal::Denied(OwnerRefusal::NotThisVault), ErrorCode::MigrationDenied),
        (MigrationRefusal::Expired, ErrorCode::MigrationDenied),
        (MigrationRefusal::NotPending, ErrorCode::MigrationDenied),
        (MigrationRefusal::BindingMismatch, ErrorCode::MigrationDenied),
        (MigrationRefusal::Unavailable, ErrorCode::MigrationUnavailable),
        (MigrationRefusal::WrongState(ServiceState::Locked), ErrorCode::MigrationUnavailable),
        (MigrationRefusal::WrongState(ServiceState::Checking), ErrorCode::WrongState),
        (cooling, ErrorCode::MigrationRateLimited),
    ];
    table.into_iter().for_each(|(refusal, expected)| {
        let response = no_authorization(COMMAND, NoAuthorization(refusal));
        assert_eq!(error_of(&response).0, expected, "{refusal:?}");
    });
    let response = no_authorization(COMMAND, NoAuthorization(cooling));
    assert!(error_of(&response).1.contains("45 seconds"), "{response:?}");
    let response = no_authorization(COMMAND, NoAuthorization(MigrationRefusal::WrongState(ServiceState::Locked)));
    assert_eq!(error_of(&response).0, ErrorCode::MigrationUnavailable);
}

#[tokio::test]
async fn a_session_holds_the_service_wide_lock_until_it_drops() {
    let served = Served::new().await;
    let session = served.service.begin_migration().await.unwrap();

    let second = served.service.begin_migration().await.err().unwrap();
    assert_eq!(second.label(), "busy");
    let (_, response) = served.run(PASSPHRASE).await;
    assert_eq!(error_of(&response).0, ErrorCode::Busy);

    drop(session);
    served.service.begin_migration().await.unwrap();
}

#[tokio::test]
async fn dropping_the_exchange_mid_prompt_retires_the_challenge() {
    let limits = Limits {
        shutdown_grace: Duration::from_millis(50),
        ..Limits::default()
    };
    let mut served = Served::with_limits(limits).await;
    let mut stream = served.connect().await;
    assert!(matches!(read_frame(&mut stream).await, Frame::Prompt(_)));
    assert!(served.service.pending_migration().await.is_pending());

    // Shutdown abandons the exchange still waiting at its prompt after the grace, dropping the handler's future.
    served.shutdown().await;

    served.assert_retired().await;
    let _session = served.service.begin_migration().await.unwrap();
    served.service.issue_migration_challenge(MigrationOperation::Export).await.unwrap();
}
