//! The release-check rejection suite for migration authorization (specification §19, §16;
//! design/migration-authorization.md), driven through a real admin socket. Rows marked *export* run the real `export`
//! command, and count it authorized once it asks for the new export passphrase, where the test hangs up. The other rows
//! need a challenge the owner cannot reach through `export`: a proof spent for another operation, a proof presented
//! twice, a challenge never issued, or a clock moved past the challenge's lifetime. They run through a handler
//! registered only here, which takes the same steps as `export`.
//!
//! One test per rejection §19 names. Cases that `migration_prompt.rs` already pins over the same socket are not
//! repeated; this file maps them so a reader of the checklist finds every case:
//!
//! | §19 case                                    | Test                                                                              |
//! |---------------------------------------------|-----------------------------------------------------------------------------------|
//! | missing                                     | `missing_authorization_has_no_way_to_start`                                       |
//! | incorrect (*export*)                        | `incorrect_*` here, and `a_wrong_passphrase_is_denied_with_one_refusal_event`     |
//! | expired                                     | `expired_between_the_prompt_and_the_check_is_denied`                              |
//! | replayed                                    | `replayed_proof_and_replayed_challenge_are_refused`                               |
//! | cancelled: CLI closes at the prompt         | `no_owner_input_cancels_with_no_authorization_and_retires_the_challenge` (prompt) |
//! | cancelled: a `lock` at the prompt           | `a_lock_at_the_prompt_is_unavailable_and_records_no_failure` (prompt)             |
//! | bound to one operation and destination      | `bound_*`                                                                         |
//! | already unlocked, no fresh proof (*export*) | `an_unlocked_vault_does_not_authorize_without_a_fresh_proof`                      |
//! | new export passphrase (*export*)            | `a_new_export_passphrase_never_authorizes`                                        |
//! | attempt limit (*export*)                    | `the_attempt_limit_applies_after_repeated_wrong_passphrases`                      |
//! | no typed secret in the log (*export*)       | `no_typed_secret_reaches_the_log`                                                 |

#![cfg(target_os = "linux")]

use crate::common;

use std::sync::Arc;

use common::approval_harness::{APPROVAL_PASSPHRASE, Captured, Fixture, captured_logs, converse, identity, read_frame, send};
use iron_vault::admin::ADMIN_SOCKET_NAME;
use iron_vault::admin::dispatch::{AdminHandler, HandlerFuture, Handlers};
use iron_vault::admin::migration_authorization::{NoAuthorization, askable_methods, no_authorization, require_migration_authorization};
use iron_vault::admin::principal::{AdminPrincipal, AdminPrincipals};
use iron_vault::admin::protocol::{AdminCommand, AdminRequest, AdminResponse, ErrorCode, Frame, OwnerInput, Prompt, VaultStatus};
use iron_vault::admin::server::{AdminServer, Exchange, Limits};
use iron_vault::admin::socket::AdminSocket;
use iron_vault::attempt_limit::FAILURE_THRESHOLD;
use iron_vault::migration_authorization::{CHALLENGE_LIFETIME, MigrationOperation, MigrationRefusal, PendingMigration};
use iron_vault::service_context::ServiceContext;
use iron_vault_store::{
    OperationalIdentity, OsFs, Passphrase, RecipientKey, RecipientSet, VaultId, VaultIdentity, seal_passphrase_envelope_for_tests,
    wrap_identity, write_identity_envelope, write_passphrase_envelope,
};
use secrecy::SecretString;
use tokio::net::UnixStream;
use tokio::sync::oneshot;
use tokio::time::Instant;
use zeroize::Zeroizing;

const PASSPHRASE: &str = "VAULT-correct-5d1a";
const WRONG_PASSPHRASE: &str = "VAULT-wrong-0b77";
const EXPORT_PASSPHRASE: &str = "EXPORT-new-8c3f";
const COMMAND: &str = "export";

/// How the stand-in command spends the authorization it gets.
#[derive(Clone, Copy)]
enum Mode {
    /// Authorize the operation in `spend`, which may differ from the one the challenge was issued for.
    Spend,
    /// Prove the challenge, then try to prove it again and to take it again.
    Replay,
}

struct Gate {
    service: Arc<ServiceContext>,
    issued_for: MigrationOperation,
    spend: MigrationOperation,
    mode: Mode,
}

impl Gate {
    async fn spend(&self, exchange: &mut Exchange) -> Result<AdminResponse, iron_vault::admin::server::ExchangeError> {
        let session = match self.service.begin_migration().await {
            Ok(session) => session,
            Err(refusal) => return Ok(no_authorization(COMMAND, NoAuthorization(refusal))),
        };
        let methods = match askable_methods(&session).await {
            Ok(methods) => methods,
            Err(none) => return Ok(no_authorization(COMMAND, none)),
        };
        Ok(
            match require_migration_authorization(exchange, &session, self.issued_for.clone(), &methods).await? {
                Err(none) => no_authorization(COMMAND, none),
                Ok(authorization) => match authorization.authorize(vault_id(&self.service).await, &self.spend, Instant::now()) {
                    Ok(_) => AdminResponse::Lock {
                        cleared: true,
                        persisted: true,
                    },
                    Err(refusal) => no_authorization(COMMAND, NoAuthorization(refusal)),
                },
            },
        )
    }

    /// Runs the steps by hand, so that the proof can be presented again after it was spent.
    async fn replay(&self, exchange: &mut Exchange) -> Result<AdminResponse, iron_vault::admin::server::ExchangeError> {
        let _session = match self.service.begin_migration().await {
            Ok(session) => session,
            Err(refusal) => return Ok(no_authorization(COMMAND, NoAuthorization(refusal))),
        };
        let method = self.service.vault_passphrase_method().await.unwrap();
        let digest = self.service.issue_migration_challenge(self.issued_for.clone()).await.unwrap();
        let prompt = Prompt {
            label: "Vault passphrase".to_owned(),
            secret: true,
            switchable: false,
        };
        let typed = exchange.prompt(&prompt).await?;
        if let Err(refusal) = self.service.authorize_migration(&digest, &method, typed).await {
            return Ok(no_authorization(COMMAND, NoAuthorization(refusal)));
        }
        let again = OwnerInput::new(Zeroizing::new(PASSPHRASE.as_bytes().to_vec()));
        let reproved = self.service.authorize_migration(&digest, &method, again).await.unwrap_err();
        let retaken = self.service.pending_migration().await.take(&digest, Instant::now()).err();
        Ok(match (reproved, retaken) {
            (MigrationRefusal::NotPending, Some(MigrationRefusal::NotPending)) => {
                no_authorization(COMMAND, NoAuthorization(MigrationRefusal::NotPending))
            }
            _ => AdminResponse::Lock {
                cleared: true,
                persisted: true,
            },
        })
    }
}

impl AdminHandler for Gate {
    fn handle<'a>(&'a self, _principal: AdminPrincipal, _request: AdminRequest, exchange: &'a mut Exchange) -> HandlerFuture<'a> {
        Box::pin(async move {
            match self.mode {
                Mode::Spend => self.spend(exchange).await,
                Mode::Replay => self.replay(exchange).await,
            }
        })
    }
}

async fn vault_id(service: &ServiceContext) -> VaultId {
    match service.status().await.vault {
        VaultStatus::Unlocked(vault) => vault.id,
        other => panic!("expected an unlocked vault, got {other:?}"),
    }
}

fn recipient() -> RecipientKey {
    OperationalIdentity::generate().1
}

/// `identity.age` holding `vault` and `operational.age` sealed to [`PASSPHRASE`], as initialization writes them.
fn write_envelopes(fixture: &Fixture, vault: &VaultIdentity) {
    let lock = common::approval_harness::state_dir_lock(&fixture.path("state"));
    let (operational, operational_key) = OperationalIdentity::generate();
    let recipients = RecipientSet::new([operational_key, OperationalIdentity::generate().1]).unwrap();
    write_identity_envelope(&lock, &OsFs, &wrap_identity(vault, &recipients).unwrap()).unwrap();
    let passphrase = Passphrase::new(SecretString::from(PASSPHRASE)).unwrap();
    let sealed = seal_passphrase_envelope_for_tests(&operational, &passphrase).unwrap();
    write_passphrase_envelope(&lock, &OsFs, &sealed).unwrap();
}

/// How the real `export` ended.
#[derive(Debug)]
enum Exported {
    /// The vault passphrase authorized the export, which asked for the new export passphrase.
    Authorized,
    /// The export was refused, with this code and message.
    Refused(ErrorCode, String),
}

/// A Ready service and the stand-in command served on its admin socket.
struct Served {
    service: Arc<ServiceContext>,
    logs: Captured,
    operation: MigrationOperation,
    _fixture: Fixture,
    stop: Option<oneshot::Sender<()>>,
}

impl Served {
    async fn new() -> Self {
        let operation = MigrationOperation::AddRecipient(recipient());
        Self::with(Mode::Spend, operation.clone(), operation, &identity()).await
    }

    /// `envelopes_of` is the vault whose envelopes are on disk; the service itself holds [`identity`].
    async fn with(mode: Mode, issued_for: MigrationOperation, spend: MigrationOperation, envelopes_of: &VaultIdentity) -> Self {
        let logs = captured_logs();
        let fixture = Fixture::new().await;
        write_envelopes(&fixture, envelopes_of);
        let service = fixture.ready().await;
        let paths = service.paths().clone();
        let socket = AdminSocket::bind(paths.runtime_dir.as_ref().unwrap(), paths.owner).unwrap();
        let gate = Gate {
            service: Arc::clone(&service),
            issued_for: issued_for.clone(),
            spend,
            mode,
        };
        let handlers = Handlers::for_service(&service).with(AdminCommand::Ping, gate);
        let server = AdminServer::new(AdminPrincipals::new(paths.profile, paths.owner.uid), handlers, Limits::default());
        let (stop, stopped) = oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = server
                .serve(socket, async {
                    let _ = stopped.await;
                })
                .await;
        });
        Self {
            service,
            logs,
            operation: issued_for,
            _fixture: fixture,
            stop: Some(stop),
        }
    }

    async fn connect(&self) -> UnixStream {
        let runtime_dir = self.service.paths().runtime_dir.clone().unwrap();
        let mut stream = UnixStream::connect(runtime_dir.join(ADMIN_SOCKET_NAME)).await.unwrap();
        send(&mut stream, &Frame::Request(AdminRequest::Ping)).await;
        stream
    }

    /// Runs the command once, typing `typed` at the prompt (if there is one).
    async fn run(&self, typed: &str) -> (usize, AdminResponse) {
        let mut stream = self.connect().await;
        let exchanged = converse(&mut stream, &[typed]).await;
        (exchanged.prompts.len(), exchanged.response)
    }

    /// Runs the real `export`, typing `typed` at the vault passphrase prompt; returns the prompts answered and the ending.
    async fn export(&self, typed: &str) -> (usize, Exported) {
        let runtime_dir = self.service.paths().runtime_dir.clone().unwrap();
        let mut stream = UnixStream::connect(runtime_dir.join(ADMIN_SOCKET_NAME)).await.unwrap();
        send(&mut stream, &Frame::Request(AdminRequest::Export)).await;
        let mut prompts = 0;
        loop {
            match read_frame(&mut stream).await {
                Frame::Prompt(prompt) if prompt.label == "Export passphrase" => return (prompts, Exported::Authorized),
                Frame::Prompt(_) => {
                    prompts += 1;
                    let answer = OwnerInput::new(Zeroizing::new(typed.as_bytes().to_vec()));
                    send(&mut stream, &Frame::OwnerInput(answer)).await;
                }
                Frame::Notice(_) => {}
                Frame::Response(AdminResponse::Error { code, message }) => return (prompts, Exported::Refused(code, message)),
                other => panic!("unexpected frame from export: {other:?}"),
            }
        }
    }

    /// Runs the real `export` and expects a refusal, whose code and message it returns.
    async fn export_refused(&self, typed: &str) -> (ErrorCode, String) {
        match self.export(typed).await.1 {
            Exported::Refused(code, message) => (code, message),
            Exported::Authorized => panic!("expected a refusal, but export was authorized"),
        }
    }

    /// Runs the command and expects an error answer, whose code and message it returns.
    async fn refused(&self, typed: &str) -> (ErrorCode, String) {
        match self.run(typed).await.1 {
            AdminResponse::Error { code, message } => (code, message),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// This service's records of `event`, told apart from other tests' by the destination when it has one.
    fn events(&self, event: &str) -> Vec<serde_json::Value> {
        let destination = self.operation.destination().map(ToString::to_string);
        self.logs
            .events(event)
            .into_iter()
            .filter(|record| destination.as_deref().is_none_or(|d| record["destination_recipient"] == d))
            .collect()
    }

    async fn assert_retired(&self) {
        assert!(
            !self.service.pending_migration().await.is_pending(),
            "the challenge is still pending"
        );
    }
}

impl Drop for Served {
    fn drop(&mut self) {
        self.stop.take().into_iter().for_each(|stop| {
            let _ = stop.send(());
        });
    }
}

#[tokio::test]
async fn missing_authorization_has_no_way_to_start() {
    // Compile-level: `MigrationAuthorization` has no public constructor and `authorize` is its only way to an
    // `AuthorizedMigration`, so an operation that takes the latter cannot be attempted without a proof. At runtime, a
    // proof against a challenge this service never issued finds nothing pending.
    let served = Served::new().await;
    let vault = vault_id(&served.service).await;
    let elsewhere = PendingMigration::new(Instant::now())
        .issue(vault, MigrationOperation::Export, Instant::now(), [7; 32])
        .unwrap();

    let method = served.service.vault_passphrase_method().await.unwrap();
    let typed = OwnerInput::new(Zeroizing::new(PASSPHRASE.as_bytes().to_vec()));
    let refusal = served.service.authorize_migration(&elsewhere, &method, typed).await.unwrap_err();

    assert_eq!(refusal, MigrationRefusal::NotPending);
}

#[tokio::test]
async fn incorrect_approval_passphrase_in_place_of_the_vault_passphrase_is_denied() {
    let served = Served::new().await;

    let (code, message) = served.export_refused(APPROVAL_PASSPHRASE).await;

    assert_eq!(code, ErrorCode::MigrationDenied);
    assert!(message.contains("vault passphrase was wrong"), "{message}");
    served.assert_retired().await;
}

#[tokio::test]
async fn incorrect_another_vaults_passphrase_is_denied_as_not_this_vault() {
    let operation = MigrationOperation::AddRecipient(recipient());
    let served = Served::with(Mode::Spend, operation.clone(), operation, &VaultIdentity::generate()).await;

    let (code, message) = served.export_refused(PASSPHRASE).await;

    assert_eq!(code, ErrorCode::MigrationDenied);
    assert!(message.contains("does not open this vault"), "{message}");
    served.assert_retired().await;
}

#[tokio::test]
async fn expired_between_the_prompt_and_the_check_is_denied() {
    let served = Served::new().await;
    let mut stream = served.connect().await;
    assert!(matches!(read_frame(&mut stream).await, Frame::Prompt(_)));

    // The right passphrase arrives after the challenge's lifetime; it is refused before it is checked.
    tokio::time::pause();
    tokio::time::advance(CHALLENGE_LIFETIME).await;
    let answer = OwnerInput::new(Zeroizing::new(PASSPHRASE.as_bytes().to_vec()));
    send(&mut stream, &Frame::OwnerInput(answer)).await;
    let Frame::Response(AdminResponse::Error { code, message }) = read_frame(&mut stream).await else {
        panic!("expected a refusal");
    };

    assert_eq!(code, ErrorCode::MigrationDenied);
    assert!(message.contains("expired"), "{message}");
    served.assert_retired().await;
    assert_eq!(served.events("migration.authorization-refused")[0]["refusal"], "expired");
}

#[tokio::test]
async fn replayed_proof_and_replayed_challenge_are_refused() {
    let operation = MigrationOperation::Export;
    let served = Served::with(Mode::Replay, operation.clone(), operation, &identity()).await;

    let (code, message) = served.refused(PASSPHRASE).await;

    assert_eq!(code, ErrorCode::MigrationDenied);
    assert!(message.contains("already used or retired"), "{message}");
    served.assert_retired().await;
}

#[tokio::test]
async fn bound_an_export_proof_is_refused_for_add_recipient() {
    let served = Served::with(
        Mode::Spend,
        MigrationOperation::Export,
        MigrationOperation::AddRecipient(recipient()),
        &identity(),
    )
    .await;

    let (code, message) = served.refused(PASSPHRASE).await;

    assert_eq!(code, ErrorCode::MigrationDenied);
    assert!(message.contains("for another migration"), "{message}");
}

#[tokio::test]
async fn bound_a_proof_for_one_destination_is_refused_for_another() {
    let (a, b) = (
        MigrationOperation::AddRecipient(recipient()),
        MigrationOperation::AddRecipient(recipient()),
    );
    let served = Served::with(Mode::Spend, a, b, &identity()).await;

    let (code, message) = served.refused(PASSPHRASE).await;

    assert_eq!(code, ErrorCode::MigrationDenied);
    assert!(message.contains("for another migration"), "{message}");
}

#[tokio::test]
async fn an_unlocked_vault_does_not_authorize_without_a_fresh_proof() {
    let served = Served::new().await;

    // Ready, with the vault identity in memory since the unlock: still asked, every time, and an earlier proof carries
    // nothing over to the next exchange.
    let (prompts, first) = served.export(PASSPHRASE).await;
    assert!(matches!((prompts, &first), (1, Exported::Authorized)), "{first:?}");
    let (prompts, second) = served.export("").await;

    assert!(
        matches!((prompts, &second), (1, Exported::Refused(ErrorCode::MigrationDenied, _))),
        "{second:?}"
    );
}

#[tokio::test]
async fn a_new_export_passphrase_never_authorizes() {
    let served = Served::new().await;

    let (code, _) = served.export_refused(EXPORT_PASSPHRASE).await;

    assert_eq!(code, ErrorCode::MigrationDenied);
    served.assert_retired().await;
}

#[tokio::test]
async fn the_attempt_limit_applies_after_repeated_wrong_passphrases() {
    let served = Served::new().await;
    for _ in 0..FAILURE_THRESHOLD {
        assert_eq!(served.export_refused(WRONG_PASSPHRASE).await.0, ErrorCode::MigrationDenied);
    }

    // Limited: no prompt is shown, so even the right passphrase cannot be typed.
    let (prompts, response) = served.export(PASSPHRASE).await;

    assert!(
        matches!((prompts, &response), (0, Exported::Refused(ErrorCode::MigrationRateLimited, _))),
        "{response:?}"
    );
    served.assert_retired().await;
}

#[tokio::test]
async fn no_typed_secret_reaches_the_log() {
    let served = Served::new().await;
    for typed in [WRONG_PASSPHRASE, APPROVAL_PASSPHRASE, EXPORT_PASSPHRASE, PASSPHRASE] {
        served.export(typed).await;
    }

    let text = served.logs.text();
    [PASSPHRASE, WRONG_PASSPHRASE, APPROVAL_PASSPHRASE, EXPORT_PASSPHRASE]
        .iter()
        .for_each(|typed| assert!(!text.contains(typed), "a typed secret reached the log:\n{text}"));
}
