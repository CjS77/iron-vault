//! The handler registry: which async handler serves each admin command. Commands register here as their epics land;
//! a command with no handler is answered `unknown-command`.

use std::collections::BTreeMap;
use std::future::{self, Future};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use super::add::Add;
use super::approve::Approve;
use super::init::Init;
use super::list::List;
use super::principal::AdminPrincipal;
use super::protocol::{AdminCommand, AdminRequest, AdminResponse, ErrorCode};
use super::recipient_add::RecipientAdd;
use super::recipient_list::RecipientList;
use super::recipient_remove::RecipientRemove;
use super::recovery_check::RecoveryCheck;
use super::replace::Replace;
use super::rm::Rm;
use super::server::{Exchange, ExchangeError};
use super::unlock::Unlock;
use crate::audit::AuditEvent;
use crate::audit::credential::{TokenFailed, TokenIssued};
use crate::caller_token::generate_caller_token;
use crate::deployment::DeploymentProfile;
use crate::library_error::LibraryError;
use crate::service_context::{LockOutcome, ServiceContext};
use iron_vault_store::StoreFs;

/// The future a handler returns: the exchange's admin response, or the error that cancelled its command when a prompt
/// got no owner input.
pub type HandlerFuture<'a> = Pin<Box<dyn Future<Output = Result<AdminResponse, ExchangeError>> + Send + 'a>>;

/// Serves one admin command.
///
/// A handler only ever runs for a peer the admin principal check accepted: it receives the [`AdminPrincipal`] that
/// proves it. It may send prompts through the exchange, and returns the response the server sends before closing.
///
/// A prompt that fails ends the exchange: the handler returns its [`ExchangeError`], typically with `?`, before it
/// changes anything, and the server closes with the error response the fault calls for, or none when the CLI has gone.
pub trait AdminHandler: Send + Sync {
    /// Answers `request` for `principal`.
    fn handle<'a>(&'a self, principal: AdminPrincipal, request: AdminRequest, exchange: &'a mut Exchange) -> HandlerFuture<'a>;
}

/// The handler of each admin command, keyed by command.
#[derive(Default)]
pub struct Handlers(BTreeMap<AdminCommand, Box<dyn AdminHandler>>);

impl Handlers {
    /// The service's handlers that need no service context: `ping`, answering with `profile`, and `caller-token`.
    pub fn standard(profile: DeploymentProfile) -> Self {
        Self::default()
            .with(AdminCommand::Ping, Ping { profile })
            .with(AdminCommand::CallerToken, IssueCallerToken)
    }

    /// The running service's handlers: [`standard`](Self::standard)'s, for `service`'s profile, then `status`,
    /// `unlock`, `lock`, `config approve`, `add`, `replace`, `init`, `list`, `rm`, `recovery check`, `recipient list`,
    /// `recipient add` and `recipient remove`.
    /// A command that acts on the service registers here with a clone of `service`.
    pub fn for_service<F: StoreFs + Send + Sync + 'static>(service: &Arc<ServiceContext<F>>) -> Self {
        Self::standard(service.paths().profile)
            .with(AdminCommand::Status, Status(Arc::clone(service)))
            .with(AdminCommand::Unlock, Unlock::new(Arc::clone(service)))
            .with(AdminCommand::ConfigApprove, Approve::new(Arc::clone(service)))
            .with(AdminCommand::Add, Add::new(Arc::clone(service)))
            .with(AdminCommand::Replace, Replace::new(Arc::clone(service)))
            .with(AdminCommand::Init, Init::new(Arc::clone(service)))
            .with(AdminCommand::List, List::new(Arc::clone(service)))
            .with(AdminCommand::Rm, Rm::new(Arc::clone(service)))
            .with(AdminCommand::RecoveryCheck, RecoveryCheck::new(Arc::clone(service)))
            .with(AdminCommand::RecipientList, RecipientList::new(Arc::clone(service)))
            .with(AdminCommand::RecipientAdd, RecipientAdd::new(Arc::clone(service)))
            .with(AdminCommand::RecipientRemove, RecipientRemove::new(Arc::clone(service)))
            .with_lock_drain(service, LOCK_DRAIN)
    }

    /// Registers `lock` for `service` with a lock drain of `drain`: how long it waits for a request that ignores its
    /// cancellation before answering that the secrets are not confirmed cleared. [`for_service`](Self::for_service)
    /// uses a drain fit for production; a test of the expired wait shortens it.
    pub fn with_lock_drain<F: StoreFs + Send + Sync + 'static>(self, service: &Arc<ServiceContext<F>>, drain: Duration) -> Self {
        self.with(
            AdminCommand::Lock,
            Lock {
                service: Arc::clone(service),
                drain,
            },
        )
    }

    /// Registers `handler` for `command`, replacing any handler it had.
    pub fn with(mut self, command: AdminCommand, handler: impl AdminHandler + 'static) -> Self {
        self.0.insert(command, Box::new(handler));
        self
    }

    /// Runs the handler for `request`'s command.
    pub(crate) async fn dispatch(
        &self,
        principal: AdminPrincipal,
        request: AdminRequest,
        exchange: &mut Exchange,
    ) -> Result<AdminResponse, ExchangeError> {
        match self.0.get(&request.command()) {
            Some(handler) => handler.handle(principal, request, exchange).await,
            None => Ok(AdminResponse::Error {
                code: ErrorCode::UnknownCommand,
                message: format!("this service has no `{}` command", request.command().name()),
            }),
        }
    }
}

/// How long `lock` waits for requests to release the old snapshot. It is far below the CLI's 60-second socket timeout, and
/// longer than a cancelled request needs to unwind.
const LOCK_DRAIN: Duration = Duration::from_secs(10);

/// `lock`: clears the vault identity and every cached secret, then reports whether that was confirmed.
struct Lock<F> {
    service: Arc<ServiceContext<F>>,
    drain: Duration,
}

impl<F: StoreFs + Send + Sync + 'static> AdminHandler for Lock<F> {
    fn handle<'a>(&'a self, _principal: AdminPrincipal, _request: AdminRequest, _exchange: &'a mut Exchange) -> HandlerFuture<'a> {
        Box::pin(async move {
            Ok(match self.service.lock(self.drain).await {
                Ok(outcome) => AdminResponse::Lock {
                    cleared: outcome == LockOutcome::Cleared,
                },
                Err(refused) => AdminResponse::Error {
                    code: ErrorCode::WrongState,
                    message: format!(
                        "cannot lock: the service is {:?}, and lock needs Ready or Unavailable",
                        refused.state
                    ),
                },
            })
        })
    }
}

/// `ping`: changes nothing and names the deployment profile.
struct Ping {
    profile: DeploymentProfile,
}

impl AdminHandler for Ping {
    fn handle<'a>(&'a self, _principal: AdminPrincipal, _request: AdminRequest, _exchange: &'a mut Exchange) -> HandlerFuture<'a> {
        Box::pin(future::ready(Ok(AdminResponse::Ping { profile: self.profile })))
    }
}

/// `caller-token`: a fresh caller token for the owner to enroll through `config approve`. The state gate allows it in
/// every state the admin socket is served in, so it checks no state. It returns the token in the response and keeps no
/// copy; the log names the event only, never the token or its hash, which would let a log reader tie it to a caller.
struct IssueCallerToken;

impl AdminHandler for IssueCallerToken {
    fn handle<'a>(&'a self, _principal: AdminPrincipal, _request: AdminRequest, _exchange: &'a mut Exchange) -> HandlerFuture<'a> {
        let response = match generate_caller_token() {
            Ok(token) => {
                TokenIssued.emit();
                AdminResponse::CallerToken { token }
            }
            Err(e) => {
                TokenFailed {
                    error_kind: &e.kind_label(),
                }
                .emit();
                AdminResponse::Error {
                    code: ErrorCode::RandomSourceFailed,
                    message: format!("no caller token was issued: {e}"),
                }
            }
        };
        Box::pin(future::ready(Ok(response)))
    }
}

/// `status`: reports the service context's state in every service state, so the owner can diagnose why requests fail.
struct Status<F>(Arc<ServiceContext<F>>);

impl<F: StoreFs + Send + Sync + 'static> AdminHandler for Status<F> {
    fn handle<'a>(&'a self, _principal: AdminPrincipal, _request: AdminRequest, _exchange: &'a mut Exchange) -> HandlerFuture<'a> {
        Box::pin(async move { Ok(AdminResponse::Status(Box::new(self.0.status().await))) })
    }
}
