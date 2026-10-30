//! The handler registry: which async handler serves each admin command. Commands register here as their epics land;
//! a command with no handler is answered `unknown-command`.

use std::collections::BTreeMap;
use std::future::{self, Future};
use std::pin::Pin;

use super::principal::AdminPrincipal;
use super::protocol::{AdminCommand, AdminRequest, AdminResponse, ErrorCode};
use super::server::{Exchange, ExchangeError};
use crate::deployment::DeploymentProfile;

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
    /// The service's handlers: `ping`, answering with `profile`.
    pub fn standard(profile: DeploymentProfile) -> Self {
        Self::default().with(AdminCommand::Ping, Ping { profile })
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

/// `ping`: changes nothing and names the deployment profile.
struct Ping {
    profile: DeploymentProfile,
}

impl AdminHandler for Ping {
    fn handle<'a>(&'a self, _principal: AdminPrincipal, _request: AdminRequest, _exchange: &'a mut Exchange) -> HandlerFuture<'a> {
        Box::pin(future::ready(Ok(AdminResponse::Ping { profile: self.profile })))
    }
}
