//! `unlock`: opens the vault with the passphrase the service prompts for (specification §3.11, §3.12, §3.13).
//!
//! The service, not the CLI, asks for the passphrase, with echo off, so no argument ever carries it (§3.2). Only the
//! vault passphrase is asked for: an approval passphrase is a separate type and is never accepted here.

use std::sync::Arc;

use iron_vault_store::StoreFs;

use super::dispatch::{AdminHandler, HandlerFuture};
use super::principal::AdminPrincipal;
use super::protocol::{AdminRequest, AdminResponse, ErrorCode, Prompt};
use super::server::{Exchange, ExchangeError};
use crate::audit::AuditEvent;
use crate::audit::vault::UnlockRefused;
use crate::service_context::{ServiceContext, UnlockRefusal};
use crate::service_state::{AdminOperation, ServiceState, UnavailableReason};

/// The label of the one prompt `unlock` sends.
const PASSPHRASE_PROMPT: &str = "Vault passphrase";

/// `unlock`'s handler, acting on the running service.
pub(super) struct Unlock<F> {
    service: Arc<ServiceContext<F>>,
}

impl<F> Unlock<F> {
    pub(super) fn new(service: Arc<ServiceContext<F>>) -> Self {
        Self { service }
    }
}

impl<F: StoreFs + Send + Sync + 'static> AdminHandler for Unlock<F> {
    fn handle<'a>(&'a self, _principal: AdminPrincipal, _request: AdminRequest, exchange: &'a mut Exchange) -> HandlerFuture<'a> {
        Box::pin(self.run(exchange))
    }
}

impl<F: StoreFs + Send + Sync + 'static> Unlock<F> {
    /// Refuses before prompting when the service is not Locked, the vault is not Initialized, or a protected install's
    /// memory is not locked, in that order, so the owner is not asked for a passphrase that cannot be used; the context
    /// checks all three again under its mutex.
    async fn run(&self, exchange: &mut Exchange) -> Result<AdminResponse, ExchangeError> {
        let state = self.service.state().await;
        if !state.admin_allows(AdminOperation::Unlock) {
            let refusal = UnlockRefusal::WrongState(state);
            UnlockRefused { refusal: &refusal }.emit();
            return Ok(refused(refusal));
        }
        if let Err(refusal) = self.service.require_initialized().await {
            return Ok(refused(refusal));
        }
        if let Err(refusal) = self.service.require_locked_memory() {
            return Ok(refused(refusal));
        }
        if let Err(refusal) = self.service.check_unlock_attempts().await {
            return Ok(refused(refusal));
        }
        let prompt = Prompt {
            label: PASSPHRASE_PROMPT.to_owned(),
            secret: true,
        };
        let Some(passphrase) = exchange.prompt(&prompt).await?.into_vault_passphrase() else {
            // Empty or non-UTF-8 input never reaches the context's unlock, but it is a wrong guess all the same.
            self.service.record_unlock_failure().await;
            let refusal = UnlockRefusal::WrongPassphrase;
            UnlockRefused { refusal: &refusal }.emit();
            return Ok(refused(refusal));
        };
        Ok(match self.service.unlock(passphrase).await {
            Ok(state) => settled(state),
            Err(refusal) => refused(refusal),
        })
    }
}

/// The response for the state a successful unlock settled in: Ready succeeds; Unavailable names its redacted reason.
fn settled(state: ServiceState) -> AdminResponse {
    match state {
        ServiceState::Ready => AdminResponse::Success,
        other => error(
            ErrorCode::UnlockedUnavailable,
            format!(
                "the vault unlocked, but the config check failed: the service is {}",
                state_name(other)
            ),
        ),
    }
}

fn refused(refusal: UnlockRefusal) -> AdminResponse {
    match refusal {
        UnlockRefusal::WrongState(state) => error(
            ErrorCode::WrongState,
            format!("`unlock` is allowed only while the service is Locked; it is {}", state_name(state)),
        ),
        UnlockRefusal::WrongPassphrase => error(ErrorCode::UnlockDenied, "wrong passphrase".to_owned()),
        failed @ (UnlockRefusal::Failed(_) | UnlockRefusal::Interrupted) => {
            error(ErrorCode::UnlockFailed, format!("{failed}; the service stays Locked"))
        }
        UnlockRefusal::RateLimited(cooling) => error(ErrorCode::UnlockRateLimited, format!("{cooling}; the service stays Locked")),
        unprotected @ UnlockRefusal::MemoryUnprotected(_) => {
            error(ErrorCode::MemoryUnprotected, format!("{unprotected}; the service stays Locked"))
        }
    }
}

/// A state as the owner reads it, with Unavailable's redacted reason.
pub(super) fn state_name(state: ServiceState) -> String {
    match state {
        ServiceState::Unavailable(reason) => format!("Unavailable ({})", UnavailableReason::from_failure(reason).as_str()),
        other => format!("{other:?}"),
    }
}

fn error(code: ErrorCode, message: String) -> AdminResponse {
    AdminResponse::Error { code, message }
}
