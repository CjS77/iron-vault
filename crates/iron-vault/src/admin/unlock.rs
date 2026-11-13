// SPDX-License-Identifier: MPL-2.0
//! `unlock`: opens the vault with the passphrase the service prompts for (spec [§14][s14], [§15][s15],
//! [§16][s16]).
//!
//! The service, not the CLI, asks for the passphrase, with echo off, so no argument ever carries it ([§5][s5]). Only
//! the vault passphrase is asked for: an approval passphrase is a separate type and is never accepted here.
//!
//! [s5]: ../../../../design/iron-vault-specification.md#5-service-and-cli-separation-of-concerns
//! [s14]: ../../../../design/iron-vault-specification.md#14-recipients-startup-and-memory
//! [s15]: ../../../../design/iron-vault-specification.md#15-service-states-and-errors
//! [s16]: ../../../../design/iron-vault-specification.md#16-administration-recovery-and-migration

use std::sync::Arc;

use iron_vault_store::StoreFs;

use super::dispatch::{AdminHandler, HandlerFuture};
use super::principal::AdminPrincipal;
use super::protocol::{AdminRequest, AdminResponse, ErrorCode, Prompt};
use super::server::{Exchange, ExchangeError};
use crate::audit::AuditEvent;
use crate::audit::vault::UnlockRefused;
use crate::service_context::{ServiceContext, UnlockRefusal, Unlocked};
use crate::service_state::{AdminOperation, ServiceState, UnavailableReason};

/// The label of the one prompt `unlock` sends.
pub(super) const PASSPHRASE_PROMPT: &str = "Vault passphrase";

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
    /// Refuses before prompting when the service is not Locked, the vault is not Initialized, a protected install's
    /// memory is not locked, or the vault passphrase attempt limit is cooling down, in that order, so the owner is not
    /// asked for a passphrase that cannot be used. The context checks them again under its mutex.
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
            switchable: false,
        };
        let Some(passphrase) = exchange.prompt(&prompt).await?.into_vault_passphrase() else {
            // Empty or non-UTF-8 input never reaches the context's unlock, but it is a wrong guess all the same.
            self.service.record_unlock_failure().await;
            let refusal = UnlockRefusal::WrongPassphrase;
            UnlockRefused { refusal: &refusal }.emit();
            return Ok(refused(refusal));
        };
        Ok(match self.service.unlock(passphrase).await {
            Ok(unlocked) => settled(unlocked),
            Err(refusal) => refused(refusal),
        })
    }
}

/// Returns the response for the state a successful unlock settled in: Ready succeeds; Unavailable names its redacted
/// reason and, when the owner-lock file could not be removed, says the next start stays Locked.
fn settled(unlocked: Unlocked) -> AdminResponse {
    match unlocked.state {
        ServiceState::Ready => AdminResponse::Unlock {
            owner_lock_removed: unlocked.owner_lock_removed,
        },
        other => error(
            ErrorCode::UnlockedUnavailable,
            format!(
                "the vault unlocked, but the config check failed: the service is {}{}",
                state_name(other),
                if unlocked.owner_lock_removed { "" } else { OWNER_LOCK_KEPT },
            ),
        ),
    }
}

/// What the owner reads when a passphrase `unlock` could not remove the owner-lock file.
const OWNER_LOCK_KEPT: &str = "; the owner-lock file could not be removed, so the next start stays Locked";

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

/// Names a state as the owner reads it, with Unavailable's redacted reason.
pub(super) fn state_name(state: ServiceState) -> String {
    match state {
        ServiceState::Unavailable(reason) => format!("Unavailable ({})", UnavailableReason::from_failure(reason).as_str()),
        other => format!("{other:?}"),
    }
}

fn error(code: ErrorCode, message: String) -> AdminResponse {
    AdminResponse::Error { code, message }
}
