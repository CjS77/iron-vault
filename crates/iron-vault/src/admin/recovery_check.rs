// SPDX-License-Identifier: MPL-2.0
//! `recovery check`: proves that the owner's recovery key opens the vault
//! ([spec §16](../../../../design/iron-vault-specification.md#16-administration-recovery-and-migration);
//! [recovery](../../../../design/recovery.md)).
//!
//! The service prompts for the key with echo off, so no argument carries it. The checks that need no key run before the
//! prompt; the lock, the store check and the record write are the service context's. The key's text lives in three
//! places, each cleared on drop: the owner-input buffer, the `SecretString` copy that `RecoveryKeySecret::parse` reads,
//! and the parsed identity. No error or log record repeats it.

use std::sync::Arc;

use iron_vault_store::{RecoveryKeySecret, StoreFs};
use secrecy::SecretString;

use super::dispatch::{AdminHandler, HandlerFuture};
use super::principal::AdminPrincipal;
use super::protocol::{AdminRequest, AdminResponse, ErrorCode, OwnerInput, Prompt};
use super::server::{Exchange, ExchangeError};
use super::unlock::state_name;
use crate::audit::AuditEvent;
use crate::audit::recovery::RecoveryChecked;
use crate::service_context::{RecoveryProof, RecoveryRefusal, ServiceContext};

/// The label of the one prompt `recovery check` sends.
const KEY_PROMPT: &str = "Recovery key";

/// The message of a key that was judged and does not open the vault; fixed, so it says nothing about why.
const KEY_DOES_NOT_OPEN: &str = "the recovery key does not open this vault";

/// `recovery check`'s handler, acting on the running service.
pub(super) struct RecoveryCheck<F> {
    service: Arc<ServiceContext<F>>,
}

impl<F> RecoveryCheck<F> {
    pub(super) fn new(service: Arc<ServiceContext<F>>) -> Self {
        Self { service }
    }
}

impl<F: StoreFs + Send + Sync + 'static> AdminHandler for RecoveryCheck<F> {
    fn handle<'a>(&'a self, _principal: AdminPrincipal, _request: AdminRequest, exchange: &'a mut Exchange) -> HandlerFuture<'a> {
        Box::pin(self.run(exchange))
    }
}

impl<F: StoreFs + Send + Sync + 'static> RecoveryCheck<F> {
    /// Refuses before prompting when the state, the initialization state or the memory protection rules the check out,
    /// so the owner is not asked for a key that cannot be used; the context checks the first two again under its lock.
    async fn run(&self, exchange: &mut Exchange) -> Result<AdminResponse, ExchangeError> {
        if let Err(refusal) = self.service.recovery_check_allowed().await {
            return Ok(refused(refusal));
        }
        let prompt = Prompt {
            label: KEY_PROMPT.to_owned(),
            secret: true,
            switchable: false,
        };
        let Some(recipient) = recovery_key(exchange.prompt(&prompt).await?) else {
            RecoveryChecked::Invalid.emit();
            return Ok(error(
                ErrorCode::RecoveryKeyInvalid,
                "the text is not an AGE-SECRET-KEY-1... recovery key".to_owned(),
            ));
        };
        Ok(match self.service.check_recovery(recipient).await {
            Ok(proof) => proved(proof),
            Err(refusal) => refused(refusal),
        })
    }
}

/// Parses the owner's input as a recovery key identity. Returns `None` for empty, non-UTF-8 or unparsable input. The
/// input's buffer is cleared when it drops here, and a rejected input is not carried in the error.
fn recovery_key(input: OwnerInput) -> Option<iron_vault_store::RecipientIdentity> {
    let text = std::str::from_utf8(input.expose_secret()).ok()?;
    RecoveryKeySecret::parse(SecretString::from(text)).ok()
}

fn proved(proof: RecoveryProof) -> AdminResponse {
    AdminResponse::RecoveryCheck {
        vault_id: proof.vault_id,
        checked_at: proof.checked_at.unix_seconds(),
        recorded: proof.record_error.is_none(),
    }
}

fn refused(refusal: RecoveryRefusal) -> AdminResponse {
    match refusal {
        RecoveryRefusal::Busy => error(
            ErrorCode::Busy,
            "an approval, a vault write, an init, a reload or a config check is running; try again".to_owned(),
        ),
        RecoveryRefusal::WrongState(state) => error(
            ErrorCode::WrongState,
            format!(
                "`recovery check` is allowed only while the service is Locked or Ready; it is {}",
                state_name(state)
            ),
        ),
        RecoveryRefusal::NotInitialized(why) => unavailable(format!("the recovery key cannot be checked: {why}")),
        RecoveryRefusal::MemoryUnprotected(why) => error(ErrorCode::MemoryUnprotected, format!("{why}; nothing was checked")),
        RecoveryRefusal::ClockUnusable => {
            unavailable("the system clock is outside the years 1970 to 9999, so no check time can be recorded".to_owned())
        }
        RecoveryRefusal::Check(e) if e.is_key_rejected() => error(ErrorCode::RecoveryCheckFailed, KEY_DOES_NOT_OPEN.to_owned()),
        RecoveryRefusal::Check(e) => unavailable(format!("the recovery key was not judged: {e}")),
        RecoveryRefusal::Interrupted => unavailable("the check did not finish; run it again".to_owned()),
    }
}

fn unavailable(message: String) -> AdminResponse {
    error(ErrorCode::RecoveryCheckUnavailable, message)
}

fn error(code: ErrorCode, message: String) -> AdminResponse {
    AdminResponse::Error { code, message }
}
