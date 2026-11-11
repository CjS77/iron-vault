//! `forget-machine`: checks that a retired machine's recipient key is gone from the vault (specification §16;
//! `design/forget-machine.md`).
//!
//! It is read-only and runs no process. The service answers with the facts; the CLI prints the decommission guidance, which
//! the administrator carries out.

use std::sync::Arc;

use iron_vault_store::{RecipientKey, StoreFs};

use super::dispatch::{AdminHandler, HandlerFuture};
use super::principal::AdminPrincipal;
use super::protocol::{AdminRequest, AdminResponse, ErrorCode};
use super::recipient_list::refused as inventory_refused;
use super::server::Exchange;
use crate::audit::AuditEvent;
use crate::audit::recipient::ForgetChecked;
use crate::service_context::{ForgetCheck, ServiceContext};

/// `forget-machine`'s handler, acting on the running service.
pub(super) struct ForgetMachine<F> {
    service: Arc<ServiceContext<F>>,
}

impl<F> ForgetMachine<F> {
    pub(super) fn new(service: Arc<ServiceContext<F>>) -> Self {
        Self { service }
    }
}

impl<F: StoreFs + Send + Sync + 'static> AdminHandler for ForgetMachine<F> {
    fn handle<'a>(&'a self, _principal: AdminPrincipal, request: AdminRequest, _exchange: &'a mut Exchange) -> HandlerFuture<'a> {
        Box::pin(async move {
            let AdminRequest::ForgetMachine { recipient } = request else {
                return Ok(error(ErrorCode::RecipientInvalid, "the request is not `forget-machine`".to_owned()));
            };
            let Ok(key) = recipient.parse::<RecipientKey>() else {
                return Ok(error(
                    ErrorCode::RecipientInvalid,
                    "the recipient must be an age1... X25519 recipient key".to_owned(),
                ));
            };
            Ok(match self.service.check_forgotten(&key).await {
                Ok(check) => {
                    audit(&key, &check).emit();
                    answer(&key, check)
                }
                Err(refusal) => inventory_refused("forget-machine", refusal),
            })
        })
    }
}

/// The audit event for what the check found.
fn audit<'a>(key: &'a RecipientKey, check: &'a ForgetCheck) -> ForgetChecked<'a> {
    match check {
        ForgetCheck::Enrolled(entry) => ForgetChecked {
            recipient: key,
            enrolled: Some(entry),
            independence_holds: true,
            recovery_due: false,
        },
        ForgetCheck::Forgotten { independence, recovery } => ForgetChecked {
            recipient: key,
            enrolled: None,
            independence_holds: independence.is_none(),
            recovery_due: recovery.due(),
        },
    }
}

/// A key still enrolled is an error whose message is the next step; otherwise the facts for the guidance.
fn answer(key: &RecipientKey, check: ForgetCheck) -> AdminResponse {
    match check {
        ForgetCheck::Enrolled(entry) => {
            let label: String = entry.label().as_str().chars().filter(|c| !c.is_control()).collect();
            error(
                ErrorCode::MachineNotForgotten,
                format!(
                    "{key} is still a recipient of this vault (role {}, label {label}); run `iron-vault recipient remove {key}`, then \
                     `forget-machine` again. If that is refused because the key is the host unlock identity this machine's unlock \
                     handoff holds, this is the machine being retired: run `forget-machine` on the vault that stays",
                    entry.role().name()
                ),
            )
        }
        ForgetCheck::Forgotten { independence, recovery } => AdminResponse::ForgetMachine { independence, recovery },
    }
}

fn error(code: ErrorCode, message: String) -> AdminResponse {
    AdminResponse::Error { code, message }
}
