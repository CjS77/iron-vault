// SPDX-License-Identifier: MPL-2.0
//! `replace`: writes new material and origins under a name the manifest already lists, healthy or damaged
//! (spec [§6][s6], [§14][s14]; [credential commands: Order of steps](../../../../design/credential-commands.md#order-of-steps)).
//!
//! Unlike `add`, the service-wide lock is taken before any prompt, so the vault change check and the summary the owner
//! reads stay true until the write. Owner presence comes before the secret prompts, so a caller without the approval
//! passphrase never gets the owner to type a new secret into the exchange. A `lock` cancels any of the prompts.
//!
//! [s6]: ../../../../design/iron-vault-specification.md#6-credential-records-and-configuration
//! [s14]: ../../../../design/iron-vault-specification.md#14-recipients-startup-and-memory

use std::sync::Arc;

use iron_vault_store::StoreFs;

use super::add::{MaterialAnswer, ask_material, checked_arguments};
use super::dispatch::{AdminHandler, HandlerFuture};
use super::owner_presence::{no_presence, require_owner_presence};
use super::principal::AdminPrincipal;
use super::protocol::{AdminRequest, AdminResponse, ErrorCode};
use super::server::{Exchange, ExchangeError};
use super::unlock::state_name;
use crate::service_context::{CredentialChanged, ServiceContext, VaultChangeRefusal};
use crate::service_state::AdminOperation;
use crate::vault_change_check::PlannedChange;

/// `replace`'s handler, acting on the running service.
pub(super) struct Replace<F> {
    service: Arc<ServiceContext<F>>,
}

impl<F> Replace<F> {
    pub(super) fn new(service: Arc<ServiceContext<F>>) -> Self {
        Self { service }
    }
}

impl<F: StoreFs + Send + Sync + 'static> AdminHandler for Replace<F> {
    fn handle<'a>(&'a self, _principal: AdminPrincipal, request: AdminRequest, exchange: &'a mut Exchange) -> HandlerFuture<'a> {
        Box::pin(self.run(request, exchange))
    }
}

impl<F: StoreFs + Send + Sync + 'static> Replace<F> {
    /// Checks the state and the arguments, plans the change under the service-wide lock, shows its summary, asks for
    /// owner presence and then the material, and writes.
    async fn run(&self, request: AdminRequest, exchange: &mut Exchange) -> Result<AdminResponse, ExchangeError> {
        let AdminRequest::Replace { name, kind, origins } = request else {
            return Ok(error(ErrorCode::CredentialInvalid, "the request is not `replace`".to_owned()));
        };
        let state = self.service.state().await;
        if !state.admin_allows(AdminOperation::VaultChange) {
            return Ok(refused(VaultChangeRefusal::WrongState(state)));
        }
        let (name, origins) = match checked_arguments(&name, &origins) {
            Ok(checked) => checked,
            Err(rule) => return Ok(error(ErrorCode::CredentialInvalid, rule)),
        };
        let change = PlannedChange::Replace {
            name: name.clone(),
            kind,
            origins,
        };
        let plan = match self.service.plan_vault_change(change).await {
            Ok(plan) => plan,
            Err(refusal) => return Ok(refused(refusal)),
        };
        exchange.notice(&plan.summary().to_string()).await?;
        let proof = match require_owner_presence(exchange, &plan).await? {
            Ok(proof) => proof,
            Err(none) => return Ok(no_presence("replace", none)),
        };
        let material = match ask_material(kind, &name, exchange, || plan.lock_requested()).await? {
            MaterialAnswer::Typed(material) => material,
            MaterialAnswer::Invalid(rule) => return Ok(error(ErrorCode::CredentialInvalid, rule)),
            MaterialAnswer::CancelledByLock => {
                tracing::warn!("vault change cancelled at its prompt by a lock; nothing was written");
                let message = "`replace` was cancelled because a `lock` ran while it waited for the new secret; nothing was written";
                return Ok(error(ErrorCode::WrongState, message.to_owned()));
            }
        };
        Ok(match plan.change_credential(Some(material), proof).await {
            Ok(CredentialChanged::Replaced(record_id)) => AdminResponse::Replace { record_id },
            // A planned replace commits as a replace; this arm only keeps the match total.
            Ok(CredentialChanged::Removed) => error(ErrorCode::VaultWriteFailed, "the change committed was not a replace".to_owned()),
            Err(refusal) => refused(refusal),
        })
    }
}

/// Returns the error response for a refused or failed change, with the code from the step table in
/// [credential commands: Order of steps](../../../../design/credential-commands.md#order-of-steps).
fn refused(refusal: VaultChangeRefusal) -> AdminResponse {
    let code = match &refusal {
        VaultChangeRefusal::Busy => ErrorCode::Busy,
        VaultChangeRefusal::WrongState(state) => {
            let message = format!("`replace` is allowed only while the service is Ready; it is {}", state_name(*state));
            return error(ErrorCode::WrongState, message);
        }
        VaultChangeRefusal::UnknownCredential(_) => ErrorCode::UnknownCredential,
        VaultChangeRefusal::InUse { .. } | VaultChangeRefusal::UsedByRoutes { .. } => ErrorCode::CredentialInUse,
        VaultChangeRefusal::Invalid(_) => ErrorCode::CredentialInvalid,
        VaultChangeRefusal::NotActive(state) => {
            let message = format!(
                "the credential was replaced, but the config check after it failed; the service is {}",
                state_name(*state)
            );
            return error(ErrorCode::CommittedNotActive, message);
        }
        VaultChangeRefusal::ChangeUncertain { cause, state } => {
            let message = format!(
                "the replacement may have been written: {cause}; the service is {}",
                state_name(*state)
            );
            return error(ErrorCode::VaultWriteFailed, message);
        }
        // The plan refuses a name the manifest lacks, so `NameTaken` cannot come from `replace`; it is still no success.
        VaultChangeRefusal::Failed(_) | VaultChangeRefusal::Uncertain { .. } | VaultChangeRefusal::NameTaken(_) => {
            ErrorCode::VaultWriteFailed
        }
    };
    error(code, refusal.to_string())
}

fn error(code: ErrorCode, message: String) -> AdminResponse {
    AdminResponse::Error { code, message }
}
