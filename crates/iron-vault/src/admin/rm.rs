//! `rm`: removes a credential record after owner presence (spec [§6][s6], [§16][s16];
//! [admin protocol: rm](../../../../design/admin-protocol.md#rm); [credential commands](../../../../design/credential-commands.md)).
//!
//! The service-wide lock, the manifest lookup and the vault change check all come from
//! [`ServiceContext::plan_vault_change`], so a name a route still uses is refused before any prompt, and the lock is
//! held through the notice, the passphrase prompt and the write. The service describes the removal in a notice, and the
//! owner proves presence by typing an approver's approval passphrase or TPM approval PIN after reading it.
//!
//! [s6]: ../../../../design/iron-vault-specification.md#6-credential-records-and-configuration
//! [s16]: ../../../../design/iron-vault-specification.md#16-administration-recovery-and-migration

use std::sync::Arc;

use iron_vault_policy::CredentialName;
use iron_vault_store::StoreFs;

use super::add::name_rule;
use super::dispatch::{AdminHandler, HandlerFuture};
use super::owner_presence::{no_presence, require_owner_presence};
use super::principal::AdminPrincipal;
use super::protocol::{AdminRequest, AdminResponse, ErrorCode};
use super::server::{Exchange, ExchangeError};
use super::unlock::state_name;
use crate::service_context::{OwnerPresence, ServiceContext, VaultChangePlan, VaultChangeRefusal};
use crate::service_state::AdminOperation;
use crate::vault_change_check::PlannedChange;

/// `rm`'s handler, acting on the running service.
pub(super) struct Rm<F> {
    service: Arc<ServiceContext<F>>,
}

impl<F> Rm<F> {
    pub(super) fn new(service: Arc<ServiceContext<F>>) -> Self {
        Self { service }
    }
}

impl<F: StoreFs + Send + Sync + 'static> AdminHandler for Rm<F> {
    fn handle<'a>(&'a self, _principal: AdminPrincipal, request: AdminRequest, exchange: &'a mut Exchange) -> HandlerFuture<'a> {
        Box::pin(self.run(request, exchange))
    }
}

impl<F: StoreFs + Send + Sync + 'static> Rm<F> {
    /// Checks the state and the name, plans the change, then asks for owner presence and writes. A prompt that gets no
    /// owner input drops the plan, which releases the service-wide lock, before anything is written.
    async fn run(&self, request: AdminRequest, exchange: &mut Exchange) -> Result<AdminResponse, ExchangeError> {
        let AdminRequest::Rm { name } = request else {
            return Ok(error(ErrorCode::CredentialInvalid, "the request is not `rm`".to_owned()));
        };
        let state = self.service.state().await;
        if !state.admin_allows(AdminOperation::VaultChange) {
            return Ok(refused(VaultChangeRefusal::WrongState(state)));
        }
        let name = match CredentialName::try_from(name.as_str()) {
            Ok(name) => name,
            Err(rule) => {
                let message = format!("invalid credential name: {}", name_rule(rule.rule()));
                return Ok(error(ErrorCode::CredentialInvalid, message));
            }
        };
        let plan = match self.service.plan_vault_change(PlannedChange::Remove(name.clone())).await {
            Ok(plan) => plan,
            Err(refusal) => return Ok(refused(refusal)),
        };
        exchange.notice(&plan.summary().to_string()).await?;
        match require_owner_presence(exchange, &plan).await? {
            Ok(proof) => Ok(remove(plan, proof).await),
            Err(none) => Ok(no_presence("rm", none)),
        }
    }
}

/// Writes the removal and settles the config check, then answers once it ends.
/// The service context logs `credential.removed` at the commit.
async fn remove<F: StoreFs + Send + Sync + 'static>(plan: VaultChangePlan<'_, F>, proof: OwnerPresence) -> AdminResponse {
    match plan.change_credential(None, proof).await {
        Ok(_) => AdminResponse::Success,
        Err(refusal) => refused(refusal),
    }
}

fn refused(refusal: VaultChangeRefusal) -> AdminResponse {
    let code = match &refusal {
        VaultChangeRefusal::Busy => ErrorCode::Busy,
        VaultChangeRefusal::WrongState(state) => {
            return error(
                ErrorCode::WrongState,
                format!("`rm` is allowed only while the service is Ready; it is {}", state_name(*state)),
            );
        }
        VaultChangeRefusal::UnknownCredential(_) => ErrorCode::UnknownCredential,
        VaultChangeRefusal::InUse { .. } | VaultChangeRefusal::UsedByRoutes { .. } => ErrorCode::CredentialInUse,
        VaultChangeRefusal::Invalid(_) => ErrorCode::CredentialInvalid,
        VaultChangeRefusal::NotActive(_) => ErrorCode::CommittedNotActive,
        // `add` alone refuses a name that exists or reports its own uncertain commit.
        VaultChangeRefusal::NameTaken(_)
        | VaultChangeRefusal::Failed(_)
        | VaultChangeRefusal::Uncertain { .. }
        | VaultChangeRefusal::ChangeUncertain { .. } => ErrorCode::VaultWriteFailed,
    };
    error(code, refusal.to_string())
}

fn error(code: ErrorCode, message: String) -> AdminResponse {
    AdminResponse::Error { code, message }
}

#[cfg(test)]
mod tests;
