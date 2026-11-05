//! `rm`: removes a credential record after owner presence (specification §3.3, §3.13; `design/admin-protocol.md`, rm;
//! `design/credential-commands.md`).
//!
//! The service-wide lock, the manifest lookup and the vault change check all come from
//! [`ServiceContext::plan_vault_change`], so a name a route still uses is refused before any prompt, and the lock is
//! held through the notice, the passphrase prompt and the write. The service describes the removal in a notice, and the
//! owner proves presence by typing the approval passphrase after reading it.

use std::sync::Arc;

use iron_vault_policy::CredentialName;
use iron_vault_store::{RecordId, StoreFs};

use super::add::name_rule;
use super::dispatch::{AdminHandler, HandlerFuture};
use super::owner_presence::{NoPresence, require_owner_presence};
use super::principal::AdminPrincipal;
use super::protocol::{AdminRequest, AdminResponse, ErrorCode};
use super::server::{Exchange, ExchangeError};
use super::unlock::state_name;
use crate::service_context::{CurrentRecord, OwnerPresence, PresenceRefusal, ServiceContext, VaultChangePlan, VaultChangeRefusal};
use crate::service_state::AdminOperation;
use crate::standing::Standing;
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
        exchange.notice(&summary(&name, plan.current())).await?;
        match require_owner_presence(exchange, &plan).await? {
            Ok(proof) => Ok(remove(plan, proof, name).await),
            Err(none) => Ok(no_presence(none)),
        }
    }
}

/// Writes the removal and settles the config check, then answers once it ends.
async fn remove<F: StoreFs + Send + Sync + 'static>(
    plan: VaultChangePlan<'_, F>,
    proof: OwnerPresence,
    name: CredentialName,
) -> AdminResponse {
    let record_id = plan.current().record_id;
    match plan.change_credential(None, proof).await {
        Ok(_) => {
            log_removed(&name, &record_id);
            AdminResponse::Success
        }
        Err(refusal @ VaultChangeRefusal::NotActive(_)) => {
            // The remove committed even though the check after it left the service Unavailable.
            log_removed(&name, &record_id);
            refused(refusal)
        }
        Err(refusal) => refused(refusal),
    }
}

/// The vault change summary of a removal (design/credential-commands.md, "Vault change summary"). No route uses the
/// name, or the plan would have refused, so the routes line always says so; it stays so the owner sees the service
/// checked.
fn summary(name: &CredentialName, current: &CurrentRecord) -> String {
    let (kind, origins) = match (&current.summary, current.standing) {
        (Some(summary), _) => (
            summary.kind.as_str().to_owned(),
            summary
                .origins
                .iter()
                .map(|(host, port)| format!("{host}:{}", port.get()))
                .collect::<Vec<_>>()
                .join(", "),
        ),
        (None, Standing::Damaged(damage)) => (format!("unknown (record damaged: {damage})"), "unknown".to_owned()),
        (None, Standing::Healthy) => ("unknown".to_owned(), "unknown".to_owned()),
    };
    format!(
        "remove credential {name}\n  record: {}\n  kind: {kind}\n  origins: {origins}\n  routes using {name}: none\n",
        current.record_id
    )
}

fn log_removed(name: &CredentialName, record_id: &RecordId) {
    tracing::info!(
        event = "credential.removed",
        credential = %name,
        record_id = %record_id,
        "credential `{name}` removed; no active route used it",
    );
}

/// Owner presence was not shown: nothing was written.
fn no_presence(none: NoPresence) -> AdminResponse {
    match none {
        NoPresence::Refused(PresenceRefusal::Denied) => error(ErrorCode::ApprovalDenied, PresenceRefusal::Denied.to_string()),
        NoPresence::Refused(unavailable) => error(ErrorCode::ApprovalUnavailable, unavailable.to_string()),
        NoPresence::CancelledByLock => error(
            ErrorCode::ApprovalUnavailable,
            "the removal was cancelled because a `lock` ran while it waited for the approval passphrase; nothing was written".to_owned(),
        ),
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
        VaultChangeRefusal::InUse { .. } => ErrorCode::CredentialInUse,
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
