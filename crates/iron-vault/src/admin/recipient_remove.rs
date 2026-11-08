//! `recipient remove`: removes an enrolled recipient from the identity envelope and the inventory after owner presence
//! (specification §3.11, §3.13; `design/recipients.md`, "`recipient remove <age1…>`").
//!
//! The service-wide lock, the inventory check and the independence rule all come from
//! [`ServiceContext::plan_recipient_removal`], so a key that is not enrolled, or whose removal would leave fewer than two
//! independent ways in, is refused before any prompt. The lock is held through the summary, the approval passphrase prompt
//! and the write. Removal reaches only future envelopes (R-24), and the completion notice says so.

use std::collections::BTreeMap;
use std::sync::Arc;

use iron_vault_store::{ChangeCommitted, RecipientInventory, RecipientKey, RecipientRole, StoreFs};

use super::dispatch::{AdminHandler, HandlerFuture};
use super::owner_presence::{no_presence, require_owner_presence};
use super::principal::AdminPrincipal;
use super::protocol::{AdminRequest, AdminResponse, ErrorCode};
use super::recipient_list::refused as inventory_refused;
use super::server::{Exchange, ExchangeError};
use crate::service_context::{RecipientRefusal, RecipientRemoval, RemovalRefusal, RemovedRecipient, ServiceContext};
use crate::service_state::AdminOperation;

/// What every completed change says about copies already made (R-24).
const OLD_COPIES: &str = "Removing a recipient protects future copies of identity.age only.\n\
    Old copies of identity.age, and backups, still open with a removed key.\n\
    If a machine was lost, rotate the provider credentials it could reach.";

/// `recipient remove`'s handler, acting on the running service.
pub(super) struct RecipientRemove<F> {
    service: Arc<ServiceContext<F>>,
}

impl<F> RecipientRemove<F> {
    pub(super) fn new(service: Arc<ServiceContext<F>>) -> Self {
        Self { service }
    }
}

impl<F: StoreFs + Send + Sync + 'static> AdminHandler for RecipientRemove<F> {
    fn handle<'a>(&'a self, _principal: AdminPrincipal, request: AdminRequest, exchange: &'a mut Exchange) -> HandlerFuture<'a> {
        Box::pin(self.run(request, exchange))
    }
}

impl<F: StoreFs + Send + Sync + 'static> RecipientRemove<F> {
    /// Checks the state and the key, plans the removal, then asks for owner presence and writes. A prompt that gets no
    /// owner input drops the plan, which releases the service-wide lock, before anything is written.
    async fn run(&self, request: AdminRequest, exchange: &mut Exchange) -> Result<AdminResponse, ExchangeError> {
        let AdminRequest::RecipientRemove { recipient } = request else {
            return Ok(error(
                ErrorCode::RecipientInvalid,
                "the request is not `recipient remove`".to_owned(),
            ));
        };
        let state = self.service.state().await;
        if !state.admin_allows(AdminOperation::VaultChange) {
            return Ok(inventory_refused("recipient remove", RecipientRefusal::WrongState(state)));
        }
        let Ok(key) = recipient.parse::<RecipientKey>() else {
            return Ok(error(
                ErrorCode::RecipientInvalid,
                "the recipient must be an age1... X25519 recipient key".to_owned(),
            ));
        };
        let removal = match self.service.plan_recipient_removal(key).await {
            Ok(removal) => removal,
            Err(refusal) => return Ok(refused(refusal)),
        };
        exchange.notice(&summary(&removal)).await?;
        let proof = match require_owner_presence(exchange, &removal).await? {
            Ok(proof) => proof,
            Err(none) => return Ok(no_presence("recipient remove", none)),
        };
        match removal.remove(proof).await {
            Ok(done) => {
                exchange.notice(&completion(&done)).await?;
                Ok(AdminResponse::RecipientRemove {
                    recipients: u8::try_from(done.recipients).unwrap_or(u8::MAX),
                })
            }
            Err(refusal) => Ok(refused(refusal)),
        }
    }
}

/// The summary the owner reads before typing the approval passphrase.
fn summary<F: StoreFs + Send + Sync + 'static>(removal: &RecipientRemoval<'_, F>) -> String {
    let (entry, remaining) = (removal.removed(), removal.remaining());
    let (vault, key, role, enrolled) = (remaining.vault_id(), entry.key(), entry.role().name(), entry.enrolled_at());
    let label = entry.label().as_str().chars().filter(|c| !c.is_control()).collect::<String>();
    let after = counts(remaining);
    format!(
        "remove a recipient from the vault\n  vault: {vault}\n  recipient: {key}\n  role: {role}\n  label: {label}\n  \
         enrolled: {enrolled}\n  recipients after the change: {after}\n  removing a recipient protects future copies of identity.age only; \
         copies made before still open with this key\n  authorize with: the approval passphrase"
    )
}

/// `3 (operational 1, recovery 1, added 1)`: the recipient count and its split by role, in role order.
fn counts(inventory: &RecipientInventory) -> String {
    let by_role = inventory
        .entries()
        .fold(BTreeMap::<RecipientRole, usize>::new(), |mut counts, entry| {
            *counts.entry(entry.role()).or_default() += 1;
            counts
        });
    let split = by_role
        .iter()
        .map(|(role, count)| format!("{} {count}", role.name()))
        .collect::<Vec<_>>();
    format!("{} ({})", inventory.entries().len(), split.join(", "))
}

/// The notice after a committed removal: the fixed sentences first, then what the removed role needs next.
fn completion(done: &RemovedRecipient) -> String {
    let lines = [
        Some(format!(
            "removed {}; the vault has {} recipients.",
            done.removed.key(),
            done.recipients
        )),
        Some(OLD_COPIES.to_owned()),
        (done.removed.role() == RecipientRole::Recovery)
            .then(|| "Check the recovery key you keep with iron-vault recovery check.".to_owned()),
        done.unfinished
            .then(|| "The recipient inventory is finished at the next recipient command.".to_owned()),
    ];
    lines.into_iter().flatten().collect::<Vec<_>>().join("\n")
}

fn refused(refusal: RemovalRefusal) -> AdminResponse {
    match refusal {
        RemovalRefusal::Inventory(refusal) => inventory_refused("recipient remove", refusal),
        RemovalRefusal::NotEnrolled => error(
            ErrorCode::UnknownRecipient,
            "no enrolled recipient has this key; nothing was changed".to_owned(),
        ),
        RemovalRefusal::SetInvalid(rule) => error(
            ErrorCode::RecipientSetInvalid,
            format!("removing this recipient would break the independence rule: {rule}; nothing was changed"),
        ),
        RemovalRefusal::Failed { committed, cause } => error(ErrorCode::VaultWriteFailed, failed_message(committed, &cause)),
    }
}

/// Says whether the change may have committed, so the owner knows what to check.
fn failed_message(committed: ChangeCommitted, cause: &str) -> String {
    match committed {
        ChangeCommitted::No => format!("{cause}; nothing was changed"),
        ChangeCommitted::Unknown | ChangeCommitted::Yes => {
            format!("{cause}; the change may have committed: `iron-vault recipient list` settles it")
        }
    }
}

fn error(code: ErrorCode, message: String) -> AdminResponse {
    AdminResponse::Error { code, message }
}

#[cfg(test)]
mod tests;
