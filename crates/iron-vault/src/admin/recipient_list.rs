//! `recipient list`: every enrolled recipient of the vault identity (specification §3.13; `design/recipients.md`,
//! "`recipient list`").
//!
//! It needs Ready and the service-wide lock, and opens the inventory with the inventory check, so a staged change is
//! settled first and a damaged inventory is reported, never repaired. It shows public keys and owner labels only, so
//! the admin principal check is all the authority it needs.

use std::sync::Arc;

use iron_vault_store::{InventoryDamage, StoreFs};

use super::dispatch::{AdminHandler, HandlerFuture};
use super::principal::AdminPrincipal;
use super::protocol::{AdminRequest, AdminResponse, ErrorCode};
use super::server::Exchange;
use super::unlock::state_name;
use crate::service_context::{RecipientRefusal, ServiceContext};

/// `recipient list`'s handler, acting on the running service.
pub(super) struct RecipientList<F> {
    service: Arc<ServiceContext<F>>,
}

impl<F> RecipientList<F> {
    pub(super) fn new(service: Arc<ServiceContext<F>>) -> Self {
        Self { service }
    }
}

impl<F: StoreFs + Send + Sync + 'static> AdminHandler for RecipientList<F> {
    fn handle<'a>(&'a self, _principal: AdminPrincipal, _request: AdminRequest, _exchange: &'a mut Exchange) -> HandlerFuture<'a> {
        Box::pin(async move {
            Ok(match self.service.list_recipients().await {
                Ok(entries) => AdminResponse::RecipientList { entries },
                Err(refusal) => refused(refusal),
            })
        })
    }
}

fn refused(refusal: RecipientRefusal) -> AdminResponse {
    let (code, message) = match refusal {
        RecipientRefusal::Busy => (ErrorCode::Busy, "another operation is running; try again shortly".to_owned()),
        RecipientRefusal::WrongState(state) => (
            ErrorCode::WrongState,
            format!(
                "`recipient list` is allowed only while the service is Ready; it is {}",
                state_name(state)
            ),
        ),
        RecipientRefusal::Damaged(damage) => (ErrorCode::RecipientInventoryDamaged, damaged_message(damage)),
        RecipientRefusal::Write(cause) => (
            ErrorCode::VaultWriteFailed,
            format!(
                "a staged recipient change could not be settled and may not be durable; the next recipient command settles it again: {cause}"
            ),
        ),
        RecipientRefusal::Interrupted => (ErrorCode::VaultWriteFailed, refusal.to_string()),
    };
    AdminResponse::Error { code, message }
}

/// Names the damage. A missing inventory is what a vault initialized before recipient commands has, so the message says so.
fn damaged_message(damage: InventoryDamage) -> String {
    let note = match damage {
        InventoryDamage::Missing => "; a vault initialized before recipient commands has none",
        _ => "",
    };
    format!("the recipient inventory is damaged ({}){note}; nothing was changed", damage.label())
}

#[cfg(test)]
mod tests;
