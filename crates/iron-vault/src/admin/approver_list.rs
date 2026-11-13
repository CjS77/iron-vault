// SPDX-License-Identifier: MPL-2.0
//! `approver list`: every pinned approver in approver order
//! ([spec §14](../../../../design/iron-vault-specification.md#14-recipients-startup-and-memory);
//! [approval signers: `approver list`](../../../../design/approval-signers.md#approver-list)).
//!
//! It needs Ready and the service-wide lock. It shows approver IDs, kinds, labels and times only, so the admin principal
//! check is all the authority it needs.

use std::sync::Arc;

use iron_vault_store::StoreFs;

use super::dispatch::{AdminHandler, HandlerFuture};
use super::principal::AdminPrincipal;
use super::protocol::{AdminRequest, AdminResponse, ApproverEntry, ErrorCode};
use super::server::Exchange;
use super::unlock::state_name;
use crate::service_context::{ApproverListRefusal, ServiceContext};

/// `approver list`'s handler, acting on the running service.
pub(super) struct ApproverList<F> {
    service: Arc<ServiceContext<F>>,
}

impl<F> ApproverList<F> {
    pub(super) fn new(service: Arc<ServiceContext<F>>) -> Self {
        Self { service }
    }
}

impl<F: StoreFs + Send + Sync + 'static> AdminHandler for ApproverList<F> {
    fn handle<'a>(&'a self, _principal: AdminPrincipal, _request: AdminRequest, _exchange: &'a mut Exchange) -> HandlerFuture<'a> {
        Box::pin(async move {
            Ok(match self.service.list_approvers().await {
                Ok(approvers) => AdminResponse::ApproverList {
                    entries: approvers
                        .into_iter()
                        .map(|(approver, active)| ApproverEntry {
                            id: approver.id(),
                            kind: approver.kind(),
                            active,
                            label: approver.label().clone(),
                            enrolled_at: approver.enrolled_at(),
                        })
                        .collect(),
                },
                Err(refusal) => refused(refusal),
            })
        })
    }
}

/// Returns the error answer for a refused `approver list`.
fn refused(refusal: ApproverListRefusal) -> AdminResponse {
    let (code, message) = match refusal {
        ApproverListRefusal::Busy => (ErrorCode::Busy, "another operation is running; try again shortly".to_owned()),
        ApproverListRefusal::WrongState(state) => (
            ErrorCode::WrongState,
            format!(
                "`approver list` is allowed only while the service is Ready; it is {}",
                state_name(state)
            ),
        ),
    };
    AdminResponse::Error { code, message }
}

#[cfg(test)]
mod tests;
