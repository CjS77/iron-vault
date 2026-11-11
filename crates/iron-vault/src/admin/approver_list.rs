//! `approver list`: every pinned approver in approver order (specification §14; `design/approval-signers.md`,
//! "`approver list`").
//!
//! It needs Ready and the service-wide lock. It shows approver IDs, kinds, labels and times only, so the admin principal
//! check is all the authority it needs.

use std::sync::Arc;

use iron_vault_store::StoreFs;

use super::dispatch::{AdminHandler, HandlerFuture};
use super::principal::AdminPrincipal;
use super::protocol::{AdminRequest, AdminResponse, ApproverEntry};
use super::recipient_list::refused;
use super::server::Exchange;
use crate::service_context::ServiceContext;

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
                Err(refusal) => refused("approver list", refusal),
            })
        })
    }
}
