//! `list`: names, kinds, permitted origins and standing of every credential in the open vault, never a secret
//! (specification §3.13; `design/admin-protocol.md`, list).
//!
//! Like `status` it is answered in every state ([`AdminOperation::Status`](crate::service_state::AdminOperation)):
//! everything comes from what the service context already holds, and while no vault is open it holds nothing.

use std::sync::Arc;

use iron_vault_store::StoreFs;

use super::dispatch::{AdminHandler, HandlerFuture};
use super::principal::AdminPrincipal;
use super::protocol::{self, AdminRequest, AdminResponse, ErrorCode, Frame};
use super::server::Exchange;
use crate::service_context::ServiceContext;
use crate::standing::CredentialStanding;

/// `list`'s handler, acting on the running service.
pub(super) struct List<F> {
    service: Arc<ServiceContext<F>>,
}

impl<F> List<F> {
    pub(super) fn new(service: Arc<ServiceContext<F>>) -> Self {
        Self { service }
    }
}

impl<F: StoreFs + Send + Sync + 'static> AdminHandler for List<F> {
    fn handle<'a>(&'a self, _principal: AdminPrincipal, _request: AdminRequest, _exchange: &'a mut Exchange) -> HandlerFuture<'a> {
        Box::pin(async move { Ok(fit_one_frame(self.service.list().await)) })
    }
}

/// The list as a response, or an error naming the count when it does not fit one frame. The list is never truncated: a
/// partial inventory would hide credentials from the owner.
fn fit_one_frame(credentials: Option<Vec<CredentialStanding>>) -> AdminResponse {
    let count = credentials.as_ref().map_or(0, Vec::len);
    let frame = Frame::Response(AdminResponse::List { credentials });
    match (protocol::encode(&frame, &mut Vec::new()), frame) {
        (Ok(()), Frame::Response(response)) => response,
        _ => AdminResponse::Error {
            code: ErrorCode::ListTooLarge,
            message: format!(
                "the list of {count} credentials does not fit one admin frame of {} bytes",
                protocol::MAX_BODY_LEN
            ),
        },
    }
}
