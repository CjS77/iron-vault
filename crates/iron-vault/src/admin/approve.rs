//! `config approve`: the approval transaction on the owner's proposed config (specification §3.9, §3.2, §3.13;
//! `design/admin-protocol.md`, "config approve").
//!
//! The service writes and validates the pending config, shows its own summary as notices, and asks for the
//! confirmation, then the approval passphrase, in that order. Nothing is reserved until the passphrase has opened the
//! approver key, so a declined, cancelled or mistyped approval consumes no version. The CLI only carries the bytes and
//! the owner's answers; the service signs only its own pending transaction.

use std::sync::Arc;

use iron_vault_store::{ApprovalPassphrase, SoftwareSigner, StoreFs};
use secrecy::SecretString;

use super::dispatch::{AdminHandler, HandlerFuture};
use super::principal::AdminPrincipal;
use super::protocol::{AdminRequest, AdminResponse, ErrorCode, OwnerInput, Prompt};
use super::server::{Exchange, ExchangeError};
use crate::service_context::{ApprovalEnd, ApprovalReview, ServiceContext};

/// The label of the secret prompt for the approval passphrase.
const PASSPHRASE_PROMPT: &str = "Approval passphrase";

/// `config approve`'s handler, acting on the running service.
pub(super) struct Approve<F> {
    service: Arc<ServiceContext<F>>,
}

impl<F> Approve<F> {
    pub(super) fn new(service: Arc<ServiceContext<F>>) -> Self {
        Self { service }
    }
}

impl<F: StoreFs + Send + Sync + 'static> AdminHandler for Approve<F> {
    fn handle<'a>(&'a self, _principal: AdminPrincipal, request: AdminRequest, exchange: &'a mut Exchange) -> HandlerFuture<'a> {
        Box::pin(self.run(request, exchange))
    }
}

impl<F: StoreFs + Send + Sync + 'static> Approve<F> {
    /// Step 1, then the review; a cancelled prompt removes the pending config and ends the command without a response.
    async fn run(&self, request: AdminRequest, exchange: &mut Exchange) -> Result<AdminResponse, ExchangeError> {
        let AdminRequest::ConfigApprove(config) = request else {
            return Ok(refused(ApprovalEnd::Unavailable("the request is not `config approve`".to_owned())));
        };
        let review = match self.service.review_approval(config.into_bytes()).await {
            Ok(review) => review,
            Err(end) => return Ok(refused(end)),
        };
        match authorize(&review, exchange).await {
            Ok(Ok(signer)) => Ok(review.commit(signer).await.map_or_else(refused, AdminResponse::ConfigApprove)),
            Ok(Err(end)) => {
                review.abandon();
                Ok(refused(end))
            }
            Err(cancelled) => {
                review.abandon();
                Err(cancelled)
            }
        }
    }
}

/// Shows the summary, asks for the confirmation, then the approval passphrase, and opens the signer with it. The outer
/// error is a prompt that got no owner input; the inner one ends the approval before any reservation.
async fn authorize<F: StoreFs + Send + Sync + 'static>(
    review: &ApprovalReview<'_, F>,
    exchange: &mut Exchange,
) -> Result<Result<SoftwareSigner, ApprovalEnd>, ExchangeError> {
    exchange.notice(&review.summary()).await?;
    let confirm = Prompt {
        label: format!("Approve this config as version {}? Type yes to approve", review.version()),
        secret: false,
    };
    if exchange.prompt(&confirm).await?.expose_secret() != b"yes" {
        return Ok(Err(ApprovalEnd::Declined));
    }
    let prompt = Prompt {
        label: PASSPHRASE_PROMPT.to_owned(),
        secret: true,
    };
    let input = exchange.prompt(&prompt).await?;
    Ok(approval_passphrase(input)
        .ok_or(ApprovalEnd::Denied)
        .and_then(|passphrase| review.open_signer(&passphrase)))
}

/// The owner's input as an approval passphrase. Empty or non-UTF-8 input cannot be the passphrase, so it is refused as
/// a wrong one. The input's buffer is cleared when it drops here.
fn approval_passphrase(input: OwnerInput) -> Option<ApprovalPassphrase> {
    let text = std::str::from_utf8(input.expose_secret()).ok()?;
    ApprovalPassphrase::new(SecretString::from(text)).ok()
}

fn refused(end: ApprovalEnd) -> AdminResponse {
    let code = match end {
        ApprovalEnd::Busy => ErrorCode::Busy,
        ApprovalEnd::WrongState(_) | ApprovalEnd::Unavailable(_) => ErrorCode::ApprovalUnavailable,
        ApprovalEnd::Invalid(_) => ErrorCode::ConfigInvalid,
        ApprovalEnd::Declined => ErrorCode::Declined,
        ApprovalEnd::Denied => ErrorCode::ApprovalDenied,
        ApprovalEnd::Failed { .. } => ErrorCode::ApprovalFailed,
        ApprovalEnd::NotActive { .. } => ErrorCode::CommittedNotActive,
    };
    AdminResponse::Error {
        code,
        message: end.to_string(),
    }
}
