//! `config approve`: the approval transaction on the owner's proposed config (spec [§5][s5], [§12][s12], [§16][s16];
//! [admin protocol: config approve](../../../../design/admin-protocol.md#config-approve)).
//!
//! The service writes and validates the pending config, shows its own summary as notices, and asks for the
//! confirmation, then the approval passphrase, in that order. Nothing is reserved until the passphrase has opened the
//! approver key, so a declined, cancelled or mistyped approval consumes no version. The CLI only carries the bytes and
//! the owner's answers; the service signs only its own pending transaction.
//!
//! ```text
//! 1  pending config written and validated            config-invalid
//! 2  summary sent as notices
//! 3  "Approve this config as version n?"              declined
//! 4  approval passphrase or TPM approval PIN          approval-denied, tpm-locked-out
//!    ---------- nothing above reserves a version ----------
//! 5  reserve, sign, commit, publish, config check     approval-failed, committed-not-active
//! ```
//!
//! [s5]: ../../../../design/iron-vault-specification.md#5-service-and-cli-separation-of-concerns
//! [s12]: ../../../../design/iron-vault-specification.md#12-configuration-approval-and-reload
//! [s16]: ../../../../design/iron-vault-specification.md#16-administration-recovery-and-migration

use std::sync::Arc;

use iron_vault_store::{PinnedApprover, StoreFs};

use super::dispatch::{AdminHandler, HandlerFuture};
use super::owner_presence::{PassphraseAnswer, ask_approval_passphrase};
use super::principal::AdminPrincipal;
use super::protocol::{AdminRequest, AdminResponse, ErrorCode, Prompt};
use super::server::{Exchange, ExchangeError};
use crate::service_context::{ApprovalEnd, ApprovalReview, ApproverSigner, NO_ASKABLE_APPROVER, ServiceContext};

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
    /// Runs step 1, then the review; a cancelled prompt removes the pending config and ends the command without a
    /// response.
    async fn run(&self, request: AdminRequest, exchange: &mut Exchange) -> Result<AdminResponse, ExchangeError> {
        let AdminRequest::ConfigApprove(config) = request else {
            return Ok(refused(ApprovalEnd::Unavailable("the request is not `config approve`".to_owned())));
        };
        let review = match self.service.review_approval(config.into_bytes()).await {
            Ok(review) => review,
            Err(end) => return Ok(refused(end)),
        };
        match authorize(&review, exchange).await {
            Ok(Ok((approver, signer))) => Ok(review
                .commit(approver, signer)
                .await
                .map_or_else(refused, AdminResponse::ConfigApprove)),
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

/// Shows the summary, asks for the confirmation, then the approval passphrase or PIN, and opens the signer with it. The
/// outer error is a prompt that got no owner input; the inner one ends the approval before any reservation.
///
/// A `lock` waiting for the service-wide lock ends the approval at either prompt with [`ApprovalEnd::CancelledByLock`].
/// Once the passphrase is in, the approval is no longer at a prompt, and the `lock` waits for it to end.
async fn authorize<F: StoreFs + Send + Sync + 'static>(
    review: &ApprovalReview<'_, F>,
    exchange: &mut Exchange,
) -> Result<Result<(PinnedApprover, ApproverSigner), ApprovalEnd>, ExchangeError> {
    exchange.notice(&review.summary()).await?;
    let confirm = Prompt {
        label: format!("Approve this config as version {}? Type yes to approve", review.version()),
        secret: false,
        switchable: false,
    };
    let Some(confirmation) = exchange.prompt_unless(&confirm, review.lock_requested()).await? else {
        return Ok(Err(cancelled_by_lock()));
    };
    if confirmation.expose_secret() != b"yes" {
        return Ok(Err(ApprovalEnd::Declined));
    }
    let Some((approver, answer)) = ask_approval_passphrase(exchange, review.approvers(), || review.lock_requested()).await? else {
        return Ok(Err(ApprovalEnd::Unavailable(NO_ASKABLE_APPROVER.to_owned())));
    };
    let passphrase = match answer {
        PassphraseAnswer::Typed(passphrase) => passphrase,
        PassphraseAnswer::Unusable => return Ok(Err(review.refuse_unusable_passphrase(approver))),
        PassphraseAnswer::CancelledByLock => return Ok(Err(cancelled_by_lock())),
    };
    Ok(review
        .open_signer(approver, passphrase)
        .await
        .map(|signer| (approver.clone(), signer)))
}

fn cancelled_by_lock() -> ApprovalEnd {
    tracing::warn!("config approval cancelled at its prompt by a lock; nothing was reserved");
    ApprovalEnd::CancelledByLock
}

fn refused(end: ApprovalEnd) -> AdminResponse {
    let code = match end {
        ApprovalEnd::Busy => ErrorCode::Busy,
        ApprovalEnd::WrongState(_) | ApprovalEnd::Unavailable(_) | ApprovalEnd::CancelledByLock => ErrorCode::ApprovalUnavailable,
        ApprovalEnd::Invalid(_) => ErrorCode::ConfigInvalid,
        ApprovalEnd::Declined => ErrorCode::Declined,
        ApprovalEnd::Denied | ApprovalEnd::PinDenied => ErrorCode::ApprovalDenied,
        ApprovalEnd::LockedOut { .. } => ErrorCode::TpmLockedOut,
        ApprovalEnd::Failed { .. } => ErrorCode::ApprovalFailed,
        ApprovalEnd::NotActive { .. } => ErrorCode::CommittedNotActive,
    };
    AdminResponse::Error {
        code,
        message: end.to_string(),
    }
}
