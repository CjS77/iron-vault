//! Opening a pinned approver's key with the approval passphrase (specification §12, §6): the one check both
//! `config approve` and owner presence (design/credential-commands.md, "Owner presence") make.
//!
//! `config approve` keeps the signer it opens to sign its payload. Owner presence drops it at once and keeps only an
//! [`OwnerPresence`], so presence reserves no version, signs nothing and writes nothing.

use std::sync::Arc;

use iron_vault_store::{
    ApprovalPassphrase, ApproverId, PinnedApprover, SignError, SoftwareSigner, StoreFs, open_signer_key, read_signer_key,
};

use super::ServiceContext;
use super::approver_order::approver_order;
use crate::serving_snapshot::Admission;

/// Proof that the owner typed the approval passphrase in this exchange, after the service described the change.
///
/// Only a successful key check constructs one, and a vault change consumes it, so it is never kept or reused. It is
/// required by type: the write that needs owner presence cannot be called without it.
#[derive(Debug)]
pub struct OwnerPresence(());

/// Which check of the approver key refused, kept apart so the audit event can name it without the error's text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenialKind {
    /// The passphrase does not open the asked approver's key envelope.
    WrongPassphrase,
    /// The key inside opened, but it is not the asked approver's.
    KeyMismatch,
}

impl DenialKind {
    /// The snake_case label audit events record (`design/audit-logging.md`).
    pub const fn label(self) -> &'static str {
        match self {
            Self::WrongPassphrase => "wrong_passphrase",
            Self::KeyMismatch => "key_mismatch",
        }
    }
}

/// Why the approval passphrase check did not pass. Neither message holds anything the owner typed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PresenceRefusal {
    /// The passphrase does not open the asked approver's key envelope, or the key inside is not the asked approver's.
    #[error("the approval passphrase does not open the approver key")]
    Denied(DenialKind),
    /// The approver key could not be read, or the check did not finish.
    #[error("the approver key cannot be checked: {0}")]
    Unavailable(String),
}

impl<F: StoreFs + Send + Sync + 'static> ServiceContext<F> {
    /// Opens `approver`'s own key envelope, `approver-<approver ID>.age`, with `passphrase` as its signer, on the
    /// blocking pool, since scrypt holds a thread for seconds. A wrong passphrase, or a key that is not `approver`'s,
    /// is [`PresenceRefusal::Denied`].
    ///
    /// The task owns the passphrase and drops it when it ends. If this future is dropped first, the task still ends and
    /// drops the signer it opened.
    pub(super) async fn open_approver(
        &self,
        passphrase: ApprovalPassphrase,
        approver: PinnedApprover,
    ) -> Result<SoftwareSigner, PresenceRefusal> {
        let (locks, setup) = (Arc::clone(&self.locks), Arc::clone(&self.setup));
        let opened = tokio::task::spawn_blocking(move || {
            let envelope =
                read_signer_key(&locks.state, &setup.fs, approver.id()).map_err(|error| PresenceRefusal::Unavailable(error.to_string()))?;
            open_signer_key(&envelope, &passphrase, std::slice::from_ref(&approver)).map_err(denied_or_unavailable)
        });
        opened
            .await
            .unwrap_or_else(|_| Err(PresenceRefusal::Unavailable("the approver key check was interrupted".to_owned())))
    }

    /// `approvers` in [approver order](approver_order), by the signer of the active approval the serving snapshot was built
    /// from. The service is Unavailable, with no active approval, when it holds no snapshot.
    pub(super) fn ordered_approvers(&self, approvers: &[PinnedApprover]) -> Vec<PinnedApprover> {
        approver_order(approvers, self.active_signer())
    }

    /// The approver that signed the active approval, when the service is serving one.
    pub(super) fn active_signer(&self) -> Option<ApproverId> {
        match self.holder.load() {
            Admission::Serve(snapshot) => snapshot.signer(),
            Admission::Refuse(_) => None,
        }
    }

    /// Owner presence: [`open_approver`](Self::open_approver) as the `approver` the owner answered, dropping the signer at
    /// once. A key that is not `approver`'s is refused, with no fall-through to another approver.
    pub(super) async fn prove_presence(
        &self,
        passphrase: ApprovalPassphrase,
        approver: &PinnedApprover,
    ) -> Result<OwnerPresence, PresenceRefusal> {
        self.open_approver(passphrase, approver.clone()).await.map(|signer| {
            drop(signer);
            OwnerPresence(())
        })
    }
}

/// A wrong approval passphrase, or a key that is not the asked approver's, is the owner's refusal; anything else is
/// the service's.
fn denied_or_unavailable(error: SignError) -> PresenceRefusal {
    match error {
        SignError::WrongPassphrase => PresenceRefusal::Denied(DenialKind::WrongPassphrase),
        SignError::KeyMismatch => PresenceRefusal::Denied(DenialKind::KeyMismatch),
        other => PresenceRefusal::Unavailable(other.to_string()),
    }
}
