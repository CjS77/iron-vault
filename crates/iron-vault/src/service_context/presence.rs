//! Opening the pinned approver's key with the approval passphrase (specification §3.9, §3.3): the one check both
//! `config approve` and owner presence (design/credential-commands.md, "Owner presence") make.
//!
//! `config approve` keeps the signer it opens to sign its payload. Owner presence drops it at once and keeps only an
//! [`OwnerPresence`], so presence reserves no version, signs nothing and writes nothing.

use std::sync::Arc;

use iron_vault_store::{ApprovalPassphrase, PinnedApprover, SignError, SoftwareSigner, StoreFs, open_signer_key, read_signer_key};

use super::ServiceContext;

/// Proof that the owner typed the approval passphrase in this exchange, after the service described the change.
///
/// Only a successful key check constructs one, and a vault change consumes it, so it is never kept or reused. It is
/// required by type: the write that needs owner presence cannot be called without it.
#[derive(Debug)]
pub struct OwnerPresence(());

/// Which check of the approver key refused, kept apart so the audit event can name it without the error's text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenialKind {
    /// The passphrase does not open `approver.age`.
    WrongPassphrase,
    /// The key inside opened, but it is not the pinned approver's.
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
    /// The passphrase does not open `approver.age`, or the key inside is not the pinned approver's.
    #[error("the approval passphrase does not open the approver key")]
    Denied(DenialKind),
    /// The approver key could not be read, or the check did not finish.
    #[error("the approver key cannot be checked: {0}")]
    Unavailable(String),
}

impl<F: StoreFs + Send + Sync + 'static> ServiceContext<F> {
    /// Opens `approver.age` with `passphrase` as the signer of `pinned`, on the blocking pool, since scrypt holds a
    /// thread for seconds. A wrong passphrase, or a key that is not `pinned`'s, is [`PresenceRefusal::Denied`].
    ///
    /// The task owns the passphrase and drops it when it ends. If this future is dropped first, the task still ends and
    /// drops the signer it opened.
    pub(super) async fn open_approver(
        &self,
        passphrase: ApprovalPassphrase,
        pinned: PinnedApprover,
    ) -> Result<SoftwareSigner, PresenceRefusal> {
        let (locks, setup) = (Arc::clone(&self.locks), Arc::clone(&self.setup));
        let opened = tokio::task::spawn_blocking(move || {
            let envelope = read_signer_key(&locks.state, &setup.fs).map_err(|error| PresenceRefusal::Unavailable(error.to_string()))?;
            open_signer_key(&envelope, &passphrase, &pinned).map_err(denied_or_unavailable)
        });
        opened
            .await
            .unwrap_or_else(|_| Err(PresenceRefusal::Unavailable("the approver key check was interrupted".to_owned())))
    }

    /// Owner presence: [`open_approver`](Self::open_approver), dropping the signer at once.
    pub(super) async fn prove_presence(
        &self,
        passphrase: ApprovalPassphrase,
        pinned: PinnedApprover,
    ) -> Result<OwnerPresence, PresenceRefusal> {
        self.open_approver(passphrase, pinned).await.map(|signer| {
            drop(signer);
            OwnerPresence(())
        })
    }
}

/// A wrong approval passphrase, or a key that is not the pinned approver's, is the owner's refusal; anything else is
/// the service's.
fn denied_or_unavailable(error: SignError) -> PresenceRefusal {
    match error {
        SignError::WrongPassphrase => PresenceRefusal::Denied(DenialKind::WrongPassphrase),
        SignError::KeyMismatch => PresenceRefusal::Denied(DenialKind::KeyMismatch),
        other => PresenceRefusal::Unavailable(other.to_string()),
    }
}
