//! Opens a pinned approver's key with its approval passphrase or TPM approval PIN
//! ([specification §12](../../../../design/iron-vault-specification.md#12-configuration-approval-and-reload),
//! [§6](../../../../design/iron-vault-specification.md#6-credential-records-and-configuration)): the one check both
//! `config approve` and [owner presence](../../../../design/credential-commands.md#owner-presence) make.
//!
//! `config approve` keeps the signer it opens to sign its payload. Owner presence drops it at once and keeps only an
//! [`OwnerPresence`], so presence reserves no version, signs nothing and writes nothing.

use std::sync::Arc;

use iron_vault_store::{
    ApprovalEnvelope, ApprovalPassphrase, ApprovalPayload, ApprovalSigner, ApproverId, ApproverPublicKey, PinnedApprover, SignError,
    SignatureAlgorithm, SignerKind, SoftwareSigner, StoreFs, VaultId, open_signer_key, presence_message, read_signer_key,
    read_tpm_key_blob,
};
use iron_vault_tpm_protocol::TpmApprovalPin;

use super::ServiceContext;
use super::approver_order::approver_order;
use super::tpm_helper::{HelperError, TpmStatus};
use super::tpm_signer::TpmSigner;
use crate::serving_snapshot::Admission;

/// What the owner typed at the approver prompt: the approval passphrase of a software approver, or the TPM approval PIN
/// of a TPM approver. The prompt makes the one its approver's kind asks for.
pub enum ApproverSecret {
    /// An approval passphrase.
    Passphrase(ApprovalPassphrase),
    /// A TPM approval PIN.
    Pin(TpmApprovalPin),
}

impl From<ApprovalPassphrase> for ApproverSecret {
    fn from(passphrase: ApprovalPassphrase) -> Self {
        Self::Passphrase(passphrase)
    }
}

impl From<TpmApprovalPin> for ApproverSecret {
    fn from(pin: TpmApprovalPin) -> Self {
        Self::Pin(pin)
    }
}

/// An approver's opened signer, which `config approve` keeps to sign with and owner presence drops.
#[derive(Debug)]
pub enum ApproverSigner {
    /// A software approver's key, opened by its passphrase.
    Software(Box<SoftwareSigner>),
    /// A TPM approver's key, with the authorization value its PIN made, held until the transaction ends.
    Tpm(Box<TpmSigner>),
}

impl ApprovalSigner for ApproverSigner {
    fn algorithm(&self) -> SignatureAlgorithm {
        match self {
            Self::Software(signer) => signer.algorithm(),
            Self::Tpm(signer) => signer.algorithm(),
        }
    }

    fn public_key(&self) -> ApproverPublicKey {
        match self {
            Self::Software(signer) => signer.public_key(),
            Self::Tpm(signer) => signer.public_key(),
        }
    }

    fn sign(&self, payload: &ApprovalPayload) -> Result<ApprovalEnvelope, SignError> {
        match self {
            Self::Software(signer) => signer.sign(payload),
            Self::Tpm(signer) => signer.sign(payload),
        }
    }
}

/// Proof that the owner typed an approver's secret (approval passphrase or TPM approval PIN) in this exchange, after
/// the service described the change.
///
/// Only a successful key check constructs one, and a vault change consumes it, so it is never kept or reused. It is
/// required by type: the write that needs owner presence cannot be called without it. It names the approver whose key
/// opened, which an approver change records as the authorizing approver.
#[derive(Debug)]
pub struct OwnerPresence {
    approver: PinnedApprover,
}

impl OwnerPresence {
    /// Returns the pinned approver whose key the owner opened.
    pub fn approver(&self) -> &PinnedApprover {
        &self.approver
    }
}

/// Which check of the approver key refused, kept apart so the audit event can name it without the error's text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenialKind {
    /// The passphrase does not open the asked approver's key envelope.
    WrongPassphrase,
    /// The key inside opened, but it is not the asked approver's.
    KeyMismatch,
    /// The TPM refused the authorization the PIN made. Each such PIN counts against the TPM's lockout.
    WrongPin,
    /// A TPM approver's helper refused or could not be reached; the audit event's `tpm_status` says which.
    TpmRefused,
}

impl DenialKind {
    /// Returns the refusal for an answer that cannot be a secret of a `kind` approver (empty, not UTF-8, or for a TPM
    /// approver shorter than any enrolled PIN), which is answered as a wrong one.
    pub const fn wrong_answer(kind: SignerKind) -> Self {
        match kind {
            SignerKind::Software => Self::WrongPassphrase,
            SignerKind::Tpm => Self::WrongPin,
        }
    }

    /// Returns the snake_case label audit events record ([audit logging](../../../../design/audit-logging.md)), such as
    /// `wrong_passphrase`.
    pub const fn label(self) -> &'static str {
        match self {
            Self::WrongPassphrase => "wrong_passphrase",
            Self::KeyMismatch => "key_mismatch",
            Self::WrongPin => "wrong_pin",
            Self::TpmRefused => "tpm_refused",
        }
    }
}

/// Why the approval passphrase or PIN check did not pass. No message holds anything the owner typed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PresenceRefusal {
    /// The passphrase does not open the asked approver's key envelope, the key inside is not the asked approver's, or
    /// the TPM refused the PIN.
    #[error("{}", denial_text(*.0))]
    Denied(DenialKind),
    /// The answer cannot be the asked approver's secret (see [`DenialKind::wrong_answer`]), so it was refused as a
    /// wrong one before the key or the TPM signing helper was asked.
    #[error("{}", denial_text(*.0))]
    Unusable(DenialKind),
    /// The approver key could not be read, or the check did not finish.
    #[error("the approver key cannot be checked: {0}")]
    Unavailable(String),
    /// The TPM is in dictionary-attack lockout, or the lockout reserve withheld the try. Nothing was reserved, signed
    /// or changed.
    #[error("the TPM is locked out; try again in {wait_seconds} seconds; nothing was reserved, signed or changed")]
    TpmLockedOut {
        /// The number of whole seconds to wait.
        wait_seconds: u64,
    },
    /// The TPM signing helper refused for a reason other than the PIN, or could not be reached; `message` names the
    /// status.
    #[error("the TPM approver cannot be checked: {message}")]
    TpmUnavailable {
        /// The status the audit log's `tpm_status` field records.
        status: TpmStatus,
        /// The helper's status in words.
        message: String,
    },
}

impl PresenceRefusal {
    /// Returns what an audit event records about this refusal, when it is the kind the owner or an attacker causes: the
    /// check that refused and, for an answer the TPM signing helper saw, its status. Returns `None` for a check that
    /// could not run.
    pub fn audit(&self) -> Option<(DenialKind, Option<TpmStatus>)> {
        match self {
            Self::Denied(DenialKind::WrongPin) => Some((DenialKind::WrongPin, Some(TpmStatus::WrongPin))),
            Self::Denied(kind) | Self::Unusable(kind) => Some((*kind, None)),
            Self::Unavailable(_) => None,
            Self::TpmLockedOut { .. } => Some((DenialKind::TpmRefused, Some(TpmStatus::LockedOut))),
            Self::TpmUnavailable { status, .. } => Some((DenialKind::TpmRefused, Some(*status))),
        }
    }
}

impl From<HelperError> for PresenceRefusal {
    fn from(error: HelperError) -> Self {
        match error {
            HelperError::WrongPin => Self::Denied(DenialKind::WrongPin),
            HelperError::LockedOut { wait_seconds } => Self::TpmLockedOut { wait_seconds },
            HelperError::Failed { status, message } => Self::TpmUnavailable { status, message },
        }
    }
}

fn denial_text(kind: DenialKind) -> &'static str {
    match kind {
        DenialKind::WrongPin => "the TPM approval PIN is wrong; each wrong PIN counts against the TPM's lockout",
        _ => "the approval passphrase does not open the approver key",
    }
}

impl<F: StoreFs + Send + Sync + 'static> ServiceContext<F> {
    /// Opens `approver`'s own key with what the owner typed, on the blocking pool, since scrypt holds a thread for
    /// seconds and the TPM signing helper answers over a socket. A software approver's key envelope,
    /// `approver-<approver ID>.age`, opens with its passphrase; a TPM approver's key proves itself by signing a fresh
    /// presence payload under its PIN, which needs `vault_id`. A wrong secret, or a key that is not `approver`'s, is
    /// [`PresenceRefusal::Denied`], and a secret of the other kind is a check that could not run.
    ///
    /// The task owns the secret and drops it when it ends. If this future is dropped first, the task still ends and
    /// drops the signer it opened.
    pub(super) async fn open_approver(
        &self,
        secret: ApproverSecret,
        approver: PinnedApprover,
        vault_id: Option<VaultId>,
    ) -> Result<ApproverSigner, PresenceRefusal> {
        match (approver.kind(), secret) {
            (SignerKind::Software, ApproverSecret::Passphrase(passphrase)) => self
                .open_software(passphrase, approver)
                .await
                .map(|signer| ApproverSigner::Software(Box::new(signer))),
            (SignerKind::Tpm, ApproverSecret::Pin(pin)) => self
                .open_tpm(pin, approver, vault_id)
                .await
                .map(|signer| ApproverSigner::Tpm(Box::new(signer))),
            _ => Err(PresenceRefusal::Unavailable(
                "the answer is not the kind the approver asks for".to_owned(),
            )),
        }
    }

    async fn open_software(&self, passphrase: ApprovalPassphrase, approver: PinnedApprover) -> Result<SoftwareSigner, PresenceRefusal> {
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

    async fn open_tpm(
        &self,
        pin: TpmApprovalPin,
        approver: PinnedApprover,
        vault_id: Option<VaultId>,
    ) -> Result<TpmSigner, PresenceRefusal> {
        let unreachable = |message: &str| PresenceRefusal::TpmUnavailable {
            status: TpmStatus::Unreachable,
            message: message.to_owned(),
        };
        let Some(vault_id) = vault_id else {
            return Err(PresenceRefusal::Unavailable("no vault is open to prove presence for".to_owned()));
        };
        let Some(socket) = self.tpm_helper_socket() else {
            return Err(unreachable("the TPM signing helper is unavailable: its socket is missing"));
        };
        let (locks, setup) = (Arc::clone(&self.locks), Arc::clone(&self.setup));
        let opened = tokio::task::spawn_blocking(move || {
            let blob = read_tpm_key_blob(&locks.state, &setup.fs, approver.id())
                .map_err(|error| PresenceRefusal::Unavailable(format!("the TPM key blob is unusable: {error}")))?;
            let message = presence_message(vault_id, approver.id()).map_err(|error| PresenceRefusal::Unavailable(error.to_string()))?;
            TpmSigner::prove(socket, (blob, approver), &message, pin)
        });
        opened
            .await
            .unwrap_or_else(|_| Err(PresenceRefusal::Unavailable("the approver key check was interrupted".to_owned())))
    }

    /// Sorts `approvers` into [approver order](approver_order), by the signer of the active approval the serving
    /// snapshot was built from. The service is Unavailable, with no active approval, when it holds no snapshot.
    pub(super) fn ordered_approvers(&self, approvers: &[PinnedApprover]) -> Vec<PinnedApprover> {
        approver_order(approvers, self.active_signer())
    }

    /// Returns [`ordered_approvers`](Self::ordered_approvers) without the approvers this install cannot ask: a TPM
    /// approver with no readable key blob, or any while the helper socket is missing. A vault moved to another
    /// machine therefore starts its prompt at an approver that can answer.
    pub(super) fn askable_approvers(&self, approvers: &[PinnedApprover]) -> Vec<PinnedApprover> {
        let mut ordered = self.ordered_approvers(approvers);
        ordered.retain(|approver| self.can_ask(approver));
        ordered
    }

    fn can_ask(&self, approver: &PinnedApprover) -> bool {
        match approver.kind() {
            SignerKind::Software => true,
            SignerKind::Tpm => {
                self.tpm_helper_socket().is_some() && read_tpm_key_blob(&self.locks.state, &self.setup.fs, approver.id()).is_ok()
            }
        }
    }

    /// Returns the approver that signed the active approval, or `None` when the service is serving none.
    pub(super) fn active_signer(&self) -> Option<ApproverId> {
        match self.holder.load() {
            Admission::Serve(snapshot) => snapshot.signer(),
            Admission::Refuse(_) => None,
        }
    }

    /// Proves owner presence: runs [`open_approver`](Self::open_approver) as the `approver` the owner answered,
    /// dropping the signer at once. A key that is not `approver`'s is refused, with no fall-through to another
    /// approver.
    pub(super) async fn prove_presence(&self, secret: ApproverSecret, approver: &PinnedApprover) -> Result<OwnerPresence, PresenceRefusal> {
        let vault_id = self.inner.lock().await.open.as_ref().map(|open| open.approval.vault_id());
        self.open_approver(secret, approver.clone(), vault_id).await.map(|signer| {
            drop(signer);
            OwnerPresence {
                approver: approver.clone(),
            }
        })
    }
}

/// Classifies a signing error: a wrong approval passphrase, or a key that is not the asked approver's, is the owner's
/// refusal; anything else is the service's.
fn denied_or_unavailable(error: SignError) -> PresenceRefusal {
    match error {
        SignError::WrongPassphrase => PresenceRefusal::Denied(DenialKind::WrongPassphrase),
        SignError::KeyMismatch => PresenceRefusal::Denied(DenialKind::KeyMismatch),
        other => PresenceRefusal::Unavailable(other.to_string()),
    }
}
