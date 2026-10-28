//! The approval signer: what produces config approvals for the pinned approver (spec §3.9, §8.2 Q-9).
//!
//! The approval transaction asks a signer for an envelope over a typed payload and never needs to know which kind of
//! signer it holds, so the software signer, the TPM signer and the later YubiKey signer plug in at the same place and
//! all produce one envelope format, verified one way.

use thiserror::Error;

use super::{ApprovalDecodeError, ApprovalEnvelope, ApprovalPayload, ApprovalStateError, PinnedApprover, SignatureAlgorithm};
use crate::EnvelopeError;

/// Signs config approvals for one pinned approver.
///
/// It accepts only an [`ApprovalPayload`], never arbitrary bytes, so whoever can reach a signer can obtain approval
/// signatures and nothing else: a signer is never a general signing oracle.
pub trait ApprovalSigner {
    /// The algorithm this signer signs with.
    fn algorithm(&self) -> SignatureAlgorithm;

    /// The approver this signer's key verifies as: the value to pin when this signer is enrolled.
    fn pinned(&self) -> PinnedApprover;

    /// Signs the exact encoding of `payload` and returns the `config.toml.sig` envelope carrying it.
    fn sign(&self, payload: &ApprovalPayload) -> Result<ApprovalEnvelope, SignError>;
}

/// An approval signer could not be created, opened or used. No variant carries key material or passphrase text.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SignError {
    /// The approval passphrase does not open the approver key envelope.
    #[error("wrong approval passphrase")]
    WrongPassphrase,
    /// The decrypted signing key is not the pinned approver's key, so nothing may be signed with it.
    #[error("the approver key does not match the pinned approver")]
    KeyMismatch,
    /// The signing key's public key cannot be pinned as an approver.
    #[error("the approver key cannot be pinned: {0}")]
    Unpinnable(ApprovalStateError),
    /// The approver key envelope is damaged, oversized or not an approver key envelope.
    #[error("the approver key envelope cannot be opened: {0}")]
    Envelope(EnvelopeError),
    /// The operating system's random source failed, so no key was generated.
    #[error("the operating system's random source failed; no approver key was generated")]
    Randomness,
    /// The signature does not fit the approval envelope for its algorithm.
    #[error("the signer produced a signature the approval envelope refuses: {0}")]
    Signature(ApprovalDecodeError),
}

impl From<EnvelopeError> for SignError {
    fn from(error: EnvelopeError) -> Self {
        match error {
            EnvelopeError::WrongPassphrase => Self::WrongPassphrase,
            other => Self::Envelope(other),
        }
    }
}
