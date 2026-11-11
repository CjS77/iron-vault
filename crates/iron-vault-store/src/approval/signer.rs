//! The approval signer: what produces config approvals for the pinned approver (spec §12, implementation spec §2.2 Q-9).
//!
//! The approval transaction asks a signer for an envelope over a typed payload and never needs to know which kind of
//! signer it holds, so the software signer, the TPM signer and the later YubiKey signer plug in at the same place and
//! all produce one envelope format, verified one way.

use thiserror::Error;

use super::{ApprovalDecodeError, ApprovalEnvelope, ApprovalPayload, ApproverPublicKey, SignatureAlgorithm};
use crate::EnvelopeError;

/// Signs config approvals for one pinned approver.
///
/// It accepts only an [`ApprovalPayload`], never arbitrary bytes, so whoever can reach a signer can obtain approval
/// signatures and nothing else: a signer is never a general signing oracle.
pub trait ApprovalSigner {
    /// The algorithm this signer signs with.
    fn algorithm(&self) -> SignatureAlgorithm;

    /// The public key this signer's signatures verify against: the key to pin when this signer is enrolled.
    fn public_key(&self) -> ApproverPublicKey;

    /// Signs the exact encoding of `payload` and returns the `config.toml.sig` envelope carrying it, naming the approver
    /// ID this signer is pinned as, so the verifier checks the signature against that approver's key.
    fn sign(&self, payload: &ApprovalPayload) -> Result<ApprovalEnvelope, SignError>;
}

/// An approval signer could not be created, opened or used. No variant carries key material or passphrase text.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SignError {
    /// The approval passphrase does not open the approver key envelope.
    #[error("wrong approval passphrase")]
    WrongPassphrase,
    /// The decrypted signing key is no pinned approver's key, so nothing may be signed with it.
    #[error("the approver key does not match any pinned approver")]
    KeyMismatch,
    /// The approver key envelope is damaged, oversized or not an approver key envelope.
    #[error("the approver key envelope cannot be opened: {0}")]
    Envelope(EnvelopeError),
    /// The operating system's random source failed, so no key was generated.
    #[error("the operating system's random source failed; no approver key was generated")]
    Randomness,
    /// The TPM signing helper could not sign, or the TPM refused; the text names its status and never anything the owner typed.
    #[error("the TPM signing helper cannot sign: {0}")]
    TpmHelper(String),
    /// The task the signature was made on ended without an answer: it panicked, or the runtime is shutting down.
    #[error("the signing task ended without an answer")]
    Interrupted,
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
