// SPDX-License-Identifier: MPL-2.0
//! The [`ApprovalSigner`] trait: what signs a config approval for a pinned approver
//! ([spec §12](../../../../design/iron-vault-specification.md#12-configuration-approval-and-reload),
//! [implementation spec §2.2](../../../../design/implementation-specification.md#22-product-decisions-and-resulting-behavior)
//! Q-9).
//!
//! The approval transaction asks a signer for an envelope over a typed payload and never learns which kind of signer it
//! holds. The software signer, the TPM signer and the later YubiKey signer plug in at the same place, and all produce
//! one envelope format that the service verifies one way.

use thiserror::Error;

use super::{ApprovalDecodeError, ApprovalEnvelope, ApprovalPayload, ApproverPublicKey, SignatureAlgorithm};
use crate::EnvelopeError;

/// Signs config approvals for one pinned approver.
///
/// It accepts only an [`ApprovalPayload`], never arbitrary bytes. Whoever can reach a signer can get approval signatures
/// from it and nothing else, so a signer is never a general signing oracle.
pub trait ApprovalSigner {
    /// The algorithm this signer signs with.
    fn algorithm(&self) -> SignatureAlgorithm;

    /// The public key this signer's signatures verify against: the key to pin when the signer is enrolled.
    fn public_key(&self) -> ApproverPublicKey;

    /// Signs the exact encoding of `payload` and returns the `config.toml.sig` envelope that carries it. The envelope
    /// names the approver ID this signer is pinned as, so the verifier checks the signature against that approver's key.
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
    /// The TPM signing helper could not sign, or the TPM refused. The text names the status, never anything the owner
    /// typed.
    #[error("the TPM signing helper cannot sign: {0}")]
    TpmHelper(String),
    /// The signer ended with neither a signature nor an error, because the thread or task running it panicked or was
    /// cancelled. A caller that signs off its own thread reports this, since [`ApprovalSigner::sign`] has no other way
    /// to say the signer never answered.
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
