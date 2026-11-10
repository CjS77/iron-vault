//! Verifying a config approval against the approval state at startup and reload (spec §12, §19).
//!
//! The checks run in a fixed order and stop at the first failure. The signature is checked before any payload field
//! is trusted, so an unsigned payload never reaches the vault, digest or version checks. Verification only reads the
//! state: loading a config never advances a counter or repairs trusted state from a caller-supplied file.

#[cfg(test)]
mod tests;

use std::cmp::Ordering;

use ed25519_dalek::{Signature, VerifyingKey};
use thiserror::Error;

use super::state::ApproverKey;
use super::{
    ApprovalDecodeError, ApprovalEnvelope, ApprovalPayload, ApprovalState, ApprovalVersion, ApproverId, ConfigDigest, PinnedApprover,
    SignatureAlgorithm,
};

/// A config approval that passed every check in [`verify_approval`]: the committed approval, signed by a pinned
/// approver, for this vault and the exact config bytes given.
///
/// Only [`verify_approval`] builds one, so holding one is proof the checks ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedApproval {
    version: ApprovalVersion,
    digest: ConfigDigest,
    approver: ApproverId,
}

impl VerifiedApproval {
    /// The committed approval version the config was approved as.
    pub fn version(&self) -> ApprovalVersion {
        self.version
    }

    /// The digest of the verified config bytes.
    pub fn digest(&self) -> ConfigDigest {
        self.digest
    }

    /// The pinned approver that signed the approval, from the envelope. The service asks it first at the next prompt.
    pub fn approver(&self) -> ApproverId {
        self.approver
    }
}

/// Why a config approval does not verify. Any variant stops proxying (spec §12).
///
/// No variant carries key material, signature bytes or config bytes. Versions are not secret, so they are named for the
/// operator.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum VerifyError {
    /// The signature file is not a well-formed approval envelope.
    #[error("the config signature file is malformed: {0}")]
    Malformed(#[from] ApprovalDecodeError),
    /// The envelope's approver ID is not one this vault pins: the approver was never enrolled or has been removed.
    #[error("the config approval is signed by approver {approver}, which this vault does not pin")]
    UnknownApprover {
        /// The approver ID the envelope names.
        approver: ApproverId,
    },
    /// The envelope names another algorithm than the named approver's.
    #[error("the config approval is signed with {envelope:?}, but the named approver uses {pinned:?}")]
    WrongAlgorithm {
        /// The named approver's algorithm.
        pinned: SignatureAlgorithm,
        /// The algorithm the envelope names.
        envelope: SignatureAlgorithm,
    },
    /// The signature does not verify against the named approver's public key over the encoded payload.
    #[error("the config approval signature does not verify against the named approver's key")]
    BadSignature,
    /// The signed payload names a different vault.
    #[error("the config approval is for a different vault")]
    WrongVault,
    /// The config bytes are not the ones the approval signed.
    #[error("the config has changed since it was approved; approve it again")]
    ConfigChanged,
    /// No approval has been committed, so no config can be active.
    #[error("the config approval is for version {version}, but no approval has been committed")]
    NothingCommitted {
        /// The version the approval is for.
        version: ApprovalVersion,
    },
    /// The approval is for a version older than the committed one: an old config and signature pair.
    #[error("the config approval is for version {version}, but version {committed} is committed")]
    Superseded {
        /// The version the approval is for.
        version: ApprovalVersion,
        /// The committed version.
        committed: ApprovalVersion,
    },
    /// The approval is for a version newer than the committed one: signed but never committed.
    #[error("the config approval is for version {version}, which was never committed; version {committed} is committed")]
    Uncommitted {
        /// The version the approval is for.
        version: ApprovalVersion,
        /// The committed version.
        committed: ApprovalVersion,
    },
    /// The approval is for the committed version but a different config digest. A version is signed once, so only a
    /// misbehaving or compromised signer produces this.
    #[error("the config approval for version {version} names a different config from the committed approval")]
    DigestNotCommitted {
        /// The committed version the approval is for.
        version: ApprovalVersion,
    },
}

/// Verifies the `config.toml.sig` bytes `envelope` for the `config.toml` bytes `config` against `state` (spec §12).
///
/// Checks, in order: the envelope decodes; its approver ID is pinned; that approver uses its algorithm; its signature
/// verifies against that approver's key over the exact payload bytes; the payload names this vault; the payload digest
/// is the digest of `config`; and the payload's version and digest are the committed approval. Reads nothing but its arguments and
/// changes nothing.
pub fn verify_approval(state: &ApprovalState, config: &[u8], envelope: &[u8]) -> Result<VerifiedApproval, VerifyError> {
    let payload = verify_signed(state, ConfigDigest::of(config), envelope)?;
    check_committed(state.committed(), payload.version(), payload.digest())?;
    // Decoded a second time, after the checks above passed, so `verify_signed` keeps returning only the payload.
    let approver = ApprovalEnvelope::decode(envelope)?.approver_id();
    Ok(VerifiedApproval {
        version: payload.version(),
        digest: payload.digest(),
        approver,
    })
}

/// Runs every check of [`verify_approval`] but the last, the committed approval, and returns the signed payload.
///
/// For the approval transaction, which must check a new approval before it commits it, so the committed approval is
/// not yet the one to compare with.
pub(crate) fn verify_signed(state: &ApprovalState, digest: ConfigDigest, envelope: &[u8]) -> Result<ApprovalPayload, VerifyError> {
    let envelope = ApprovalEnvelope::decode(envelope)?;
    check_signature(state, &envelope)?;
    let payload = *envelope.payload();
    if payload.vault_id() != state.vault_id() {
        return Err(VerifyError::WrongVault);
    }
    if payload.digest() != digest {
        return Err(VerifyError::ConfigChanged);
    }
    Ok(payload)
}

/// Checks the envelope's algorithm and signature against the pinned approver its ID names, never against a key in the
/// envelope itself. Any one pinned approver's signature approves (spec §12); the ID only selects which key to check.
fn check_signature(state: &ApprovalState, envelope: &ApprovalEnvelope) -> Result<(), VerifyError> {
    let approver = state.approver(envelope.approver_id()).ok_or(VerifyError::UnknownApprover {
        approver: envelope.approver_id(),
    })?;
    match approver.algorithm() == envelope.algorithm() {
        true => verify_with(approver, envelope),
        false => Err(VerifyError::WrongAlgorithm {
            pinned: approver.algorithm(),
            envelope: envelope.algorithm(),
        }),
    }
}

/// Checks the envelope's signature against one approver's key.
fn verify_with(approver: &PinnedApprover, envelope: &ApprovalEnvelope) -> Result<(), VerifyError> {
    match approver.public_key().key() {
        ApproverKey::Ed25519(key) => verify_ed25519(key, &envelope.payload().encode(), envelope.signature()),
    }
}

/// Ed25519 verification with `verify_strict`, which refuses malleable signatures; the pinned key is already a valid,
/// non-weak point.
fn verify_ed25519(key: &VerifyingKey, message: &[u8], signature: &[u8]) -> Result<(), VerifyError> {
    let signature = Signature::from_slice(signature).map_err(|_| VerifyError::BadSignature)?;
    key.verify_strict(message, &signature).map_err(|_| VerifyError::BadSignature)
}

/// Accepts only the committed approval: its version and its digest.
fn check_committed(
    committed: Option<(ApprovalVersion, ConfigDigest)>,
    version: ApprovalVersion,
    digest: ConfigDigest,
) -> Result<(), VerifyError> {
    let (committed, committed_digest) = committed.ok_or(VerifyError::NothingCommitted { version })?;
    match version.cmp(&committed) {
        Ordering::Less => Err(VerifyError::Superseded { version, committed }),
        Ordering::Greater => Err(VerifyError::Uncommitted { version, committed }),
        Ordering::Equal if digest == committed_digest => Ok(()),
        Ordering::Equal => Err(VerifyError::DigestNotCommitted { version }),
    }
}
