//! Verifying a config approval against the approval state at startup and reload (spec §3.9, §3.15).
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
use super::{ApprovalDecodeError, ApprovalEnvelope, ApprovalState, ApprovalVersion, ConfigDigest, PinnedApprover, SignatureAlgorithm};

/// A config approval that passed every check in [`verify_approval`]: the committed approval, signed by the pinned
/// approver, for this vault and the exact config bytes given.
///
/// Only [`verify_approval`] builds one, so holding one is proof the checks ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedApproval {
    version: ApprovalVersion,
    digest: ConfigDigest,
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
}

/// Why a config approval does not verify. Any variant stops proxying (spec §3.9).
///
/// No variant carries key material, signature bytes or config bytes. Versions are not secret, so they are named for the
/// operator.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum VerifyError {
    /// The signature file is not a well-formed approval envelope.
    #[error("the config signature file is malformed: {0}")]
    Malformed(#[from] ApprovalDecodeError),
    /// The envelope names an algorithm other than the pinned approver's.
    #[error("the config approval is signed with {envelope:?}, but the pinned approver uses {pinned:?}")]
    WrongAlgorithm {
        /// The pinned approver's algorithm.
        pinned: SignatureAlgorithm,
        /// The algorithm the envelope names.
        envelope: SignatureAlgorithm,
    },
    /// The signature does not verify against the pinned public key over the encoded payload.
    #[error("the config approval signature does not verify against the pinned approver")]
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

/// Verifies the `config.toml.sig` bytes `envelope` for the `config.toml` bytes `config` against `state` (spec §3.9).
///
/// Checks, in order: the envelope decodes; its algorithm is the pinned approver's; its signature verifies against the
/// pinned key over the exact payload bytes; the payload names this vault; the payload digest is the digest of
/// `config`; and the payload's version and digest are the committed approval. Reads nothing but its arguments and
/// changes nothing.
pub fn verify_approval(state: &ApprovalState, config: &[u8], envelope: &[u8]) -> Result<VerifiedApproval, VerifyError> {
    let envelope = ApprovalEnvelope::decode(envelope)?;
    check_signature(state.approver(), &envelope)?;
    let payload = envelope.payload();
    if payload.vault_id() != state.vault_id() {
        return Err(VerifyError::WrongVault);
    }
    if payload.digest() != ConfigDigest::of(config) {
        return Err(VerifyError::ConfigChanged);
    }
    check_committed(state.committed(), payload.version(), payload.digest())?;
    Ok(VerifiedApproval { version: payload.version(), digest: payload.digest() })
}

/// Checks the envelope's algorithm and signature against `approver`, never against anything in the envelope itself.
fn check_signature(approver: &PinnedApprover, envelope: &ApprovalEnvelope) -> Result<(), VerifyError> {
    let (pinned, claimed) = (approver.algorithm(), envelope.algorithm());
    if pinned != claimed {
        return Err(VerifyError::WrongAlgorithm { pinned, envelope: claimed });
    }
    match approver.key() {
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
