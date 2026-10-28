//! Config approvals: the payload a signer signs and the `config.toml.sig` envelope that carries it (spec §3.9, §8.2 Q-9).
//!
//! The signature covers the purpose, the vault ID, the approval version and the config digest together, so an old
//! config cannot be paired with a newer signature and an old approval's version cannot be edited. Software, TPM and
//! later YubiKey signers all produce the same envelope, so it is verified one way. Both byte layouts are in
//! `design/storage-formats.md`.
//!
//! The approval state, which pins the approver and holds the version counters, is in [`state`]; checking an approval
//! against it is in [`verify`]. The signer that produces approvals is [`signer`], with the software signer in
//! [`software_signer`].

mod encoding;
mod signer;
mod software_signer;
mod state;
mod verify;

use std::fmt;
use std::num::NonZeroU64;

use blake2::{Blake2b256, Digest};
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::vault_id::{VaultId, VaultIdError};

pub use signer::{ApprovalSigner, SignError};
pub use software_signer::{
    ApprovalPassphrase, SoftwareSigner, SoftwareSignerKey, open_signer_key, read_signer_key, seal_signer_key, write_signer_key,
};
pub use state::{
    ApprovalState, ApprovalStateError, InvalidKeyReason, MAX_APPROVAL_STATE_LEN, PinnedApprover, open_approval_state, seal_approval_state,
};
pub use verify::{VerifiedApproval, VerifyError, verify_approval};

/// The largest approval envelope accepted, in bytes, checked before anything else is read.
///
/// A v1 envelope with an Ed25519 signature is 175 bytes and one with a DER ECDSA P-256 signature at most 183. The
/// limit leaves room for a later algorithm with a large signature while keeping a planted file cheap to refuse.
pub const MAX_APPROVAL_ENVELOPE_LEN: usize = 4096;

/// The purpose every approval payload names, so a signature made for anything else is never read as a config
/// approval.
pub const APPROVAL_PURPOSE: &str = "iron-vault-config-v1";

/// A reserved approval version: positive, because zero is the reserved counter's value before any approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ApprovalVersion(NonZeroU64);

impl ApprovalVersion {
    /// Version 1, the first a new vault reserves.
    pub const FIRST: Self = Self(NonZeroU64::MIN);

    /// The version `value`, or `None` for zero.
    pub fn new(value: u64) -> Option<Self> {
        NonZeroU64::new(value).map(Self)
    }

    /// The version as an integer.
    pub fn get(self) -> u64 {
        self.0.get()
    }

    /// The version after this one, or `None` once the counter is exhausted; it never wraps.
    pub fn next(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }
}

impl fmt::Display for ApprovalVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// The BLAKE2b-256 digest of the exact config bytes the service reviewed.
///
/// It is built only from config bytes, so every digest names a config. Equality is constant time because verification
/// compares a digest from a caller-supplied signature file against one the service computed.
#[derive(Debug, Clone, Copy)]
pub struct ConfigDigest([u8; 32]);

impl ConfigDigest {
    /// The digest of `config`, byte for byte: whitespace and comments count.
    pub fn of(config: &[u8]) -> Self {
        Self(Blake2b256::digest(config).into())
    }

    /// A digest read back from an encoding the service wrote or verifies.
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The digest's 32 bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl PartialEq for ConfigDigest {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for ConfigDigest {}

/// The algorithm a config approval is signed with, by its one-byte wire ID.
///
/// ID `00` is never valid. ID `02` is reserved for ECDSA P-256, which the TPM signer will use; it is not a variant
/// until that signer exists, so this build refuses it as unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SignatureAlgorithm {
    /// Ed25519 (RFC 8032), used by the software signer; a signature is exactly 64 bytes.
    Ed25519,
}

/// The wire ID reserved for ECDSA P-256 with SHA-256, the TPM signer's algorithm.
pub const RESERVED_ECDSA_P256_ID: u8 = 0x02;

impl SignatureAlgorithm {
    /// The algorithm's wire ID.
    pub fn id(self) -> u8 {
        match self {
            Self::Ed25519 => 0x01,
        }
    }

    /// The algorithm with wire ID `id`.
    pub fn from_id(id: u8) -> Result<Self, ApprovalDecodeError> {
        match id {
            0x01 => Ok(Self::Ed25519),
            _ => Err(ApprovalDecodeError::UnknownAlgorithm(id)),
        }
    }

    /// Whether `len` is a valid signature length for this algorithm.
    fn accepts_signature_len(self, len: usize) -> bool {
        match self {
            Self::Ed25519 => len == 64,
        }
    }
}

/// What a config approval signs: this vault, a reserved version and the digest of the reviewed config.
///
/// The purpose is not a field: every payload is for [`APPROVAL_PURPOSE`], which the encoding writes and decoding
/// requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalPayload {
    vault_id: VaultId,
    version: ApprovalVersion,
    digest: ConfigDigest,
}

impl ApprovalPayload {
    /// The payload approving the config with `digest` as `version` of vault `vault_id`.
    pub fn new(vault_id: VaultId, version: ApprovalVersion, digest: ConfigDigest) -> Self {
        Self { vault_id, version, digest }
    }

    /// The vault the approval is for.
    pub fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    /// The approval version the service reserved.
    pub fn version(&self) -> ApprovalVersion {
        self.version
    }

    /// The digest of the approved config.
    pub fn digest(&self) -> ConfigDigest {
        self.digest
    }

    /// The exact bytes a signer signs; one payload has one encoding.
    pub fn encode(&self) -> Vec<u8> {
        encoding::encode_payload(self)
    }

    /// The payload `bytes` encode, accepted only in its one canonical form.
    pub fn decode(bytes: &[u8]) -> Result<Self, ApprovalDecodeError> {
        encoding::decode_payload(bytes)
    }
}

/// The contents of `config.toml.sig`: a payload, the algorithm that signed it and the signature.
///
/// It carries no public key: the service verifies against the approver key pinned in protected vault metadata, never
/// a key from the signature file. The signature covers [`ApprovalPayload::encode`], which is the payload's exact bytes
/// in the envelope because decoding accepts only that encoding.
#[derive(Clone, PartialEq, Eq)]
pub struct ApprovalEnvelope {
    algorithm: SignatureAlgorithm,
    payload: ApprovalPayload,
    signature: Vec<u8>,
}

impl ApprovalEnvelope {
    /// An envelope for `payload` signed with `algorithm`, refusing a signature of the wrong length for it.
    pub fn new(algorithm: SignatureAlgorithm, payload: ApprovalPayload, signature: Vec<u8>) -> Result<Self, ApprovalDecodeError> {
        match algorithm.accepts_signature_len(signature.len()) {
            true => Ok(Self { algorithm, payload, signature }),
            false => Err(ApprovalDecodeError::SignatureLength { algorithm, len: signature.len() }),
        }
    }

    /// The algorithm the signature claims; the verifier checks it against the pinned approver's.
    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    /// The signed payload, not yet verified.
    pub fn payload(&self) -> &ApprovalPayload {
        &self.payload
    }

    /// The signature bytes, not yet verified.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// The `config.toml.sig` bytes.
    pub fn encode(&self) -> Vec<u8> {
        encoding::encode_envelope(self)
    }

    /// The envelope `bytes` encode, after the size limit, accepted only in its one canonical form.
    pub fn decode(bytes: &[u8]) -> Result<Self, ApprovalDecodeError> {
        encoding::decode_envelope(bytes)
    }
}

/// Shows the signature's length rather than its bytes, which are long and say nothing to a reader.
impl fmt::Debug for ApprovalEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApprovalEnvelope")
            .field("algorithm", &self.algorithm)
            .field("payload", &self.payload)
            .field("signature_len", &self.signature.len())
            .finish()
    }
}

/// Bytes that are not an approval payload or envelope. No variant carries input bytes.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ApprovalDecodeError {
    /// The envelope is larger than [`MAX_APPROVAL_ENVELOPE_LEN`]; nothing else was read.
    #[error("approval envelope exceeds the {limit}-byte limit")]
    TooLarge {
        /// The limit that was exceeded.
        limit: usize,
    },
    /// The bytes end inside a fixed-width field.
    #[error("approval data is truncated")]
    Truncated,
    /// A length prefix reaches past the end of the bytes.
    #[error("approval data field length runs past the end")]
    LengthPastEnd,
    /// The bytes do not start with the payload or envelope magic.
    #[error("not an approval payload or envelope")]
    BadMagic,
    /// The payload or envelope has a format version this build cannot read.
    #[error("unknown approval format version {0}")]
    UnknownFormatVersion(u8),
    /// The payload names a purpose other than [`APPROVAL_PURPOSE`].
    #[error("approval payload is not for purpose {APPROVAL_PURPOSE}")]
    WrongPurpose,
    /// The vault ID is not a random version 4 UUID.
    #[error(transparent)]
    InvalidVaultId(#[from] VaultIdError),
    /// The payload's approval version is zero, which is never reserved.
    #[error("approval version is zero")]
    ZeroVersion,
    /// The envelope names a signature algorithm this build does not support.
    #[error("unknown signature algorithm ID {0}")]
    UnknownAlgorithm(u8),
    /// The signature's length is wrong for its algorithm.
    #[error("{algorithm:?} signature is {len} bytes")]
    SignatureLength {
        /// The algorithm the envelope names.
        algorithm: SignatureAlgorithm,
        /// The signature's length.
        len: usize,
    },
    /// Bytes follow the last field.
    #[error("approval data has trailing bytes")]
    TrailingBytes,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_zero_is_unrepresentable_and_next_never_wraps() {
        assert_eq!(ApprovalVersion::new(0), None);
        assert_eq!(ApprovalVersion::FIRST.get(), 1);
        assert_eq!(ApprovalVersion::FIRST.next().map(ApprovalVersion::get), Some(2));
        assert_eq!(ApprovalVersion::new(u64::MAX).and_then(ApprovalVersion::next), None);
    }

    #[test]
    fn config_digest_is_blake2b_256() {
        let abc = "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319";
        let hex: String = ConfigDigest::of(b"abc").as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, abc);
    }

    #[test]
    fn config_digest_changes_with_any_byte_including_whitespace() {
        let config = b"[listener.agent]\nbind = \"127.0.0.1:8080\"\n";
        let original = ConfigDigest::of(config);
        assert_eq!(original, ConfigDigest::of(config));
        (0..config.len()).for_each(|at| {
            let mut changed = config.to_vec();
            changed[at] ^= 0x01;
            assert_ne!(ConfigDigest::of(&changed), original, "byte {at}");
        });
        assert_ne!(ConfigDigest::of(&[&config[..], b" "].concat()), original);
        assert_ne!(ConfigDigest::of(&config[..config.len() - 1]), original);
    }

    #[test]
    fn algorithm_ids_round_trip_and_reserved_ids_are_unknown() {
        assert_eq!(SignatureAlgorithm::from_id(SignatureAlgorithm::Ed25519.id()), Ok(SignatureAlgorithm::Ed25519));
        [0x00, RESERVED_ECDSA_P256_ID, 0xff]
            .into_iter()
            .for_each(|id| assert_eq!(SignatureAlgorithm::from_id(id), Err(ApprovalDecodeError::UnknownAlgorithm(id))));
    }
}
