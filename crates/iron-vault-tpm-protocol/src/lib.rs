//! The TPM signing helper's wire protocol, the TPM key blob, and the TPM approval PIN with the authorization value
//! derived from it (`design/tpm-approval-signer.md`).
//!
//! Both the service and `iron-vault-tpm-signer` use this crate, so it has no TPM dependency: the service never links
//! `tpm2-tss`. It checks framing only; the TPM structures inside a key blob are the helper's to parse.

mod blob;
mod frame;
mod pin;
mod request;
mod response;
#[cfg(test)]
mod tests;
mod wire;

pub use blob::{MAX_TPM_KEY_BLOB_LEN, TpmKeyBlob};
pub use frame::{MAX_FRAME_LEN, read_frame};
pub use pin::{AUTH_VALUE_LEN, MIN_PIN_SCALARS, PinRuleError, TpmApprovalPin, TpmAuthValue};
pub use request::{Request, SignRequest};
pub use response::Response;

/// The length of a pinned TPM approval key: an uncompressed SEC1 P-256 point, `04 ‖ x ‖ y`.
pub const PUBLIC_KEY_LEN: usize = 65;
/// The length of a TPM signature on the wire: `r ‖ s`, each a 32-byte big-endian integer.
pub const SIGNATURE_LEN: usize = 64;
/// The length of an approver ID.
pub const APPROVER_ID_LEN: usize = 16;

/// The three parts of a TPM approval key the TPM hands back at creation, which every signature needs again. None is
/// secret: the private area is wrapped by the parent and loads only on the TPM that made it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmKeyParts {
    /// The transient primary's name: its `nameAlg` and the digest of its public area.
    pub primary_name: Vec<u8>,
    /// The key's marshalled `TPM2B_PUBLIC`.
    pub public: Vec<u8>,
    /// The key's marshalled `TPM2B_PRIVATE`.
    pub private: Vec<u8>,
}

/// Why bytes are not a well-formed helper frame, request, response or key blob.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    /// The frame or blob is longer than its limit; nothing past the length was read.
    #[error("{len} bytes is over the {limit}-byte limit")]
    TooLarge {
        /// The length found.
        len: usize,
        /// The limit it broke.
        limit: usize,
    },
    /// The bytes do not start with the expected magic.
    #[error("wrong magic")]
    WrongMagic,
    /// The format version is not the one this code reads.
    #[error("unsupported format version {0}")]
    UnsupportedVersion(u8),
    /// The request names an operation this code does not know.
    #[error("unknown operation {0:#04x}")]
    UnknownOperation(u8),
    /// The response names a status this code does not know.
    #[error("unknown status {0:#04x}")]
    UnknownStatus(u8),
    /// The bytes end inside a field.
    #[error("truncated")]
    Truncated,
    /// A length prefix is larger than the bytes left.
    #[error("a length prefix runs past the end")]
    LengthPastEnd,
    /// Bytes follow the last field.
    #[error("trailing bytes")]
    TrailingBytes,
    /// The key blob names another approver than the one asked for.
    #[error("the key blob belongs to another approver")]
    ApproverMismatch,
    /// Reading the frame failed.
    #[error("reading the frame failed: {0}")]
    Io(#[from] std::io::Error),
}
