//! The pinned approvers: each approval signer the approval state records, with the ID and label it is known by (spec §12,
//! §14).

use std::fmt;

use ed25519_dalek::{SigningKey, VerifyingKey};
use uuid::{Uuid, Variant, Version};

use super::ApprovalStateError;
use crate::approval::SignatureAlgorithm;
use crate::{RecipientLabel, RecipientLabelError, UtcSecond};

/// The most approvers one approval state pins. Each entry is at most 171 bytes, so 16 keep the file well inside
/// [`super::MAX_APPROVAL_STATE_LEN`]; enrolling a seventeenth is refused, so the service never writes a state it cannot
/// read back.
pub const MAX_APPROVERS: usize = 16;

/// The approver ID: a random version 4 UUID naming one pinned approver, generated when it is enrolled and never reused,
/// so a signature by a removed approver can never be read as a later one's. Its text form is the lowercase hyphenated
/// UUID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ApproverId(Uuid);

impl ApproverId {
    /// A fresh ID from the operating system's random source, for an approver being enrolled.
    pub fn generate() -> Self {
        Self(Uuid::new_v4())
    }

    /// The ID from its 16 raw bytes, refusing a UUID that is not a random version 4 UUID.
    pub fn from_bytes(bytes: [u8; 16]) -> Result<Self, ApprovalStateError> {
        let uuid = Uuid::from_bytes(bytes);
        match (uuid.get_version(), uuid.get_variant()) {
            (Some(Version::Random), Variant::RFC4122) => Ok(Self(uuid)),
            _ => Err(ApprovalStateError::InvalidApproverId),
        }
    }

    /// The ID's 16 raw bytes, in the order its text form shows them; approvers are kept in ascending order of these.
    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

impl fmt::Display for ApproverId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0.hyphenated(), f)
    }
}

/// Which kind of approval signer a pinned approver is: what signs for it, and so how the service asks for it. The
/// signature algorithm cannot say this, because a TPM and a hardware key may both sign with P-256.
///
/// Codes 2 (`tpm`) and 3 (`hardware`) are reserved for later epics and are refused on reading, so those epics need no
/// new approval state format version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerKind {
    /// The software signer: an Ed25519 key in its own approver key envelope, opened by its approval passphrase.
    Software,
}

/// The highest signer kind code reserved for a later epic; codes above it are unknown.
const LAST_RESERVED_SIGNER_KIND: u8 = 3;

impl SignerKind {
    /// The kind's code in the approval state payload.
    pub fn code(self) -> u8 {
        match self {
            Self::Software => 1,
        }
    }

    /// The kind with `code`, refusing a reserved or unknown code.
    pub fn from_code(code: u8) -> Result<Self, ApprovalStateError> {
        match code {
            1 => Ok(Self::Software),
            2..=LAST_RESERVED_SIGNER_KIND => Err(ApprovalStateError::ReservedSignerKind(code)),
            _ => Err(ApprovalStateError::UnknownSignerKind(code)),
        }
    }

    /// The name `approver list` prints and the audit log records.
    pub fn name(self) -> &'static str {
        match self {
            Self::Software => "software",
        }
    }

    /// Whether a signer of this kind can sign with `algorithm`.
    pub fn allows(self, algorithm: SignatureAlgorithm) -> bool {
        match self {
            Self::Software => algorithm == SignatureAlgorithm::Ed25519,
        }
    }
}

/// The owner's name for an approval signer, such as `Dave YubiKey 3`, which a prompt shows. It follows the recipient
/// label rule (`design/recipients.md`), so it can neither start a log line nor reorder a prompt. It is never interpreted
/// and need not be unique: nothing looks an approver up by its label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApproverLabel(RecipientLabel);

impl ApproverLabel {
    /// Validates `text` under the recipient label rule.
    pub fn new(text: &str) -> Result<Self, RecipientLabelError> {
        RecipientLabel::new(text).map(Self)
    }

    /// The label text.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for ApproverLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An approval signer's public key, tagged with its algorithm, checked when it is built: a signer reports one before it
/// is enrolled, and an approver holding it always has a usable key, so an unusable key is refused at enrolment, not at
/// the next reload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApproverPublicKey(ApproverKey);

/// A validated public key, tagged with its algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApproverKey {
    /// An Ed25519 key that is a valid, non-weak point.
    Ed25519(VerifyingKey),
}

/// Why a public key cannot be pinned as an approver. Carries no key bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidKeyReason {
    /// The bytes do not decode to a point on the curve.
    NotAPoint,
    /// The key is a small-order point, which strict verification refuses for every signature.
    WeakKey,
}

impl ApproverPublicKey {
    /// The key `public_key` for `algorithm`, refusing a key of the wrong length, a non-point or a weak key.
    pub fn new(algorithm: SignatureAlgorithm, public_key: Vec<u8>) -> Result<Self, ApprovalStateError> {
        match algorithm {
            SignatureAlgorithm::Ed25519 => {
                let bytes: [u8; 32] = public_key
                    .try_into()
                    .map_err(|key: Vec<u8>| ApprovalStateError::PublicKeyLength { algorithm, len: key.len() })?;
                let key = VerifyingKey::from_bytes(&bytes).map_err(|_| invalid(algorithm, InvalidKeyReason::NotAPoint))?;
                match key.is_weak() {
                    true => Err(invalid(algorithm, InvalidKeyReason::WeakKey)),
                    false => Ok(Self(ApproverKey::Ed25519(key))),
                }
            }
        }
    }

    /// The Ed25519 public key of `signing_key`.
    ///
    /// Infallible because an Ed25519 public key is a clamped scalar times the basepoint: clamping makes the scalar a
    /// multiple of the cofactor and the basepoint has prime order, so the result is never a small-order point.
    pub(crate) fn from_signing_key(signing_key: &SigningKey) -> Self {
        Self(ApproverKey::Ed25519(signing_key.verifying_key()))
    }

    /// The algorithm approvals must be signed with.
    pub fn algorithm(&self) -> SignatureAlgorithm {
        match self.0 {
            ApproverKey::Ed25519(_) => SignatureAlgorithm::Ed25519,
        }
    }

    /// The encoded public key.
    pub fn as_bytes(&self) -> &[u8] {
        match &self.0 {
            ApproverKey::Ed25519(key) => key.as_bytes(),
        }
    }

    /// The validated key approvals must verify against.
    pub(crate) fn key(&self) -> &ApproverKey {
        &self.0
    }
}

fn invalid(algorithm: SignatureAlgorithm, reason: InvalidKeyReason) -> ApprovalStateError {
    ApprovalStateError::InvalidApproverKey { algorithm, reason }
}

/// One enrolled approval signer as the approval state records it: its approver ID, signer kind, public key, label and
/// enrolment time. Its kind always allows its key's algorithm.
///
/// A config approval verifies only against a pinned approver's key, never one read from the config or the signature
/// file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedApprover {
    id: ApproverId,
    kind: SignerKind,
    key: ApproverPublicKey,
    label: ApproverLabel,
    enrolled_at: UtcSecond,
}

impl PinnedApprover {
    /// The approver `id`, a `kind` signer with `key`, labelled `label`, enrolled at `enrolled_at`, refusing a kind that
    /// does not allow the key's algorithm. The caller reads the clock; the store never does.
    pub fn new(
        id: ApproverId,
        kind: SignerKind,
        key: ApproverPublicKey,
        label: ApproverLabel,
        enrolled_at: UtcSecond,
    ) -> Result<Self, ApprovalStateError> {
        let algorithm = key.algorithm();
        match kind.allows(algorithm) {
            true => Ok(Self {
                id,
                kind,
                key,
                label,
                enrolled_at,
            }),
            false => Err(ApprovalStateError::KindAlgorithmMismatch { kind, algorithm }),
        }
    }

    /// The approver's ID.
    pub fn id(&self) -> ApproverId {
        self.id
    }

    /// What kind of signer this approver is, which says how the service asks for it.
    pub fn kind(&self) -> SignerKind {
        self.kind
    }

    /// The public key approvals by this approver must verify against.
    pub fn public_key(&self) -> &ApproverPublicKey {
        &self.key
    }

    /// The algorithm this approver signs with.
    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.key.algorithm()
    }

    /// The owner's name for this approver.
    pub fn label(&self) -> &ApproverLabel {
        &self.label
    }

    /// The UTC second this approver was enrolled.
    pub fn enrolled_at(&self) -> UtcSecond {
        self.enrolled_at
    }
}

#[cfg(any(test, feature = "test-support"))]
impl ApproverId {
    /// The approver ID [`PinnedApprover::for_tests`] gives `key`: a version 4 UUID made from the key's first 16 bytes, so
    /// a test signer can name the approver it is pinned as without being told. Only `test-support` exposes it.
    pub fn for_tests(key: &ApproverPublicKey) -> Self {
        let mut bytes = [0; 16];
        bytes.copy_from_slice(&key.as_bytes()[..16]);
        Self(uuid::Builder::from_random_bytes(bytes).into_uuid())
    }
}

#[cfg(any(test, feature = "test-support"))]
impl PinnedApprover {
    /// `key` pinned as [`ApproverId::for_tests`], a software signer with the label `init` gives it, and enrolled at the
    /// epoch: for tests that need an approval state and do not care which approver it names. Only `test-support`
    /// exposes it.
    pub fn for_tests(key: ApproverPublicKey) -> Self {
        Self::software_for_tests(
            ApproverId::for_tests(&key),
            key,
            test_label("approval passphrase"),
            UtcSecond::EPOCH,
        )
    }

    /// A software signer approver from its parts, for tests whose keys are all Ed25519. Only `test-support` exposes it.
    pub fn software_for_tests(id: ApproverId, key: ApproverPublicKey, label: ApproverLabel, enrolled_at: UtcSecond) -> Self {
        Self::new(id, SignerKind::Software, key, label, enrolled_at)
            .unwrap_or_else(|error| unreachable!("a software signer refused its key: {error}"))
    }
}

#[cfg(test)]
impl PinnedApprover {
    /// The approver whose ID, Ed25519 key, label and enrolment time all follow from `seed`, so a test can build the same
    /// approver twice and compare.
    pub(crate) fn from_seed(seed: u8) -> Self {
        let id = ApproverId(uuid::Builder::from_random_bytes([seed; 16]).into_uuid());
        let key = ApproverPublicKey::from_signing_key(&SigningKey::from_bytes(&[seed; 32]));
        let at = UtcSecond::from_unix_seconds(u64::from(seed)).unwrap();
        Self::software_for_tests(id, key, test_label(&format!("approver {seed}")), at)
    }
}

/// A label a test names, which follows the rule by construction.
#[cfg(any(test, feature = "test-support"))]
fn test_label(text: &str) -> ApproverLabel {
    ApproverLabel::new(text).unwrap_or_else(|rule| unreachable!("test label {text:?}: {rule}"))
}
