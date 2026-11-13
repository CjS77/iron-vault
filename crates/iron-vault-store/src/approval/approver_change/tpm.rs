// SPDX-License-Identifier: MPL-2.0
//! Enrolling a TPM approver for `approver add --kind tpm`
//! ([TPM approval signer, "Enrollment"](../../../../../design/tpm-approval-signer.md#enrollment)). The TPM signing
//! helper makes the key, the service writes its blob as `approver-<approver ID>.tpm`, and the approver is pinned only
//! after the helper has signed a fresh presence payload from that blob and the signature verifies against the new key:
//!
//! ```text
//! helper: create key ─→ write approver-<id>.tpm ─→ read it back ─→ helper: sign presence payload
//!                                                                          │
//!                                       verify against the new key ←───────┘
//!                                                  │
//!                                                  └─→ pin in approval.age  ← commit
//! ```

use iron_vault_tpm_protocol::{MAX_TPM_KEY_BLOB_LEN, PUBLIC_KEY_LEN, SIGNATURE_LEN, TpmKeyBlob};
use thiserror::Error;

use super::{ApproverChangeError, ApproverChanges, KeyCheckError};
use crate::approval::state::ApproverKey;
use crate::approval::verify::verify_p256;
use crate::approval::{
    ApprovalState, ApproverId, ApproverLabel, ApproverPublicKey, PinnedApprover, PresencePayload, SignatureAlgorithm, SignerKind,
};
use crate::durable::{ReadError, durable_replace, read_state_file};
use crate::{StateDirLock, StateFileName, StoreFs, UtcSecond, VaultId};

/// Why the TPM signing helper did not make or use a key: its refusal by status, or that it could not be reached. The
/// message names the status, never anything the owner typed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{message}")]
pub struct TpmHelperFailure {
    /// What the helper said, by status.
    pub message: String,
    /// The whole seconds to wait when the failure is the TPM's lockout, or the
    /// [lockout reserve](../../../../../design/tpm-approval-signer.md#lockout-reserve) withholding the try; `None` for
    /// every other failure.
    pub locked_out_for: Option<u64>,
}

impl TpmHelperFailure {
    /// A failure other than a lockout.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            locked_out_for: None,
        }
    }

    /// The TPM is in lockout, or the reserve withheld the try; the owner waits `wait_seconds`.
    pub fn locked_out(message: impl Into<String>, wait_seconds: u64) -> Self {
        Self {
            message: message.into(),
            locked_out_for: Some(wait_seconds),
        }
    }
}

/// A TPM approval key the helper created.
#[derive(Debug)]
pub struct CreatedTpmKey {
    /// The key's parts, which every signature needs again, kept as the approver's key blob.
    pub blob: TpmKeyBlob,
    /// The key's uncompressed SEC1 point, to pin.
    pub public_key: [u8; PUBLIC_KEY_LEN],
}

/// What an enrollment needs of the TPM signing helper. The service implements it over the helper's socket and holds the
/// owner's PIN; the store never sees the PIN or the authorization value.
pub trait TpmHelper {
    /// Creates a key for the new approver `id` under the owner's PIN.
    fn create(&mut self, id: ApproverId) -> Result<CreatedTpmKey, TpmHelperFailure>;

    /// Signs `message` with the key in `blob`, which must be the one `pinned_key` names.
    fn sign(
        &mut self,
        blob: &TpmKeyBlob,
        pinned_key: &[u8; PUBLIC_KEY_LEN],
        message: &[u8],
    ) -> Result<[u8; SIGNATURE_LEN], TpmHelperFailure>;
}

impl<F: StoreFs> ApproverChanges<'_, F> {
    /// Enrolls a new TPM approver named `label`, with `helper` making its key, and returns the pinned approver.
    ///
    /// It has `helper` create a key under a new approver ID, durably writes the blob as `approver-<id>.tpm`, reads it
    /// back, has `helper` sign a fresh presence payload from the file and verifies that signature against the new key.
    /// Only then does it enroll the approver in `approval.age`, the commit point. A failure before the commit leaves
    /// `state` as it was and at most an orphan blob; the TPM holds nothing to clean up.
    pub fn enroll_tpm_approver(
        &self,
        state: &mut ApprovalState,
        label: ApproverLabel,
        now: UtcSecond,
        helper: &mut impl TpmHelper,
    ) -> Result<PinnedApprover, ApproverChangeError> {
        self.refuse_before_any_file(state)?;
        let id = ApproverId::generate();
        let created = helper.create(id).map_err(ApproverChangeError::TpmHelper)?;
        let key = ApproverPublicKey::new(SignatureAlgorithm::EcdsaP256, created.public_key.to_vec())
            .map_err(ApproverChangeError::ApproverInvalid)?;
        let approver = PinnedApprover::new(id, SignerKind::Tpm, key, label, now).map_err(ApproverChangeError::ApproverInvalid)?;
        let bytes = created
            .blob
            .encode()
            .map_err(|e| ApproverChangeError::TpmHelper(TpmHelperFailure::new(format!("returned an unusable key: {e}"))))?;
        durable_replace(self.lock, self.fs, &StateFileName::tpm_key_blob(id), &bytes).map_err(ApproverChangeError::KeyFile)?;
        self.check_tpm_blob(&approver, state, (&created.public_key, helper))?;
        state
            .enroll_approver(self.lock, self.fs, self.identity, approver.clone())
            .map_err(ApproverChangeError::ApprovalState)?;
        Ok(approver)
    }

    /// Reads the blob back and has the helper sign a fresh presence payload from it, verified against `approver`'s key, so
    /// a pinned TPM approver always has a blob that signs under its PIN.
    fn check_tpm_blob(
        &self,
        approver: &PinnedApprover,
        state: &ApprovalState,
        (pinned_key, helper): (&[u8; PUBLIC_KEY_LEN], &mut impl TpmHelper),
    ) -> Result<(), ApproverChangeError> {
        let check = |error| ApproverChangeError::KeyCheck(error);
        let blob = read_tpm_key_blob(self.lock, self.fs, approver.id()).map_err(|error| check(error.into()))?;
        let message = presence_message(state.vault_id(), approver.id()).map_err(check)?;
        let signature = helper.sign(&blob, pinned_key, &message).map_err(ApproverChangeError::TpmHelper)?;
        match verify_tpm_signature(approver, &message, &signature) {
            true => Ok(()),
            false => Err(check(KeyCheckError::Signature)),
        }
    }
}

/// Why `approver-<id>.tpm` cannot be used as a key blob.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TpmBlobError {
    /// The file cannot be read, or does not exist.
    #[error("it cannot be read: {0}")]
    Read(ReadError),
    /// The file is not a well-formed key blob for the approver.
    #[error("it is not a key blob for the approver")]
    Blob,
}

impl From<TpmBlobError> for KeyCheckError {
    fn from(error: TpmBlobError) -> Self {
        match error {
            TpmBlobError::Read(error) => Self::Read(error),
            TpmBlobError::Blob => Self::Blob,
        }
    }
}

/// Reads the key blob of the TPM approver `id`, `approver-<id>.tpm`, and checks its framing and the approver ID it names.
pub fn read_tpm_key_blob(lock: &StateDirLock, fs: &impl StoreFs, id: ApproverId) -> Result<TpmKeyBlob, TpmBlobError> {
    let bytes = read_state_file(lock, fs, &StateFileName::tpm_key_blob(id), MAX_TPM_KEY_BLOB_LEN as u64).map_err(TpmBlobError::Read)?;
    TpmKeyBlob::decode(&bytes, id.as_bytes()).map_err(|_| TpmBlobError::Blob)
}

/// Builds a [presence payload](../../../../../design/storage-formats.md#presence-payload-v1) for `approver_id` of `vault_id`, with a fresh
/// nonce from the operating system's random source: the bytes the helper signs to prove owner presence. The caller
/// verifies the signature and drops the message.
pub fn presence_message(vault_id: VaultId, approver_id: ApproverId) -> Result<Vec<u8>, KeyCheckError> {
    Ok(PresencePayload::new(vault_id, approver_id, fresh_nonce()?).encode())
}

/// Returns `true` if and only if `signature` (`r ‖ s`) over `message` verifies against the ECDSA P-256 key that `approver`
/// pins. An approver that pins an Ed25519 key always gets `false`.
pub fn verify_tpm_signature(approver: &PinnedApprover, message: &[u8], signature: &[u8]) -> bool {
    match approver.public_key().key() {
        ApproverKey::EcdsaP256 { key, .. } => verify_p256(key, message, signature).is_ok(),
        ApproverKey::Ed25519(_) => false,
    }
}

/// Draws 32 bytes from the operating system's random source, for one presence payload.
fn fresh_nonce() -> Result<[u8; 32], KeyCheckError> {
    let mut nonce = [0; 32];
    getrandom::fill(&mut nonce).map_err(|_| KeyCheckError::Randomness)?;
    Ok(nonce)
}
