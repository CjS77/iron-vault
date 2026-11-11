//! Enrolling a TPM approver (`design/tpm-approval-signer.md`, "Enrollment"): the TPM signing helper makes the key, the
//! service writes its blob as `approver-<approver ID>.tpm`, and the approver is pinned only after the helper has signed a
//! fresh presence payload from that blob and the signature verifies against the new key.

use iron_vault_tpm_protocol::{MAX_TPM_KEY_BLOB_LEN, PUBLIC_KEY_LEN, SIGNATURE_LEN, TpmKeyBlob};
use thiserror::Error;

use super::{ApproverChangeError, ApproverChanges, KeyCheckError};
use crate::approval::state::ApproverKey;
use crate::approval::verify::verify_p256;
use crate::approval::{
    ApprovalState, ApproverId, ApproverLabel, ApproverPublicKey, PinnedApprover, PresencePayload, SignatureAlgorithm, SignerKind,
};
use crate::durable::{durable_replace, read_state_file};
use crate::{StateFileName, StoreFs, UtcSecond};

/// Why the TPM signing helper did not make or use a key: its refusal by status, or that it could not be reached. The text
/// names the status and never anything the owner typed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{0}")]
pub struct TpmHelperFailure(pub String);

/// A TPM approval key the helper created.
#[derive(Debug)]
pub struct CreatedTpmKey {
    /// The key's parts, which every signature needs again; kept as the approver's key blob.
    pub blob: TpmKeyBlob,
    /// The key's uncompressed SEC1 point, to pin.
    pub public_key: [u8; PUBLIC_KEY_LEN],
}

/// What an enrollment needs of the TPM signing helper. The service implements it over the helper's socket, holding the
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
    /// Has `helper` create a key under a new approver ID, durably writes the blob as `approver-<id>.tpm`, reads it back and
    /// has `helper` sign a fresh presence payload from the file, verified against the new key, and only then enrolls the
    /// approver in `approval.age`: the commit point. A failure before it leaves `state` as it was and at most an orphan
    /// blob; the TPM holds nothing to clean up.
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
            .map_err(|e| ApproverChangeError::TpmHelper(TpmHelperFailure(format!("returned an unusable key: {e}"))))?;
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
        let file = StateFileName::tpm_key_blob(approver.id());
        let bytes = read_state_file(self.lock, self.fs, &file, MAX_TPM_KEY_BLOB_LEN as u64).map_err(|e| check(KeyCheckError::Read(e)))?;
        let blob = TpmKeyBlob::decode(&bytes, approver.id().as_bytes()).map_err(|_| check(KeyCheckError::Blob))?;
        let message = PresencePayload::new(state.vault_id(), approver.id(), fresh_nonce()?).encode();
        let signature = helper.sign(&blob, pinned_key, &message).map_err(ApproverChangeError::TpmHelper)?;
        match approver.public_key().key() {
            ApproverKey::EcdsaP256 { key, .. } => verify_p256(key, &message, &signature).map_err(|_| check(KeyCheckError::Signature)),
            ApproverKey::Ed25519(_) => Err(check(KeyCheckError::Signature)),
        }
    }
}

/// 32 bytes from the operating system's random source, for one presence payload.
fn fresh_nonce() -> Result<[u8; 32], ApproverChangeError> {
    let mut nonce = [0; 32];
    getrandom::fill(&mut nonce).map_err(|_| ApproverChangeError::KeyCheck(KeyCheckError::Randomness))?;
    Ok(nonce)
}
