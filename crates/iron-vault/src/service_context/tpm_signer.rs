//! A TPM approver's key in use (`design/tpm-approval-signer.md`, "Prompt and proof"): owner presence proves the PIN by
//! having the TPM signing helper sign a fresh presence payload, and `config approve` keeps the authorization value that
//! proof used to have the helper sign the approval payload at step 3. Migration authorization proves the PIN the same way
//! over the challenge's migration proof payload.

use std::fmt;
use std::path::PathBuf;

use iron_vault_store::{
    ApprovalEnvelope, ApprovalPayload, ApprovalSigner, ApproverPublicKey, PinnedApprover, SignError, SignatureAlgorithm,
    verify_tpm_signature,
};
use iron_vault_tpm_protocol::{PUBLIC_KEY_LEN, TpmApprovalPin, TpmAuthValue, TpmKeyBlob};

use super::presence::PresenceRefusal;
use super::tpm_helper::{TpmStatus, sign_message};

/// A TPM approver whose PIN the TPM has accepted in this exchange.
///
/// It holds the authorization value, never the PIN, from the presence proof to the end of the approval; the value is
/// cleared on drop and never logged or written.
pub struct TpmSigner {
    socket: PathBuf,
    auth: TpmAuthValue,
    blob: TpmKeyBlob,
    approver: PinnedApprover,
    key: [u8; PUBLIC_KEY_LEN],
}

impl TpmSigner {
    /// Proves `pin` for `approver`: derives the authorization value from it, drops the PIN, has the helper at `socket` sign
    /// `message` (a fresh presence payload or a migration proof payload) with the key in `blob`, and verifies the signature
    /// against the pinned key. Nothing is reserved or written, and a right PIN spends no TPM try.
    pub(super) fn prove(
        socket: PathBuf,
        (blob, approver): (TpmKeyBlob, PinnedApprover),
        message: &[u8],
        pin: TpmApprovalPin,
    ) -> Result<Self, PresenceRefusal> {
        let auth = TpmAuthValue::derive(approver.id().as_bytes(), &pin);
        drop(pin);
        let key: [u8; PUBLIC_KEY_LEN] = approver
            .public_key()
            .as_bytes()
            .try_into()
            .map_err(|_| PresenceRefusal::Unavailable("the pinned TPM key is not a P-256 point".to_owned()))?;
        let signature = sign_message(&socket, (&auth, &blob, &key), message)?;
        match verify_tpm_signature(&approver, message, &signature) {
            true => Ok(Self {
                socket,
                auth,
                blob,
                approver,
                key,
            }),
            false => Err(PresenceRefusal::TpmUnavailable {
                status: TpmStatus::BadSignature,
                message: "the helper's signature does not verify against the pinned key".to_owned(),
            }),
        }
    }
}

impl ApprovalSigner for TpmSigner {
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::EcdsaP256
    }

    fn public_key(&self) -> ApproverPublicKey {
        *self.approver.public_key()
    }

    /// Step 3: has the helper sign the approval payload under the version already reserved. A failure is the signer's, so
    /// the version is consumed.
    fn sign(&self, payload: &ApprovalPayload) -> Result<ApprovalEnvelope, SignError> {
        let signature = sign_message(&self.socket, (&self.auth, &self.blob, &self.key), &payload.encode())
            .map_err(|error| SignError::TpmHelper(error.to_string()))?;
        ApprovalEnvelope::new(SignatureAlgorithm::EcdsaP256, self.approver.id(), *payload, signature.to_vec()).map_err(SignError::Signature)
    }
}

impl fmt::Debug for TpmSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TpmSigner")
            .field("algorithm", &SignatureAlgorithm::EcdsaP256)
            .finish_non_exhaustive()
    }
}
