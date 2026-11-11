//! The TPM approval-key PIN as a source-owner method (design/tpm-approval-signer.md, "Migration";
//! design/migration-authorization.md, "Source-owner method").

use std::future::Future;
use std::sync::Arc;

use iron_vault_store::{ApproverId, MigrationProofPayload, PinnedApprover};
use iron_vault_tpm_protocol::TpmApprovalPin;

use super::sealed::Sealed;
use super::{MethodRefusal, MigrationChallenge, OwnerRefusal, SourceOwnerMethod};
use crate::admin::protocol::OwnerInput;
use crate::library_error::LibraryError;

/// The proof a TPM approver gives: derive the authorization value from the PIN, have the TPM signing helper sign the
/// message with the approver's key, and verify the signature against the pinned key. It blocks on the helper.
type PinProof = dyn Fn(TpmApprovalPin, &[u8]) -> Result<(), MethodRefusal> + Send + Sync;

/// A `tpm` approver's TPM approval PIN, proving a challenge by having the TPM sign its migration proof payload (`IVMA`).
///
/// The TPM signs the payload that wraps the challenge's binding digest, never the bare digest, so no earlier approval
/// or presence signature, and no signature over another challenge, proves this one. The PIN is never cached: each proof
/// derives the authorization value afresh and drops it, and the TPM's own lockout bounds guessing.
pub struct TpmApprovalPinMethod {
    approver: PinnedApprover,
    proof: Arc<PinProof>,
}

impl TpmApprovalPinMethod {
    /// The label the audit events' `method` field records.
    pub const LABEL: &'static str = "tpm_pin";

    /// The method for `approver`, proving with `proof`, which the service context builds over the helper's socket and
    /// the approver's key blob. Only the context makes one, so the proof is always the helper's.
    pub(crate) fn new(
        approver: PinnedApprover,
        proof: impl Fn(TpmApprovalPin, &[u8]) -> Result<(), MethodRefusal> + Send + Sync + 'static,
    ) -> Self {
        Self {
            approver,
            proof: Arc::new(proof),
        }
    }

    /// The `tpm` approver whose PIN this method asks for.
    pub fn pinned(&self) -> &PinnedApprover {
        &self.approver
    }
}

impl std::fmt::Debug for TpmApprovalPinMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TpmApprovalPinMethod")
            .field("approver", &self.approver.id())
            .finish()
    }
}

impl Sealed for TpmApprovalPinMethod {}

impl SourceOwnerMethod for TpmApprovalPinMethod {
    fn label(&self) -> &'static str {
        Self::LABEL
    }

    fn approver(&self) -> Option<ApproverId> {
        Some(self.approver.id())
    }

    /// Runs the proof on the blocking pool, because the helper answers over a socket and a TPM signature takes a while.
    /// An answer that is not UTF-8, or shorter than any enrolled PIN, is a wrong PIN and never reaches the TPM, so it spends
    /// no lockout try.
    fn prove(&self, challenge: &MigrationChallenge, input: OwnerInput) -> impl Future<Output = Result<(), MethodRefusal>> + Send {
        let proof = Arc::clone(&self.proof);
        let message = MigrationProofPayload::new(*challenge.binding_digest().as_bytes()).encode();
        let pin = pin_of(input);
        async move {
            let pin = pin.ok_or(MethodRefusal::Owner(OwnerRefusal::WrongPin))?;
            tokio::task::spawn_blocking(move || proof(pin, &message))
                .await
                .unwrap_or_else(|join| {
                    tracing::warn!(error_kind = %join.kind_label(), "the TPM approval PIN check ended without an answer");
                    Err(MethodRefusal::Unavailable)
                })
        }
    }
}

/// The owner's input as a PIN; the input's buffer is cleared when it drops here.
fn pin_of(input: OwnerInput) -> Option<TpmApprovalPin> {
    TpmApprovalPin::answered(std::str::from_utf8(input.expose_secret()).ok()?)
}
