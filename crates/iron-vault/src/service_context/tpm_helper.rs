//! The service's side of the TPM signing helper (`design/tpm-approval-signer.md`, "Helper protocol"): one connection per
//! request, one framed request and one framed response, with the helper's 30-second deadline.
//!
//! A [`HelperSession`] holds the owner's PIN until the first request derives the authorization value from it, then only
//! the value, so the PIN is cleared as soon as the value exists.

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use crate::deployment::DeploymentProfile;
use iron_vault_store::{ApproverId, CreatedTpmKey, TpmHelper, TpmHelperFailure};
use iron_vault_tpm_protocol::{
    PUBLIC_KEY_LEN, Request, Response, SIGNATURE_LEN, SignRequest, TpmApprovalPin, TpmAuthValue, TpmKeyBlob, read_frame,
};

/// Where the helper's socket is in a protected install; the helper is offered only while it exists.
pub(super) const SIGNER_SOCKET: &str = "/run/iron-vault-tpm/signer.sock";

/// The helper socket a service of `profile` offers the `tpm` kind through. Only a protected install runs the helper: a
/// development install has no TPM-bound key to protect, and a container has no TPM device.
pub(super) fn offered_socket(profile: DeploymentProfile) -> Option<PathBuf> {
    (profile == DeploymentProfile::Protected).then(|| PathBuf::from(SIGNER_SOCKET))
}

/// How long the service waits for the helper before it reads silence as the helper being unavailable.
const DEADLINE: Duration = Duration::from_secs(30);

/// One enrollment's conversation with the helper.
pub(super) struct HelperSession {
    socket: PathBuf,
    pin: Option<TpmApprovalPin>,
    auth: Option<TpmAuthValue>,
}

impl HelperSession {
    /// A session over the helper at `socket`, authorizing with the key under `pin`.
    pub(super) fn new(socket: PathBuf, pin: TpmApprovalPin) -> Self {
        Self {
            socket,
            pin: Some(pin),
            auth: None,
        }
    }

    /// The authorization value for approver `id`, derived once; the PIN is dropped as the value is made.
    fn auth_for(&mut self, id: &ApproverId) -> Result<TpmAuthValue, TpmHelperFailure> {
        if let Some(pin) = self.pin.take() {
            self.auth = Some(TpmAuthValue::derive(id.as_bytes(), &pin));
        }
        self.auth.clone().ok_or_else(|| unavailable("the authorization value is gone"))
    }

    /// The helper's answer to `request`.
    fn ask(&self, request: &Request) -> Result<Response, TpmHelperFailure> {
        let mut stream = UnixStream::connect(&self.socket).map_err(|e| unavailable(&format!("cannot connect ({})", e.kind())))?;
        stream
            .set_read_timeout(Some(DEADLINE))
            .and_then(|()| stream.set_write_timeout(Some(DEADLINE)))
            .map_err(|e| unavailable(&e.kind().to_string()))?;
        let frame = request.encode().map_err(|e| unavailable(&e.to_string()))?;
        stream
            .write_all(&frame)
            .map_err(|e| unavailable(&format!("cannot send ({})", e.kind())))?;
        let body = read_frame(&mut stream).map_err(|e| unavailable(&format!("no answer ({e})")))?;
        Response::decode(&body).map_err(|e| unavailable(&format!("an answer that does not decode ({e})")))
    }
}

impl TpmHelper for HelperSession {
    fn create(&mut self, id: ApproverId) -> Result<CreatedTpmKey, TpmHelperFailure> {
        let auth = self.auth_for(&id)?;
        match self.ask(&Request::Create { auth })? {
            Response::Created { key, public_key } => Ok(CreatedTpmKey {
                blob: TpmKeyBlob::new(*id.as_bytes(), key),
                public_key,
            }),
            other => Err(refusal(&other)),
        }
    }

    fn sign(
        &mut self,
        blob: &TpmKeyBlob,
        pinned_key: &[u8; PUBLIC_KEY_LEN],
        message: &[u8],
    ) -> Result<[u8; SIGNATURE_LEN], TpmHelperFailure> {
        let id = ApproverId::from_bytes(*blob.approver_id()).map_err(|_| unavailable("the key blob names no approver"))?;
        let request = Request::Sign(SignRequest {
            auth: self.auth_for(&id)?,
            key: blob.key().clone(),
            pinned_key: *pinned_key,
            message: message.to_vec(),
        });
        match self.ask(&request)? {
            Response::Signed { signature } => Ok(signature),
            other => Err(refusal(&other)),
        }
    }
}

fn unavailable(detail: &str) -> TpmHelperFailure {
    TpmHelperFailure(format!("the TPM signing helper is unavailable: {detail}"))
}

/// A helper answer that is not the success the request wanted, named by its status and never by owner input.
fn refusal(response: &Response) -> TpmHelperFailure {
    let status = match response {
        Response::WrongPin => "the TPM refused the authorization value".to_owned(),
        Response::LockedOut { wait_seconds } => format!("the TPM is locked out; try again in {wait_seconds} seconds"),
        Response::NotThisTpm => "not this TPM".to_owned(),
        Response::KeyMismatch => "key mismatch".to_owned(),
        Response::WeakDaSettings => {
            "dictionary-attack settings too weak: the lockout interval is under 600 seconds, or the maximum leaves no share".to_owned()
        }
        Response::RefusedMessage => "refused message".to_owned(),
        Response::TpmError { code } => format!("TPM error {code:#010x}"),
        Response::Malformed => "malformed request".to_owned(),
        Response::Created { .. } | Response::Signed { .. } => "an answer the request did not ask for".to_owned(),
    };
    TpmHelperFailure(format!("the TPM signing helper refused: {status}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_protected_install_offers_the_helper_socket() {
        assert_eq!(offered_socket(DeploymentProfile::Development), None);
        assert_eq!(offered_socket(DeploymentProfile::Container), None);
        assert_eq!(offered_socket(DeploymentProfile::Protected), Some(PathBuf::from(SIGNER_SOCKET)));
    }
}
