// SPDX-License-Identifier: MPL-2.0
//! Talks to the TPM signing helper
//! ([TPM approval signer: Helper protocol](../../../../design/tpm-approval-signer.md#helper-protocol)), the separate
//! process that reaches the TPM, so the service never does: one connection per request, one framed request and one
//! framed response, with the helper's 30-second deadline.
//!
//! A [`HelperSession`] holds the owner's PIN until the first request derives the authorization value from it, then only
//! the value, so the PIN is cleared as soon as the value exists.

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::deployment::DeploymentProfile;
use iron_vault_store::{ApproverId, CreatedTpmKey, TpmHelper, TpmHelperFailure};
use iron_vault_tpm_protocol::{
    PUBLIC_KEY_LEN, Request, Response, SIGNATURE_LEN, SignRequest, TpmApprovalPin, TpmAuthValue, TpmKeyBlob, read_frame,
};

/// The path of the helper's socket in a protected install; the helper is offered only while it exists.
pub(super) const SIGNER_SOCKET: &str = "/run/iron-vault-tpm/signer.sock";

/// Returns the helper socket a service of `profile` offers the `tpm` kind through, or `None` for a profile with no
/// helper. Only a protected install runs the helper: a development install has no TPM-bound key to protect, and a
/// container has no TPM device.
pub(super) fn offered_socket(profile: DeploymentProfile) -> Option<PathBuf> {
    (profile == DeploymentProfile::Protected).then(|| PathBuf::from(SIGNER_SOCKET))
}

/// How long the service waits for the helper before it reads silence as the helper being unavailable.
const DEADLINE: Duration = Duration::from_secs(30);

/// The helper's answer, or the lack of one, named for the audit log's `tpm_status` field. Never owner input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmStatus {
    /// The TPM refused the authorization value (helper status `02`).
    WrongPin,
    /// The TPM is in lockout, or the lockout reserve withheld the try (`03`).
    LockedOut,
    /// The key blob belongs to another TPM, or this one after a clear (`04`).
    NotThisTpm,
    /// The loaded key is not the pinned key (`05`).
    KeyMismatch,
    /// The TPM's dictionary-attack settings are too weak to limit guessing (`06`).
    WeakDaSettings,
    /// The message is none of the three the helper signs (`07`).
    RefusedMessage,
    /// Any other TPM failure (`08`).
    TpmError,
    /// The request did not decode (`09`).
    Malformed,
    /// The helper could not be reached, or its answer was not one the request asked for.
    Unreachable,
    /// The helper signed, but the signature does not verify against the pinned key.
    BadSignature,
}

impl TpmStatus {
    /// Returns the snake_case label audit events record, such as `not_this_tpm`.
    pub const fn label(self) -> &'static str {
        match self {
            Self::WrongPin => "wrong_pin",
            Self::LockedOut => "locked_out",
            Self::NotThisTpm => "not_this_tpm",
            Self::KeyMismatch => "key_mismatch",
            Self::WeakDaSettings => "weak_da_settings",
            Self::RefusedMessage => "refused_message",
            Self::TpmError => "tpm_error",
            Self::Malformed => "malformed",
            Self::Unreachable => "unreachable",
            Self::BadSignature => "bad_signature",
        }
    }
}

/// Why a helper request did not return what it asked for. The text names the status and never anything the owner typed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(super) enum HelperError {
    /// The TPM refused the authorization value; one try is spent.
    #[error("the TPM signing helper refused: the TPM refused the authorization value")]
    WrongPin,
    /// The TPM is in lockout, or the reserve withheld the try.
    #[error("the TPM signing helper refused: the TPM is locked out; try again in {wait_seconds} seconds")]
    LockedOut {
        /// The number of whole seconds to wait.
        wait_seconds: u64,
    },
    /// Any other refusal, or no usable answer.
    #[error("{message}")]
    Failed {
        /// The status the audit log names.
        status: TpmStatus,
        /// What to tell the owner.
        message: String,
    },
}

impl From<HelperError> for TpmHelperFailure {
    fn from(error: HelperError) -> Self {
        match error {
            HelperError::LockedOut { wait_seconds } => Self::locked_out(error.to_string(), wait_seconds),
            other => Self::new(other.to_string()),
        }
    }
}

/// Sends `request` over a fresh connection to the socket at `socket` and returns the helper's answer.
fn ask(socket: &Path, request: &Request) -> Result<Response, HelperError> {
    let mut stream = UnixStream::connect(socket).map_err(|e| unavailable(&format!("cannot connect ({})", e.kind())))?;
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

/// Has the helper at `socket` sign `message` with the key in `blob` under `auth`.
///
/// Blocks until the helper answers or the deadline passes, so an async caller runs it on the blocking pool; the
/// approval transaction's step 3 calls it directly, a moment after step 2 proved the same value.
pub(super) fn sign_message(
    socket: &Path,
    (auth, blob, pinned_key): (&TpmAuthValue, &TpmKeyBlob, &[u8; PUBLIC_KEY_LEN]),
    message: &[u8],
) -> Result<[u8; SIGNATURE_LEN], HelperError> {
    let request = Request::Sign(SignRequest {
        auth: auth.clone(),
        key: blob.key().clone(),
        pinned_key: *pinned_key,
        message: message.to_vec(),
    });
    match ask(socket, &request)? {
        Response::Signed { signature } => Ok(signature),
        other => Err(refusal(&other)),
    }
}

/// One enrollment's conversation with the helper.
pub(super) struct HelperSession {
    socket: PathBuf,
    pin: Option<TpmApprovalPin>,
    auth: Option<TpmAuthValue>,
}

impl HelperSession {
    /// Starts a session over the helper at `socket`, authorizing with the key under `pin`.
    pub(super) fn new(socket: PathBuf, pin: TpmApprovalPin) -> Self {
        Self {
            socket,
            pin: Some(pin),
            auth: None,
        }
    }

    /// Returns the authorization value for approver `id`, derived once; the PIN is dropped as the value is made.
    fn auth_for(&mut self, id: &ApproverId) -> Result<TpmAuthValue, TpmHelperFailure> {
        if let Some(pin) = self.pin.take() {
            self.auth = Some(TpmAuthValue::derive(id.as_bytes(), &pin));
        }
        self.auth
            .clone()
            .ok_or_else(|| unavailable("the authorization value is gone").into())
    }
}

impl TpmHelper for HelperSession {
    fn create(&mut self, id: ApproverId) -> Result<CreatedTpmKey, TpmHelperFailure> {
        let auth = self.auth_for(&id)?;
        match ask(&self.socket, &Request::Create { auth })? {
            Response::Created { key, public_key } => Ok(CreatedTpmKey {
                blob: TpmKeyBlob::new(*id.as_bytes(), key),
                public_key,
            }),
            other => Err(refusal(&other).into()),
        }
    }

    fn sign(
        &mut self,
        blob: &TpmKeyBlob,
        pinned_key: &[u8; PUBLIC_KEY_LEN],
        message: &[u8],
    ) -> Result<[u8; SIGNATURE_LEN], TpmHelperFailure> {
        let id = ApproverId::from_bytes(*blob.approver_id()).map_err(|_| unavailable("the key blob names no approver"))?;
        let auth = self.auth_for(&id)?;
        Ok(sign_message(&self.socket, (&auth, blob, pinned_key), message)?)
    }
}

fn unavailable(detail: &str) -> HelperError {
    HelperError::Failed {
        status: TpmStatus::Unreachable,
        message: format!("the TPM signing helper is unavailable: {detail}"),
    }
}

/// Maps a helper answer that is not the success the request wanted to the error it means.
fn refusal(response: &Response) -> HelperError {
    let failed = |status, text: &str| HelperError::Failed {
        status,
        message: format!("the TPM signing helper refused: {text}"),
    };
    match response {
        Response::WrongPin => HelperError::WrongPin,
        Response::LockedOut { wait_seconds } => HelperError::LockedOut {
            wait_seconds: *wait_seconds,
        },
        Response::NotThisTpm => failed(TpmStatus::NotThisTpm, "not this TPM"),
        Response::KeyMismatch => failed(TpmStatus::KeyMismatch, "key mismatch"),
        Response::WeakDaSettings => failed(
            TpmStatus::WeakDaSettings,
            "dictionary-attack settings too weak: the lockout interval is under 600 seconds, or the maximum leaves no share",
        ),
        Response::RefusedMessage => failed(TpmStatus::RefusedMessage, "refused message"),
        Response::TpmError { code } => failed(TpmStatus::TpmError, &format!("TPM error {code:#010x}")),
        Response::Malformed => failed(TpmStatus::Malformed, "malformed request"),
        Response::Created { .. } | Response::Signed { .. } => failed(TpmStatus::Unreachable, "an answer the request did not ask for"),
    }
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
