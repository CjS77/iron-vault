//! Source-owner methods
//! ([migration authorization: Source-owner method](../../../../design/migration-authorization.md#source-owner-method)):
//! the ways the owner proves authority over the vault identity for one migration challenge, and the one path from such a
//! proof to a [`MigrationAuthorization`].
//!
//! `export` and `recipient add` depend only on [`SourceOwnerMethod`], so a later factor, such as a YubiKey touch, arrives
//! as one more method without a change to either command. v0 has two, on Linux: the vault passphrase
//! (`VaultPassphraseMethod`) and a `tpm` approver's TPM approval PIN (`TpmApprovalPinMethod`). Step 6 of the admin
//! exchange offers them as [`AskableMethod`]s, and `prove_challenge` runs the one the owner answered.

// Both methods run their check on tokio's blocking pool, which this crate has only on Linux.
#[cfg(target_os = "linux")]
mod askable;
#[cfg(target_os = "linux")]
mod tpm_pin;
#[cfg(target_os = "linux")]
mod vault_passphrase;

use std::future::Future;

use iron_vault_store::ApproverId;
use thiserror::Error;

#[cfg(target_os = "linux")]
use super::MigrationAuthorization;
use super::MigrationChallenge;
use crate::admin::protocol::OwnerInput;

#[cfg(target_os = "linux")]
pub use askable::{AskableMethod, AskableMethods};
#[cfg(target_os = "linux")]
pub use tpm_pin::TpmApprovalPinMethod;
#[cfg(target_os = "linux")]
pub use vault_passphrase::VaultPassphraseMethod;

/// The owner's input was checked and proves no authority. Each such refusal of the vault passphrase counts toward the
/// passphrase attempt limit; the TPM counts a wrong PIN itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum OwnerRefusal {
    /// The secret does not open the enrolled factor: for the vault passphrase, it does not open `operational.age`, or
    /// the input is empty or not UTF-8.
    #[error("the secret is wrong")]
    WrongSecret,
    /// The factor opened, but to a vault identity other than the one the service holds.
    #[error("the factor is not this vault's")]
    NotThisVault,
    /// The TPM refused the authorization value the PIN made, or the input is empty or not UTF-8.
    #[error("the TPM approval PIN is wrong")]
    WrongPin,
}

impl OwnerRefusal {
    /// Returns the label the audit events' `refusal` field records: `wrong_passphrase`, `not_this_vault` or
    /// `wrong_pin`.
    pub fn label(self) -> &'static str {
        match self {
            Self::WrongSecret => "wrong_passphrase",
            Self::NotThisVault => "not_this_vault",
            Self::WrongPin => "wrong_pin",
        }
    }
}

/// Why a source-owner method did not prove a challenge. The messages hold nothing the owner typed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum MethodRefusal {
    /// The owner's input proves no authority.
    #[error(transparent)]
    Owner(OwnerRefusal),
    /// The factor could not be checked, so the input was judged neither way.
    #[error("the source-owner factor cannot be checked")]
    Unavailable,
    /// The TPM is in dictionary-attack lockout, or the helper's lockout reserve withheld the try; nothing was tried.
    #[error("the TPM is locked out; try again in {wait_seconds} seconds")]
    TpmLockedOut {
        /// The whole seconds to wait.
        wait_seconds: u64,
    },
    /// The TPM signing helper refused for a reason other than the PIN or a lockout, could not be reached, or signed with
    /// another key, so the PIN was judged neither way.
    #[error("the TPM approver cannot be checked: the helper answered {status}")]
    TpmUnavailable {
        /// The helper's status, as the audit log's `tpm_status` labels it.
        status: &'static str,
    },
}

mod sealed {
    /// Keeps [`SourceOwnerMethod`](super::SourceOwnerMethod) implementable only inside this crate, so code outside it
    /// cannot write a "method" that proves every challenge.
    pub trait Sealed {}
}

/// A way to prove authority over the vault identity through a factor already enrolled for this vault
/// ([glossary: *Source-owner method*](../../../../design/glossary.md#terms)). The service runs it itself, for one challenge it has
/// taken out of the pending slot.
pub trait SourceOwnerMethod: sealed::Sealed + Sync {
    /// Returns the stable label the audit events' `method` field records.
    fn label(&self) -> &'static str;

    /// Returns the pinned approver whose key proves the challenge, which the audit events record as `approver_id`, or
    /// `None` for a method that uses no approver's key.
    fn approver(&self) -> Option<ApproverId> {
        None
    }

    /// Returns `true` if and only if the passphrase attempt limit bounds this method. Only the vault passphrase returns
    /// `true`: a hardware method is bounded by its device's own lockout, and the service adds no limit of its own.
    fn attempt_limited(&self) -> bool {
        false
    }

    /// Proves `challenge` with the owner's `input`, which the method drops, and so clears, before it returns.
    fn prove(&self, challenge: &MigrationChallenge, input: OwnerInput) -> impl Future<Output = Result<(), MethodRefusal>> + Send;
}

/// Runs `method` on `challenge` and, only when it proves it, makes the authorization that carries the challenge. This is
/// the one path to a [`MigrationAuthorization`]. A refused challenge is dropped here, so it can never be proved again.
// Only the Linux-only service context's migration session proves a challenge.
#[cfg(target_os = "linux")]
pub(crate) async fn prove_challenge<M: SourceOwnerMethod>(
    method: &M,
    challenge: MigrationChallenge,
    input: OwnerInput,
) -> Result<MigrationAuthorization, MethodRefusal> {
    method.prove(&challenge, input).await?;
    Ok(MigrationAuthorization::proved(challenge, super::MethodName::of(method)))
}
