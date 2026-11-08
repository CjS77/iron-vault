//! Source-owner methods (design/migration-authorization.md, "Source-owner method"): the ways the owner proves authority
//! over the vault identity for one migration challenge, and the one path from such a proof to a
//! [`MigrationAuthorization`].
//!
//! `export` and `recipient add` depend only on [`SourceOwnerMethod`], so the TPM approval-key PIN (EP-33) and a YubiKey
//! touch arrive as further methods without touching either command. v0 has one, the vault passphrase
//! (`VaultPassphraseMethod`, on Linux).

// The vault passphrase method runs its check on tokio's blocking pool, which this crate has only on Linux.
#[cfg(target_os = "linux")]
mod vault_passphrase;

use std::future::Future;

use thiserror::Error;

#[cfg(target_os = "linux")]
use super::MigrationAuthorization;
use super::MigrationChallenge;
use crate::admin::protocol::OwnerInput;

#[cfg(target_os = "linux")]
pub use vault_passphrase::VaultPassphraseMethod;

/// The owner's input was checked and proves no authority. Only these count toward the passphrase attempt limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum OwnerRefusal {
    /// The secret does not open the enrolled factor: for the vault passphrase, it does not open `operational.age`, or
    /// the input is empty or not UTF-8.
    #[error("the secret is wrong")]
    WrongSecret,
    /// The factor opened, but to a vault identity other than the one the service holds.
    #[error("the factor is not this vault's")]
    NotThisVault,
}

impl OwnerRefusal {
    /// The label the audit events' `refusal` field records. The design names a wrong secret `wrong_passphrase`, its one
    /// v0 form; a method with another secret chooses its label when it lands.
    pub fn label(self) -> &'static str {
        match self {
            Self::WrongSecret => "wrong_passphrase",
            Self::NotThisVault => "not_this_vault",
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
}

mod sealed {
    /// Keeps [`SourceOwnerMethod`](super::SourceOwnerMethod) implementable only inside this crate, so code outside it
    /// cannot write a "method" that proves every challenge.
    pub trait Sealed {}
}

/// A way to prove authority over the vault identity through a factor already enrolled for this vault (glossary:
/// *Source-owner method*). The service runs it itself, for one challenge it has taken out of the pending slot.
pub trait SourceOwnerMethod: sealed::Sealed + Sync {
    /// The stable label the audit events' `method` field records.
    fn label(&self) -> &'static str;

    /// Proves `challenge` with the owner's `input`, which the method drops, and so clears, before it returns.
    fn prove(&self, challenge: &MigrationChallenge, input: OwnerInput) -> impl Future<Output = Result<(), MethodRefusal>> + Send;
}

/// Runs `method` on `challenge` and, only when it proves it, makes the authorization that carries the challenge: the one
/// path to a [`MigrationAuthorization`]. A refused challenge is dropped here, so it can never be proved again.
// Only the Linux-only service context's migration session proves a challenge.
#[cfg(target_os = "linux")]
pub(crate) async fn prove_challenge<M: SourceOwnerMethod>(
    method: &M,
    challenge: MigrationChallenge,
    input: OwnerInput,
) -> Result<MigrationAuthorization, MethodRefusal> {
    method.prove(&challenge, input).await?;
    Ok(MigrationAuthorization::proved(challenge))
}
