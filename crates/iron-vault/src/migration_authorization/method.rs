//! Source-owner methods (design/migration-authorization.md, "Source-owner method"): the ways the owner proves authority
//! over the vault identity for one migration challenge, and the one path from such a proof to a
//! [`MigrationAuthorization`].
//!
//! `export` and `recipient add` depend only on [`SourceOwnerMethod`], so the TPM approval-key PIN (EP-33) and a YubiKey
//! touch arrive as further methods without touching either command. v0 has one, [`VaultPassphraseMethod`].

use std::future::Future;
use std::sync::Arc;

use iron_vault_store::{CheckUnavailable, Passphrase, PassphraseCheckError};
use thiserror::Error;

use super::{MigrationAuthorization, MigrationChallenge};
use crate::admin::protocol::OwnerInput;
use crate::admin::unlock::vault_passphrase;

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
pub(crate) async fn prove_challenge<M: SourceOwnerMethod>(
    method: &M,
    challenge: MigrationChallenge,
    input: OwnerInput,
) -> Result<MigrationAuthorization, MethodRefusal> {
    method.prove(&challenge, input).await?;
    Ok(MigrationAuthorization::proved(challenge))
}

/// The check that opens the envelopes on disk with a passphrase and compares the vault identity they hold with the
/// one the service holds.
type PassphraseCheck = dyn Fn(&Passphrase) -> Result<(), PassphraseCheckError> + Send + Sync;

/// The v0 source-owner method: the vault passphrase, read against the envelopes on disk (design: "The v0 method").
///
/// Nothing held in memory counts: every proof opens `operational.age` and `identity.age` again. It has nothing to sign;
/// the challenge it proves is bound by the service, which took it out of the pending slot by its binding digest.
pub struct VaultPassphraseMethod {
    check: Arc<PassphraseCheck>,
}

impl VaultPassphraseMethod {
    /// The method running `check`, which the service context builds over its state directory and the public key of
    /// the vault identity it holds. Only the context makes one, so the check is always the store's.
    pub(crate) fn new(check: impl Fn(&Passphrase) -> Result<(), PassphraseCheckError> + Send + Sync + 'static) -> Self {
        Self { check: Arc::new(check) }
    }
}

impl std::fmt::Debug for VaultPassphraseMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VaultPassphraseMethod")
    }
}

impl sealed::Sealed for VaultPassphraseMethod {}

impl SourceOwnerMethod for VaultPassphraseMethod {
    fn label(&self) -> &'static str {
        "vault_passphrase"
    }

    /// Runs the check on the blocking pool, because scrypt holds a thread for about a second. The task owns the
    /// passphrase, so a future dropped mid-check still drops it when the task ends.
    fn prove(&self, _challenge: &MigrationChallenge, input: OwnerInput) -> impl Future<Output = Result<(), MethodRefusal>> + Send {
        let check = Arc::clone(&self.check);
        let passphrase = vault_passphrase(input);
        async move {
            let passphrase = passphrase.ok_or(MethodRefusal::Owner(OwnerRefusal::WrongSecret))?;
            tokio::task::spawn_blocking(move || check(&passphrase).map_err(method_refusal))
                .await
                .unwrap_or(Err(MethodRefusal::Unavailable))
        }
    }
}

/// The store's answer as a method refusal. An unreadable or damaged envelope is the service's problem, not the owner's,
/// so it is logged for the operator and judges the input neither way.
fn method_refusal(error: PassphraseCheckError) -> MethodRefusal {
    match error {
        PassphraseCheckError::WrongPassphrase => MethodRefusal::Owner(OwnerRefusal::WrongSecret),
        PassphraseCheckError::NotThisVault => MethodRefusal::Owner(OwnerRefusal::NotThisVault),
        PassphraseCheckError::Unavailable(unavailable) => {
            let failure = unavailable_failure(&unavailable);
            tracing::warn!(failure, "the vault passphrase cannot be checked for migration authorization");
            MethodRefusal::Unavailable
        }
    }
}

/// Which part of the vault stopped the check, as a fixed label: the store's error text may carry library text, which
/// a log never formats (`design/audit-logging.md`, "Library errors").
fn unavailable_failure(unavailable: &CheckUnavailable) -> &'static str {
    match unavailable {
        CheckUnavailable::Read(_) => "envelope_unreadable",
        CheckUnavailable::PassphraseEnvelope(_) => "passphrase_envelope_damaged",
        CheckUnavailable::IdentityEnvelope(_) => "identity_envelope_damaged",
    }
}
