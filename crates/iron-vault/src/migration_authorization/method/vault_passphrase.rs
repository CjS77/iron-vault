//! The v0 source-owner method, the vault passphrase (design/migration-authorization.md, "The v0 method").

use std::future::Future;
use std::sync::Arc;

use iron_vault_store::{CheckUnavailable, Passphrase, PassphraseCheckError};

use super::sealed::Sealed;
use super::{MethodRefusal, MigrationChallenge, OwnerRefusal, SourceOwnerMethod};
use crate::admin::protocol::OwnerInput;
use crate::library_error::LibraryError;

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
    /// The label the audit events' `method` field records.
    pub const LABEL: &'static str = "vault_passphrase";

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

impl Sealed for VaultPassphraseMethod {}

impl SourceOwnerMethod for VaultPassphraseMethod {
    fn label(&self) -> &'static str {
        Self::LABEL
    }

    /// Runs the check on the blocking pool, because scrypt holds a thread for about a second. The task owns the
    /// passphrase, so a future dropped mid-check still drops it when the task ends.
    fn prove(&self, _challenge: &MigrationChallenge, input: OwnerInput) -> impl Future<Output = Result<(), MethodRefusal>> + Send {
        let check = Arc::clone(&self.check);
        let passphrase = input.into_vault_passphrase();
        async move {
            let passphrase = passphrase.ok_or(MethodRefusal::Owner(OwnerRefusal::WrongSecret))?;
            tokio::task::spawn_blocking(move || check(&passphrase).map_err(method_refusal))
                .await
                .unwrap_or_else(|join| {
                    tracing::warn!(error_kind = %join.kind_label(), "the vault passphrase check ended without an answer");
                    Err(MethodRefusal::Unavailable)
                })
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
