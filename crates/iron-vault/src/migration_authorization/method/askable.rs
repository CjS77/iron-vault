//! The source-owner methods step 6 of the admin exchange can ask
//! ([migration authorization: Which method is asked](../../../../../design/migration-authorization.md#which-method-is-asked)):
//! the vault passphrase first, then each `tpm` approver in approver order, in one prompt the owner can switch between
//! them.
//!
//! For example, with two `tpm` approvers and no cooldown, the prompt offers, in order:
//!
//! ```text
//! Vault passphrase
//! TPM approval PIN for "desk"
//! TPM approval PIN for "laptop"
//! ```
//!
//! During a cooldown the first line is left out. With no `tpm` approver as well, nothing is left to ask, and the
//! exchange ends with `migration-rate-limited`.

use iron_vault_store::ApproverId;

use super::sealed::Sealed;
use super::{MethodRefusal, MigrationChallenge, SourceOwnerMethod, TpmApprovalPinMethod, VaultPassphraseMethod};
use crate::admin::protocol::OwnerInput;
use crate::attempt_limit::AttemptsCoolingDown;
use crate::migration_authorization::MigrationRefusal;

/// One source-owner method this install can ask now.
#[derive(Debug)]
pub enum AskableMethod {
    /// The vault passphrase.
    VaultPassphrase(VaultPassphraseMethod),
    /// A `tpm` approver's TPM approval PIN, boxed because the approver it holds makes it larger than the other
    /// variant.
    TpmPin(Box<TpmApprovalPinMethod>),
}

impl Sealed for AskableMethod {}

impl SourceOwnerMethod for AskableMethod {
    fn label(&self) -> &'static str {
        match self {
            Self::VaultPassphrase(method) => method.label(),
            Self::TpmPin(method) => method.label(),
        }
    }

    fn approver(&self) -> Option<ApproverId> {
        match self {
            Self::VaultPassphrase(method) => method.approver(),
            Self::TpmPin(method) => method.approver(),
        }
    }

    fn attempt_limited(&self) -> bool {
        match self {
            Self::VaultPassphrase(method) => method.attempt_limited(),
            Self::TpmPin(method) => method.attempt_limited(),
        }
    }

    async fn prove(&self, challenge: &MigrationChallenge, input: OwnerInput) -> Result<(), MethodRefusal> {
        match self {
            Self::VaultPassphrase(method) => method.prove(challenge, input).await,
            Self::TpmPin(method) => method.prove(challenge, input).await,
        }
    }
}

/// The methods step 6 asks, in order, and the cooldown that left the vault passphrase out, if one did.
#[derive(Debug)]
pub struct AskableMethods {
    asked: Vec<AskableMethod>,
    cooling: Option<AttemptsCoolingDown>,
}

impl AskableMethods {
    /// Lists the vault passphrase, unless the attempt limit is `cooling` down, then each method in `tpm`, in the order
    /// given.
    pub(crate) fn new(passphrase: VaultPassphraseMethod, cooling: Option<AttemptsCoolingDown>, tpm: Vec<TpmApprovalPinMethod>) -> Self {
        let passphrase = cooling.is_none().then_some(AskableMethod::VaultPassphrase(passphrase));
        let asked = passphrase
            .into_iter()
            .chain(tpm.into_iter().map(|method| AskableMethod::TpmPin(Box::new(method))))
            .collect();
        Self { asked, cooling }
    }

    /// Returns the methods to ask, the first asked first; empty when none can be asked.
    pub fn asked(&self) -> &[AskableMethod] {
        &self.asked
    }

    /// Returns the refusal when no method can be asked: [`MigrationRefusal::AttemptsCoolingDown`] when a cooldown left
    /// the vault passphrase out, and [`MigrationRefusal::Unavailable`] otherwise.
    pub fn none_left(&self) -> MigrationRefusal {
        self.cooling
            .map_or(MigrationRefusal::Unavailable, MigrationRefusal::AttemptsCoolingDown)
    }
}
