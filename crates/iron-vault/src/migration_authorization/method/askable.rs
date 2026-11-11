//! The source-owner methods step 6 of the admin exchange can ask (design/migration-authorization.md, "Which method is
//! asked"): the vault passphrase first, then each `tpm` approver in approver order, in one switchable prompt.

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
    /// A `tpm` approver's TPM approval PIN; boxed, since it holds the approver it asks.
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

/// The methods step 6 asks, in order, and why the vault passphrase was left out, when it was for a cooldown.
#[derive(Debug)]
pub struct AskableMethods {
    asked: Vec<AskableMethod>,
    cooling: Option<AttemptsCoolingDown>,
}

impl AskableMethods {
    /// The vault passphrase, unless the attempt limit is `cooling` down, then `tpm`.
    pub(crate) fn new(passphrase: VaultPassphraseMethod, cooling: Option<AttemptsCoolingDown>, tpm: Vec<TpmApprovalPinMethod>) -> Self {
        let passphrase = cooling.is_none().then_some(AskableMethod::VaultPassphrase(passphrase));
        let asked = passphrase
            .into_iter()
            .chain(tpm.into_iter().map(|method| AskableMethod::TpmPin(Box::new(method))))
            .collect();
        Self { asked, cooling }
    }

    /// The methods to ask, the first asked first; empty when none can be asked.
    pub fn asked(&self) -> &[AskableMethod] {
        &self.asked
    }

    /// The refusal when no method can be asked: the cooldown that left the vault passphrase out, or else unavailable.
    pub fn none_left(&self) -> MigrationRefusal {
        self.cooling
            .map_or(MigrationRefusal::Unavailable, MigrationRefusal::AttemptsCoolingDown)
    }
}
