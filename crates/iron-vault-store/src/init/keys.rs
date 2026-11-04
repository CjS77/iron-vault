//! Every key initialization generates, before anything is written (design/vault-initialization.md, "The exchange").

use std::fmt;

use crate::{
    OperationalIdentity, PinnedApprover, RecipientIdentity, RecoveryKey, RecoveryKeySecret, SignError, SoftwareSigner, SoftwareSignerKey,
    VaultIdentity,
};

/// The keys of a vault not yet written, with the recovery key's text for the one reveal.
///
/// Generating them all first means the recovery key the owner saves is the key that will be enrolled. It has no
/// `Clone`, and its `Debug` shows nothing of any key.
pub struct NewVaultKeys {
    sealing: SealingKeys,
    recovery_secret: RecoveryKeySecret,
}

/// The keys initialization writes with, once the recovery key's text is gone: what [`crate::initialize`] takes.
///
/// It keeps the recovery key's recipient identity only for the identity envelope's unwrap check, and every key is
/// dropped when initialization returns, so the service keeps no recovery path it could use by itself (spec §3.13).
pub struct SealingKeys {
    pub(super) vault: VaultIdentity,
    pub(super) operational: RecipientIdentity,
    pub(super) recovery: RecipientIdentity,
    pub(super) signer: SoftwareSignerKey,
    pub(super) approver: PinnedApprover,
}

impl NewVaultKeys {
    /// Generates the vault identity, the operational identity, the recovery key and the software signer key.
    ///
    /// Fails only when the operating system's random source does.
    pub fn generate() -> Result<Self, SignError> {
        let (signer, approver) = SoftwareSigner::generate()?;
        let (operational, _) = OperationalIdentity::generate();
        let (recovery_secret, recovery) = RecoveryKey::generate_with_identity();
        Ok(Self {
            sealing: SealingKeys {
                vault: VaultIdentity::generate(),
                operational,
                recovery,
                signer,
                approver,
            },
            recovery_secret,
        })
    }

    /// The recovery key's secret text, for the service's one reveal to the owner.
    pub fn recovery_secret(&self) -> &RecoveryKeySecret {
        &self.recovery_secret
    }

    /// Drops the recovery key's text, keeping its recipient identity for the unwrap check.
    pub fn into_sealing(self) -> SealingKeys {
        self.sealing
    }
}

impl fmt::Debug for NewVaultKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NewVaultKeys([REDACTED])")
    }
}

impl fmt::Debug for SealingKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SealingKeys([REDACTED])")
    }
}
