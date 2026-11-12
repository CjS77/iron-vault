//! Every key initialization generates, before anything is written
//! ([the exchange](../../../../design/vault-initialization.md#the-exchange)).

use std::fmt;

use crate::{
    ApproverId, ApproverPublicKey, OperationalIdentity, RecipientIdentity, RecoveryKey, RecoveryKeySecret, SignError, SoftwareSigner,
    SoftwareSignerKey, VaultId, VaultIdentity,
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
/// It keeps the recovery key's recipient identity, and the host unlock identity when one is enrolled, only for the
/// identity envelope's unwrap check. Every key is dropped when initialization returns, so the service keeps no recovery
/// path it could use by itself ([spec §16](../../../../design/iron-vault-specification.md#16-administration-recovery-and-migration)).
pub struct SealingKeys {
    pub(super) vault: VaultIdentity,
    pub(super) vault_id: VaultId,
    pub(super) operational: RecipientIdentity,
    pub(super) recovery: RecipientIdentity,
    pub(super) host_unlock: Option<RecipientIdentity>,
    pub(super) signer: SoftwareSignerKey,
    pub(super) approver: ApproverPublicKey,
    pub(super) approver_id: ApproverId,
}

impl NewVaultKeys {
    /// Generates the vault identity and ID, the operational identity, the recovery key and the software signer key.
    ///
    /// Fails only when the operating system's random source does.
    pub fn generate() -> Result<Self, SignError> {
        let (signer, approver) = SoftwareSigner::generate()?;
        let (operational, _) = OperationalIdentity::generate();
        let (recovery_secret, recovery) = RecoveryKey::generate_with_identity();
        Ok(Self {
            sealing: SealingKeys {
                vault: VaultIdentity::generate(),
                vault_id: VaultId::new_random(),
                operational,
                recovery,
                host_unlock: None,
                signer,
                approver,
                approver_id: ApproverId::generate(),
            },
            recovery_secret,
        })
    }

    /// Returns the recovery key's secret text, for the service's one reveal to the owner.
    pub fn recovery_secret(&self) -> &RecoveryKeySecret {
        &self.recovery_secret
    }

    /// Drops the recovery key's text, keeping its recipient identity for the unwrap check.
    pub fn into_sealing(self) -> SealingKeys {
        self.sealing
    }
}

impl SealingKeys {
    /// Returns the approver ID the software signer is pinned as. It is chosen before anything is written, so the
    /// service can name it in the first approval's audit records, even when initialization fails after the reservation.
    pub fn approver_id(&self) -> ApproverId {
        self.approver_id
    }

    /// Enrols `host_unlock`, the identity read from the unlock handoff, as a third recipient of the identity envelope,
    /// so a container-profile service can unlock with no owner present
    /// ([spec §17](../../../../design/iron-vault-specification.md#17-docker-remote-servers-and-appliances)). The recovery
    /// key stays a separate recipient, so losing the host's TPM never loses the vault.
    pub fn with_host_unlock(mut self, host_unlock: RecipientIdentity) -> Self {
        self.host_unlock = Some(host_unlock);
        self
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
