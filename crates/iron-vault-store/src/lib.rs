//! Vault identity, recipient envelopes, record files, manifests, approval metadata, durable transactions,
//! recovery, and connector storage.

mod approval;
mod durable;
#[cfg(test)]
mod durable_faults;
mod envelope;
#[cfg(any(test, feature = "test-support"))]
pub mod fault_fs;
mod manifest;
mod passphrase;
mod permitted_origins;
mod recipient;
mod record;
mod recovery;
mod record_id;
#[cfg(test)]
mod secret_types_tests;
mod sealed;
mod stale_temps;
mod stanza;
mod state_dir;
mod state_file_name;
mod store_fs;
#[cfg(test)]
mod test_dir;
mod vault;
mod vault_id;
mod vault_identity;

pub use approval::{
    APPROVAL_PURPOSE, ApprovalDecodeError, ApprovalEnvelope, ApprovalPassphrase, ApprovalPayload, ApprovalSigner, ApprovalState,
    ApprovalStateError, ApprovalVersion, ConfigDigest, MAX_APPROVAL_ENVELOPE_LEN, MAX_APPROVAL_STATE_LEN, PinnedApprover,
    RESERVED_ECDSA_P256_ID, SignError, SignatureAlgorithm, SoftwareSigner, SoftwareSignerKey, VerifiedApproval, VerifyError,
    open_approval_state, open_signer_key, read_signer_key, seal_approval_state, seal_signer_key, verify_approval, write_signer_key,
};
pub use durable::{ReadError, WriteError, WriteStep, durable_remove, durable_replace, read_state_file};
pub use envelope::{
    EnvelopeError, MAX_IDENTITY_ENVELOPE_LEN, read_identity_envelope, stanza_kinds, unwrap_identity, wrap_identity, write_identity_envelope,
};
pub use manifest::{
    MAX_MANIFEST_ENTRIES, MAX_MANIFEST_LEN, ManifestEntry, ManifestError, VaultManifest, open_manifest, record_digest, seal_manifest,
};
pub use passphrase::{
    MAX_PASSPHRASE_ENVELOPE_LEN, MAX_PASSPHRASE_WORK_FACTOR, OperationalIdentity, PASSPHRASE_WORK_FACTOR, Passphrase, PassphraseError,
    UnlockError, open_passphrase_envelope, read_passphrase_envelope, reseal_passphrase_envelope, seal_passphrase_envelope,
    unlock_with_passphrase, write_passphrase_envelope,
};
pub use permitted_origins::{PermittedOrigins, PermittedOriginsError};
pub use recipient::{
    MAX_RECIPIENTS, ParseRecipientIdentityError, ParseRecipientKeyError, RecipientIdentity, RecipientKey, RecipientSet, RecipientSetError,
};
pub use recovery::{RecoveryError, RecoveryKey, RecoveryKeySecret};
pub use record::{CredentialRecord, RecordError, Source, decode, encode};
pub use record_id::{RecordId, RecordIdError};
pub use sealed::{OpenError, SealError, open, seal};
pub use stale_temps::sweep_stale_temps;
pub use stanza::StanzaKind;
pub use state_dir::{LockError, StateDirLock};
pub use state_file_name::{StateFileName, StateFileNameError};
pub use store_fs::{OsFs, StoreFs};
pub use vault::{MAX_RECORD_FILE_LEN, OpenReport, RecordDamage, SharedStateDamage, Vault, VaultError, WriteReport};
pub use vault_id::{VaultId, VaultIdError};
pub use vault_identity::{ParseVaultPublicKeyError, VaultIdentity, VaultPublicKey};
