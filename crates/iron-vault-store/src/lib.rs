//! Vault identity, recipient envelopes, record files, manifests, approval metadata, durable transactions,
//! recovery, and connector storage.

mod approval;
mod config_dir;
#[cfg(test)]
mod config_dir_faults;
mod config_file_name;
mod dir_lock;
mod durable;
#[cfg(test)]
mod durable_faults;
mod envelope;
#[cfg(any(test, feature = "test-support"))]
pub mod fault_fs;
mod mac_file;
mod manifest;
mod partial_restore;
mod passphrase;
mod permitted_origins;
mod recipient;
mod record;
mod record_id;
mod recovery;
mod sealed;
#[cfg(test)]
mod secret_types_tests;
mod stale_temps;
mod stanza;
mod state_dir;
mod state_file_name;
mod state_generation;
mod store_fs;
#[cfg(test)]
mod test_dir;
#[cfg(test)]
mod test_request;
mod vault;
mod vault_id;
mod vault_identity;
mod wire;

#[cfg(any(test, feature = "test-support"))]
pub use approval::seal_signer_key_for_tests;
pub use approval::{
    APPROVAL_PURPOSE, AdmissionPaused, ApprovalDecodeError, ApprovalEnvelope, ApprovalError, ApprovalFailure, ApprovalPassphrase,
    ApprovalPayload, ApprovalProgress, ApprovalRecoveryError, ApprovalSigner, ApprovalState, ApprovalStateError, ApprovalStep,
    ApprovalStorage, ApprovalVersion, CommittedApproval, ConfigDigest, DiscardedFile, InvalidKeyReason, MAX_APPROVAL_ENVELOPE_LEN,
    MAX_APPROVAL_STATE_LEN, PendingConfig, PinnedApprover, PreparedApproval, PublishedPairFault, RESERVED_ECDSA_P256_ID, RecoveredApproval,
    RecoveryFailure, SignError, SignatureAlgorithm, SoftwareSigner, SoftwareSignerKey, VerifiedApproval, VerifyError, open_approval_state,
    open_signer_key, read_signer_key, recover_approval, seal_approval_state, seal_signer_key, verify_approval, write_signer_key,
};
pub use config_dir::{
    ConfigDirLock, ConfigReadError, ConfigWriteError, PublishSet, RemoveStagingError, publish, read_config_file, remove_pending_and_staged,
    sweep_stale_config_temps, write_pending, write_staged,
};
pub use config_file_name::{ConfigFileName, MAX_CONFIG_LEN};
pub use dir_lock::LockError;
pub use durable::{MAX_STATE_FILE_LEN, ReadError, WriteError, WriteStep, durable_remove, durable_replace, read_state_file};
pub use envelope::{
    EnvelopeError, MAX_IDENTITY_ENVELOPE_LEN, read_identity_envelope, stanza_kinds, unwrap_identity, wrap_identity, write_identity_envelope,
};
pub use manifest::{
    MAX_MANIFEST_ENTRIES, MAX_MANIFEST_LEN, ManifestEntry, ManifestError, VaultManifest, open_manifest, record_digest, seal_manifest,
};
pub use partial_restore::PartialRestore;
#[cfg(any(test, feature = "test-support"))]
pub use passphrase::seal_passphrase_envelope_for_tests;
pub use passphrase::{
    MAX_PASSPHRASE_ENVELOPE_LEN, MAX_PASSPHRASE_WORK_FACTOR, OperationalIdentity, PASSPHRASE_WORK_FACTOR, Passphrase, PassphraseError,
    UnlockError, open_passphrase_envelope, read_passphrase_envelope, reseal_passphrase_envelope, seal_passphrase_envelope,
    unlock_with_passphrase, write_passphrase_envelope,
};
pub use permitted_origins::{PermittedOrigins, PermittedOriginsError};
pub use recipient::{
    MAX_RECIPIENTS, ParseRecipientIdentityError, ParseRecipientKeyError, RecipientIdentity, RecipientKey, RecipientSet, RecipientSetError,
};
pub use record::{CredentialRecord, RecordError, ResolvedCredential, Source, decode, encode};
pub use record_id::{RecordId, RecordIdError};
pub use recovery::{RecoveryError, RecoveryKey, RecoveryKeySecret};
pub use sealed::{OpenError, SealError, open, seal};
pub use stale_temps::sweep_stale_temps;
pub use stanza::StanzaKind;
pub use state_dir::StateDirLock;
pub use state_file_name::{StateFileName, StateFileNameError};
pub use state_generation::StateGeneration;
pub use store_fs::{OsFs, StoreFs};
pub use vault::{MAX_RECORD_FILE_LEN, OpenReport, RecordDamage, SharedStateDamage, Vault, VaultError, WriteReport};
pub use vault_id::{VaultId, VaultIdError};
pub use vault_identity::{ParseVaultPublicKeyError, VaultIdentity, VaultPublicKey};
