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
mod error_kind;
mod export_identity;
mod export_snapshot;
#[cfg(any(test, feature = "test-support"))]
pub mod fault_fs;
mod import;
mod import_check;
mod init;
mod initialization;
mod inventory_check;
mod mac_file;
mod manifest;
pub mod migration_bundle;
mod owner_lock;
mod partial_restore;
mod passphrase;
mod permitted_origins;
mod recipient;
mod recipient_inventory;
mod record;
mod record_id;
mod recovery;
mod recovery_check;
mod recovery_record;
mod reset;
mod rewrap;
mod sealed;
#[cfg(test)]
mod secret_types_tests;
mod stale_temps;
mod stanza;
mod state_dir;
mod state_file_name;
mod state_generation;
mod store_fs;
mod store_owned;
#[cfg(test)]
mod test_dir;
#[cfg(test)]
mod test_request;
#[cfg(test)]
mod test_vault;
mod vault;
mod vault_id;
mod vault_identity;
mod wire;

#[cfg(any(test, feature = "test-support"))]
pub use approval::seal_signer_key_for_tests;
pub use approval::{
    APPROVAL_PURPOSE, AdmissionPaused, ApprovalDecodeError, ApprovalEnvelope, ApprovalError, ApprovalFailure, ApprovalPassphrase,
    ApprovalPayload, ApprovalProgress, ApprovalRecoveryError, ApprovalSigner, ApprovalState, ApprovalStateError, ApprovalStep,
    ApprovalStorage, ApprovalVersion, ApproverChangeError, ApproverChangeStep, ApproverChanges, ApproverId, ApproverLabel,
    ApproverPublicKey, CommittedApproval, ConfigDigest, CreatedTpmKey, DiscardedFile, InvalidKeyReason, KeyCheckError, KeyFileOutcome,
    MAX_APPROVAL_ENVELOPE_LEN, MAX_APPROVAL_STATE_LEN, MAX_APPROVERS, MayHaveCommitted, MigrationProofPayload, PendingConfig,
    PinnedApprover, PreparedApproval, PresencePayload, PublishedPairFault, ReadBack, RecoveredApproval, RecoveryFailure, ReservedApproval,
    SignError, SignatureAlgorithm, SignerKind, SoftwareSigner, SoftwareSignerKey, TpmBlobError, TpmHelper, TpmHelperFailure,
    VerifiedApproval, VerifyError, open_approval_state, open_signer_key, presence_message, read_signer_key, read_tpm_key_blob,
    recover_approval, seal_approval_state, seal_signer_key, verify_approval, verify_tpm_signature, write_signer_key,
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
pub use error_kind::ErrorKindLabel;
pub use export_identity::{
    BundledApproverKeyError, ExportPassphrase, check_approver_key_form, open_bundled_approver_key, open_exported_identity,
    seal_bundled_approver_key, seal_exported_identity,
};
pub use export_snapshot::{
    ExportedBundle, SnapshotDamage, SnapshotError, SnapshotStep, SnapshotSummary, check_config_digest, check_export_snapshot,
    check_record_digest, stream_export_snapshot,
};
pub use import::{ImportError, ImportFailure, ImportKeys, ImportProgress, ImportStep, ImportedVault, import_vault};
pub use import_check::{BundleCheckError, ControlFiles, OpenBundleError, OpenedBundle, VerifiedBundle, open_bundle, verify_bundle};
pub use init::{
    FirstApproval, InitError, InitFailure, InitPassphrases, InitPassphrasesError, InitStep, InitializedVault, MIN_PASSPHRASE_CHARS,
    NewVaultKeys, SOFTWARE_APPROVER_LABEL, SealingKeys, WhichPassphrase, initialize,
};
pub use initialization::{
    BeginError, Discarded, INITIAL_CONFIG, InitStateError, InitializationState, UnfinishedKind, begin_import, begin_initialization,
    ensure_initializable, finish_import, finish_initialization, require_initialized,
};
pub use inventory_check::{ChangeRecovery, CheckedInventory, InventoryCheckError, InventoryDamage, check_recipient_inventory};
pub use manifest::{
    MAX_MANIFEST_ENTRIES, MAX_MANIFEST_LEN, ManifestEntry, ManifestError, VaultManifest, open_manifest, record_digest, seal_manifest,
    unverified_vault_id,
};
pub use owner_lock::{owner_lock_present, remove_owner_lock, write_owner_lock};
pub use partial_restore::PartialRestore;
#[cfg(any(test, feature = "test-support"))]
pub use passphrase::seal_passphrase_envelope_for_tests;
pub use passphrase::{
    CheckUnavailable, MAX_PASSPHRASE_ENVELOPE_LEN, MAX_PASSPHRASE_WORK_FACTOR, OperationalIdentity, PASSPHRASE_WORK_FACTOR, Passphrase,
    PassphraseCheckError, PassphraseError, UnlockError, open_passphrase_envelope, read_passphrase_envelope, reseal_passphrase_envelope,
    seal_passphrase_envelope, unlock_with_passphrase, verify_vault_passphrase, write_passphrase_envelope,
};
pub use permitted_origins::{PermittedOrigins, PermittedOriginsError};
pub use recipient::{
    MAX_RECIPIENTS, ParseRecipientIdentityError, ParseRecipientKeyError, RecipientIdentity, RecipientKey, RecipientSet, RecipientSetError,
};
pub use recipient_inventory::{
    MAX_RECIPIENT_INVENTORY_LEN, RecipientChange, RecipientChangeRefusal, RecipientEntry, RecipientInventory, RecipientInventoryError,
    RecipientInventoryReadError, RecipientInventoryWriteError, RecipientLabel, RecipientLabelError, RecipientRole, envelope_digest,
    open_recipient_inventory, read_recipient_inventory, seal_recipient_inventory, write_recipient_inventory,
};
pub use record::{CredentialRecord, RecordError, ResolvedCredential, Source, decode, encode};
pub use record_id::{RecordId, RecordIdError};
pub use recovery::{RecoveryError, RecoveryKey, RecoveryKeySecret};
pub use recovery_check::{MalformedReason, RecoveryCheck, RecoveryCheckError, check_recovery_key};
pub use recovery_record::{
    MAX_RECOVERY_CHECK_RECORD_LEN, RecoveryCheckReadError, RecoveryCheckRecord, RecoveryCheckRecordError, UtcSecond, UtcSecondError,
    read_recovery_check, write_recovery_check,
};
pub use reset::{
    DiscardError, DiscardFailure, DiscardedVault, ResetScope, ResetStep, UnverifiedVaultIdError, discard_vault, read_unverified_vault_id,
    reset_scope,
};
pub use rewrap::{
    ChangeCommitted, EnvelopeProofError, RecipientChangeError, RecipientChangeFault, RecipientChangeStep, RecipientChangeWriteError,
    RewrappedIdentity, rewrap_identity,
};
pub use sealed::{OpenError, SealError, open, seal};
pub use stale_temps::sweep_stale_temps;
pub use stanza::StanzaKind;
pub use state_dir::StateDirLock;
pub use state_file_name::{StateFileName, StateFileNameError};
pub use state_generation::StateGeneration;
pub use store_fs::{OsFs, StoreFs};
pub use vault::{DamagedRecord, MAX_RECORD_FILE_LEN, OpenReport, RecordDamage, SharedStateDamage, Vault, VaultError, WriteReport};
pub use vault_id::{VaultId, VaultIdError};
pub use vault_identity::{ParseVaultPublicKeyError, VaultIdentity, VaultPublicKey};
