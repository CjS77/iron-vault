//! Vault identity, recipient envelopes, record files, manifests, approval metadata, durable transactions,
//! recovery, and connector storage.

mod durable;
#[cfg(any(test, feature = "test-support"))]
pub mod fault_fs;
mod manifest;
mod permitted_origins;
mod record;
mod record_id;
mod sealed;
mod state_dir;
mod state_file_name;
mod store_fs;
#[cfg(test)]
mod test_dir;
mod vault_id;
mod vault_identity;

pub use durable::{ReadError, WriteError, WriteStep, durable_remove, durable_replace, read_state_file};
pub use manifest::{
    MAX_MANIFEST_ENTRIES, MAX_MANIFEST_LEN, ManifestEntry, ManifestError, VaultManifest, open_manifest, record_digest, seal_manifest,
};
pub use permitted_origins::{PermittedOrigins, PermittedOriginsError};
pub use record::{CredentialRecord, RecordError, Source, decode, encode};
pub use record_id::{RecordId, RecordIdError};
pub use sealed::{OpenError, SealError, open, seal};
pub use state_dir::{LockError, StateDirLock};
pub use state_file_name::{StateFileName, StateFileNameError};
pub use store_fs::{OsFs, StoreFs};
pub use vault_id::{VaultId, VaultIdError};
pub use vault_identity::{ParseVaultPublicKeyError, VaultIdentity, VaultPublicKey};
