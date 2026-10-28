//! Vault identity, recipient envelopes, record files, manifests, approval metadata, durable transactions,
//! recovery, and connector storage.

mod permitted_origins;
mod record;
mod record_id;
mod sealed;
mod state_dir;
mod vault_identity;

pub use permitted_origins::{PermittedOrigins, PermittedOriginsError};
pub use record::{CredentialRecord, RecordError, Source, decode, encode};
pub use record_id::{RecordId, RecordIdError};
pub use sealed::{OpenError, SealError, open, seal};
pub use state_dir::{LockError, StateDirLock};
pub use vault_identity::{ParseVaultPublicKeyError, VaultIdentity, VaultPublicKey};
