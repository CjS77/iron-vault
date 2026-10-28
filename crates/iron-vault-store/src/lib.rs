//! Vault identity, recipient envelopes, record files, manifests, approval metadata, durable transactions,
//! recovery, and connector storage.

mod sealed;
mod state_dir;
mod vault_identity;

pub use sealed::{OpenError, SealError, open, seal};
pub use state_dir::{LockError, StateDirLock};
pub use vault_identity::{ParseVaultPublicKeyError, VaultIdentity, VaultPublicKey};
