//! Vault identity, recipient envelopes, record files, manifests, approval metadata, durable transactions,
//! recovery, and connector storage.

mod state_dir;

pub use state_dir::{LockError, StateDirLock};
