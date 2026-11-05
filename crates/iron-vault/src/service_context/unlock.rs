//! `unlock`'s initialization check (design/vault-initialization.md, "Unlock needs an initialized vault"): the state
//! directories are read before the passphrase prompt and again under the context's mutex, so no passphrase is asked
//! for, or spent on scrypt, when there is no vault to open.

use std::sync::Arc;

use iron_vault_store::{StoreFs, require_initialized};

use super::{ServiceContext, UNLOCK_REFUSED, UnlockRefusal};

impl<F: StoreFs + Send + Sync + 'static> ServiceContext<F> {
    /// Reads the initialization state on the blocking pool under the service's own directory locks and returns the
    /// foreign files beside the manifest when it is Initialized. Any other state refuses with the reason the owner reads,
    /// logged at WARN like every other unlock refusal.
    pub(crate) async fn require_initialized(&self) -> Result<Vec<String>, UnlockRefusal> {
        let (locks, setup) = (Arc::clone(&self.locks), Arc::clone(&self.setup));
        tokio::task::spawn_blocking(move || require_initialized(&locks.state, &locks.config, &setup.fs))
            .await
            .map_err(|_| UnlockRefusal::Interrupted)?
            .map_err(UnlockRefusal::Failed)
            .inspect_err(|refusal| tracing::warn!("{UNLOCK_REFUSED}: {refusal}"))
    }
}

/// Logs each foreign file by name at WARN, `vault.foreign-file`, and never its contents. `unlock` goes on regardless:
/// the manifest alone decides which files belong to the vault.
pub(crate) fn log_foreign_files(files: &[String]) {
    files.iter().for_each(
        |file| tracing::warn!(event = "vault.foreign-file", file = %file.escape_debug(), "unlock found a file that is not the vault's"),
    );
}
