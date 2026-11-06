//! `unlock`'s initialization check (design/vault-initialization.md, "Unlock needs an initialized vault"): the state
//! directories are read before the passphrase prompt and again under the context's mutex, so no passphrase is asked
//! for, or spent on scrypt, when there is no vault to open. Its memory check (§3.11) runs at the same two points, so a
//! protected install whose memory is not locked never asks for the passphrase or opens the vault.

use std::sync::Arc;

use iron_vault_store::{StoreFs, require_initialized};

use super::{ServiceContext, UnlockRefusal};
use crate::audit::AuditEvent;
use crate::audit::vault::{ForeignFile, UnlockRefused};
use crate::deployment::DeploymentProfile;
use crate::hardening::MemoryProtection;

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
            .inspect_err(|refusal| UnlockRefused { refusal }.emit())
    }

    /// [`memory_guard`] for this service's profile and startup memory protection status, logged at WARN like every
    /// other unlock refusal.
    ///
    /// Every path that opens the vault identity takes this guard first. When unattended TPM or host unlock arrives
    /// (Starting to Checking, EP-32), it must refuse here too, before it unwraps the identity: a protected install never
    /// holds a secret in swappable memory, whatever unlocked it.
    pub(crate) fn require_locked_memory(&self) -> Result<(), UnlockRefusal> {
        memory_guard(self.setup.paths.profile, &self.setup.hardening.memory).inspect_err(|refusal| UnlockRefused { refusal }.emit())
    }
}

/// Refuses an unlock in a protected install unless `memory` is `Locked` (§3.11). No secret is in memory before unlock,
/// so the service stays Locked with nothing to leak, and `status` says why. An `Unsupported` platform refuses too: no
/// protected platform ships without a locking adapter. Development mode has reported the failure at startup and goes
/// on.
pub(crate) fn memory_guard(profile: DeploymentProfile, memory: &MemoryProtection) -> Result<(), UnlockRefusal> {
    match (profile, memory) {
        (DeploymentProfile::Development, _) | (DeploymentProfile::Protected, MemoryProtection::Locked) => Ok(()),
        (DeploymentProfile::Protected, unprotected) => Err(UnlockRefusal::MemoryUnprotected(unprotected.clone())),
    }
}

/// Why `memory` is not protection, as the owner reads it in a [`UnlockRefusal::MemoryUnprotected`] message.
pub(crate) fn unprotected_reason(memory: &MemoryProtection) -> String {
    match memory {
        MemoryProtection::Unavailable(why) => why.to_string(),
        MemoryProtection::Unsupported => "this platform has no memory-locking adapter".to_owned(),
        MemoryProtection::Locked => "memory is locked".to_owned(),
    }
}

/// Records each foreign file by escaped name as `vault.foreign-file`, and never its contents. `unlock` goes on regardless:
/// the manifest alone decides which files belong to the vault.
pub(crate) fn log_foreign_files(files: &[String]) {
    files.iter().for_each(|file| ForeignFile { file }.emit());
}
