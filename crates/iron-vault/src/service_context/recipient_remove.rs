//! `recipient remove`'s side of the service context (`design/recipients.md`, "`recipient remove <age1…>`").
//!
//! [`ServiceContext::plan_recipient_removal`] takes the service-wide lock without waiting and runs steps 2 and 3: the
//! inventory check, then the independence rule on the set without the key. The [`RecipientRemoval`] it returns holds the
//! lock through the summary, the passphrase prompt and the write, so owner presence authorizes exactly the change the
//! owner was shown. Like a vault change's plan it keeps no vault identity, so a `lock` while the owner is at the prompt
//! leaves no copy behind; the write takes the identity from the context again, and refuses unless the service is still in
//! the state and at the check generation it recorded.
//!
//! A removal changes no credential and no serving snapshot, so it runs no config check. A blocking task owns the lock
//! guard while it writes, so a dropped caller never leaves a half-finished change running without the lock.

use std::sync::Arc;

use iron_vault_store::{
    ChangeCommitted, PinnedApprover, RecipientChange, RecipientChangeError, RecipientChangeRefusal, RecipientChangeWriteError,
    RecipientEntry, RecipientInventory, RecipientKey, StoreFs, rewrap_identity,
};
use tokio::sync::OwnedMutexGuard;

use super::recipients::{ReadyVault, log_failure, ready_vault, step_failure, unwritten};
use super::{ApproverSecret, OwnerPresence, PresenceRefusal, RecipientRefusal, ServiceContext};
use crate::audit::AuditEvent;
use crate::audit::recipient::{ChangeFailure, Removed};
use crate::service_state::ServiceState;

/// The `change` label of the audit records this module writes.
const CHANGE: &str = "remove";

/// Why a recipient removal ended without removing the recipient.
#[derive(Debug, thiserror::Error)]
pub enum RemovalRefusal {
    /// Before any write: busy, not Ready, or the inventory check refused or could not settle a staged change.
    #[error(transparent)]
    Inventory(#[from] RecipientRefusal),
    /// No enrolled recipient has the key.
    #[error("no enrolled recipient has this key")]
    NotEnrolled,
    /// The set without the key would break the independence rule; the refusal names which part.
    #[error("{0}")]
    SetInvalid(RecipientChangeRefusal),
    /// The change failed while it was written; `committed` says whether `identity.age` was replaced.
    #[error("{cause}")]
    Failed {
        /// Whether the change committed.
        committed: ChangeCommitted,
        /// What failed, without key material.
        cause: String,
    },
}

/// What a committed removal did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovedRecipient {
    /// The recipient that was removed.
    pub removed: RecipientEntry,
    /// The recipient count after the removal.
    pub recipients: usize,
    /// Set when a step after the commit point failed: the next recipient command finishes the inventory.
    pub unfinished: bool,
}

/// Steps 2 and 3 of `recipient remove` done: the service-wide lock is held, the inventory is current and the independence
/// rule allows the set without the key. See the module docs.
pub struct RecipientRemoval<'a, F> {
    service: &'a ServiceContext<F>,
    service_wide: OwnedMutexGuard<()>,
    /// The service state and check generation at step 2, which the write checks again.
    state: ServiceState,
    checks: u64,
    /// The pinned approvers in approver order, from the approval state the service holds.
    approvers: Vec<PinnedApprover>,
    /// The inventory the check opened, which the write rewraps from.
    inventory: RecipientInventory,
    removed: RecipientEntry,
    /// The inventory the removal leads to, as the summary describes it.
    after: RecipientInventory,
}

impl<F: StoreFs + Send + Sync + 'static> ServiceContext<F> {
    /// Takes the service-wide lock, refusing at once with [`RecipientRefusal::Busy`] while another holds it, then runs the
    /// checks before any prompt. A key that is not enrolled, or whose removal breaks the independence rule, is logged as
    /// `recipient.change-failed` and refused.
    pub async fn plan_recipient_removal(&self, key: RecipientKey) -> Result<RecipientRemoval<'_, F>, RemovalRefusal> {
        let service_wide = Arc::clone(&self.service_wide)
            .try_lock_owned()
            .map_err(|_| RecipientRefusal::Busy)?;
        let ReadyVault {
            identity,
            vault_id,
            state,
            checks,
            approvers,
        } = ready_vault(&*self.inner.lock().await)?;
        let (service_wide, inventory) = self.check_inventory(service_wide, identity, vault_id).await?;
        let host_unlock = self.configured_host_unlock().await;
        let (removed, after) = apply_removal(&inventory, &key, host_unlock.as_ref()).inspect_err(|refusal| log_refused(&key, refusal))?;
        Ok(RecipientRemoval {
            service: self,
            service_wide,
            state,
            checks,
            approvers: self.askable_approvers(&approvers),
            inventory,
            removed,
            after,
        })
    }
}

/// The entry `key` names and the inventory without it, if the independence rule allows that set with `host_unlock` as
/// the configured host unlock adapter's recipient key.
fn apply_removal(
    inventory: &RecipientInventory,
    key: &RecipientKey,
    host_unlock: Option<&RecipientKey>,
) -> Result<(RecipientEntry, RecipientInventory), RemovalRefusal> {
    let removed = inventory.get(key).cloned().ok_or(RemovalRefusal::NotEnrolled)?;
    let after = RecipientChange::Remove(key.clone())
        .apply_configured(inventory, host_unlock)
        .map_err(|refusal| match refusal {
            RecipientChangeRefusal::NotEnrolled => RemovalRefusal::NotEnrolled,
            rule => RemovalRefusal::SetInvalid(rule),
        })?;
    Ok((removed, after))
}

fn log_refused(key: &RecipientKey, refusal: &RemovalRefusal) {
    let failure = match refusal {
        RemovalRefusal::NotEnrolled => ChangeFailure::UnknownRecipient,
        RemovalRefusal::SetInvalid(_) => ChangeFailure::SetInvalid,
        _ => return,
    };
    log_failure(CHANGE, key, failure);
}

impl<F: StoreFs + Send + Sync + 'static> RecipientRemoval<'_, F> {
    /// The recipient the removal takes out.
    pub fn removed(&self) -> &RecipientEntry {
        &self.removed
    }

    /// The inventory after the removal, which the summary counts the remaining recipients from.
    pub fn remaining(&self) -> &RecipientInventory {
        &self.after
    }

    /// Completes once a `lock` is waiting for the service-wide lock this removal holds, so a prompt can end the change
    /// rather than make the `lock` wait for the owner.
    pub async fn lock_requested(&self) {
        self.service.lock_requested().await;
    }

    /// The pinned approvers in approver order: owner presence asks the first and lets the owner switch to the rest.
    pub fn approvers(&self) -> &[PinnedApprover] {
        &self.approvers
    }

    /// Owner presence (`design/credential-commands.md`): opens `approver`'s own key envelope with
    /// `passphrase` and drops the signer at once. Nothing is reserved, signed or written.
    pub async fn prove_presence(
        &self,
        secret: impl Into<ApproverSecret>,
        approver: &PinnedApprover,
    ) -> Result<OwnerPresence, PresenceRefusal> {
        self.service.prove_presence(secret.into(), approver).await
    }

    /// Step 7: rewraps the vault identity for the set without the recipient, if the service is still in the state and at
    /// the check generation of step 2. It logs `recipient.removed` at the commit point, and `recipient.change-failed` when
    /// a step fails. Taking the proof by value makes one proof authorize one change.
    pub async fn remove(self, _proof: OwnerPresence) -> Result<RemovedRecipient, RemovalRefusal> {
        let Self {
            service,
            service_wide,
            state,
            checks,
            inventory,
            removed,
            after,
            ..
        } = self;
        let identity = {
            let inner = service.inner.lock().await;
            let unchanged = inner.state == state && inner.checks == checks;
            inner
                .identity
                .clone()
                .filter(|_| unchanged)
                .ok_or(RecipientRefusal::WrongState(inner.state))?
        };
        let (locks, setup, key) = (Arc::clone(&service.locks), Arc::clone(&service.setup), removed.key().clone());
        let written = tokio::task::spawn_blocking(move || {
            let _held = service_wide;
            rewrap_identity(&locks.state, &setup.fs, &identity, &inventory, &RecipientChange::Remove(key), None)
        })
        .await;
        match written {
            Ok(Ok(rewrapped)) => {
                let recipients = after.entries().len();
                Removed {
                    entry: &removed,
                    recipients,
                }
                .emit();
                let unfinished = rewrapped
                    .unfinished
                    .inspect(|error| log_write_failure(removed.key(), error))
                    .is_some();
                Ok(RemovedRecipient {
                    removed,
                    recipients,
                    unfinished,
                })
            }
            Ok(Err(error)) => Err(refused_write(removed.key(), &error)),
            Err(_) => Err(RemovalRefusal::Failed {
                committed: ChangeCommitted::Unknown,
                cause: "the recipient change's task did not finish".to_owned(),
            }),
        }
    }
}

/// Logs a step that failed, naming its kind and whether the change committed.
fn log_write_failure(key: &RecipientKey, error: &RecipientChangeWriteError) {
    log_failure(CHANGE, key, step_failure(error));
}

/// The refusal for a change that failed before the commit point or at it, logged as `recipient.change-failed`.
fn refused_write(key: &RecipientKey, error: &RecipientChangeError) -> RemovalRefusal {
    match error {
        RecipientChangeError::Write(write) => {
            log_write_failure(key, write);
            RemovalRefusal::Failed {
                committed: write.committed(),
                cause: write.to_string(),
            }
        }
        RecipientChangeError::Refused(rule) => {
            let refusal = RemovalRefusal::SetInvalid(*rule);
            log_refused(key, &refusal);
            refusal
        }
        // Wrapping, proving and sealing happen before the first write.
        other => {
            log_failure(CHANGE, key, unwritten());
            RemovalRefusal::Failed {
                committed: ChangeCommitted::No,
                cause: other.to_string(),
            }
        }
    }
}
