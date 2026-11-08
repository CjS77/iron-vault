//! `recipient add` in the running service (`design/recipients.md`, "`recipient add <age1…>`"): step 3, the inventory
//! check and the change applied in memory, and steps 9 and 10, consuming the authorization and the rewrap.
//!
//! Both run inside the [`MigrationSession`] that holds the service-wide lock, and both hand a clone of that lock to the
//! blocking task that touches the state directory, so a connection that drops mid-write cannot let another command
//! start on a half-finished change. Step 10 consumes the authorization against the key in the plan, so a rewrap cannot
//! start without an authorization for exactly the change the owner was shown.

use std::sync::Arc;

use iron_vault_store::{
    ChangeCommitted, ErrorKindLabel, RecipientChange, RecipientChangeError, RecipientChangeRefusal, RecipientEntry, RecipientInventory,
    RecipientKey, RecipientLabel, RecipientRole, StoreFs, rewrap_identity,
};

use super::ServiceContext;
use super::migration::MigrationSession;
use super::recipients::{ReadyVault, RecipientRefusal, log_failure, ready_vault, step_failure, unwritten};
use crate::audit::AuditEvent;
use crate::audit::recipient::{Added, ChangeFailure};
use crate::migration_authorization::{MigrationAuthorization, MigrationOperation, MigrationRefusal};
use crate::service_state::ServiceState;

/// The `change` label of the audit records this module writes.
const CHANGE: &str = "add";

/// Why step 3 refused: nothing was written, and no challenge was issued.
#[derive(Debug, thiserror::Error)]
pub enum PlanRefusal {
    /// The service is not Ready, or the inventory check found it damaged or could not settle a staged change.
    #[error(transparent)]
    Inventory(#[from] RecipientRefusal),
    /// The key is already enrolled, or the set after the change would break the independence rule.
    #[error(transparent)]
    Rule(RecipientChangeRefusal),
    /// The clock is outside the range an enrolment time can hold.
    #[error("the service clock is outside the range an enrolment time can hold")]
    Clock,
}

/// Why step 10 did not commit, or may not have.
#[derive(Debug, thiserror::Error)]
pub enum AddRefusal {
    /// The service no longer holds the vault identity.
    #[error("the service no longer holds the vault identity")]
    WrongState(ServiceState),
    /// The authorization was not for this vault and this change, or expired, or the service changed since step 2. Nothing
    /// was written.
    #[error("migration authorization was refused")]
    Unauthorized(MigrationRefusal),
    /// The recipient change failed; [`RecipientChangeError`] says whether it may have committed.
    #[error(transparent)]
    Failed(RecipientChangeError),
    /// The task running the rewrap ended without a result, so what reached the disk is unknown.
    #[error("the recipient change did not finish")]
    Interrupted,
}

/// Step 3's result: the inventory the check opened, the entry to enrol and the inventory the change would write.
#[derive(Debug)]
pub struct RecipientAddPlan {
    entry: RecipientEntry,
    current: RecipientInventory,
    after: RecipientInventory,
}

impl RecipientAddPlan {
    /// The entry to enrol.
    pub fn entry(&self) -> &RecipientEntry {
        &self.entry
    }

    /// The inventory after the change, for the summary. It still carries the old envelope's digest.
    pub fn after(&self) -> &RecipientInventory {
        &self.after
    }
}

/// A committed `recipient add`.
#[derive(Debug)]
pub struct Enrolled {
    /// The inventory that describes the new `identity.age`.
    pub inventory: RecipientInventory,
    /// Whether the inventory file or the staged file's removal is left for the next recipient command to finish.
    pub unfinished: bool,
}

impl<F: StoreFs + Send + Sync + 'static> ServiceContext<F> {
    /// Step 3: opens the inventory under the session's lock and applies the add to it in memory. An already-enrolled key
    /// or a set that breaks the independence rule is refused here, recorded as `recipient.change-failed`, before any
    /// challenge.
    pub async fn plan_recipient_add(
        &self,
        session: &MigrationSession<'_, F>,
        key: RecipientKey,
        label: RecipientLabel,
    ) -> Result<RecipientAddPlan, PlanRefusal> {
        let ReadyVault { identity, vault_id, .. } = ready_vault(&*self.inner.lock().await)?;
        let (_, current) = self.check_inventory(session.hold(), identity, vault_id).await?;
        let enrolled_at = self.clock.now().map_err(|_| PlanRefusal::Clock)?;
        let entry = RecipientEntry::new(key, RecipientRole::Added, label, enrolled_at);
        let after = RecipientChange::Add(entry.clone())
            .apply(&current)
            .inspect_err(|rule| log_failure(CHANGE, entry.key(), rule_failure(*rule)))
            .map_err(PlanRefusal::Rule)?;
        Ok(RecipientAddPlan { entry, current, after })
    }

    /// Steps 9 and 10: consumes `authorization` for adding the plan's key, then rewraps the vault identity for it and
    /// writes the inventory that describes it, on the blocking pool with the session's lock. Records `recipient.added`
    /// once the envelope is replaced, and `recipient.change-failed` for a failure, with whether the change committed.
    /// An authorization for another key or operation is refused before anything is written.
    pub async fn add_recipient(
        &self,
        session: &MigrationSession<'_, F>,
        authorization: MigrationAuthorization,
        plan: RecipientAddPlan,
    ) -> Result<Enrolled, AddRefusal> {
        let RecipientAddPlan { entry, current, .. } = plan;
        let operation = MigrationOperation::AddRecipient(entry.key().clone());
        session.consume(authorization, &operation).await.map_err(AddRefusal::Unauthorized)?;
        let inner = self.inner.lock().await;
        let identity = inner.identity.clone().ok_or(AddRefusal::WrongState(inner.state))?;
        drop(inner);
        let (locks, setup, held) = (Arc::clone(&self.locks), Arc::clone(&self.setup), session.hold());
        let change = RecipientChange::Add(entry.clone());
        let rewrapped = tokio::task::spawn_blocking(move || {
            let _held = held;
            rewrap_identity(&locks.state, &setup.fs, &identity, &current, &change, None)
        })
        .await;
        match rewrapped {
            Err(_) => {
                let ended = ChangeFailure::WriteFailed {
                    step: None,
                    error_kind: ErrorKindLabel::fixed("task_ended"),
                    committed: ChangeCommitted::Unknown,
                };
                log_failure(CHANGE, entry.key(), ended);
                Err(AddRefusal::Interrupted)
            }
            Ok(Err(error)) => {
                log_failure(CHANGE, entry.key(), failure_of(&error));
                Err(AddRefusal::Failed(error))
            }
            Ok(Ok(done)) => {
                Added {
                    entry: &entry,
                    recipients: done.inventory.entries().len(),
                }
                .emit();
                done.unfinished
                    .iter()
                    .for_each(|error| log_failure(CHANGE, entry.key(), step_failure(error)));
                Ok(Enrolled {
                    unfinished: done.unfinished.is_some(),
                    inventory: done.inventory,
                })
            }
        }
    }
}

fn rule_failure(rule: RecipientChangeRefusal) -> ChangeFailure {
    match rule {
        RecipientChangeRefusal::AlreadyEnrolled => ChangeFailure::AlreadyEnrolled,
        _ => ChangeFailure::SetInvalid,
    }
}

/// A rewrap that did not commit, or may not have.
fn failure_of(error: &RecipientChangeError) -> ChangeFailure {
    match error {
        RecipientChangeError::Refused(rule) => rule_failure(*rule),
        RecipientChangeError::Write(write) => step_failure(write),
        _ => unwritten(),
    }
}
