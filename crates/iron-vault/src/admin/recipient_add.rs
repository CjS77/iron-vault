//! `recipient add`: enrols a recipient key the owner supplies, after migration authorization (specification §3.13, §3.15,
//! R-23; `design/recipients.md`, "`recipient add <age1…>`"; `design/migration-authorization.md`, "Admin exchange").
//!
//! The new key opens the vault identity, so this is the alternate migration path: an unlocked vault or an admin connection
//! is not enough. The exchange holds the service-wide lock from the session through the response, shows its summary, and
//! asks for the vault passphrase; only the authorization that answer proves reaches the rewrap, which consumes it
//! against the key in the plan.

use std::collections::BTreeMap;
use std::sync::Arc;

use iron_vault_store::{
    ChangeCommitted, RecipientChangeError, RecipientChangeRefusal, RecipientInventory, RecipientKey, RecipientLabel, RecipientRole,
    RecoveryKey, StoreFs,
};

use super::dispatch::{AdminHandler, HandlerFuture};
use super::init::reveal_recovery_key;
use super::migration_authorization::{NoAuthorization, no_authorization, require_migration_authorization};
use super::principal::AdminPrincipal;
use super::protocol::{AdminRequest, AdminResponse, ErrorCode};
use super::recipient_list::{OLD_COPIES, refused as inventory_refused};
use super::server::{Exchange, ExchangeError};
use super::{DEAD_RECOVERY_KEY, unconfirmed_rotated_key};
use crate::migration_authorization::{MigrationOperation, MigrationRefusal};
use crate::service_context::{AddRefusal, Enrolled, PlanRefusal, RecipientAddPlan, RecipientRefusal, ServiceContext};

const COMMAND: &str = "recipient add";

/// The last line of the completion notice after a new recovery key (design/recipients.md, "The completion notice").
const ROTATE_REMINDER: &str =
    "\nCheck the new key with iron-vault recovery check, then remove the old recovery key with iron-vault recipient remove.";

/// `recipient add`'s handler, acting on the running service.
pub(super) struct RecipientAdd<F> {
    service: Arc<ServiceContext<F>>,
}

impl<F> RecipientAdd<F> {
    pub(super) fn new(service: Arc<ServiceContext<F>>) -> Self {
        Self { service }
    }
}

impl<F: StoreFs + Send + Sync + 'static> AdminHandler for RecipientAdd<F> {
    fn handle<'a>(&'a self, _principal: AdminPrincipal, request: AdminRequest, exchange: &'a mut Exchange) -> HandlerFuture<'a> {
        Box::pin(self.run(request, exchange))
    }
}

impl<F: StoreFs + Send + Sync + 'static> RecipientAdd<F> {
    /// The ten steps of the admin exchange. Every early return drops the session, which releases the service-wide lock and
    /// retires any pending challenge.
    async fn run(&self, request: AdminRequest, exchange: &mut Exchange) -> Result<AdminResponse, ExchangeError> {
        match request {
            AdminRequest::RecipientAdd { recipient, label } => self.add_key(&recipient, &label, exchange).await,
            AdminRequest::RecipientAddRecovery { label } => self.add_recovery(&label, exchange).await,
            _ => Ok(error(ErrorCode::RecipientInvalid, "the request is not `recipient add`".to_owned())),
        }
    }

    /// `recipient add <age1…>`: the key the owner supplied, enrolled with the `added` role.
    async fn add_key(&self, recipient: &str, label: &str, exchange: &mut Exchange) -> Result<AdminResponse, ExchangeError> {
        let (key, label) = match parse_arguments(recipient, label) {
            Ok(parsed) => parsed,
            Err(message) => return Ok(error(ErrorCode::RecipientInvalid, message)),
        };
        let session = match self.service.begin_migration().await {
            Ok(session) => session,
            Err(refusal) => return Ok(not_begun(refusal)),
        };
        let plan = match self.service.plan_recipient_add(&session, key.clone(), label).await {
            Ok(plan) => plan,
            Err(refusal) => return Ok(plan_refused(refusal)),
        };
        exchange.notice(&summary(&plan)).await?;
        let operation = MigrationOperation::AddRecipient(key.clone());
        let authorization = match require_migration_authorization(exchange, &session, operation).await? {
            Ok(authorization) => authorization,
            Err(none) => return Ok(no_authorization(COMMAND, none)),
        };
        match self.service.add_recipient(&session, authorization, plan).await {
            Ok(enrolled) => completed(exchange, &key, RecipientRole::Added, enrolled).await,
            Err(refusal) => Ok(add_refused(refusal, UNKNOWN_KEY)),
        }
    }

    /// `recipient add --recovery`: the service generates the key, shows it once before the challenge is issued (a challenge
    /// lives 2 minutes and saving a key can take longer), and enrols it only after the owner confirms and authorizes. From
    /// the reveal on, every ending says what to do with the key shown.
    async fn add_recovery(&self, label: &str, exchange: &mut Exchange) -> Result<AdminResponse, ExchangeError> {
        let label = match RecipientLabel::new(label) {
            Ok(label) => label,
            Err(rule) => return Ok(error(ErrorCode::RecipientInvalid, format!("invalid label: {rule}"))),
        };
        let session = match self.service.begin_migration().await {
            Ok(session) => session,
            Err(refusal) => return Ok(not_begun(refusal)),
        };
        // Generated before the inventory check because the plan keeps the identity to prove the new envelope; a refused
        // check drops it unrevealed, so the order is invisible to the owner.
        let (secret, identity) = RecoveryKey::generate_with_identity();
        let key = identity.recipient_key();
        let plan = match self.service.plan_recovery_add(&session, identity, label).await {
            Ok(plan) => plan,
            Err(refusal) => return Ok(plan_refused(refusal)),
        };
        exchange.notice(&summary(&plan)).await?;
        if let Err(declined) = reveal_recovery_key(exchange, &secret).await? {
            return Ok(declined);
        }
        drop(secret);
        let operation = MigrationOperation::AddRecipient(key.clone());
        let authorization = match require_migration_authorization(exchange, &session, operation).await? {
            Ok(authorization) => authorization,
            Err(none) => return Ok(key_dead(no_authorization(COMMAND, none))),
        };
        match self.service.add_recipient(&session, authorization, plan).await {
            Ok(enrolled) => completed(exchange, &key, RecipientRole::Recovery, enrolled).await,
            Err(refusal) => Ok(revealed_key_advice(&key, refusal)),
        }
    }
}

/// Step 1's argument rules. The message names the rule, never the argument.
fn parse_arguments(recipient: &str, label: &str) -> Result<(RecipientKey, RecipientLabel), String> {
    let key = recipient
        .parse()
        .map_err(|_| "the recipient is not an age1... X25519 recipient key".to_owned())?;
    let label = RecipientLabel::new(label).map_err(|rule| format!("invalid label: {rule}"))?;
    Ok((key, label))
}

/// The summary the owner confirms by typing the vault passphrase: what the migration challenge binds, what the vault has
/// afterwards, and what the factor is.
fn summary(plan: &RecipientAddPlan) -> String {
    let (entry, after) = (plan.entry(), plan.after());
    let (title, next) = match entry.role() {
        RecipientRole::Recovery => (
            "add a new recovery key to the vault",
            "next: the new recovery key is shown once; save it, then type yes",
        ),
        _ => (
            "add a recipient to the vault",
            "this key will open the vault identity, and with it every credential, in every copy of identity.age written from now on",
        ),
    };
    format!(
        "{title}\n  vault: {}\n  recipient: {}\n  role: {}\n  label: {}\n  recipients after the change: {}\n  {next}\n  \
         authorize with: the vault passphrase\n",
        after.vault_id(),
        entry.key(),
        entry.role().name(),
        entry.label(),
        role_counts(after),
    )
}

/// `3 (operational 1, recovery 1, added 1)`: the count and its split by role, in role order.
fn role_counts(inventory: &RecipientInventory) -> String {
    let by_role = inventory.entries().fold(BTreeMap::new(), |mut counts, entry| {
        *counts.entry(entry.role()).or_insert(0usize) += 1;
        counts
    });
    let split: Vec<String> = by_role.iter().map(|(role, count)| format!("{} {count}", role.name())).collect();
    format!("{} ({})", inventory.entries().len(), split.join(", "))
}

/// Step 10's success: the completion notice, then the new key and the recipient count. A new recovery key adds the
/// reminder to check it and retire the old one.
/// The completion notice, ending in a newline like every other notice.
fn completion(key: &RecipientKey, role: RecipientRole, recipients: usize, unfinished: bool) -> String {
    let pending = if unfinished {
        "\nThe recipient inventory is finished at the next recipient command."
    } else {
        ""
    };
    let rotate = if role == RecipientRole::Recovery { ROTATE_REMINDER } else { "" };
    format!(
        "enrolled {key} as {}; the vault has {recipients} recipients.\n{OLD_COPIES}{rotate}{pending}\n",
        role.name()
    )
}

async fn completed(
    exchange: &mut Exchange,
    key: &RecipientKey,
    role: RecipientRole,
    enrolled: Enrolled,
) -> Result<AdminResponse, ExchangeError> {
    let recipients = enrolled.inventory.entries().len();
    exchange.notice(&completion(key, role, recipients, enrolled.unfinished)).await?;
    Ok(AdminResponse::RecipientAdd {
        recipient: key.clone(),
        recipients: u8::try_from(recipients).unwrap_or(u8::MAX),
    })
}

/// Step 2's refusals. A service that is not Ready is `wrong-state` here, before any prompt; `no_authorization` reads a
/// Locked state as a `lock` that cancelled a prompt.
fn not_begun(refusal: MigrationRefusal) -> AdminResponse {
    match refusal {
        MigrationRefusal::WrongState(state) => inventory_refused(COMMAND, RecipientRefusal::WrongState(state)),
        other => no_authorization(COMMAND, NoAuthorization(other)),
    }
}

fn plan_refused(refusal: PlanRefusal) -> AdminResponse {
    match refusal {
        PlanRefusal::Inventory(refusal) => inventory_refused(COMMAND, refusal),
        PlanRefusal::Rule(rule) => rule_refused(rule),
        PlanRefusal::Clock => error(
            ErrorCode::VaultWriteFailed,
            "the service clock is outside the range an enrolment time can hold; nothing was changed".to_owned(),
        ),
    }
}

/// What an uncommitted-or-not `recipient add <age1…>` tells the owner when the write may have committed.
const UNKNOWN_KEY: &str = "the change may have committed: run `iron-vault recipient list` to see whether the key is enrolled";

/// The response for a failed step 9 or 10; `unknown` is the advice for an outcome that may have committed.
fn add_refused(refusal: AddRefusal, unknown: &str) -> AdminResponse {
    match refusal {
        AddRefusal::WrongState(state) => inventory_refused(COMMAND, RecipientRefusal::WrongState(state)),
        AddRefusal::Unauthorized(refusal) => no_authorization(COMMAND, NoAuthorization(refusal)),
        AddRefusal::Failed(RecipientChangeError::Refused(rule)) => rule_refused(rule),
        AddRefusal::Failed(RecipientChangeError::Write(write)) => match write.committed() {
            ChangeCommitted::No => error(ErrorCode::VaultWriteFailed, format!("{write}; nothing was changed")),
            _ => error(ErrorCode::VaultWriteFailed, format!("{write}; {unknown}")),
        },
        AddRefusal::Failed(other) => error(ErrorCode::VaultWriteFailed, format!("{other}; nothing was changed")),
        AddRefusal::Interrupted => error(
            ErrorCode::VaultWriteFailed,
            format!("the recipient change did not finish; {unknown}"),
        ),
    }
}

/// Appends what to do with the recovery key shown, for an ending that enrolled nothing.
fn key_dead(response: AdminResponse) -> AdminResponse {
    with_advice(response, DEAD_RECOVERY_KEY)
}

/// A failed step 9 or 10 after the reveal: the key is dead unless the rewrap may have committed, in which case the one
/// piece of advice names the key to look for.
fn revealed_key_advice(key: &RecipientKey, refusal: AddRefusal) -> AdminResponse {
    let may_have_committed = match &refusal {
        AddRefusal::Interrupted => true,
        AddRefusal::Failed(RecipientChangeError::Write(write)) => write.committed() != ChangeCommitted::No,
        _ => false,
    };
    let response = add_refused(refusal, &unconfirmed_rotated_key(key));
    match may_have_committed {
        true => response,
        false => key_dead(response),
    }
}

fn with_advice(response: AdminResponse, advice: &str) -> AdminResponse {
    match response {
        AdminResponse::Error { code, message } => AdminResponse::Error {
            code,
            message: format!("{message}; {advice}"),
        },
        other => other,
    }
}

fn rule_refused(rule: RecipientChangeRefusal) -> AdminResponse {
    let code = match rule {
        RecipientChangeRefusal::AlreadyEnrolled => ErrorCode::RecipientEnrolled,
        _ => ErrorCode::RecipientSetInvalid,
    };
    error(code, format!("{rule}; nothing was changed"))
}

fn error(code: ErrorCode, message: String) -> AdminResponse {
    AdminResponse::Error { code, message }
}

#[cfg(test)]
mod tests;
