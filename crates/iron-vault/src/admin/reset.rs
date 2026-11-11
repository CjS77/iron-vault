//! `reset`: discards the vault and the config after a confirmation typed at a terminal (`design/reset.md`, "The exchange").
//!
//! The service writes the summary and compares the confirmation; the CLI only refuses to send the request without a
//! terminal. No owner factor is asked: reset is for the owner who has lost them, and the admin principal could delete the
//! files anyway. Nothing is written before the confirmation, so a refusal, a cancelled prompt or a closed CLI leaves the
//! directories as they were.

use std::sync::Arc;
use std::time::Duration;

use iron_vault_store::{DiscardError, InitializationState, StoreFs, UnfinishedKind};

use super::dispatch::{AdminHandler, HandlerFuture};
use super::principal::AdminPrincipal;
use super::protocol::{AdminRequest, AdminResponse, ErrorCode, MAX_RESET_FOREIGN, Prompt};
use super::server::{Exchange, ExchangeError};
use super::unlock::state_name;
use crate::service_context::{ResetOutcome, ResetPlan, ResetRefusal, ServiceContext, failure_step};

/// `reset`'s handler, acting on the running service.
pub(super) struct Reset<F> {
    service: Arc<ServiceContext<F>>,
    /// The lock drain, as for `lock`: reset withdraws the vault the same way.
    drain: Duration,
}

impl<F> Reset<F> {
    pub(super) fn new(service: Arc<ServiceContext<F>>, drain: Duration) -> Self {
        Self { service, drain }
    }
}

impl<F: StoreFs + Send + Sync + 'static> AdminHandler for Reset<F> {
    fn handle<'a>(&'a self, _principal: AdminPrincipal, _request: AdminRequest, exchange: &'a mut Exchange) -> HandlerFuture<'a> {
        Box::pin(self.run(exchange))
    }
}

impl<F: StoreFs + Send + Sync + 'static> Reset<F> {
    async fn run(&self, exchange: &mut Exchange) -> Result<AdminResponse, ExchangeError> {
        let plan = match self.service.reset_plan().await {
            Ok(plan) => plan,
            Err(refusal) => return Ok(refused(refusal)),
        };
        exchange.notice(&summary(&plan)).await?;
        let prompt = Prompt {
            label: confirmation_label(&plan),
            secret: false,
            switchable: false,
        };
        if !plan.confirmed_by(exchange.prompt(&prompt).await?.expose_secret()) {
            return Ok(error(
                ErrorCode::Declined,
                "the confirmation does not match, so nothing was removed".to_owned(),
            ));
        }
        Ok(match self.service.reset(plan, self.drain).await {
            Ok(outcome) => result(outcome),
            Err(refusal) => refused(refusal),
        })
    }
}

fn confirmation_label(plan: &ResetPlan) -> String {
    let what = if plan.vault.is_some() { "this vault" } else { "these files" };
    format!("Type {} to discard {what}", plan.confirmation())
}

/// The summary the owner reads before the confirmation: what goes, what stays, and what to keep.
fn summary(plan: &ResetPlan) -> String {
    let lines = [
        format!("discard {}", discarding(plan)),
        format!("service: {}; it stops serving at once and stays Locked", state_name(plan.from)),
        credentials_line(plan),
        config_line(plan),
        foreign_line(plan),
        "nothing can be recovered afterwards. Keep your own copy of the config and of the output of `iron-vault list`, and \
         have the providers reissue the credentials."
            .to_owned(),
        "copies of the old vault in backups still open with the old recovery key and vault passphrase: rotate at the provider any \
         credential that may have leaked. Removal is not secure erasure."
            .to_owned(),
    ];
    lines
        .into_iter()
        .filter(|line| !line.is_empty())
        .map(|line| format!("  {line}\n"))
        .collect()
}

fn discarding(plan: &ResetPlan) -> String {
    let scope = &plan.scope;
    match (scope.state, plan.vault) {
        (InitializationState::Initialized, Some(vault)) => {
            let unverified = if vault.verified {
                ""
            } else {
                " (unverified: the vault is not open)"
            };
            format!("the vault {}{unverified}", vault.id)
        }
        (InitializationState::Unfinished(UnfinishedKind::Initialization), _) => "the unfinished initialization".to_owned(),
        (InitializationState::Unfinished(UnfinishedKind::Import), _) => {
            format!("the unfinished import and its {} record files", scope.record_files)
        }
        (InitializationState::UnfinishedReset, _) => "the files of an interrupted reset".to_owned(),
        _ => "vault files with no Initialized vault".to_owned(),
    }
}

fn credentials_line(plan: &ResetPlan) -> String {
    match &plan.credentials {
        Some(names) => format!(
            "credentials that go with it: {}",
            if names.is_empty() { "none".to_owned() } else { names.join(", ") }
        ),
        None => format!(
            "record files that go with it: {} (unverified: only the manifest says which are live)",
            plan.scope.record_files
        ),
    }
}

fn config_line(plan: &ResetPlan) -> String {
    match plan.scope.config_files.as_slice() {
        [] => "no config file is there".to_owned(),
        files => format!(
            "the config is deleted too: {}",
            files.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
        ),
    }
}

fn foreign_line(plan: &ResetPlan) -> String {
    match plan.scope.foreign.as_slice() {
        [] => String::new(),
        files => format!(
            "files that stay, which `init` refuses until they are moved aside: {}",
            files
                .iter()
                .map(|file| iron_vault_policy::escaped(file))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn result(outcome: ResetOutcome) -> AdminResponse {
    let ResetOutcome {
        vault_id,
        discarded,
        cleared,
    } = outcome;
    AdminResponse::Reset {
        vault_id,
        removed: u64::try_from(discarded.removed.len()).unwrap_or(u64::MAX),
        foreign: discarded
            .foreign
            .iter()
            .take(MAX_RESET_FOREIGN)
            .map(|file| iron_vault_policy::escaped(file))
            .collect(),
        cleared,
        finish_uncertain: discarded.finish_uncertain.is_some(),
    }
}

fn refused(refusal: ResetRefusal) -> AdminResponse {
    match refusal {
        ResetRefusal::WrongState(state) => error(
            ErrorCode::WrongState,
            format!(
                "`reset` needs the service Locked, Ready or Unavailable; it is {}",
                state_name(state)
            ),
        ),
        ResetRefusal::NothingToReset(message) => error(ErrorCode::NothingToReset, message),
        ResetRefusal::Changed(change) => error(
            ErrorCode::Declined,
            format!("{change}, so nothing was removed; run `iron-vault reset` again"),
        ),
        ResetRefusal::Unreadable(why) => error(
            ErrorCode::ResetFailed,
            format!("cannot read the directories, so nothing was removed: {why}"),
        ),
        ResetRefusal::Failed(failure) => failed(&failure),
        ResetRefusal::Interrupted => error(
            ErrorCode::ResetFailed,
            "the reset's task ended without a result; run `iron-vault reset` again, which resumes".to_owned(),
        ),
    }
}

/// `reset-failed`, naming the step and the file, and whether the vault is intact or the next reset resumes.
fn failed(failure: &DiscardError) -> AdminResponse {
    let advice = match failure_step(&failure.cause) {
        iron_vault_store::ResetStep::Begin => "the vault is intact",
        _ => "the vault is partly discarded; run `iron-vault reset` again, which resumes",
    };
    error(ErrorCode::ResetFailed, format!("{}; {advice}", failure.cause))
}

fn error(code: ErrorCode, message: String) -> AdminResponse {
    AdminResponse::Error { code, message }
}
