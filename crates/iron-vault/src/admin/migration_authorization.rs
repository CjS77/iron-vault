//! The migration authorization step of an admin exchange (specification §16, §19; design/migration-authorization.md,
//! "Admin exchange", steps 5 to 7): issue the challenge, ask for a source-owner method's secret (the vault passphrase
//! first, then each `tpm` approver's TPM approval PIN) and check it. `export` and `recipient add` both run it and both
//! answer a refusal through [`no_authorization`], so the two cannot drift apart, as `owner_presence` keeps `replace` and
//! `rm` together.
//!
//! **The service-wide lock is held from step 2 until the response, and the type enforces it.** The attempt limit and the
//! single pending slot rely on it: without it two exchanges could guess in parallel before the first failure is
//! recorded. The helper takes a [`MigrationSession`], which owns the lock and is the only way to get one, so it cannot be
//! called without the lock, as a `VaultChangePlan` keeps `replace` and `rm` under it. The session also supplies the
//! `lock_requested` that ends a prompt when a `lock` waits, and retires any pending challenge when it drops, however the
//! exchange ends.

use iron_vault_store::StoreFs;

use super::owner_presence::passphrase_prompt;
use super::protocol::{AdminResponse, ErrorCode, Prompt, PromptAnswer};
use super::server::{Exchange, ExchangeError};
use super::unlock::{PASSPHRASE_PROMPT, state_name};
use crate::audit::migration::{AuthorizationRefused, Authorized, ChallengeIssued, Refusal};
use crate::audit::{AuditEvent, NamedApprover};
use crate::migration_authorization::{
    AskableMethod, AskableMethods, BindingDigest, MethodName, MigrationAuthorization, MigrationOperation, MigrationRefusal, OwnerRefusal,
    VaultPassphraseMethod,
};
use crate::service_context::MigrationSession;
use crate::service_state::ServiceState;

/// Why migration authorization was not given. Nothing was exported or rewrapped either way. A `lock` that ended the
/// prompt is `WrongState(Locked)`, which [`no_authorization`] answers as `migration-unavailable`.
#[derive(Debug, PartialEq, Eq)]
pub struct NoAuthorization(pub MigrationRefusal);

/// What the exchange's outcome is: the authorization, a refusal, or a prompt that got no owner input.
type Outcome = Result<Result<MigrationAuthorization, NoAuthorization>, ExchangeError>;

/// The method an exchange names before anyone answers when it can ask none.
const NO_METHOD: MethodName = MethodName {
    label: VaultPassphraseMethod::LABEL,
    approver: None,
};

/// Runs steps 5 to 7 for `operation` inside `session`: issues the challenge, asks the methods this install can ask in
/// one switchable secret prompt that a waiting `lock` ends, and checks the answer with the method answered. A wrong
/// answer ends the exchange; there is no second try and no move to another method. The outer error is a prompt that got
/// no owner input, which cancels the command.
///
/// Each challenge issued closes with one audit record, `migration.authorized` or `migration.authorization-refused`, and is
/// retired however the exchange ends. A refusal before the challenge is issued records nothing.
pub async fn require_migration_authorization<F: StoreFs + Send + Sync + 'static>(
    exchange: &mut Exchange,
    session: &MigrationSession<'_, F>,
    operation: MigrationOperation,
) -> Result<Result<MigrationAuthorization, NoAuthorization>, ExchangeError> {
    let service = session.service();
    // Built first so that nothing can fail between issuing the challenge and its closing record. They are still built in
    // this exchange, under the service-wide lock, so they check against the vault identity held now.
    let methods = match service.migration_methods().await {
        Ok(methods) => methods,
        Err(refusal) => return Ok(Err(NoAuthorization(refusal))),
    };
    let digest = match service.issue_migration_challenge(operation.clone()).await {
        Ok(digest) => digest,
        Err(refusal) => return Ok(Err(NoAuthorization(refusal))),
    };
    let first = methods.asked().first().map_or(NO_METHOD, MethodName::of);
    ChallengeIssued {
        operation: &operation,
        method: first.label,
    }
    .emit();
    let (answered, outcome) = prompt_and_prove(exchange, session, &digest, &methods).await;
    record_ending(&operation, answered.unwrap_or(first), &outcome);
    outcome
}

/// What the summary's `authorize with:` line names: the method step 6 asks first. Its methods are built again at step 5,
/// under the same service-wide lock, so the line names the method the prompt starts at.
pub async fn authorize_with<F: StoreFs + Send + Sync + 'static>(session: &MigrationSession<'_, F>) -> String {
    let methods = session.service().migration_methods().await;
    match methods.as_ref().ok().and_then(|methods| methods.asked().first()) {
        Some(AskableMethod::TpmPin(method)) => {
            format!("the TPM approval PIN for \"{}\"", NamedApprover::from(method.pinned()).label_text())
        }
        _ => "the vault passphrase".to_owned(),
    }
}

/// Steps 6 and 7: the prompt over `methods`, then the answered method's check. Returns the method answered, if any.
async fn prompt_and_prove<F: StoreFs + Send + Sync + 'static>(
    exchange: &mut Exchange,
    session: &MigrationSession<'_, F>,
    digest: &BindingDigest,
    methods: &AskableMethods,
) -> (Option<MethodName>, Outcome) {
    let service = session.service();
    let asked = methods.asked();
    let switchable = asked.len() > 1;
    for method in asked.iter().cycle() {
        let prompt = Prompt {
            label: prompt_label(method),
            secret: true,
            switchable,
        };
        let input = match exchange.prompt_or_switch_unless(&prompt, session.lock_requested()).await {
            Ok(Some(PromptAnswer::Switch)) => continue,
            Ok(Some(PromptAnswer::OwnerInput(input))) => input,
            Ok(None) => {
                service.retire_migration_challenge().await;
                tracing::warn!("migration authorization cancelled at its prompt by a lock; nothing was checked");
                return (None, Ok(Err(NoAuthorization(MigrationRefusal::WrongState(ServiceState::Locked)))));
            }
            Err(cancelled) => {
                service.retire_migration_challenge().await;
                return (None, Err(cancelled));
            }
        };
        // Every outcome of the check retires the challenge itself.
        let proved = service.authorize_migration(digest, method, input).await;
        return (
            Some(MethodName::of(method)),
            Ok(proved.map_err(|refusal| NoAuthorization(after_challenge(refusal)))),
        );
    }
    // No method can be asked: a limited owner is not asked to type.
    service.retire_migration_challenge().await;
    (None, Ok(Err(NoAuthorization(methods.none_left()))))
}

/// The secret prompt's label for `method`.
fn prompt_label(method: &AskableMethod) -> String {
    match method {
        AskableMethod::VaultPassphrase(_) => PASSPHRASE_PROMPT.to_owned(),
        AskableMethod::TpmPin(method) => passphrase_prompt(method.pinned()),
    }
}

/// A refusal after the challenge was issued. The exchange holds the service-wide lock, so only a `lock` can change the
/// state, and it waits for that lock; any other state change (a stop) means the check could not be completed, which the
/// design's closing labels call `unavailable`. `wrong-state` is only for the refusals before a challenge exists.
fn after_challenge(refusal: MigrationRefusal) -> MigrationRefusal {
    match refusal {
        MigrationRefusal::WrongState(state) if state != ServiceState::Locked => MigrationRefusal::Unavailable,
        other => other,
    }
}

/// The closing audit record of a challenge: how its exchange ended at the attempt limit, the prompt or the check.
fn record_ending(operation: &MigrationOperation, method: MethodName, outcome: &Outcome) {
    let refusal = match outcome {
        Ok(Ok(_)) => return Authorized { operation, method }.emit(),
        Ok(Err(NoAuthorization(refusal))) => Refusal::Refused(*refusal),
        Err(_) => Refusal::Cancelled,
    };
    AuthorizationRefused {
        operation,
        method,
        refusal,
    }
    .emit();
}

/// The answer when migration authorization for `command` was not given, so nothing was exported or rewrapped. Every
/// refusal passes through here, so this is the one place that maps them to `migration-denied`, `migration-unavailable`
/// `migration-rate-limited` and `tpm-locked-out` (design/migration-authorization.md, "Error codes"). The messages are
/// fixed phrases and never hold owner input; the rate-limited and locked-out ones add the seconds to wait.
pub fn no_authorization(command: &str, none: NoAuthorization) -> AdminResponse {
    let (code, message) = match none.0 {
        MigrationRefusal::Denied(owner) => (ErrorCode::MigrationDenied, format!("{}; {NOTHING_DONE}", denial(owner))),
        MigrationRefusal::Expired => (
            ErrorCode::MigrationDenied,
            format!("the migration authorization expired; {NOTHING_DONE}"),
        ),
        MigrationRefusal::NotPending => (
            ErrorCode::MigrationDenied,
            format!("the migration authorization was already used or retired; {NOTHING_DONE}"),
        ),
        MigrationRefusal::BindingMismatch => (
            ErrorCode::MigrationDenied,
            format!("the migration authorization is for another migration; {NOTHING_DONE}"),
        ),
        MigrationRefusal::AttemptsCoolingDown(cooling) => (ErrorCode::MigrationRateLimited, format!("{cooling}; {NOTHING_DONE}")),
        MigrationRefusal::Unavailable => (
            ErrorCode::MigrationUnavailable,
            format!("migration authorization could not be checked; {NOTHING_DONE}"),
        ),
        MigrationRefusal::TpmLockedOut { wait_seconds } => (
            ErrorCode::TpmLockedOut,
            format!("the TPM is locked out; try again in {wait_seconds} seconds; {NOTHING_DONE}"),
        ),
        MigrationRefusal::TpmUnavailable { status } => (
            ErrorCode::MigrationUnavailable,
            format!("the TPM approver cannot be checked: the TPM signing helper answered {status}; {NOTHING_DONE}"),
        ),
        MigrationRefusal::WrongState(ServiceState::Locked) => (
            ErrorCode::MigrationUnavailable,
            format!("`{command}` was cancelled because a `lock` ran while it waited at its authorization prompt; {NOTHING_DONE}"),
        ),
        MigrationRefusal::WrongState(state) => (
            ErrorCode::WrongState,
            format!(
                "`{command}` is allowed only while the service is Ready; it is {}",
                state_name(state)
            ),
        ),
        MigrationRefusal::Busy(_) => (
            ErrorCode::Busy,
            "an approval, a vault write, an init, a reload, a config check or another migration is running; try again".to_owned(),
        ),
    };
    AdminResponse::Error { code, message }
}

/// What every refusal ends with: the command did nothing.
const NOTHING_DONE: &str = "nothing was exported or rewrapped";

/// Why an owner refusal is a denial. The passphrase phrases differ so that the owner can tell a mistyped passphrase from
/// the passphrase of another vault.
fn denial(refusal: OwnerRefusal) -> &'static str {
    match refusal {
        OwnerRefusal::WrongSecret => "the vault passphrase was wrong",
        OwnerRefusal::NotThisVault => "the vault passphrase does not open this vault",
        OwnerRefusal::WrongPin => "the TPM approval PIN is wrong; each wrong PIN counts against the TPM's lockout",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service_state::FailureReason;

    #[test]
    fn a_state_change_after_the_challenge_is_unavailable_except_a_lock() {
        let changed = [ServiceState::Checking, ServiceState::Unavailable(FailureReason::PolicyInvalid)];
        changed
            .into_iter()
            .for_each(|state| assert_eq!(after_challenge(MigrationRefusal::WrongState(state)), MigrationRefusal::Unavailable));
        let locked = MigrationRefusal::WrongState(ServiceState::Locked);
        assert_eq!(after_challenge(locked), locked);
        assert_eq!(after_challenge(MigrationRefusal::Expired), MigrationRefusal::Expired);
    }
}
