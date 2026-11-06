//! The migration authorization step of an admin exchange (specification §3.13, §3.15; design/migration-authorization.md,
//! "Admin exchange", steps 5 to 7): issue the challenge, check the attempt limit, ask for the vault passphrase and verify
//! it. `export` and `recipient add` both run it and both answer a refusal through [`no_authorization`], so the two
//! cannot drift apart, as `owner_presence` keeps `replace` and `rm` together.
//!
//! **The caller holds the service-wide lock from step 2 until its response**, as `replace` does. The attempt limit and the
//! single pending slot rely on it: without it two exchanges could guess in parallel before the first failure is
//! recorded. The helper cannot take the lock for the caller, so its `lock_requested` argument is the lock holder's, which
//! completes once a `lock` waits for the lock and ends the exchange at its prompt.

use std::future::Future;

use iron_vault_store::StoreFs;

use super::protocol::{AdminResponse, ErrorCode, Prompt};
use super::server::{Exchange, ExchangeError};
use super::unlock::{PASSPHRASE_PROMPT, state_name};
use crate::audit::AuditEvent;
use crate::audit::migration::{AuthorizationRefused, Authorized, ChallengeIssued, Refusal};
use crate::migration_authorization::{
    BindingDigest, MigrationAuthorization, MigrationOperation, MigrationRefusal, OwnerRefusal, SourceOwnerMethod, VaultPassphraseMethod,
};
use crate::service_context::ServiceContext;
use crate::service_state::ServiceState;

/// Why migration authorization was not given. Nothing was exported or rewrapped either way.
#[derive(Debug, PartialEq, Eq)]
pub enum NoAuthorization {
    /// The challenge was not issued or was refused; [`no_authorization`] gives the response each refusal gets.
    Refused(MigrationRefusal),
    /// A `lock` came for the service-wide lock while the owner was at the prompt; the passphrase was never checked.
    CancelledByLock,
}

/// Runs steps 5 to 7 for `operation`: issues the challenge, checks the attempt limit before any prompt, asks for the vault
/// passphrase with a secret prompt that `lock_requested` ends, and verifies the answer. There is no second try. The outer
/// error is a prompt that got no owner input, which cancels the command.
///
/// Each challenge issued is retired however the exchange ends and closes with one audit record, `migration.authorized` or
/// `migration.authorization-refused`. A refusal before the challenge is issued records nothing.
pub async fn require_migration_authorization<F: StoreFs + Send + Sync + 'static>(
    exchange: &mut Exchange,
    service: &ServiceContext<F>,
    operation: MigrationOperation,
    lock_requested: impl Future<Output = ()>,
) -> Result<Result<MigrationAuthorization, NoAuthorization>, ExchangeError> {
    // Built first so that nothing can fail between issuing the challenge and its closing record. It is still built in
    // this exchange, under the service-wide lock, so it checks against the vault identity held now.
    let method = match service.vault_passphrase_method().await {
        Ok(method) => method,
        Err(refusal) => return Ok(Err(NoAuthorization::Refused(refusal))),
    };
    let digest = match service.issue_migration_challenge(operation.clone()).await {
        Ok(digest) => digest,
        Err(refusal) => return Ok(Err(NoAuthorization::Refused(refusal))),
    };
    ChallengeIssued {
        operation: &operation,
        method: method.label(),
    }
    .emit();
    let outcome = prompt_and_prove(exchange, service, &digest, &method, lock_requested).await;
    record_ending(&operation, method.label(), &outcome);
    outcome
}

/// Steps 6 and 7: the attempt limit, the prompt and the method's check.
async fn prompt_and_prove<F: StoreFs + Send + Sync + 'static>(
    exchange: &mut Exchange,
    service: &ServiceContext<F>,
    digest: &BindingDigest,
    method: &VaultPassphraseMethod,
    lock_requested: impl Future<Output = ()>,
) -> Result<Result<MigrationAuthorization, NoAuthorization>, ExchangeError> {
    // A limited owner is not asked to type; the check retires the challenge.
    if let Err(refusal) = service.check_migration_attempts().await {
        return Ok(Err(NoAuthorization::Refused(refusal)));
    }
    let prompt = Prompt {
        label: PASSPHRASE_PROMPT.to_owned(),
        secret: true,
    };
    let input = match exchange.prompt_unless(&prompt, lock_requested).await {
        Ok(Some(input)) => input,
        Ok(None) => {
            service.retire_migration_challenge().await;
            tracing::warn!("migration authorization cancelled at its prompt by a lock; nothing was checked");
            return Ok(Err(NoAuthorization::CancelledByLock));
        }
        Err(cancelled) => {
            service.retire_migration_challenge().await;
            return Err(cancelled);
        }
    };
    // Every outcome of the check retires the challenge itself.
    Ok(service
        .authorize_migration(digest, method, input)
        .await
        .map_err(NoAuthorization::Refused))
}

/// The closing audit record of a challenge: how its exchange ended at the attempt limit, the prompt or the check.
fn record_ending(
    operation: &MigrationOperation,
    method: &'static str,
    outcome: &Result<Result<MigrationAuthorization, NoAuthorization>, ExchangeError>,
) {
    let refusal = match outcome {
        Ok(Ok(_)) => return Authorized { operation, method }.emit(),
        Ok(Err(NoAuthorization::Refused(refusal))) => Refusal::Refused(*refusal),
        Ok(Err(NoAuthorization::CancelledByLock)) => Refusal::Refused(MigrationRefusal::WrongState(ServiceState::Locked)),
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
/// and `migration-rate-limited` (design/migration-authorization.md, "Error codes"). The messages are fixed phrases and
/// never hold owner input; the rate-limited one adds the seconds to wait.
pub fn no_authorization(command: &str, none: NoAuthorization) -> AdminResponse {
    let refusal = match none {
        NoAuthorization::Refused(refusal) => refusal,
        NoAuthorization::CancelledByLock => MigrationRefusal::WrongState(ServiceState::Locked),
    };
    let (code, message) = match refusal {
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
        MigrationRefusal::WrongState(ServiceState::Locked) => (
            ErrorCode::MigrationUnavailable,
            format!("`{command}` was cancelled because a `lock` ran while it waited for the vault passphrase; {NOTHING_DONE}"),
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
            "another migration is waiting for its owner; try again when it ends".to_owned(),
        ),
    };
    AdminResponse::Error { code, message }
}

/// What every refusal ends with: the command did nothing.
const NOTHING_DONE: &str = "nothing was exported or rewrapped";

/// Why an owner refusal is a denial, as a fixed phrase that does not say which of the two it was more than the owner needs.
fn denial(refusal: OwnerRefusal) -> &'static str {
    match refusal {
        OwnerRefusal::WrongSecret => "the vault passphrase was wrong",
        OwnerRefusal::NotThisVault => "the vault passphrase does not open this vault",
    }
}
