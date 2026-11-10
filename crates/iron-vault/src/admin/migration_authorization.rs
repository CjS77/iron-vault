//! The migration authorization step of an admin exchange (specification §16, §19; design/migration-authorization.md,
//! "Admin exchange", steps 5 to 7): issue the challenge, check the attempt limit, ask for the vault passphrase and verify
//! it. `export` and `recipient add` both run it and both answer a refusal through [`no_authorization`], so the two
//! cannot drift apart, as `owner_presence` keeps `replace` and `rm` together.
//!
//! **The service-wide lock is held from step 2 until the response, and the type enforces it.** The attempt limit and the
//! single pending slot rely on it: without it two exchanges could guess in parallel before the first failure is
//! recorded. The helper takes a [`MigrationSession`], which owns the lock and is the only way to get one, so it cannot be
//! called without the lock, as a `VaultChangePlan` keeps `replace` and `rm` under it. The session also supplies the
//! `lock_requested` that ends a prompt when a `lock` waits, and retires any pending challenge when it drops, however the
//! exchange ends.

use iron_vault_store::StoreFs;

use super::protocol::{AdminResponse, ErrorCode, Prompt};
use super::server::{Exchange, ExchangeError};
use super::unlock::{PASSPHRASE_PROMPT, state_name};
use crate::audit::AuditEvent;
use crate::audit::migration::{AuthorizationRefused, Authorized, ChallengeIssued, Refusal};
use crate::migration_authorization::{
    BindingDigest, MigrationAuthorization, MigrationOperation, MigrationRefusal, OwnerRefusal, SourceOwnerMethod, VaultPassphraseMethod,
};
use crate::service_context::MigrationSession;
use crate::service_state::ServiceState;

/// Why migration authorization was not given. Nothing was exported or rewrapped either way. A `lock` that ended the
/// prompt is `WrongState(Locked)`, which [`no_authorization`] answers as `migration-unavailable`.
#[derive(Debug, PartialEq, Eq)]
pub struct NoAuthorization(pub MigrationRefusal);

/// Runs steps 5 to 7 for `operation` inside `session`: issues the challenge, checks the attempt limit before any prompt,
/// asks for the vault passphrase with a secret prompt that a waiting `lock` ends, and verifies the answer. There is no
/// second try. The outer error is a prompt that got no owner input, which cancels the command.
///
/// Each challenge issued closes with one audit record, `migration.authorized` or `migration.authorization-refused`, and is
/// retired however the exchange ends. A refusal before the challenge is issued records nothing.
pub async fn require_migration_authorization<F: StoreFs + Send + Sync + 'static>(
    exchange: &mut Exchange,
    session: &MigrationSession<'_, F>,
    operation: MigrationOperation,
) -> Result<Result<MigrationAuthorization, NoAuthorization>, ExchangeError> {
    let service = session.service();
    // Built first so that nothing can fail between issuing the challenge and its closing record. It is still built in
    // this exchange, under the service-wide lock, so it checks against the vault identity held now.
    let method = match service.vault_passphrase_method().await {
        Ok(method) => method,
        Err(refusal) => return Ok(Err(NoAuthorization(refusal))),
    };
    let digest = match service.issue_migration_challenge(operation.clone()).await {
        Ok(digest) => digest,
        Err(refusal) => return Ok(Err(NoAuthorization(refusal))),
    };
    ChallengeIssued {
        operation: &operation,
        method: method.label(),
    }
    .emit();
    let outcome = prompt_and_prove(exchange, session, &digest, &method).await;
    record_ending(&operation, method.label(), &outcome);
    outcome
}

/// Steps 6 and 7: the attempt limit, the prompt and the method's check.
async fn prompt_and_prove<F: StoreFs + Send + Sync + 'static>(
    exchange: &mut Exchange,
    session: &MigrationSession<'_, F>,
    digest: &BindingDigest,
    method: &VaultPassphraseMethod,
) -> Result<Result<MigrationAuthorization, NoAuthorization>, ExchangeError> {
    let service = session.service();
    // A limited owner is not asked to type; the check retires the challenge.
    if let Err(refusal) = service.check_migration_attempts().await {
        return Ok(Err(NoAuthorization(refusal)));
    }
    let prompt = Prompt {
        label: PASSPHRASE_PROMPT.to_owned(),
        secret: true,
        switchable: false,
    };
    let input = match exchange.prompt_unless(&prompt, session.lock_requested()).await {
        Ok(Some(input)) => input,
        Ok(None) => {
            service.retire_migration_challenge().await;
            tracing::warn!("migration authorization cancelled at its prompt by a lock; nothing was checked");
            return Ok(Err(NoAuthorization(MigrationRefusal::WrongState(ServiceState::Locked))));
        }
        Err(cancelled) => {
            service.retire_migration_challenge().await;
            return Err(cancelled);
        }
    };
    // Every outcome of the check retires the challenge itself.
    let proved = service.authorize_migration(digest, method, input).await;
    Ok(proved.map_err(|refusal| NoAuthorization(after_challenge(refusal))))
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
fn record_ending(
    operation: &MigrationOperation,
    method: &'static str,
    outcome: &Result<Result<MigrationAuthorization, NoAuthorization>, ExchangeError>,
) {
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
/// and `migration-rate-limited` (design/migration-authorization.md, "Error codes"). The messages are fixed phrases and
/// never hold owner input; the rate-limited one adds the seconds to wait.
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
            "an approval, a vault write, an init, a reload, a config check or another migration is running; try again".to_owned(),
        ),
    };
    AdminResponse::Error { code, message }
}

/// What every refusal ends with: the command did nothing.
const NOTHING_DONE: &str = "nothing was exported or rewrapped";

/// Why an owner refusal is a denial. The two phrases differ so that the owner can tell a mistyped passphrase from the
/// passphrase of another vault.
fn denial(refusal: OwnerRefusal) -> &'static str {
    match refusal {
        OwnerRefusal::WrongSecret => "the vault passphrase was wrong",
        OwnerRefusal::NotThisVault => "the vault passphrase does not open this vault",
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
