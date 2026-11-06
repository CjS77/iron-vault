//! Migration authorization in a running service context (specification §3.13, §3.15, R-23;
//! design/migration-authorization.md): the vault passphrase method proving a challenge against the envelopes on disk,
//! each refusal retiring the challenge, the passphrase attempt limit across challenges, and a `lock` during the check.
//!
//! Each test builds the harness vault, then writes `identity.age` and `operational.age` sealed to [`PASSPHRASE`] before
//! the service starts. The service reaches Ready from the known vault identity, without reading those envelopes, so a
//! test can plant another vault's envelopes under a Ready service.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::fs;
use std::sync::Arc;
use std::time::Duration;

use common::approval_harness::{APPROVAL_PASSPHRASE, Fixture, identity};
use common::gated_fs::GatedFs;
use iron_vault::admin::protocol::{OwnerInput, VaultStatus};
use iron_vault::migration_authorization::{
    AttemptsCoolingDown, BASE_COOLDOWN, BindingDigest, CHALLENGE_LIFETIME, FAILURE_THRESHOLD, MigrationAuthorization, MigrationOperation,
    MigrationRefusal, OwnerRefusal, PendingMigration,
};
use iron_vault::service_context::{LockOutcome, ServiceContext};
use iron_vault::service_state::ServiceState;
use iron_vault_store::{
    OperationalIdentity, OsFs, Passphrase, RecipientKey, RecipientSet, StateDirLock, StoreFs, VaultId, VaultIdentity,
    seal_passphrase_envelope_for_tests, wrap_identity, write_identity_envelope, write_passphrase_envelope,
};
use secrecy::SecretString;
use tokio::time::Instant;
use zeroize::Zeroizing;

/// The vault passphrase, a wrong one, and the new export passphrase an owner would choose after authorization.
const PASSPHRASE: &str = "VAULT-correct-5d1a";
const WRONG_PASSPHRASE: &str = "VAULT-wrong-0b77";
const EXPORT_PASSPHRASE: &str = "EXPORT-new-8c3f";
const RECIPIENT: &str = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";
const DRAIN: Duration = Duration::from_secs(10);

fn input(text: &str) -> OwnerInput {
    OwnerInput::new(Zeroizing::new(text.as_bytes().to_vec()))
}

fn add_recipient() -> MigrationOperation {
    MigrationOperation::AddRecipient(RECIPIENT.parse::<RecipientKey>().unwrap())
}

/// `identity.age` holding `vault` for an operational identity and a second recipient, and `operational.age` sealing that
/// operational identity to [`PASSPHRASE`], as initialization writes them.
fn write_envelopes(fixture: &Fixture, vault: &VaultIdentity) {
    let lock = StateDirLock::acquire(&fixture.path("state")).unwrap();
    let (operational, operational_key) = OperationalIdentity::generate();
    let recipients = RecipientSet::new([operational_key, OperationalIdentity::generate().1]).unwrap();
    write_identity_envelope(&lock, &OsFs, &wrap_identity(vault, &recipients).unwrap()).unwrap();
    let passphrase = Passphrase::new(SecretString::from(PASSPHRASE)).unwrap();
    write_passphrase_envelope(
        &lock,
        &OsFs,
        &seal_passphrase_envelope_for_tests(&operational, &passphrase).unwrap(),
    )
    .unwrap();
}

/// A fixture whose envelopes on disk open to the service's own vault identity with [`PASSPHRASE`].
async fn fixture() -> Fixture {
    let fixture = Fixture::new().await;
    write_envelopes(&fixture, &identity());
    fixture
}

async fn vault_id<F: StoreFs + Send + Sync + 'static>(service: &ServiceContext<F>) -> VaultId {
    match service.status().await.vault {
        VaultStatus::Unlocked(vault) => vault.id,
        other => panic!("expected an unlocked vault, got {other:?}"),
    }
}

/// Issues a challenge for `operation` and answers it with `typed` through the vault passphrase method.
async fn attempt<F: StoreFs + Send + Sync + 'static>(
    service: &ServiceContext<F>,
    operation: MigrationOperation,
    typed: &str,
) -> (BindingDigest, Result<MigrationAuthorization, MigrationRefusal>) {
    let digest = service.issue_migration_challenge(operation).await.unwrap();
    service.check_migration_attempts().await.unwrap();
    let method = service.vault_passphrase_method().await.unwrap();
    (digest, service.authorize_migration(&digest, &method, input(typed)).await)
}

/// Answers `digest` again with the right passphrase: a retired challenge is refused as not pending.
async fn assert_retired<F: StoreFs + Send + Sync + 'static>(service: &ServiceContext<F>, digest: &BindingDigest) {
    assert!(!service.pending_migration().await.is_pending(), "the challenge is still pending");
    let method = service.vault_passphrase_method().await.unwrap();
    let again = service.authorize_migration(digest, &method, input(PASSPHRASE)).await.unwrap_err();
    assert_eq!(again, MigrationRefusal::NotPending);
}

#[tokio::test]
async fn the_vault_passphrase_authorizes_the_operation_its_challenge_names() {
    let fixture = fixture().await;
    let service = fixture.ready().await;
    let vault = vault_id(&service).await;

    for operation in [MigrationOperation::Export, add_recipient()] {
        let (digest, proved) = attempt(&service, operation.clone(), PASSPHRASE).await;
        let authorized = proved.unwrap().authorize(vault, &operation, Instant::now()).unwrap();
        assert_eq!(authorized.operation(), &operation);
        assert_retired(&service, &digest).await;
    }
}

#[tokio::test]
async fn an_authorization_permits_only_the_operation_it_was_proved_for() {
    let fixture = fixture().await;
    let service = fixture.ready().await;
    let vault = vault_id(&service).await;

    let (_, proved) = attempt(&service, add_recipient(), PASSPHRASE).await;
    let refusal = proved
        .unwrap()
        .authorize(vault, &MigrationOperation::Export, Instant::now())
        .unwrap_err();
    assert_eq!(refusal, MigrationRefusal::BindingMismatch);
}

#[tokio::test]
async fn a_wrong_passphrase_is_denied_and_retires_the_challenge() {
    let fixture = fixture().await;
    let service = fixture.ready().await;

    let (digest, proved) = attempt(&service, MigrationOperation::Export, WRONG_PASSPHRASE).await;

    assert_eq!(proved.unwrap_err(), MigrationRefusal::Denied(OwnerRefusal::WrongSecret));
    assert_retired(&service, &digest).await;
}

#[tokio::test]
async fn neither_the_export_passphrase_nor_the_approval_passphrase_authorizes() {
    let fixture = fixture().await;
    let service = fixture.ready().await;

    for typed in [EXPORT_PASSPHRASE, APPROVAL_PASSPHRASE, ""] {
        let (digest, proved) = attempt(&service, MigrationOperation::Export, typed).await;
        assert_eq!(
            proved.unwrap_err(),
            MigrationRefusal::Denied(OwnerRefusal::WrongSecret),
            "{typed:?}"
        );
        assert_retired(&service, &digest).await;
    }
}

#[tokio::test]
async fn another_vaults_envelopes_are_not_this_vault_even_with_their_passphrase() {
    let fixture = Fixture::new().await;
    write_envelopes(&fixture, &VaultIdentity::generate());
    let service = fixture.ready().await;

    let (digest, proved) = attempt(&service, MigrationOperation::Export, PASSPHRASE).await;

    assert_eq!(proved.unwrap_err(), MigrationRefusal::Denied(OwnerRefusal::NotThisVault));
    assert_retired(&service, &digest).await;
}

#[tokio::test]
async fn an_expired_challenge_is_refused_and_retired() {
    let fixture = fixture().await;
    let service = fixture.ready().await;
    let digest = service.issue_migration_challenge(MigrationOperation::Export).await.unwrap();
    tokio::time::pause();
    tokio::time::advance(CHALLENGE_LIFETIME).await;

    let method = service.vault_passphrase_method().await.unwrap();
    let refusal = service.authorize_migration(&digest, &method, input(PASSPHRASE)).await.unwrap_err();

    assert_eq!(refusal, MigrationRefusal::Expired);
    assert_retired(&service, &digest).await;
}

#[tokio::test]
async fn a_challenge_never_issued_is_not_pending() {
    let fixture = fixture().await;
    let service = fixture.ready().await;
    let vault = vault_id(&service).await;
    let elsewhere = PendingMigration::new(Instant::now())
        .issue(vault, MigrationOperation::Export, Instant::now(), [7; 32])
        .unwrap();

    let method = service.vault_passphrase_method().await.unwrap();
    let refusal = service
        .authorize_migration(&elsewhere, &method, input(PASSPHRASE))
        .await
        .unwrap_err();

    assert_eq!(refusal, MigrationRefusal::NotPending);
}

#[tokio::test]
async fn a_second_challenge_is_busy_while_one_is_pending_until_it_is_retired() {
    let fixture = fixture().await;
    let service = fixture.ready().await;
    let first = service.issue_migration_challenge(MigrationOperation::Export).await.unwrap();

    let busy = service.issue_migration_challenge(add_recipient()).await.unwrap_err();
    assert!(matches!(busy, MigrationRefusal::Busy(_)), "{busy:?}");

    service.retire_migration_challenge().await;
    assert_retired(&service, &first).await;
    assert!(service.issue_migration_challenge(add_recipient()).await.is_ok());
}

#[tokio::test]
async fn a_locked_service_issues_no_challenge_and_proves_none() {
    let fixture = fixture().await;
    let service = fixture.ready().await;
    let digest = service.issue_migration_challenge(MigrationOperation::Export).await.unwrap();
    let method = service.vault_passphrase_method().await.unwrap();
    assert_eq!(service.lock(DRAIN).await, Ok(LockOutcome::Cleared));

    let locked = MigrationRefusal::WrongState(ServiceState::Locked);
    assert_eq!(
        service.issue_migration_challenge(MigrationOperation::Export).await.unwrap_err(),
        locked
    );
    assert_eq!(service.vault_passphrase_method().await.unwrap_err(), locked);
    let refusal = service.authorize_migration(&digest, &method, input(PASSPHRASE)).await.unwrap_err();
    assert_eq!(refusal, locked);
    assert!(!service.pending_migration().await.is_pending());
}

/// Starts the authorization of a new export challenge with `typed` on a task, holds it at the read of `operational.age`,
/// and locks the service there. Returns the refusal the check ends with, once the challenge is retired.
async fn lock_mid_check(service: &Arc<ServiceContext<GatedFs>>, fs: &GatedFs, typed: &'static str) -> MigrationRefusal {
    let digest = service.issue_migration_challenge(MigrationOperation::Export).await.unwrap();
    let method = service.vault_passphrase_method().await.unwrap();
    let (reached, release) = fs.arm("operational.age");
    let checking = {
        let service = Arc::clone(service);
        tokio::spawn(async move { service.authorize_migration(&digest, &method, input(typed)).await })
    };
    reached.await.unwrap();

    assert_eq!(
        service.lock(DRAIN).await,
        Ok(LockOutcome::Cleared),
        "the check kept the vault identity alive"
    );
    release.send(()).unwrap();
    let refusal = checking.await.unwrap().unwrap_err();
    assert!(!service.pending_migration().await.is_pending());
    refusal
}

#[tokio::test]
async fn a_lock_during_the_check_refuses_even_the_right_passphrase() {
    let fixture = fixture().await;
    let fs = GatedFs::default();
    let service = fixture.ready_on(fs.clone()).await;

    let refusal = lock_mid_check(&service, &fs, PASSPHRASE).await;

    assert_eq!(refusal, MigrationRefusal::WrongState(ServiceState::Locked));
    assert_eq!(refusal.label(), "locked");
}

#[tokio::test]
async fn the_attempt_limit_counts_wrong_passphrases_across_challenges() {
    let fixture = fixture().await;
    let service = fixture.ready().await;
    for _ in 0..FAILURE_THRESHOLD {
        let (_, proved) = attempt(&service, MigrationOperation::Export, WRONG_PASSPHRASE).await;
        assert_eq!(proved.unwrap_err(), MigrationRefusal::Denied(OwnerRefusal::WrongSecret));
    }
    let cooling = MigrationRefusal::AttemptsCoolingDown(AttemptsCoolingDown {
        retry_after: BASE_COOLDOWN.as_secs(),
    });

    // Before the prompt: the check refuses and retires the challenge, so the owner is never asked to type.
    service.issue_migration_challenge(MigrationOperation::Export).await.unwrap();
    assert_eq!(service.check_migration_attempts().await.unwrap_err(), cooling);
    assert!(!service.pending_migration().await.is_pending());

    // At the answer: even the right passphrase is refused unchecked, and the challenge is retired.
    let digest = service.issue_migration_challenge(MigrationOperation::Export).await.unwrap();
    let method = service.vault_passphrase_method().await.unwrap();
    let refusal = service.authorize_migration(&digest, &method, input(PASSPHRASE)).await.unwrap_err();
    assert_eq!(refusal, cooling);
    assert!(!service.pending_migration().await.is_pending());
}

#[tokio::test]
async fn a_proof_resets_the_attempt_count() {
    let fixture = fixture().await;
    let service = fixture.ready().await;
    for _ in 1..FAILURE_THRESHOLD {
        attempt(&service, MigrationOperation::Export, WRONG_PASSPHRASE).await.1.unwrap_err();
    }
    attempt(&service, MigrationOperation::Export, PASSPHRASE).await.1.unwrap();

    attempt(&service, MigrationOperation::Export, WRONG_PASSPHRASE).await.1.unwrap_err();
    service.check_migration_attempts().await.unwrap();
}

#[tokio::test]
async fn an_unavailable_check_a_cancelled_prompt_and_a_lock_record_no_failure() {
    let fixture = fixture().await;
    let fs = GatedFs::default();
    let service = fixture.ready_on(fs.clone()).await;
    for _ in 1..FAILURE_THRESHOLD {
        attempt(&service, MigrationOperation::Export, WRONG_PASSPHRASE).await.1.unwrap_err();
    }

    // Unavailable: the passphrase envelope cannot be read.
    let (operational, aside) = (fixture.path("state/operational.age"), fixture.path("operational.age.aside"));
    fs::rename(&operational, &aside).unwrap();
    let (digest, proved) = attempt(&service, MigrationOperation::Export, WRONG_PASSPHRASE).await;
    assert_eq!(proved.unwrap_err(), MigrationRefusal::Unavailable);
    fs::rename(&aside, &operational).unwrap();
    assert_retired(&service, &digest).await;

    // Cancelled: the prompt got no answer, so the exchange retires its challenge without a check.
    service.issue_migration_challenge(MigrationOperation::Export).await.unwrap();
    service.check_migration_attempts().await.unwrap();
    service.retire_migration_challenge().await;

    // Locked mid-check: the wrong passphrase was checked, but the outcome is discarded unrecorded.
    let refusal = lock_mid_check(&service, &fs, WRONG_PASSPHRASE).await;
    assert_eq!(refusal, MigrationRefusal::WrongState(ServiceState::Locked));

    let mut limiter = service.attempt_limiter().await;
    assert!(limiter.check(Instant::now()).is_ok(), "a non-owner outcome counted as a failure");
    limiter.record_failure(Instant::now());
    assert!(
        limiter.check(Instant::now()).is_err(),
        "the count was not one short of the threshold"
    );
}
