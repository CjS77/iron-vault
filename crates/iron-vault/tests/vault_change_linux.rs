//! The service side of `replace` and `rm` (design/credential-commands.md): the plan's checks before any prompt, owner
//! presence through the approval passphrase, and the write followed by the config check through
//! `ServiceEvent::VaultChanged`, which must settle out of Checking even when its caller is dropped (§15).
//!
//! Each test uses the `config approve` harness: a vault holding `fx_key`, used by the route `fx`, with a software
//! approver sealed under [`APPROVAL_PASSPHRASE`].

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::fs;
use std::sync::Arc;

use common::WAIT;
use common::approval_harness::{APPROVAL_PASSPHRASE, Fixture, WRONG_PASSPHRASE, approval_passphrase, captured_logs, get, identity};
use common::gated_fs::GatedFs;
use iron_vault::service_context::{ApprovalEnd, CredentialChanged, DenialKind, PresenceRefusal, ServiceContext, VaultChangeRefusal};
use iron_vault::service_state::{ServiceState, UnavailableReason};
use iron_vault::serving_snapshot::{Admission, ServingSnapshot};
use iron_vault::vault_change_check::PlannedChange;
use iron_vault_kinds::CredentialMaterial;
use iron_vault_policy::Port;
use iron_vault_store::{
    ApproverId, ApproverLabel, OsFs, PermittedOrigins, PinnedApprover, SoftwareSigner, StateDirLock, StoreFs, UtcSecond, Vault,
    seal_signer_key_for_tests, write_signer_key,
};

/// Adds `old_key`, which no route uses.
async fn add_unused<F: StoreFs + Send + Sync + 'static>(service: &ServiceContext<F>) {
    let origins = PermittedOrigins::new([("old.example".parse().unwrap(), Port::HTTPS)].into()).unwrap();
    let material = CredentialMaterial::Static { key: "old-secret".into() };
    service.add_credential("old_key".parse().unwrap(), material, origins).await.unwrap();
}

fn remove(name: &str) -> PlannedChange {
    PlannedChange::Remove(name.parse().unwrap())
}

fn served<F: StoreFs + Send + Sync + 'static>(service: &ServiceContext<F>) -> Arc<ServingSnapshot> {
    match service.holder().load() {
        Admission::Serve(snapshot) => snapshot,
        Admission::Refuse(reason) => panic!("expected a served snapshot, got {reason:?}"),
    }
}

fn approval_bytes(fixture: &Fixture) -> Vec<u8> {
    fs::read(fixture.path("state/approval.age")).unwrap()
}

/// Enrolls a second software approver beside the one `init` pinned, its key sealed under the same approval passphrase,
/// and returns its ID. Run before the service starts, which holds the state-directory lock.
fn enroll_second_approver(fixture: &Fixture) -> ApproverId {
    let lock = StateDirLock::acquire(&fixture.path("state")).unwrap();
    let (vault, _) = Vault::open(&lock, &OsFs, identity()).unwrap();
    let mut state = vault.load_approval_state(&lock, &OsFs).unwrap();
    let (key, pinned) = SoftwareSigner::generate().unwrap();
    let sealed = seal_signer_key_for_tests(&key, &approval_passphrase(APPROVAL_PASSPHRASE)).unwrap();
    let id = ApproverId::generate();
    write_signer_key(&lock, &OsFs, id, &sealed).unwrap();
    let approver = PinnedApprover::software_for_tests(id, pinned, ApproverLabel::new("second").unwrap(), UtcSecond::EPOCH);
    state.enroll_approver(&lock, &OsFs, &identity(), approver).unwrap();
    id
}

/// Swaps the key files of approvers `a` and `b`, so each holds the other's genuine sealed key.
fn swap_key_files(fixture: &Fixture, a: ApproverId, b: ApproverId) {
    let (a, b) = (
        fixture.path(&format!("state/approver-{a}.age")),
        fixture.path(&format!("state/approver-{b}.age")),
    );
    let (a_key, b_key) = (fs::read(&a).unwrap(), fs::read(&b).unwrap());
    fs::write(&a, b_key).unwrap();
    fs::write(&b, a_key).unwrap();
}

#[tokio::test]
async fn the_approval_passphrase_proves_presence() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    add_unused(&service).await;
    let plan = service.plan_vault_change(remove("old_key")).await.unwrap();

    assert!(plan.prove_presence(approval_passphrase(APPROVAL_PASSPHRASE)).await.is_ok());
}

#[tokio::test]
async fn a_wrong_passphrase_is_refused_and_writes_nothing() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    add_unused(&service).await;
    let before = approval_bytes(&fixture);
    let plan = service.plan_vault_change(remove("old_key")).await.unwrap();

    let refused = plan.prove_presence(approval_passphrase(WRONG_PASSPHRASE)).await;

    assert_eq!(refused.unwrap_err(), PresenceRefusal::Denied(DenialKind::WrongPassphrase));
    assert_eq!(approval_bytes(&fixture), before);
    logs.assert_no_passphrase();
}

#[tokio::test]
async fn a_key_no_approver_pins_in_the_key_file_is_refused_and_writes_nothing() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let approver = fixture.approver_id();
    let service = fixture.ready().await;
    add_unused(&service).await;
    let (other, _) = SoftwareSigner::generate().unwrap();
    let sealed = seal_signer_key_for_tests(&other, &approval_passphrase(APPROVAL_PASSPHRASE)).unwrap();
    fs::write(fixture.path(&format!("state/approver-{approver}.age")), sealed).unwrap();
    let before = approval_bytes(&fixture);
    let plan = service.plan_vault_change(remove("old_key")).await.unwrap();

    let refused = plan.prove_presence(approval_passphrase(APPROVAL_PASSPHRASE)).await;

    assert_eq!(refused.unwrap_err(), PresenceRefusal::Denied(DenialKind::KeyMismatch));
    assert_eq!(approval_bytes(&fixture), before);
    logs.assert_no_passphrase();
}

/// Both approvers' keys open under the one passphrase, so only the key check keeps the asked approver's prompt from
/// signing as the other: whichever approver is asked, its file holds the other's key.
#[tokio::test]
async fn a_key_file_swapped_with_another_pinned_approvers_is_refused_as_key_mismatch_by_presence_and_approval() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let first = fixture.approver_id();
    let second = enroll_second_approver(&fixture);
    swap_key_files(&fixture, first, second);
    let service = fixture.ready().await;
    add_unused(&service).await;
    let before = approval_bytes(&fixture);
    let plan = service.plan_vault_change(remove("old_key")).await.unwrap();

    let refused = plan.prove_presence(approval_passphrase(APPROVAL_PASSPHRASE)).await;
    assert_eq!(refused.unwrap_err(), PresenceRefusal::Denied(DenialKind::KeyMismatch));
    drop(plan);
    let review = service.review_approval(fixture.config("rates").into_bytes()).await.unwrap();
    let opened = review.open_signer(approval_passphrase(APPROVAL_PASSPHRASE)).await;
    assert!(matches!(opened, Err(ApprovalEnd::Denied)), "{opened:?}");
    review.abandon();

    assert_eq!(approval_bytes(&fixture), before);
    let refusals: Vec<_> = logs
        .events("config.approval-refused")
        .iter()
        .map(|record| record["refusal"].clone())
        .collect();
    assert_eq!(refusals, ["key_mismatch"], "{}", logs.text());
    logs.assert_no_passphrase();
}

#[tokio::test]
async fn removing_a_name_a_route_uses_is_refused_before_any_prompt_naming_the_route() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;

    let Err(refusal @ VaultChangeRefusal::UsedByRoutes { .. }) = service.plan_vault_change(remove("fx_key")).await else {
        panic!("expected credential-in-use");
    };

    assert_eq!(
        refusal.to_string(),
        "credential fx_key is used by route fx; approve a config without that route, then run `rm` again"
    );
}

#[tokio::test]
async fn an_unknown_name_and_a_held_lock_are_refused() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    add_unused(&service).await;

    let unknown = service.plan_vault_change(remove("never_added")).await;
    assert!(matches!(unknown, Err(VaultChangeRefusal::UnknownCredential(_))));
    let _plan = service.plan_vault_change(remove("old_key")).await.unwrap();
    assert!(matches!(
        service.plan_vault_change(remove("old_key")).await,
        Err(VaultChangeRefusal::Busy)
    ));
}

#[tokio::test]
async fn a_removal_reaches_ready_on_a_new_snapshot_and_the_old_one_drops_when_its_requests_end() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    add_unused(&service).await;
    // Held as a request admitted before the change would hold it.
    let old = served(&service);
    let plan = service.plan_vault_change(remove("old_key")).await.unwrap();
    let proof = plan.prove_presence(approval_passphrase(APPROVAL_PASSPHRASE)).await.unwrap();

    assert_eq!(plan.change_credential(None, proof).await.unwrap(), CredentialChanged::Removed);

    assert_eq!(service.state().await, ServiceState::Ready);
    assert!(!Arc::ptr_eq(&old, &served(&service)), "the check built a new serving snapshot");
    let names: Vec<_> = service
        .list()
        .await
        .unwrap()
        .into_iter()
        .map(|standing| standing.name.to_string())
        .collect();
    assert_eq!(names, ["fx_key"]);
    assert_eq!(get(&fixture, "fx").await.status, 200);
    let probe = Arc::downgrade(&old);
    drop(old);
    assert!(probe.upgrade().is_none(), "the old snapshot outlived its last request");
}

#[tokio::test]
async fn material_of_another_kind_than_planned_writes_nothing() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    add_unused(&service).await;
    let origins = PermittedOrigins::new([("old.example".parse().unwrap(), Port::HTTPS)].into()).unwrap();
    let change = PlannedChange::Replace {
        name: "old_key".parse().unwrap(),
        kind: iron_vault_policy::CredentialKind::Static,
        origins,
    };
    let plan = service.plan_vault_change(change).await.unwrap();
    let proof = plan.prove_presence(approval_passphrase(APPROVAL_PASSPHRASE)).await.unwrap();

    let refused = plan.change_credential(None, proof).await;

    assert!(matches!(refused, Err(VaultChangeRefusal::Invalid(_))));
    assert_eq!(service.state().await, ServiceState::Ready);
    assert_eq!(service.list().await.unwrap().len(), 2);
}

#[tokio::test]
async fn a_lock_ends_a_plan_at_its_prompt_and_runs_once_the_plan_is_dropped() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    add_unused(&service).await;
    let plan = service.plan_vault_change(remove("old_key")).await.unwrap();
    let locking = tokio::spawn({
        let service = Arc::clone(&service);
        async move { service.lock(WAIT).await }
    });

    tokio::time::timeout(WAIT, plan.lock_requested()).await.unwrap();
    assert!(!locking.is_finished(), "the lock waits for the service-wide lock the plan holds");
    drop(plan);

    tokio::time::timeout(WAIT, locking).await.unwrap().unwrap().unwrap();
    assert_eq!(service.state().await, ServiceState::Locked);
}

#[tokio::test]
async fn a_stop_while_the_owner_types_ends_the_change_with_nothing_written() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    add_unused(&service).await;
    let plan = service.plan_vault_change(remove("old_key")).await.unwrap();
    let proof = plan.prove_presence(approval_passphrase(APPROVAL_PASSPHRASE)).await.unwrap();
    let manifest = fs::read(fixture.path("state/manifest.age")).unwrap();
    // A stop takes only the context's mutex, so the plan's service-wide lock does not hold it back.
    service.stop().await;

    let refused = plan.change_credential(None, proof).await;

    assert!(matches!(refused, Err(VaultChangeRefusal::WrongState(ServiceState::Stopped))));
    assert_eq!(fs::read(fixture.path("state/manifest.age")).unwrap(), manifest);
}

#[tokio::test]
async fn a_check_generation_change_while_the_owner_types_ends_the_change_with_nothing_written() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    add_unused(&service).await;
    let plan = service.plan_vault_change(remove("old_key")).await.unwrap();
    let proof = plan.prove_presence(approval_passphrase(APPROVAL_PASSPHRASE)).await.unwrap();
    service.advance_check_generation().await;

    let refused = plan.change_credential(None, proof).await;

    assert!(matches!(refused, Err(VaultChangeRefusal::WrongState(ServiceState::Ready))));
    assert_eq!(service.list().await.unwrap().len(), 2);
}

/// A change aborted while the config check after its write holds it still settles in Ready: the write and the check
/// belong to a task of their own, which also keeps the service-wide lock until it ends.
#[tokio::test]
async fn a_change_aborted_during_its_config_check_still_settles_out_of_checking() {
    let fixture = Fixture::new().await;
    let fs = GatedFs::default();
    let service = fixture.ready_on(fs.clone()).await;
    add_unused(&service).await;
    // The write reads only the state directory, so the first read of the config is the config check's.
    let (reached, release) = fs.arm("config.toml");
    let changing = tokio::spawn({
        let service = Arc::clone(&service);
        async move {
            let plan = service.plan_vault_change(remove("old_key")).await.unwrap();
            let proof = plan.prove_presence(approval_passphrase(APPROVAL_PASSPHRASE)).await.unwrap();
            plan.change_credential(None, proof).await.map(drop)
        }
    });
    tokio::time::timeout(WAIT, reached).await.unwrap().unwrap();
    assert!(matches!(service.holder().load(), Admission::Refuse(UnavailableReason::Checking)));

    changing.abort();
    assert!(changing.await.unwrap_err().is_cancelled());
    assert!(matches!(
        service.plan_vault_change(remove("fx_key")).await,
        Err(VaultChangeRefusal::Busy)
    ));
    release.send(()).unwrap();

    assert_eq!(tokio::time::timeout(WAIT, service.state()).await.unwrap(), ServiceState::Ready);
    let names: Vec<_> = service
        .list()
        .await
        .unwrap()
        .into_iter()
        .map(|standing| standing.name.to_string())
        .collect();
    assert_eq!(names, ["fx_key"]);
    assert_eq!(get(&fixture, "fx").await.status, 200);
}
