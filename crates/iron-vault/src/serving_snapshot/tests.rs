use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

use iron_vault_kinds::CredentialMaterial;
use iron_vault_policy::{AccountDirectory, AccountName, CatalogEntry, CredentialCatalog, ParsedConfig, Port, ValidatedConfig, activate};
use iron_vault_store::{OsFs, PermittedOrigins, StateDirLock, Vault, VaultIdentity};

use super::*;
use crate::deployment::DeploymentProfile;
use crate::secret_types_tests::{MARKER, assert_hides_marker};
use crate::trusted_path::ExpectedOwner;

fn config(route: &str, credential: &str) -> String {
    format!(
        r#"schema_version = 1

[listeners.local]
unix_socket = "/run/iron-vault/proxy.sock"

[callers.agent]
listener = "local"
token_hash = "blake2b:0123456789abcdef00112233445566778899aabbccddeeff0f1e2d3c4b5a6978"
routes = ["{route}"]

[routes.{route}]
prefix = "/{route}"
upstream = "https://api.{route}.example"
credential = "{credential}"
slot = {{ header = "X-Api-Key" }}
methods = ["GET"]
paths = ["/**"]
rate_limit = {{ requests = 60, per_seconds = 60, burst = 10 }}
"#
    )
}

struct NoAccounts;

impl AccountDirectory for NoAccounts {
    fn uid(&self, _: &AccountName) -> Option<u32> {
        None
    }

    fn service_account_uid(&self) -> u32 {
        990
    }

    fn overflow_uid(&self) -> u32 {
        65534
    }
}

/// A scratch state directory, removed on drop.
pub(crate) struct Scratch(pub(crate) PathBuf);

impl Scratch {
    pub(crate) fn new() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "iv-snapshot-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A vault holding a static record named `credential` that may reach `api.<route>.example`.
fn vault(scratch: &Scratch, route: &str, credential: &str) -> Vault {
    let lock = StateDirLock::acquire(&scratch.0).unwrap();
    let mut vault = Vault::create(&lock, &OsFs, VaultIdentity::generate()).unwrap();
    let origins = PermittedOrigins::new([(format!("api.{route}.example").parse().unwrap(), Port::HTTPS)].into()).unwrap();
    let material = CredentialMaterial::Static {
        key: MARKER.to_owned().into(),
    };
    vault.add(&lock, &OsFs, credential.parse().unwrap(), material, origins).unwrap();
    vault
}

fn policy(route: &str, credential: &str, vault: &Vault) -> ActivePolicy {
    let config = ValidatedConfig::try_from(ParsedConfig::from_toml(config(route, credential).as_bytes()).unwrap()).unwrap();
    activate(&config, vault, &NoAccounts).unwrap()
}

fn parts(policy: &ActivePolicy) -> (UpstreamClients, RateLimiter) {
    let clients = UpstreamClients::new(policy, DeploymentProfile::Development, ExpectedOwner { uid: 0 }).unwrap();
    (clients, RateLimiter::new(policy, Instant::now()))
}

fn snapshot(scratch: &Scratch, route: &str) -> Result<ServingSnapshot, SnapshotError> {
    let vault = vault(scratch, route, "key");
    let policy = policy(route, "key", &vault);
    let (clients, limiter) = parts(&policy);
    ServingSnapshot::new(policy, vault, clients, limiter)
}

fn route(name: &str) -> RouteName {
    name.parse().unwrap()
}

#[test]
fn a_request_that_loaded_a_snapshot_keeps_it_after_serve() {
    let (first, second) = (Scratch::new(), Scratch::new());
    let holder = SnapshotHolder::new(snapshot(&first, "old").unwrap());
    let in_flight = served(&holder);

    holder.serve(snapshot(&second, "new").unwrap());

    assert!(in_flight.policy().is_available(&route("old")));
    assert!(!in_flight.policy().is_available(&route("new")));
    assert!(in_flight.record(&"key".parse().unwrap()).is_some());
    let after = served(&holder);
    assert!(after.policy().is_available(&route("new")));
    assert!(!after.policy().is_available(&route("old")));
    assert!(!Arc::ptr_eq(&in_flight, &after));
}

fn served(holder: &SnapshotHolder) -> Arc<ServingSnapshot> {
    match holder.load() {
        Admission::Serve(snapshot) => snapshot,
        Admission::Refuse(reason) => panic!("expected a snapshot, got a refusal: {reason:?}"),
    }
}

fn refused(holder: &SnapshotHolder) -> Option<UnavailableReason> {
    match holder.load() {
        Admission::Refuse(reason) => Some(reason),
        Admission::Serve(_) => None,
    }
}

#[test]
fn loads_between_replacements_share_one_snapshot() {
    let scratch = Scratch::new();
    let holder = SnapshotHolder::new(snapshot(&scratch, "fx").unwrap());
    assert!(Arc::ptr_eq(&served(&holder), &served(&holder)));
}

#[test]
fn a_policy_activated_against_another_vault_is_refused() {
    let (a, b) = (Scratch::new(), Scratch::new());
    let activated_against = vault(&a, "fx", "key");
    let policy = policy("fx", "key", &activated_against);
    let other = vault(&b, "fx", "other_key");
    let (clients, limiter) = parts(&policy);

    let refused = ServingSnapshot::new(policy, other, clients, limiter).unwrap_err();

    assert_eq!(refused, SnapshotError::AvailableWithoutRecord { route: route("fx") });
    assert_eq!(
        refused.to_string(),
        "route fx is available in the policy, but the vault has no healthy record for its credential"
    );
}

/// Reports every credential as damaged, so activation marks every route unavailable.
struct AllUnusable;

impl CredentialCatalog for AllUnusable {
    fn entry(&self, _: &CredentialName) -> CatalogEntry {
        CatalogEntry::Unusable
    }
}

#[test]
fn a_route_unavailable_in_the_policy_but_healthy_in_the_vault_is_refused() {
    let scratch = Scratch::new();
    let vault = vault(&scratch, "fx", "key");
    let config = ValidatedConfig::try_from(ParsedConfig::from_toml(config("fx", "key").as_bytes()).unwrap()).unwrap();
    let policy = activate(&config, &AllUnusable, &NoAccounts).unwrap();
    let (clients, limiter) = parts(&policy);

    let refused = ServingSnapshot::new(policy, vault, clients, limiter).unwrap_err();

    assert_eq!(refused, SnapshotError::UnavailableWithRecord { route: route("fx") });
    assert_eq!(
        refused.to_string(),
        "route fx is unavailable in the policy, but the vault holds a healthy record for its credential"
    );
}

#[test]
fn the_record_for_a_route_carries_its_permitted_origins() {
    let scratch = Scratch::new();
    let snapshot = snapshot(&scratch, "fx").unwrap();
    let origins = snapshot.record(&"key".parse().unwrap()).unwrap().origins().as_set().clone();
    assert_eq!(origins, [("api.fx.example".parse().unwrap(), Port::HTTPS)].into());
}

#[test]
fn debug_hides_the_secret_material() {
    let scratch = Scratch::new();
    let holder = SnapshotHolder::new(snapshot(&scratch, "fx").unwrap());
    assert_hides_marker(&holder.load());
    assert_hides_marker(&holder);
}

#[test]
fn a_holder_with_no_snapshot_refuses_with_its_reason() {
    let holder = SnapshotHolder::refusing(UnavailableReason::Locked);
    assert_eq!(refused(&holder), Some(UnavailableReason::Locked));
}

#[test]
fn a_pause_refuses_with_checking_and_keeps_the_old_snapshot_running() {
    let scratch = Scratch::new();
    let holder = SnapshotHolder::new(snapshot(&scratch, "fx").unwrap());
    let in_flight = served(&holder);

    let pause = holder.pause();

    assert_eq!(refused(&holder), Some(UnavailableReason::Checking));
    assert!(!in_flight.is_withdrawn());
    drop(pause);
    assert_eq!(refused(&holder), Some(UnavailableReason::Checking), "an unended pause stays closed");
}

#[test]
fn a_pause_that_resumes_serves_the_new_snapshot_and_lets_the_old_one_finish() {
    let (first, second) = (Scratch::new(), Scratch::new());
    let holder = SnapshotHolder::new(snapshot(&first, "old").unwrap());
    let in_flight = served(&holder);

    holder.pause().resume(snapshot(&second, "new").unwrap());

    assert!(!in_flight.is_withdrawn());
    let after = served(&holder);
    assert!(!after.is_withdrawn());
    assert!(after.policy().is_available(&route("new")));
}

#[test]
fn a_pause_that_fails_refuses_with_the_failure_and_withdraws_the_old_snapshot() {
    let scratch = Scratch::new();
    let holder = SnapshotHolder::new(snapshot(&scratch, "fx").unwrap());
    let in_flight = served(&holder);

    holder.pause().fail(FailureReason::PolicyInvalid);

    assert_eq!(refused(&holder), Some(UnavailableReason::PolicyInvalid));
    assert!(in_flight.is_withdrawn());
}

#[test]
fn a_refusal_withdraws_every_snapshot_served_since_the_last_one() {
    let (first, second) = (Scratch::new(), Scratch::new());
    let holder = SnapshotHolder::new(snapshot(&first, "old").unwrap());
    let streaming = served(&holder);
    holder.pause().resume(snapshot(&second, "new").unwrap());
    let current = served(&holder);

    holder.refuse(UnavailableReason::Locked);

    assert!(streaming.is_withdrawn(), "a request still streaming from the replaced snapshot");
    assert!(current.is_withdrawn());
}

#[test]
fn a_snapshot_served_after_a_withdrawal_is_not_withdrawn() {
    let (first, second) = (Scratch::new(), Scratch::new());
    let holder = SnapshotHolder::new(snapshot(&first, "old").unwrap());
    let old = served(&holder);
    holder.refuse(UnavailableReason::RecoveryNeeded);

    holder.serve(snapshot(&second, "new").unwrap());

    assert!(old.is_withdrawn());
    assert!(!served(&holder).is_withdrawn());
}

#[test]
fn a_snapshot_no_holder_serves_is_never_withdrawn() {
    let scratch = Scratch::new();
    assert!(!snapshot(&scratch, "fx").unwrap().is_withdrawn());
}

#[test]
fn a_pause_on_a_holder_that_already_refuses_keeps_its_reason() {
    let scratch = Scratch::new();
    let holder = SnapshotHolder::new(snapshot(&scratch, "fx").unwrap());
    holder.refuse(UnavailableReason::PolicyInvalid);

    let pause = holder.pause();

    assert_eq!(refused(&holder), Some(UnavailableReason::PolicyInvalid));
    drop(pause);
    assert_eq!(
        refused(&holder),
        Some(UnavailableReason::PolicyInvalid),
        "an unended pause stays closed"
    );
}

#[test]
fn a_pause_from_policy_invalid_resumes_on_the_new_snapshot() {
    let (first, second) = (Scratch::new(), Scratch::new());
    let holder = SnapshotHolder::new(snapshot(&first, "old").unwrap());
    holder.refuse(UnavailableReason::PolicyInvalid);

    holder.pause().resume(snapshot(&second, "new").unwrap());

    assert!(served(&holder).policy().is_available(&route("new")));
}

#[test]
fn a_pause_from_policy_invalid_fails_with_the_failure_reason() {
    let scratch = Scratch::new();
    let holder = SnapshotHolder::new(snapshot(&scratch, "fx").unwrap());
    holder.refuse(UnavailableReason::PolicyInvalid);

    holder.pause().fail(FailureReason::RecoveryNeeded);

    assert_eq!(refused(&holder), Some(UnavailableReason::RecoveryNeeded));
}

const DRAIN: Duration = Duration::from_secs(5);

#[tokio::test(start_paused = true)]
async fn a_withdrawal_with_no_request_holding_a_snapshot_is_released_at_once() {
    let scratch = Scratch::new();
    let holder = SnapshotHolder::new(snapshot(&scratch, "fx").unwrap());

    assert_eq!(holder.refuse(UnavailableReason::Locked).released(DRAIN).await, 0);
}

#[tokio::test(start_paused = true)]
async fn a_withdrawal_waits_for_every_request_that_holds_a_served_snapshot() {
    let (first, second) = (Scratch::new(), Scratch::new());
    let holder = SnapshotHolder::new(snapshot(&first, "old").unwrap());
    let streaming = served(&holder);
    holder.pause().resume(snapshot(&second, "new").unwrap());
    let current = served(&holder);
    let mut withdrawn = holder.refuse(UnavailableReason::Locked);

    assert_eq!(withdrawn.released(DRAIN).await, 2, "both snapshots are held");
    drop(streaming);
    assert_eq!(withdrawn.released(DRAIN).await, 1, "the current snapshot is still held");
    drop(current);
    assert_eq!(withdrawn.released(DRAIN).await, 0);
}

#[tokio::test(start_paused = true)]
async fn a_release_during_the_wait_ends_it_before_the_drain() {
    let scratch = Scratch::new();
    let holder = SnapshotHolder::new(snapshot(&scratch, "fx").unwrap());
    let request = served(&holder);
    let mut withdrawn = holder.refuse(UnavailableReason::Locked);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(1)).await;
        drop(request);
    });
    let started = tokio::time::Instant::now();

    assert_eq!(withdrawn.released(DRAIN).await, 0);

    assert_eq!(started.elapsed(), Duration::from_secs(1));
}

#[tokio::test(start_paused = true)]
async fn a_checking_pause_withdraws_nothing_to_wait_for() {
    let scratch = Scratch::new();
    let holder = SnapshotHolder::new(snapshot(&scratch, "fx").unwrap());
    let request = served(&holder);

    assert_eq!(holder.refuse(UnavailableReason::Checking).released(DRAIN).await, 0);

    assert!(!request.is_withdrawn());
}
