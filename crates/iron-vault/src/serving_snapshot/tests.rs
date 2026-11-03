use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

use iron_vault_kinds::CredentialMaterial;
use iron_vault_policy::{
    AccountDirectory, AccountName, Capabilities, CatalogEntry, CredentialCatalog, ParsedConfig, Port, ValidatedConfig, activate,
};
use iron_vault_store::{OsFs, PermittedOrigins, StateDirLock, Vault, VaultIdentity};

use super::*;
use crate::deployment::DeploymentProfile;
use crate::secret_types_tests::{MARKER, assert_hides_marker};
use crate::trusted_path::ExpectedOwner;
use crate::upstream::client::TransportLimits;

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
    activate(&config, &Capabilities::default(), vault, &NoAccounts).unwrap()
}

fn parts(policy: &ActivePolicy) -> (UpstreamClients, RateLimiter) {
    let clients = UpstreamClients::new(
        policy,
        DeploymentProfile::Development,
        ExpectedOwner { uid: 0 },
        TransportLimits::default(),
    )
    .unwrap();
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
fn a_request_that_loaded_a_snapshot_keeps_it_after_replace() {
    let (first, second) = (Scratch::new(), Scratch::new());
    let holder = SnapshotHolder::new(snapshot(&first, "old").unwrap());
    let in_flight = holder.load();

    holder.replace(snapshot(&second, "new").unwrap());

    assert!(in_flight.policy().is_available(&route("old")));
    assert!(!in_flight.policy().is_available(&route("new")));
    assert!(in_flight.record(&"key".parse().unwrap()).is_some());
    let after = holder.load();
    assert!(after.policy().is_available(&route("new")));
    assert!(!after.policy().is_available(&route("old")));
    assert!(!Arc::ptr_eq(&in_flight, &after));
}

#[test]
fn loads_between_replacements_share_one_snapshot() {
    let scratch = Scratch::new();
    let holder = SnapshotHolder::new(snapshot(&scratch, "fx").unwrap());
    assert!(Arc::ptr_eq(&holder.load(), &holder.load()));
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
    let policy = activate(&config, &Capabilities::default(), &AllUnusable, &NoAccounts).unwrap();
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
    assert_hides_marker(&*holder.load());
    assert_hides_marker(&holder);
}
