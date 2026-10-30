use std::cell::RefCell;

use iron_vault_policy::{
    AccountDirectory, AccountName, Capabilities, CatalogEntry, CredentialCatalog, CredentialKind, CredentialName, ParsedConfig,
    ValidatedConfig, activate,
};

use super::*;

const SHARED_CA: &str = "/etc/iron-vault/ca/shared.pem";
const BROKEN_CA: &str = "/etc/iron-vault/ca/broken.pem";
const UNAVAILABLE_CA: &str = "/etc/iron-vault/ca/unavailable.pem";

/// Two routes share one pinned CA, two share a CA that fails to load, one uses the built-in roots, and one pins a CA
/// but is unavailable because its credential record is damaged.
const CONFIG: &str = r#"schema_version = 1

[listeners.local]
unix_socket = "/run/iron-vault/proxy.sock"

[callers.agent]
listener = "local"
token_hash = "blake2b:0123456789abcdef00112233445566778899aabbccddeeff0f1e2d3c4b5a6978"
routes = ["public", "shared_a", "shared_b", "broken_a", "broken_b", "damaged"]

[routes.public]
prefix = "/public"
upstream = "https://api.public.example"
credential = "key"
slot = { header = "X-Api-Key" }
methods = ["GET"]
paths = ["/**"]
rate_limit = { requests = 60, per_seconds = 60, burst = 10 }

[routes.shared_a]
prefix = "/shared-a"
upstream = "https://a.internal.example"
credential = "key"
slot = { header = "X-Api-Key" }
methods = ["GET"]
paths = ["/**"]
rate_limit = { requests = 60, per_seconds = 60, burst = 10 }
ca_file = "/etc/iron-vault/ca/shared.pem"

[routes.shared_b]
prefix = "/shared-b"
upstream = "https://b.internal.example"
credential = "key"
slot = { header = "X-Api-Key" }
methods = ["GET"]
paths = ["/**"]
rate_limit = { requests = 60, per_seconds = 60, burst = 10 }
ca_file = "/etc/iron-vault/ca/shared.pem"

[routes.broken_a]
prefix = "/broken-a"
upstream = "https://c.internal.example"
credential = "key"
slot = { header = "X-Api-Key" }
methods = ["GET"]
paths = ["/**"]
rate_limit = { requests = 60, per_seconds = 60, burst = 10 }
ca_file = "/etc/iron-vault/ca/broken.pem"

[routes.broken_b]
prefix = "/broken-b"
upstream = "https://d.internal.example"
credential = "key"
slot = { header = "X-Api-Key" }
methods = ["GET"]
paths = ["/**"]
rate_limit = { requests = 60, per_seconds = 60, burst = 10 }
ca_file = "/etc/iron-vault/ca/broken.pem"

[routes.damaged]
prefix = "/damaged"
upstream = "https://e.internal.example"
credential = "damaged_key"
slot = { header = "X-Api-Key" }
methods = ["GET"]
paths = ["/**"]
rate_limit = { requests = 60, per_seconds = 60, burst = 10 }
ca_file = "/etc/iron-vault/ca/unavailable.pem"
"#;

/// `key` is usable on every route upstream; `damaged_key` is unusable, so its route is unavailable.
struct Catalog(BTreeSet<(iron_vault_policy::Host, iron_vault_policy::Port)>);

impl CredentialCatalog for Catalog {
    fn entry(&self, name: &CredentialName) -> CatalogEntry {
        match name.as_str() {
            "damaged_key" => CatalogEntry::Unusable,
            _ => CatalogEntry::Usable {
                kind: CredentialKind::Static,
                origins: self.0.clone(),
            },
        }
    }
}

/// A host with no accounts: this config has no peer callers, so activation never looks one up.
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

fn policy() -> ActivePolicy {
    let config = ValidatedConfig::try_from(ParsedConfig::from_toml(CONFIG.as_bytes()).unwrap()).unwrap();
    let origins = config
        .routes()
        .values()
        .map(|route| (route.upstream().host().clone(), route.upstream().port()))
        .collect();
    activate(&config, &Capabilities::default(), &Catalog(origins), &NoAccounts).unwrap()
}

fn broken() -> PinnedCaError {
    PinnedCaError::NoCertificates {
        path: PathBuf::from(BROKEN_CA),
    }
}

/// Builds the clients with a loader that fails for [`BROKEN_CA`], recording every path it is asked for.
fn build(loaded: &RefCell<Vec<PathBuf>>) -> UpstreamClients {
    UpstreamClients::build(&policy(), TransportLimits::default(), |path| {
        loaded.borrow_mut().push(path.to_path_buf());
        match path == Path::new(BROKEN_CA) {
            true => Err(broken()),
            false => Ok(UpstreamTrust::BuiltIn),
        }
    })
    .unwrap()
}

fn route(name: &str) -> RouteName {
    name.parse().unwrap()
}

#[test]
fn each_distinct_ca_file_of_an_available_route_is_loaded_once_in_path_order() {
    let loaded = RefCell::new(Vec::new());
    build(&loaded);
    assert_eq!(loaded.into_inner(), [PathBuf::from(BROKEN_CA), PathBuf::from(SHARED_CA)]);
}

#[test]
fn routes_pinning_the_same_ca_share_its_client() {
    let clients = build(&RefCell::default());
    let a = clients.for_route(&route("shared_a")).unwrap();
    let b = clients.for_route(&route("shared_b")).unwrap();
    assert!(std::ptr::eq(a, b));
    assert!(std::ptr::eq(a, &clients.pinned[Path::new(SHARED_CA)]));
}

#[test]
fn a_route_without_a_ca_file_gets_the_built_in_client() {
    let clients = build(&RefCell::default());
    assert!(std::ptr::eq(clients.for_route(&route("public")).unwrap(), &clients.built_in));
}

#[test]
fn a_ca_that_fails_to_load_fails_only_its_routes() {
    let clients = build(&RefCell::default());
    ["broken_a", "broken_b"].iter().for_each(|name| {
        let error = clients.for_route(&route(name)).unwrap_err();
        assert!(
            matches!(&error, RouteClientError::PinnedCa { route: failed, source: PinnedClientError::Ca(source) } if *failed == route(name) && *source == broken()),
            "{error:?}"
        );
    });
    let unusable: Vec<&str> = clients.unusable_routes().map(|(route, _)| route.as_str()).collect();
    assert_eq!(unusable, ["broken_a", "broken_b"]);
    assert!(clients.for_route(&route("shared_a")).is_ok());
}

#[test]
fn an_unavailable_or_unknown_route_has_no_client() {
    let clients = build(&RefCell::default());
    ["damaged", "nowhere"].iter().for_each(|name| {
        assert!(matches!(clients.for_route(&route(name)), Err(RouteClientError::NotAvailable(failed)) if failed == route(name)));
    });
    assert!(!clients.pinned.contains_key(Path::new(UNAVAILABLE_CA)));
}
