//! An authorized request and its route's slot, for tests that resolve a credential record.

use iron_vault_policy::{
    ActivePolicy, AuthorizedRequest, Capabilities, CatalogEntry, CredentialCatalog, CredentialKind, CredentialName, Method, ParsedConfig,
    Port, RequestTarget, Slot, ValidatedConfig, activate, authorize,
};

/// One caller and one static-key route to `https://api.example.com` with a header slot.
const CONFIG: &str = r#"schema_version = 1

[listeners.local]
unix_socket = "/run/iron-vault/proxy.sock"

[callers.agent]
listener = "local"
token_hash = "blake2b:0123456789abcdef00112233445566778899aabbccddeeff0f1e2d3c4b5a6978"
routes = ["fx"]

[routes.fx]
prefix = "/fx"
upstream = "https://api.example.com"
credential = "fx_key"
slot = { header = "X-Api-Key" }
methods = ["GET"]
paths = ["/**"]
rate_limit = { requests = 60, per_seconds = 60, burst = 10 }
"#;

/// The route's upstream, the one origin a record must permit for the route to activate.
pub(crate) const HOST: &str = "api.example.com";

/// Every credential is a static key permitting [`HOST`].
struct Catalog;

impl CredentialCatalog for Catalog {
    fn entry(&self, _: &CredentialName) -> CatalogEntry {
        CatalogEntry::Usable {
            kind: CredentialKind::Static,
            origins: [(HOST.parse().unwrap(), Port::HTTPS)].into(),
        }
    }
}

/// The `fx` route's header slot and an authorized `GET /fx/latest` on it.
pub(crate) fn header_request() -> (Slot, AuthorizedRequest) {
    let config = ValidatedConfig::try_from(ParsedConfig::from_toml(CONFIG.as_bytes()).unwrap()).unwrap();
    let policy: ActivePolicy = activate(&config, &Capabilities::default(), &Catalog).unwrap();
    let (path, query) = RequestTarget::parse("/fx/latest").unwrap().into_parts();
    let request = authorize(&policy, &"agent".parse().unwrap(), &Method::Get, &path, query).unwrap();
    let slot = policy.route(request.route()).unwrap().slot().clone();
    (slot, request)
}
