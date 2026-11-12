//! Checked requests for the test upstream, built through the public policy API exactly as the service builds them:
//! parse a config, activate it, authorize, assemble and run the final check.

use std::collections::BTreeSet;

use iron_vault_policy::{
    AccountDirectory, AccountName, ActivePolicy, BoundCredential, CatalogEntry, CheckedRequest, CredentialCatalog, CredentialKind,
    CredentialName, HeaderName, HeaderValue, Host, Method, OutgoingRequest, ParsedConfig, Port, RequestTarget, UpstreamTarget,
    ValidatedConfig, activate, authorize, final_check, sanitize,
};
use secrecy::SecretString;

/// The listener's caller-token header; the default when a listener names none.
const TOKEN_HEADER: &str = "Proxy-Authorization";

/// One caller granted two routes to `origin`: `query` fills an `access_key` query parameter, `header` an `X-Api-Key`
/// header. Both upstreams sit under the base path `/v1`.
fn config(origin: &str) -> String {
    format!(
        r#"schema_version = 1

[listeners.local]
unix_socket = "/run/iron-vault/proxy.sock"

[callers.agent]
listener = "local"
token_hash = "blake2b:0123456789abcdef00112233445566778899aabbccddeeff0f1e2d3c4b5a6978"
routes = ["query", "header"]

[routes.query]
prefix = "/query"
upstream = "{origin}/v1"
credential = "key"
slot = {{ query = "access_key" }}
methods = ["GET", "POST"]
paths = ["/**"]
rate_limit = {{ requests = 60, per_seconds = 60, burst = 10 }}

[routes.header]
prefix = "/header"
upstream = "{origin}/v1"
credential = "key"
slot = {{ header = "X-Api-Key" }}
methods = ["GET", "POST"]
paths = ["/**"]
rate_limit = {{ requests = 60, per_seconds = 60, burst = 10 }}
"#
    )
}

/// Permits the one static credential on exactly the test upstream's origin.
struct Catalog(BTreeSet<(Host, Port)>);

impl CredentialCatalog for Catalog {
    fn entry(&self, _: &CredentialName) -> CatalogEntry {
        CatalogEntry::Usable {
            kind: CredentialKind::Static,
            origins: self.0.clone(),
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

/// The test config for `origin` (`https://localhost:<port>`), activated.
pub fn policy(origin: &str) -> ActivePolicy {
    let config = ValidatedConfig::try_from(ParsedConfig::from_toml(config(origin).as_bytes()).unwrap()).unwrap();
    let origins = config
        .routes()
        .values()
        .map(|route| (route.upstream().host().clone(), route.upstream().port()))
        .collect();
    activate(&config, &Catalog(origins), &NoAccounts).unwrap()
}

/// The checked request the service would send for the caller request `method target` with `headers`, filling the
/// selected route's slot with `secret`.
pub fn checked(origin: &str, method: Method, target: &str, headers: &[(&str, &str)], secret: &str) -> CheckedRequest {
    let policy = policy(origin);
    let (path, query) = RequestTarget::parse(target).unwrap().into_parts();
    let authorized = authorize(&policy, &"agent".parse().unwrap(), &method, &path, query).unwrap();
    let route = policy.route(authorized.route()).unwrap();
    let target = UpstreamTarget::build(route.upstream(), &authorized).unwrap();
    let outgoing = sanitize(typed(headers), &TOKEN_HEADER.parse().unwrap()).unwrap();
    let value = iron_vault_policy::SlotValue::new(SecretString::from(secret)).unwrap();
    let request = OutgoingRequest::assemble(&authorized, target, outgoing, route.slot(), route.credential(), &value).unwrap();
    let permitted = [(route.upstream().host().clone(), route.upstream().port())].into();
    final_check(
        request,
        &authorized,
        route.upstream(),
        route.slot(),
        &BoundCredential::new(&value, &permitted),
    )
    .unwrap()
}

fn typed(headers: &[(&str, &str)]) -> Vec<(HeaderName, HeaderValue)> {
    headers
        .iter()
        .map(|(name, value)| (name.parse().unwrap(), HeaderValue::try_from(*value).unwrap()))
        .collect()
}
