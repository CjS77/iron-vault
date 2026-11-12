use std::cell::RefCell;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use iron_vault_kinds::CredentialMaterial;
use iron_vault_policy::{
    AccountDirectory, AccountName, AuthzError, CallerToken, CatalogEntry, CredentialCatalog, ParsedConfig, Port, Refusal, TokenHash,
    ValidatedConfig, activate,
};
use iron_vault_store::{OsFs, PermittedOrigins, RecordId, Source, StateDirLock, Vault, VaultIdentity};
use secrecy::ExposeSecret;

use super::*;
use crate::deployment::DeploymentProfile;
use crate::secret_types_tests::{MARKER, assert_hides_marker};
use crate::serving_snapshot::tests::Scratch;
use crate::trusted_path::ExpectedOwner;
use crate::upstream::client::TransportLimits;
use crate::upstream::clients::UpstreamClients;

mod refusal;

const FX_SECRET: &str = "fx-secret-4f1a";
/// The marker secret, so the `Debug` check can look for it in every form.
const BRAVE_SECRET: &str = MARKER;
const VENICE_SECRET: &str = "venice-secret-7b3d";
const FX_MCP_UID: u32 = 1001;
const TOKEN_BYTES: [u8; 32] = [7; 32];

/// The [§6](../../../../design/iron-vault-specification.md#6-credential-records-and-configuration) example with a real
/// token hash for `brave-cli` and a Basic route for `naomi-backoffice`.
fn config() -> String {
    let hash = TokenHash::of(&CallerToken::from_bytes(TOKEN_BYTES));
    format!(
        r#"schema_version = 1

[listeners.local]
unix_socket = "/run/iron-vault/proxy.sock"

[callers.fx-mcp]
listener = "local"
auth = "peer"
user = "fx-mcp"
routes = ["fx"]

[listeners.loopback]
address = "127.0.0.1:7878"

[callers.brave-cli]
listener = "loopback"
token_hash = "{hash}"
routes = ["brave"]

[callers.naomi-backoffice]
listener = "naomi-backoffice"
auth = "isolated-network"
routes = ["venice", "brave", "billing"]

[listeners.naomi-backoffice]
address = "10.20.0.2:7878"
tls_certificate = "/etc/iron-vault/tls/server.crt"
tls_key = "/etc/iron-vault/tls/server.key"

[routes.fx]
prefix = "/fx"
upstream = "https://api.fx.example"
credential = "fx_key"
slot = {{ query = "access_key" }}
methods = ["GET"]
paths = ["/latest", "/historical/**"]
rate_limit = {{ requests = 60, per_seconds = 60, burst = 10 }}

[routes.venice]
prefix = "/venice"
upstream = "https://api.venice.ai/api/v1"
credential = "venice"
slot = {{ header = "Authorization", format = "Bearer {{}}" }}
methods = ["POST"]
paths = ["/chat/completions"]
rate_limit = {{ requests = 120, per_seconds = 60, burst = 20 }}

[routes.brave]
prefix = "/brave"
upstream = "https://api.search.brave.com"
credential = "brave"
slot = {{ header = "X-Subscription-Token" }}
methods = ["GET"]
paths = ["/res/v1/web/search"]
rate_limit = {{ requests = 60, per_seconds = 60, burst = 10 }}

[routes.billing]
prefix = "/billing"
upstream = "https://api.billing.example"
credential = "billing"
slot = "basic"
methods = ["GET"]
paths = ["/**"]
rate_limit = {{ requests = 60, per_seconds = 60, burst = 10 }}
"#
    )
}

/// `fx-mcp` is uid 1001; nobody else has an account.
struct Accounts;

impl AccountDirectory for Accounts {
    fn uid(&self, account: &AccountName) -> Option<u32> {
        (account.as_str() == "fx-mcp").then_some(FX_MCP_UID)
    }

    fn service_account_uid(&self) -> u32 {
        990
    }

    fn overflow_uid(&self) -> u32 {
        65534
    }
}

fn origins(host: &str) -> PermittedOrigins {
    PermittedOrigins::new([(host.parse().unwrap(), Port::HTTPS)].into()).unwrap()
}

fn record(name: &str, material: CredentialMaterial, host: &str) -> (CredentialName, CredentialRecord) {
    let record = CredentialRecord::new(
        RecordId::new_random(),
        name.parse().unwrap(),
        material,
        origins(host),
        Source::DirectEntry,
    )
    .unwrap();
    (name.parse().unwrap(), record)
}

fn key(secret: &str) -> CredentialMaterial {
    CredentialMaterial::Static { key: secret.into() }
}

fn records() -> BTreeMap<CredentialName, CredentialRecord> {
    let basic = CredentialMaterial::Basic {
        username: "alice".into(),
        password: "s3cret".into(),
    };
    [
        record("fx_key", key(FX_SECRET), "api.fx.example"),
        record("brave", key(BRAVE_SECRET), "api.search.brave.com"),
        record("venice", key(VENICE_SECRET), "api.venice.ai"),
        record("billing", basic, "api.billing.example"),
    ]
    .into()
}

/// The records as activation sees them.
struct Catalog<'a>(&'a BTreeMap<CredentialName, CredentialRecord>);

impl CredentialCatalog for Catalog<'_> {
    fn entry(&self, name: &CredentialName) -> CatalogEntry {
        self.0.get(name).map_or(CatalogEntry::Unknown, |record| CatalogEntry::Usable {
            kind: record.kind(),
            origins: record.origins().as_set().clone(),
        })
    }
}

fn validated() -> ValidatedConfig {
    ValidatedConfig::try_from(ParsedConfig::from_toml(config().as_bytes()).unwrap()).unwrap()
}

/// In-memory sources that record every credential lookup, the only way to reach a record's `resolve`.
struct TestSources {
    policy: ActivePolicy,
    limiter: RateLimiter,
    records: BTreeMap<CredentialName, CredentialRecord>,
    looked_up: RefCell<Vec<String>>,
    start: Instant,
}

impl TestSources {
    fn new() -> Self {
        let records = records();
        let policy = activate(&validated(), &Catalog(&records), &Accounts).unwrap();
        let start = Instant::now();
        let limiter = RateLimiter::new(&policy, start);
        Self {
            policy,
            limiter,
            records,
            looked_up: RefCell::new(Vec::new()),
            start,
        }
    }

    /// Sources whose limiter is built from `config` instead of the policy requests are authorized against, so a charge
    /// can meet a route or grant the limiter does not know.
    fn with_limiter_config(config: &str) -> Self {
        let mut sources = Self::new();
        let parsed = ParsedConfig::from_toml(config.as_bytes()).unwrap();
        let validated = ValidatedConfig::try_from(parsed).unwrap();
        let policy = activate(&validated, &Catalog(&sources.records), &Accounts).unwrap();
        sources.limiter = RateLimiter::new(&policy, sources.start);
        sources
    }

    /// Buckets start empty and refill at one token a second, so one second in each holds exactly one token.
    fn one_token(&self) -> Instant {
        self.start + Duration::from_secs(1)
    }

    fn run(&self, tags: &ConnectionTags, head: RequestHead) -> Result<Prepared, PipelineRefusal> {
        self.run_identified(tags, head).0
    }

    /// As [`run`](Self::run), with what the pipeline found before it stopped.
    fn run_identified(&self, tags: &ConnectionTags, head: RequestHead) -> (Result<Prepared, PipelineRefusal>, Identified) {
        let mut identified = Identified::default();
        (run(self, tags, head, self.one_token(), &mut identified), identified)
    }

    fn looked_up(&self) -> Vec<String> {
        self.looked_up.borrow().clone()
    }
}

impl Sources for TestSources {
    fn policy(&self) -> &ActivePolicy {
        &self.policy
    }

    fn limiter(&self) -> &RateLimiter {
        &self.limiter
    }

    fn record(&self, credential: &CredentialName) -> Option<&CredentialRecord> {
        self.looked_up.borrow_mut().push(credential.to_string());
        self.records.get(credential)
    }
}

fn tags(listener: &str, peer_uid: Option<u32>) -> ConnectionTags {
    ConnectionTags::new(listener.parse().unwrap(), peer_uid)
}

fn loopback() -> ConnectionTags {
    tags("loopback", None)
}

fn head(method: &str, target: &str, headers: &[(&str, &str)]) -> RequestHead {
    RequestHead {
        method: method.to_owned(),
        target: target.to_owned(),
        headers: headers
            .iter()
            .map(|(n, v)| (n.parse().unwrap(), HeaderValue::try_from(*v).unwrap()))
            .collect(),
    }
}

fn bearer() -> String {
    format!("Bearer {}", CallerToken::from_bytes(TOKEN_BYTES).expose_once().expose_secret())
}

/// A `brave-cli` search with its token and `slot` in the slot header, plus `extra` headers.
fn brave_search(slot: &str, extra: &[(&str, &str)]) -> RequestHead {
    let token = bearer();
    let headers: Vec<_> = [("Proxy-Authorization", token.as_str()), ("X-Subscription-Token", slot)]
        .into_iter()
        .chain(extra.iter().copied())
        .collect();
    head("GET", "/brave/res/v1/web/search?q=rust", &headers)
}

/// Every header of the checked request as text.
fn headers(prepared: &Prepared) -> Vec<(String, String)> {
    let pairs = prepared.request().headers().iter();
    pairs
        .map(|(n, v)| (n.as_str().to_owned(), String::from_utf8(v.as_bytes().to_vec()).unwrap()))
        .collect()
}

/// The places in the checked request that hold `secret`: header names, and `url` for the URL.
fn holders(prepared: &Prepared, secret: &str) -> Vec<String> {
    let url = prepared.request().url().as_str().contains(secret).then(|| "url".to_owned());
    let in_headers = headers(prepared).into_iter().filter(|(_, v)| v.contains(secret)).map(|(n, _)| n);
    url.into_iter().chain(in_headers).collect()
}

#[test]
fn a_header_slot_holds_the_credential_and_nothing_else_does() {
    let sources = TestSources::new();
    let prepared = sources.run(&loopback(), brave_search("placeholder", &[])).unwrap();

    assert_eq!(holders(&prepared, BRAVE_SECRET), ["X-Subscription-Token"]);
    assert!(headers(&prepared).contains(&("X-Subscription-Token".to_owned(), BRAVE_SECRET.to_owned())));
    assert!(headers(&prepared).iter().all(|(n, _)| n != "Proxy-Authorization"));
    assert_eq!(
        prepared.request().url().as_str(),
        "https://api.search.brave.com/res/v1/web/search?q=rust"
    );
    assert_eq!(prepared.route().as_str(), "brave");
    assert_eq!(prepared.credential().as_str(), "brave");
    assert!(prepared.patterns().iter().any(|pattern| pattern == BRAVE_SECRET.as_bytes()));
}

#[test]
fn the_callers_accept_encoding_is_replaced_by_the_services_and_other_caller_headers_kept() {
    let sources = TestSources::new();
    let extra = [
        ("Accept-Encoding", "gzip, br"),
        ("accept-encoding", "zstd"),
        ("Accept", "application/json"),
    ];
    let prepared = sources.run(&loopback(), brave_search("placeholder", &extra)).unwrap();

    let sent = headers(&prepared);
    let accept_encoding: Vec<_> = sent
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("accept-encoding"))
        .map(|(_, value)| value.as_str())
        .collect();
    assert_eq!(accept_encoding, ["gzip, deflate, br"], "{sent:?}");
    assert!(sent.iter().any(|(name, _)| name.eq_ignore_ascii_case("accept")), "{sent:?}");
}

#[test]
fn a_query_slot_holds_the_credential_and_nothing_else_does() {
    let sources = TestSources::new();
    let request = head("GET", "/fx/latest?base=USD&access_key=placeholder", &[]);
    let prepared = sources.run(&tags("local", Some(FX_MCP_UID)), request).unwrap();

    assert_eq!(holders(&prepared, FX_SECRET), ["url"]);
    assert_eq!(
        prepared.request().url().query(),
        Some(format!("base=USD&access_key={FX_SECRET}").as_str())
    );
}

#[test]
fn a_basic_slot_holds_the_credential_and_nothing_else_does() {
    let sources = TestSources::new();
    let request = head("GET", "/billing/v1/invoices", &[("Authorization", "Basic placeholder")]);
    let prepared = sources.run(&tags("naomi-backoffice", None), request).unwrap();

    let token = "YWxpY2U6czNjcmV0"; // base64("alice:s3cret")
    assert_eq!(holders(&prepared, token), ["Authorization"]);
    let expected = [
        ("Accept-Encoding".to_owned(), "gzip, deflate, br".to_owned()),
        ("Authorization".to_owned(), format!("Basic {token}")),
    ];
    assert_eq!(headers(&prepared), expected);
}

#[test]
fn an_unauthenticated_request_is_not_charged_or_resolved() {
    let sources = TestSources::new();
    let mut unauthenticated = brave_search("placeholder", &[]);
    unauthenticated.headers.retain(|(name, _)| name.as_str() != "Proxy-Authorization");

    let refused = sources.run(&loopback(), unauthenticated).unwrap_err();

    assert_eq!(refused, PipelineRefusal::Unauthenticated(Unauthenticated));
    assert!(sources.looked_up().is_empty());
    assert!(
        sources.run(&loopback(), brave_search("placeholder", &[])).is_ok(),
        "the one token is still there"
    );
}

#[test]
fn an_ungranted_request_is_not_charged_or_resolved() {
    let sources = TestSources::new();
    let token = bearer();
    let fx_from_brave_cli = head("GET", "/fx/latest", &[("Proxy-Authorization", token.as_str())]);

    let refused = sources.run(&loopback(), fx_from_brave_cli).unwrap_err();

    let forbidden = AuthzError::Forbidden {
        route: "fx".parse().unwrap(),
        reason: Refusal::NotGranted,
    };
    assert_eq!(refused, PipelineRefusal::Authz(forbidden));
    assert!(sources.looked_up().is_empty());
    let fx = head("GET", "/fx/latest", &[]);
    assert!(
        sources.run(&tags("local", Some(FX_MCP_UID)), fx).is_ok(),
        "the fx token is still there"
    );
}

#[test]
fn a_rate_limited_request_is_not_resolved() {
    let sources = TestSources::new();
    let at_start = run(
        &sources,
        &loopback(),
        brave_search("placeholder", &[]),
        sources.start,
        &mut Identified::default(),
    );

    assert!(matches!(at_start, Err(PipelineRefusal::Charge(ChargeError::Limited(_)))));
    assert!(sources.looked_up().is_empty());
}

#[test]
fn a_charged_request_spends_its_token() {
    let sources = TestSources::new();
    assert!(sources.run(&loopback(), brave_search("placeholder", &[])).is_ok());
    let second = sources.run(&loopback(), brave_search("placeholder", &[]));
    assert!(matches!(second, Err(PipelineRefusal::Charge(ChargeError::Limited(_)))));
    assert_eq!(sources.looked_up(), ["brave"]);
}

#[test]
fn ambiguous_framing_is_refused_before_the_charge() {
    let sources = TestSources::new();
    let framing = [("Content-Length", "3"), ("Content-Length", "4")];

    let refused = sources.run(&loopback(), brave_search("placeholder", &framing)).unwrap_err();

    assert_eq!(refused, PipelineRefusal::Sanitize(SanitizeError::ConflictingContentLength));
    assert!(sources.looked_up().is_empty());
    assert!(
        sources.run(&loopback(), brave_search("placeholder", &[])).is_ok(),
        "the one token is still there"
    );
}

#[test]
fn a_malformed_target_is_not_charged_or_resolved() {
    let sources = TestSources::new();
    let token = bearer();
    let traversal = head("GET", "/brave/../fx/latest", &[("Proxy-Authorization", &token)]);

    let refused = sources.run(&loopback(), traversal).unwrap_err();

    assert!(matches!(refused, PipelineRefusal::Target(_)), "{refused:?}");
    assert!(sources.looked_up().is_empty());
    assert!(
        sources.run(&loopback(), brave_search("placeholder", &[])).is_ok(),
        "the one token is still there"
    );
}

#[test]
fn a_method_off_the_allowlist_is_refused_before_authorization() {
    let sources = TestSources::new();
    let token = bearer();
    let refused = sources.run(
        &loopback(),
        head("TRACE", "/brave/res/v1/web/search", &[("Proxy-Authorization", &token)]),
    );
    assert_eq!(refused.unwrap_err(), PipelineRefusal::Method);
    assert!(sources.looked_up().is_empty());
}

#[test]
fn a_foreign_marker_in_the_slot_is_refused_after_resolving_only_the_routes_credential() {
    let sources = TestSources::new();

    let refused = sources.run(&loopback(), brave_search("{iv:fx_key}", &[])).unwrap_err();

    assert_eq!(refused, PipelineRefusal::Assemble(AssembleError::ForeignMarker));
    assert_eq!(sources.looked_up(), ["brave"], "the marker's credential is never looked up");
}

#[test]
fn the_routes_own_marker_in_the_slot_is_replaced_by_its_credential() {
    let sources = TestSources::new();
    let prepared = sources.run(&loopback(), brave_search("{iv:brave}", &[])).unwrap();
    assert_eq!(holders(&prepared, BRAVE_SECRET), ["X-Subscription-Token"]);
    assert_eq!(sources.looked_up(), ["brave"]);
}

#[test]
fn a_marker_outside_the_slot_is_forwarded_as_inert_text() {
    let sources = TestSources::new();
    let prepared = sources
        .run(&loopback(), brave_search("placeholder", &[("X-Note", "{iv:fx_key}")]))
        .unwrap();

    assert!(headers(&prepared).contains(&("X-Note".to_owned(), "{iv:fx_key}".to_owned())));
    assert!(holders(&prepared, FX_SECRET).is_empty());
    assert_eq!(sources.looked_up(), ["brave"]);
}

#[test]
fn a_route_without_a_healthy_record_is_refused_unsent() {
    let mut sources = TestSources::new();
    sources.records.remove(&"brave".parse::<CredentialName>().unwrap());

    let refused = sources.run(&loopback(), brave_search("placeholder", &[])).unwrap_err();

    let missing = PipelineRefusal::NoHealthyRecord {
        route: "brave".parse().unwrap(),
        credential: "brave".parse().unwrap(),
    };
    assert_eq!(refused, missing);
    assert_eq!(refused.to_string(), "route brave has no healthy record for credential brave");
}

#[test]
fn prepare_reads_a_serving_snapshot() {
    let scratch = Scratch::new();
    let lock = StateDirLock::acquire(&scratch.0).unwrap();
    let mut vault = Vault::create(&lock, &OsFs, VaultIdentity::generate()).unwrap();
    records().into_iter().for_each(|(name, record)| {
        let host = record.origins().as_set().first().unwrap().0.to_string();
        let material = match record.material() {
            CredentialMaterial::Static { key } => CredentialMaterial::Static {
                key: key.expose_secret().into(),
            },
            CredentialMaterial::Basic { username, password } => CredentialMaterial::Basic {
                username: username.expose_secret().into(),
                password: password.expose_secret().into(),
            },
        };
        vault.add(&lock, &OsFs, name, material, origins(&host)).unwrap();
    });
    let policy = activate(&validated(), &vault, &Accounts).unwrap();
    let clients = UpstreamClients::new(
        &policy,
        DeploymentProfile::Development,
        ExpectedOwner { uid: 0 },
        TransportLimits::default(),
    )
    .unwrap();
    let start = Instant::now();
    let limiter = RateLimiter::new(&policy, start);
    let snapshot = ServingSnapshot::new(policy, vault, clients, limiter).unwrap();

    let prepared = prepare(
        &snapshot,
        &loopback(),
        brave_search("placeholder", &[]),
        start + Duration::from_secs(1),
        &mut Identified::default(),
    )
    .unwrap();

    assert_eq!(holders(&prepared, BRAVE_SECRET), ["X-Subscription-Token"]);
}

#[test]
fn debug_hides_the_method_target_and_header_values() {
    let target = format!("/brave/search?q={MARKER}");
    assert_hides_marker(&head("GET", &target, &[("X-Subscription-Token", MARKER)]));
    assert_hides_marker(&head(MARKER, "/brave/search", &[]));

    let sources = TestSources::new();
    assert_hides_marker(&sources.run(&loopback(), brave_search("placeholder", &[])).unwrap());
}
