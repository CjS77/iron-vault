use std::cell::Cell;

use secrecy::ExposeSecret;

use super::*;
use crate::activation::{Capabilities, CatalogEntry, CredentialCatalog, activate};
use crate::caller_token::CALLER_TOKEN_BYTES;
use crate::config::ParsedConfig;
use crate::name::CredentialName;
use crate::token_hash::TokenHash;
use crate::validated::ValidatedConfig;

/// Reports every credential as unusable: identification never looks at routes, so their availability is irrelevant.
struct NoCredentials;

impl CredentialCatalog for NoCredentials {
    fn entry(&self, _: &CredentialName) -> CatalogEntry {
        CatalogEntry::Unusable
    }
}

/// The token made of 32 copies of `byte`; each test caller has its own byte.
fn token(byte: u8) -> String {
    CallerToken::from_bytes([byte; CALLER_TOKEN_BYTES])
        .expose_once()
        .expose_secret()
        .to_owned()
}

fn hash(byte: u8) -> String {
    TokenHash::of(&CallerToken::from_bytes([byte; CALLER_TOKEN_BYTES])).to_string()
}

const ALPHA: u8 = 1;
const BETA: u8 = 2;
const GAMMA: u8 = 3;
const DELTA: u8 = 4;
const UNKNOWN: u8 = 9;

/// One listener per mechanism: `sock` (socket), `net` (isolated network), `local` (two token callers on
/// `Proxy-Authorization`), `dedicated` (a token caller on `X-Iron-Vault-Token`), `explicit` (a token caller whose
/// listener names `Proxy-Authorization` as its `token_header`), and `empty` (no callers).
fn policy() -> ActivePolicy {
    let doc = format!(
        r#"schema_version = 1

[listeners.sock]
unix_socket = "/run/iron-vault/cli.sock"

[listeners.net]
address = "10.20.0.2:7878"
tls_certificate = "/etc/iron-vault/tls/server.crt"
tls_key = "/etc/iron-vault/tls/server.key"

[listeners.local]
unix_socket = "/run/iron-vault/proxy.sock"

[listeners.dedicated]
address = "127.0.0.1:7878"
token_header = "X-Iron-Vault-Token"

[listeners.explicit]
address = "127.0.0.1:7879"
token_header = "Proxy-Authorization"

[listeners.empty]
address = "127.0.0.1:7880"

[callers.cli]
listener = "sock"
auth = "socket"
routes = ["fx"]

[callers.naomi]
listener = "net"
auth = "isolated-network"
routes = ["fx"]

[callers.alpha]
listener = "local"
token_hash = "{}"
routes = ["fx"]

[callers.beta]
listener = "local"
token_hash = "{}"
routes = ["fx"]

[callers.gamma]
listener = "dedicated"
token_hash = "{}"
routes = ["fx"]

[callers.delta]
listener = "explicit"
token_hash = "{}"
routes = ["fx"]

[routes.fx]
prefix = "/fx"
upstream = "https://api.fx.example"
credential = "fx_key"
slot = {{ query = "access_key" }}
methods = ["GET"]
paths = ["/**"]
rate_limit = {{ requests = 60, per_seconds = 60, burst = 10 }}
"#,
        hash(ALPHA),
        hash(BETA),
        hash(GAMMA),
        hash(DELTA),
    );
    let config = ValidatedConfig::try_from(ParsedConfig::from_toml(doc.as_bytes()).unwrap()).unwrap();
    activate(&config, &Capabilities::default(), &NoCredentials).unwrap()
}

fn headers(fields: &[(&str, &str)]) -> Vec<(HeaderName, HeaderValue)> {
    fields
        .iter()
        .map(|(name, value)| (name.parse().unwrap(), HeaderValue::try_from(*value).unwrap()))
        .collect()
}

fn identify(listener: &str, fields: &[(&str, &str)]) -> Result<CallerName, Unauthenticated> {
    identify_caller(&policy(), &listener.parse().unwrap(), &headers(fields))
}

fn identified(listener: &str, fields: &[(&str, &str)]) -> String {
    identify(listener, fields).unwrap().as_str().to_owned()
}

fn bearer(byte: u8) -> String {
    format!("Bearer {}", token(byte))
}

#[test]
fn a_socket_listener_names_its_caller() {
    assert_eq!(identified("sock", &[]), "cli");
}

#[test]
fn an_isolated_network_listener_names_its_caller() {
    assert_eq!(identified("net", &[]), "naomi");
}

#[test]
fn a_token_on_a_listener_identified_caller_is_not_checked() {
    assert_eq!(identified("sock", &[("Proxy-Authorization", "Bearer nonsense")]), "cli");
    assert_eq!(identified("net", &[("Proxy-Authorization", &bearer(ALPHA))]), "naomi");
}

#[test]
fn a_bearer_token_names_its_caller() {
    assert_eq!(identified("local", &[("Proxy-Authorization", &bearer(ALPHA))]), "alpha");
    assert_eq!(identified("local", &[("proxy-authorization", &bearer(BETA))]), "beta");
}

#[test]
fn the_bearer_scheme_is_case_insensitive() {
    ["bearer", "BEARER", "bEaReR"].iter().for_each(|scheme| {
        let value = format!("{scheme} {}", token(BETA));
        assert_eq!(identified("local", &[("Proxy-Authorization", &value)]), "beta", "{scheme}");
    });
}

#[test]
fn a_dedicated_header_holds_the_whole_token() {
    assert_eq!(identified("dedicated", &[("X-Iron-Vault-Token", &token(GAMMA))]), "gamma");
    assert_eq!(identified("dedicated", &[("x-iron-vault-token", &token(GAMMA))]), "gamma");
}

#[test]
fn a_dedicated_header_listener_ignores_proxy_authorization() {
    assert_eq!(
        identify("dedicated", &[("Proxy-Authorization", &bearer(GAMMA))]),
        Err(Unauthenticated)
    );
    let both = [("Proxy-Authorization", "Bearer nonsense"), ("X-Iron-Vault-Token", &token(GAMMA))];
    assert_eq!(identified("dedicated", &both), "gamma");
    assert_eq!(
        identify("dedicated", &[("X-Iron-Vault-Token", &bearer(GAMMA))]),
        Err(Unauthenticated)
    );
}

#[test]
fn naming_proxy_authorization_as_token_header_keeps_the_bearer_form() {
    assert_eq!(identified("explicit", &[("Proxy-Authorization", &bearer(DELTA))]), "delta");
    assert_eq!(
        identify("explicit", &[("Proxy-Authorization", &token(DELTA))]),
        Err(Unauthenticated)
    );
}

#[test]
fn a_missing_token_is_refused() {
    assert_eq!(identify("local", &[]), Err(Unauthenticated));
    assert_eq!(identify("local", &[("Authorization", &bearer(ALPHA))]), Err(Unauthenticated));
    assert_eq!(identify("dedicated", &[]), Err(Unauthenticated));
}

#[test]
fn a_repeated_token_header_is_refused() {
    let same = bearer(ALPHA);
    assert_eq!(
        identify("local", &[("Proxy-Authorization", &same), ("proxy-authorization", &same)]),
        Err(Unauthenticated)
    );
    let mixed = [("Proxy-Authorization", "Bearer nonsense"), ("Proxy-Authorization", &same)];
    assert_eq!(identify("local", &mixed), Err(Unauthenticated));
    let dedicated = token(GAMMA);
    assert_eq!(
        identify(
            "dedicated",
            &[("X-Iron-Vault-Token", &dedicated), ("X-Iron-Vault-Token", &dedicated)]
        ),
        Err(Unauthenticated)
    );
}

#[test]
fn a_wrong_scheme_is_refused() {
    let alpha = token(ALPHA);
    [
        format!("Basic {alpha}"),
        alpha.clone(),
        format!("Bearer  {alpha}"),
        format!("Bearer\t{alpha}"),
        format!(" Bearer {alpha}"),
        format!("Bearer{alpha}"),
        format!("Bearer {alpha} "),
        "Bearer ".to_owned(),
        "Bearer".to_owned(),
        String::new(),
    ]
    .iter()
    .for_each(|value| {
        assert_eq!(
            identify("local", &[("Proxy-Authorization", value)]),
            Err(Unauthenticated),
            "{value:?}"
        )
    });
}

#[test]
fn a_malformed_token_is_refused() {
    let alpha = token(ALPHA);
    let unprefixed = alpha.replacen("ivt_", "ivx_", 1);
    let truncated = &alpha[..alpha.len() - 1];
    let bad_character = format!("{}=", &alpha[..alpha.len() - 1]);
    [unprefixed.as_str(), truncated, bad_character.as_str(), "ivt_"]
        .iter()
        .for_each(|presented| {
            let value = format!("Bearer {presented}");
            assert_eq!(
                identify("local", &[("Proxy-Authorization", &value)]),
                Err(Unauthenticated),
                "{presented}"
            );
            assert_eq!(
                identify("dedicated", &[("X-Iron-Vault-Token", presented)]),
                Err(Unauthenticated),
                "{presented}"
            );
        });
}

#[test]
fn an_unknown_token_is_refused() {
    assert_eq!(
        identify("local", &[("Proxy-Authorization", &bearer(UNKNOWN))]),
        Err(Unauthenticated)
    );
    assert_eq!(
        identify("dedicated", &[("X-Iron-Vault-Token", &token(UNKNOWN))]),
        Err(Unauthenticated)
    );
}

#[test]
fn a_token_for_another_listener_is_refused() {
    assert_eq!(identify("local", &[("Proxy-Authorization", &bearer(DELTA))]), Err(Unauthenticated));
    assert_eq!(
        identify("explicit", &[("Proxy-Authorization", &bearer(ALPHA))]),
        Err(Unauthenticated)
    );
    assert_eq!(
        identify("dedicated", &[("X-Iron-Vault-Token", &token(ALPHA))]),
        Err(Unauthenticated)
    );
}

#[test]
fn a_listener_without_callers_identifies_no_one() {
    assert_eq!(identify("empty", &[("Proxy-Authorization", &bearer(ALPHA))]), Err(Unauthenticated));
    assert_eq!(
        identify("unconfigured", &[("Proxy-Authorization", &bearer(ALPHA))]),
        Err(Unauthenticated)
    );
}

#[test]
fn matching_visits_every_candidate_even_when_the_first_matches() {
    let visits = Cell::new(0);
    let comparisons = [("first", true), ("second", false), ("third", false)]
        .into_iter()
        .inspect(|_| visits.set(visits.get() + 1));
    assert_eq!(sole_match(comparisons), Some("first"));
    assert_eq!(visits.get(), 3);
}

#[test]
fn matching_needs_exactly_one_match() {
    assert_eq!(sole_match([("a", false), ("b", true), ("c", false)].into_iter()), Some("b"));
    assert_eq!(sole_match([("a", false), ("b", false)].into_iter()), None);
    assert_eq!(sole_match([("a", true), ("b", true)].into_iter()), None);
    assert_eq!(sole_match(std::iter::empty::<(&str, bool)>()), None);
}

#[test]
fn a_refusal_discloses_nothing() {
    let marker = token(UNKNOWN);
    let refusals = [
        identify("local", &[("Proxy-Authorization", &format!("Bearer {marker}"))]),
        identify("dedicated", &[("X-Iron-Vault-Token", &marker)]),
        identify("local", &[("Proxy-Authorization", &format!("Basic {marker}"))]),
    ];
    refusals.iter().for_each(|refusal| {
        let error = refusal.clone().unwrap_err();
        [error.to_string(), format!("{error:?}"), format!("{error:#?}")]
            .iter()
            .for_each(|text| {
                [
                    "ivt_",
                    &marker[4..],
                    "Bearer",
                    "Proxy-Authorization",
                    "X-Iron-Vault-Token",
                    "alpha",
                    "gamma",
                ]
                .iter()
                .for_each(|secret| assert!(!text.contains(secret), "{text} contains {secret}"));
            });
    });
}
