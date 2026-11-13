// SPDX-License-Identifier: MPL-2.0
use std::cell::Cell;

use secrecy::ExposeSecret;

use super::*;
use crate::activation::{CatalogEntry, CredentialCatalog, activate};
use crate::caller_token::CALLER_TOKEN_BYTES;
use crate::config::ParsedConfig;
use crate::name::CredentialName;
use crate::test_accounts::{FakeAccounts, SERVICE_UID};
use crate::token_hash::TokenHash;
use crate::validated::ValidatedConfig;

/// Reports every credential as unusable, which is enough because identification never looks at routes.
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

/// One listener per mechanism: `sock` (peer caller `cli`, account `code`), `ops-sock` (peer caller `ops`, account
/// `fx-other`), `net` (isolated network), `local` (two token callers on `Proxy-Authorization`), `dedicated` (a token
/// caller on `X-Iron-Vault-Token`), `explicit` (a token caller whose listener names `Proxy-Authorization` as its
/// `token_header`), and `empty` (no callers).
fn policy() -> ActivePolicy {
    let doc = format!(
        r#"schema_version = 1

[listeners.sock]
unix_socket = "/run/iron-vault/cli.sock"

[listeners.ops-sock]
unix_socket = "/run/iron-vault/ops.sock"

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
auth = "peer"
user = "code"
routes = ["fx"]

[callers.ops]
listener = "ops-sock"
auth = "peer"
user = "fx-other"
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
    activate(&config, &NoCredentials, &FakeAccounts::host()).unwrap()
}

fn headers(fields: &[(&str, &str)]) -> Vec<(HeaderName, HeaderValue)> {
    fields
        .iter()
        .map(|(name, value)| (name.parse().unwrap(), HeaderValue::try_from(*value).unwrap()))
        .collect()
}

/// Identifies a caller connecting over a transport that reports no peer uid, as TCP does.
fn identify(listener: &str, fields: &[(&str, &str)]) -> Result<CallerName, Unauthenticated> {
    identify_from(listener, None, fields)
}

fn identify_from(listener: &str, peer_uid: Option<u32>, fields: &[(&str, &str)]) -> Result<CallerName, Unauthenticated> {
    identify_caller(&policy(), &listener.parse().unwrap(), peer_uid, &headers(fields))
}

fn identified(listener: &str, fields: &[(&str, &str)]) -> String {
    identify(listener, fields).unwrap().as_str().to_owned()
}

fn bearer(byte: u8) -> String {
    format!("Bearer {}", token(byte))
}

/// The uids [`FakeAccounts::host`] gives `code` (caller `cli`), `fx-other` (caller `ops`) and an unconfigured account.
const CODE_UID: u32 = 1000;
const FX_OTHER_UID: u32 = 1002;
const UNCONFIGURED_UID: u32 = 1001;

#[test]
fn a_peer_uid_names_its_caller() {
    assert_eq!(identify_from("sock", Some(CODE_UID), &[]).unwrap().as_str(), "cli");
    assert_eq!(identify_from("ops-sock", Some(FX_OTHER_UID), &[]).unwrap().as_str(), "ops");
}

#[test]
fn another_listeners_peer_uid_is_refused() {
    assert_eq!(identify_from("sock", Some(FX_OTHER_UID), &[]), Err(Unauthenticated));
    assert_eq!(identify_from("ops-sock", Some(CODE_UID), &[]), Err(Unauthenticated));
}

#[test]
fn an_unconfigured_or_missing_peer_uid_is_refused() {
    [Some(UNCONFIGURED_UID), Some(0), Some(SERVICE_UID), None]
        .iter()
        .for_each(|uid| assert_eq!(identify_from("sock", *uid, &[]), Err(Unauthenticated), "{uid:?}"));
}

#[test]
fn a_token_on_a_peer_listener_is_not_checked() {
    let alpha = bearer(ALPHA);
    let fields = [("Proxy-Authorization", alpha.as_str())];
    assert_eq!(identify_from("sock", Some(UNCONFIGURED_UID), &fields), Err(Unauthenticated));
    assert_eq!(identify_from("sock", None, &fields), Err(Unauthenticated));
    assert_eq!(identify_from("sock", Some(CODE_UID), &fields).unwrap().as_str(), "cli");
}

#[test]
fn a_peer_uid_does_not_identify_on_other_listeners() {
    assert_eq!(identify_from("local", Some(CODE_UID), &[]), Err(Unauthenticated));
    let alpha = bearer(ALPHA);
    assert_eq!(
        identify_from("local", Some(CODE_UID), &[("Proxy-Authorization", &alpha)])
            .unwrap()
            .as_str(),
        "alpha"
    );
    assert_eq!(identify_from("net", Some(CODE_UID), &[]).unwrap().as_str(), "naomi");
}

#[test]
fn an_isolated_network_listener_names_its_caller() {
    assert_eq!(identified("net", &[]), "naomi");
}

#[test]
fn a_token_on_an_isolated_network_listener_is_not_checked() {
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

/// Token enrollment as the owner does it: `iron-vault caller-token` prints a token and its `token_hash` line, the owner
/// pastes that line into a config, and once the config is active the printed token names the caller.
#[test]
fn an_enrolled_token_hash_validates_and_its_printed_token_names_the_caller() {
    let issued = CallerToken::from_bytes(std::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11)));
    let printed_hash = TokenHash::of(&issued).to_string();
    let printed_token = issued.expose_once().expose_secret().to_owned();
    let doc = format!(
        r#"schema_version = 1

[listeners.local]
address = "127.0.0.1:7878"

[callers.agent]
listener = "local"
token_hash = "{printed_hash}"
routes = ["fx"]

[routes.fx]
prefix = "/fx"
upstream = "https://api.fx.example"
credential = "fx_key"
slot = {{ query = "access_key" }}
methods = ["GET"]
paths = ["/**"]
rate_limit = {{ requests = 60, per_seconds = 60, burst = 10 }}
"#
    );
    let config = ValidatedConfig::try_from(ParsedConfig::from_toml(doc.as_bytes()).unwrap()).unwrap();
    let policy = activate(&config, &NoCredentials, &FakeAccounts::host()).unwrap();
    let authorization = format!("Bearer {printed_token}");
    let caller = identify_caller(
        &policy,
        &"local".parse().unwrap(),
        None,
        &headers(&[("Proxy-Authorization", &authorization)]),
    );
    assert_eq!(caller.unwrap().as_str(), "agent");
}
