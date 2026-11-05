use std::collections::BTreeSet;

use iron_vault_policy::{
    AccountDirectory, AccountName, Capabilities, CatalogEntry, CredentialCatalog, CredentialKind, CredentialName, ParsedConfig,
    ValidatedConfig, activate,
};
use iron_vault_store::{PermittedOrigins, RecordDamage};

use super::*;
use crate::standing::RecordSummary;

const RECORD_ID: &str = "0b7c2f9e-6a51-4d1e-9d43-1f2a3b4c5d6e";

/// Routes `fx` and `fx-history` use `fx`, granted to `fx-mcp` and to both `fx-mcp` and `reports`; `brave` uses another
/// credential.
fn config() -> ValidatedConfig {
    let route = |name: &str, credential: &str| {
        format!(
            r#"
[routes.{name}]
prefix = "/{name}"
upstream = "https://api.fx.example/v1"
credential = "{credential}"
slot = {{ header = "X-Api-Key" }}
methods = ["GET"]
paths = ["/**"]
rate_limit = {{ requests = 60, per_seconds = 60, burst = 10 }}
"#
        )
    };
    let caller = |name: &str, hash: char, routes: &str| {
        format!(
            "\n[callers.{name}]\nlistener = \"local\"\ntoken_hash = \"blake2b:{}\"\nroutes = [{routes}]\n",
            hash.to_string().repeat(64)
        )
    };
    let toml = [
        "schema_version = 1\n\n[listeners.local]\nunix_socket = \"/run/iron-vault/proxy.sock\"\n".to_owned(),
        caller("reports", 'b', r#""fx-history""#),
        caller("fx-mcp", 'a', r#""fx", "fx-history", "brave""#),
        route("fx", "fx"),
        route("fx-history", "fx"),
        route("brave", "brave"),
    ]
    .concat();
    ValidatedConfig::try_from(ParsedConfig::from_toml(toml.as_bytes()).unwrap()).unwrap()
}

/// `brave` is usable; `fx` is usable when `healthy`, and damaged otherwise.
struct Catalog {
    healthy: bool,
}

impl CredentialCatalog for Catalog {
    fn entry(&self, name: &CredentialName) -> CatalogEntry {
        match (name.as_str(), self.healthy) {
            ("fx", false) => CatalogEntry::Unusable,
            _ => CatalogEntry::Usable {
                kind: CredentialKind::Static,
                origins: [("api.fx.example".parse().unwrap(), Port::HTTPS)].into(),
            },
        }
    }
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

fn policy(healthy: bool) -> ActivePolicy {
    activate(&config(), &Capabilities::default(), &Catalog { healthy }, &NoAccounts).unwrap()
}

fn origin(host: &str, port: u16) -> (Host, Port) {
    (host.parse().unwrap(), Port::try_from(port).unwrap())
}

fn replace() -> PlannedChange {
    let origins: BTreeSet<_> = [origin("api.fx.example", 443), origin("api.fx.example", 8443)].into();
    PlannedChange::Replace {
        name: "fx".parse().unwrap(),
        kind: CredentialKind::Static,
        origins: PermittedOrigins::new(origins).unwrap(),
    }
}

fn healthy() -> CredentialStanding {
    CredentialStanding {
        name: "fx".parse().unwrap(),
        standing: Standing::Healthy,
        unavailable_routes: Vec::new(),
        summary: Some(RecordSummary {
            kind: CredentialKind::Static,
            origins: vec![origin("api.fx.example", 443)],
        }),
    }
}

fn damaged() -> CredentialStanding {
    CredentialStanding {
        name: "fx".parse().unwrap(),
        standing: Standing::Damaged(RecordDamage::Missing),
        unavailable_routes: vec!["fx".parse().unwrap(), "fx-history".parse().unwrap()],
        summary: None,
    }
}

/// The plan's record for `before`, under [`RECORD_ID`].
fn current(before: &CredentialStanding) -> CurrentRecord {
    CurrentRecord {
        record_id: RECORD_ID.parse().unwrap(),
        standing: before.standing,
        summary: before.summary.clone(),
    }
}

#[test]
fn a_healthy_replace_shows_the_old_record_both_kinds_and_origins_and_the_routes_with_their_callers() {
    let summary = VaultChangeSummary::new(replace(), current(&healthy()), &healthy(), &policy(true));

    assert_eq!(
        summary.to_string(),
        format!(
            "replace credential fx\n  record: {RECORD_ID} -> a new record ID, assigned when the change is written\n  \
             kind: static -> static\n  origins: api.fx.example:443 -> api.fx.example:443, api.fx.example:8443\n  \
             routes using fx: fx (callers: fx-mcp), fx-history (callers: fx-mcp, reports)\n"
        )
    );
}

#[test]
fn a_damaged_replace_says_why_the_old_kind_is_unknown_and_which_routes_come_back() {
    let summary = VaultChangeSummary::new(replace(), current(&damaged()), &damaged(), &policy(false));
    let text = summary.to_string();

    assert!(text.contains("  kind: unknown (record damaged: missing) -> static\n"), "{text}");
    assert!(
        text.contains("  origins: unknown (record damaged: missing) -> api.fx.example:443"),
        "{text}"
    );
    assert!(text.ends_with("  routes available again: fx, fx-history\n"), "{text}");
}

#[test]
fn a_removal_of_a_name_no_route_uses_says_none() {
    let mut standing = healthy();
    standing.name = "old_key".parse().unwrap();
    let summary = VaultChangeSummary::new(
        PlannedChange::Remove("old_key".parse().unwrap()),
        current(&standing),
        &standing,
        &policy(true),
    );

    assert_eq!(
        summary.to_string(),
        format!(
            "remove credential old_key\n  record: {RECORD_ID}\n  kind: static\n  origins: api.fx.example:443\n  \
             routes using old_key: none\n"
        )
    );
}

#[test]
fn a_damaged_removal_says_why_its_kind_and_origins_are_unknown_and_lists_no_routes_available_again() {
    let standing = CredentialStanding {
        name: "old_key".parse().unwrap(),
        standing: Standing::Damaged(RecordDamage::Missing),
        unavailable_routes: Vec::new(),
        summary: None,
    };
    let summary = VaultChangeSummary::new(
        PlannedChange::Remove("old_key".parse().unwrap()),
        current(&standing),
        &standing,
        &policy(true),
    );

    assert_eq!(
        summary.to_string(),
        format!(
            "remove credential old_key\n  record: {RECORD_ID}\n  kind: unknown (record damaged: missing)\n  \
             origins: unknown (record damaged: missing)\n  routes using old_key: none\n"
        )
    );
}
