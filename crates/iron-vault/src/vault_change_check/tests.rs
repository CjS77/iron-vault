// SPDX-License-Identifier: MPL-2.0
use std::collections::{BTreeMap, BTreeSet};

use iron_vault_policy::{AccountName, Host, ParsedConfig, Port};

use super::*;

/// A config whose one caller is granted every route; each route is `(name, credential, upstream, slot)`.
fn config(routes: &[(&str, &str, &str, &str)]) -> ValidatedConfig {
    let names = routes.iter().map(|(name, ..)| format!("\"{name}\"")).collect::<Vec<_>>().join(", ");
    let tables: String = routes
        .iter()
        .map(|(name, credential, upstream, slot)| {
            format!(
                r#"
[routes.{name}]
prefix = "/{name}"
upstream = "{upstream}"
credential = "{credential}"
slot = {slot}
methods = ["GET"]
paths = ["/**"]
rate_limit = {{ requests = 60, per_seconds = 60, burst = 10 }}
"#
            )
        })
        .collect();
    let toml = format!(
        r#"schema_version = 1

[listeners.local]
unix_socket = "/run/iron-vault/proxy.sock"

[callers.agent]
listener = "local"
token_hash = "blake2b:0123456789abcdef00112233445566778899aabbccddeeff0f1e2d3c4b5a6978"
routes = [{names}]
{tables}"#
    );
    ValidatedConfig::try_from(ParsedConfig::from_toml(toml.as_bytes()).unwrap()).unwrap()
}

const HEADER: &str = r#"{ header = "X-Api-Key" }"#;

/// Credentials in memory: each name is a usable static record permitting `api.example:443`.
struct Catalog(BTreeMap<CredentialName, CatalogEntry>);

impl Catalog {
    fn of(names: &[&str]) -> Self {
        Self(
            names
                .iter()
                .map(|name| (name.parse().unwrap(), usable(CredentialKind::Static, &[443])))
                .collect(),
        )
    }
}

impl CredentialCatalog for Catalog {
    fn entry(&self, name: &CredentialName) -> CatalogEntry {
        self.0.get(name).cloned().unwrap_or(CatalogEntry::Unknown)
    }
}

fn usable(kind: CredentialKind, ports: &[u16]) -> CatalogEntry {
    CatalogEntry::Usable {
        kind,
        origins: origins(ports),
    }
}

fn origins(ports: &[u16]) -> BTreeSet<(Host, Port)> {
    ports
        .iter()
        .map(|port| ("api.example".parse().unwrap(), port.to_string().parse().unwrap()))
        .collect()
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

fn check(config: &ValidatedConfig, catalog: &Catalog, change: &PlannedChange) -> Result<(), Vec<AffectedRoute>> {
    vault_change_check(config, catalog, &NoAccounts, change)
}

fn replace(name: &str, kind: CredentialKind, ports: &[u16]) -> PlannedChange {
    PlannedChange::Replace {
        name: name.parse().unwrap(),
        kind,
        origins: PermittedOrigins::new(origins(ports)).unwrap(),
    }
}

fn routes(affected: &[AffectedRoute]) -> Vec<String> {
    affected.iter().map(|affected| affected.route.to_string()).collect()
}

#[test]
fn removing_a_name_two_routes_use_returns_both_in_name_order() {
    let config = config(&[
        ("zeta", "fx", "https://api.example/v1", HEADER),
        ("alpha", "fx", "https://api.example/v2", HEADER),
        ("other", "brave", "https://api.example/v3", HEADER),
    ]);

    let affected = check(
        &config,
        &Catalog::of(&["fx", "brave"]),
        &PlannedChange::Remove("fx".parse().unwrap()),
    )
    .unwrap_err();

    assert_eq!(routes(&affected), ["alpha", "zeta"]);
    assert!(
        affected
            .iter()
            .all(|affected| matches!(affected.reason, ActivationError::UnknownCredential { .. }))
    );
}

#[test]
fn removing_a_damaged_record_a_route_uses_is_refused_too() {
    let config = config(&[("fx", "fx", "https://api.example/v1", HEADER)]);
    let catalog = Catalog([("fx".parse().unwrap(), CatalogEntry::Unusable)].into());

    let affected = check(&config, &catalog, &PlannedChange::Remove("fx".parse().unwrap())).unwrap_err();

    assert_eq!(routes(&affected), ["fx"]);
}

#[test]
fn origins_that_miss_a_routes_upstream_port_return_that_route() {
    let config = config(&[
        ("fx", "fx", "https://api.example:8443/v1", HEADER),
        ("fx_main", "fx", "https://api.example/v1", HEADER),
    ]);
    let catalog = Catalog([("fx".parse().unwrap(), usable(CredentialKind::Static, &[443, 8443]))].into());

    let affected = check(&config, &catalog, &replace("fx", CredentialKind::Static, &[443])).unwrap_err();

    assert_eq!(routes(&affected), ["fx"]);
    assert!(matches!(&affected[0].reason, ActivationError::OriginNotPermitted { port, .. } if port.get() == 8443));
}

#[test]
fn static_to_basic_under_a_header_slot_is_a_kind_mismatch() {
    let config = config(&[("fx", "fx", "https://api.example/v1", HEADER)]);

    let affected = check(&config, &Catalog::of(&["fx"]), &replace("fx", CredentialKind::Basic, &[443])).unwrap_err();

    assert_eq!(routes(&affected), ["fx"]);
    assert!(matches!(
        &affected[0].reason,
        ActivationError::SlotMismatch {
            kind: CredentialKind::Basic,
            ..
        }
    ));
}

#[test]
fn replacing_a_damaged_record_checks_its_routes_against_the_new_record() {
    let config = config(&[("fx", "fx", "https://api.example/v1", HEADER)]);
    let catalog = Catalog([("fx".parse().unwrap(), CatalogEntry::Unusable)].into());

    assert_eq!(check(&config, &catalog, &replace("fx", CredentialKind::Static, &[443])), Ok(()));
    assert!(check(&config, &catalog, &replace("fx", CredentialKind::Static, &[8443])).is_err());
}

#[test]
fn an_unused_name_is_ok_to_remove_or_replace() {
    let config = config(&[("fx", "fx", "https://api.example/v1", HEADER)]);
    let catalog = Catalog::of(&["fx", "old"]);

    assert_eq!(check(&config, &catalog, &PlannedChange::Remove("old".parse().unwrap())), Ok(()));
    assert_eq!(check(&config, &catalog, &replace("old", CredentialKind::Basic, &[8443])), Ok(()));
}

#[test]
fn a_failure_on_a_route_that_does_not_use_the_name_is_not_the_changes() {
    let config = config(&[
        ("fx", "fx", "https://api.example/v1", HEADER),
        ("gone", "missing", "https://api.example/v2", HEADER),
    ]);

    assert_eq!(
        check(&config, &Catalog::of(&["fx"]), &replace("fx", CredentialKind::Static, &[443])),
        Ok(())
    );
}
