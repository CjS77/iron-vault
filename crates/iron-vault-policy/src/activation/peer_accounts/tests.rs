use std::cell::RefCell;

use super::*;
use crate::config::ParsedConfig;
use crate::test_accounts::{FakeAccounts, SERVICE_UID};

/// Two request sockets, `a` and `b`, one token caller, and the route every caller is granted.
const BASE: &str = r#"schema_version = 1

[listeners.a]
unix_socket = "/run/iron-vault/a.sock"

[listeners.b]
unix_socket = "/run/iron-vault/b.sock"

[listeners.loopback]
address = "127.0.0.1:7878"

[callers.tok]
listener = "loopback"
token_hash = "blake2b:0123456789abcdef00112233445566778899aabbccddeeff0f1e2d3c4b5a6978"
routes = ["fx"]

[routes.fx]
prefix = "/fx"
upstream = "https://api.fx.example"
credential = "fx_key"
slot = { query = "access_key" }
methods = ["GET"]
paths = ["/**"]
rate_limit = { requests = 60, per_seconds = 60, burst = 10 }
"#;

fn n<T: std::str::FromStr<Err: std::fmt::Debug>>(s: &str) -> T {
    s.parse().unwrap()
}

/// [`BASE`] with a peer caller for each `(caller, listener, user)`.
fn config(peers: &[(&str, &str, &str)]) -> ValidatedConfig {
    let doc = peers.iter().fold(BASE.to_owned(), |doc, (caller, listener, user)| {
        format!("{doc}\n[callers.{caller}]\nlistener = \"{listener}\"\nauth = \"peer\"\nuser = \"{user}\"\nroutes = [\"fx\"]\n")
    });
    ValidatedConfig::try_from(ParsedConfig::from_toml(doc.as_bytes()).unwrap()).unwrap()
}

fn resolved(peers: &[(&str, &str, &str)], accounts: &FakeAccounts) -> Result<BTreeMap<CallerName, u32>, Vec<ActivationError>> {
    resolve(&config(peers), accounts)
}

fn uids(map: &BTreeMap<CallerName, u32>) -> Vec<(&str, u32)> {
    map.iter().map(|(name, uid)| (name.as_str(), *uid)).collect()
}

#[test]
fn peer_callers_resolve_to_their_uids() {
    let map = resolved(&[("cli", "a", "code"), ("mcp", "a", "fx-mcp")], &FakeAccounts::host()).unwrap();
    assert_eq!(uids(&map), [("cli", 1000), ("mcp", 1001)]);
}

#[test]
fn a_config_without_peer_callers_resolves_nothing() {
    assert!(resolved(&[], &FakeAccounts::host()).unwrap().is_empty());
}

#[test]
fn an_unknown_account_is_refused() {
    let err = resolved(&[("cli", "a", "nobody-here")], &FakeAccounts::host()).unwrap_err();
    assert_eq!(
        err,
        [ActivationError::UnknownAccount {
            caller: n("cli"),
            user: n("nobody-here")
        }]
    );
    assert_eq!(
        err[0].to_string(),
        "caller cli names user nobody-here, which is not an account on this host"
    );
}

#[test]
fn root_is_refused_by_name_and_by_uid() {
    let accounts = FakeAccounts::with(&[("toor", 0)]);
    let err = resolved(&[("cli", "a", "root"), ("alias", "b", "toor")], &accounts).unwrap_err();
    let expected = [
        ActivationError::PrivilegedAccount {
            caller: n("alias"),
            user: n("toor"),
        },
        ActivationError::PrivilegedAccount {
            caller: n("cli"),
            user: n("root"),
        },
    ];
    assert_eq!(err, expected);
}

#[test]
fn the_service_account_is_refused_by_name_and_by_uid() {
    let accounts = FakeAccounts::with(&[("svc-alias", SERVICE_UID)]);
    let err = resolved(&[("cli", "a", "iron-vault"), ("other", "b", "svc-alias")], &accounts).unwrap_err();
    assert!(
        err.iter().all(|e| matches!(e, ActivationError::PrivilegedAccount { .. })) && err.len() == 2,
        "{err:?}"
    );
    assert_eq!(
        err[0].to_string(),
        "caller cli names user iron-vault, which is root or the service account; neither may be a peer account"
    );
}

#[test]
fn two_names_for_one_uid_on_a_listener_are_refused() {
    let accounts = FakeAccounts::with(&[("code-alias", 1000)]);
    let err = resolved(&[("cli", "a", "code"), ("cli2", "a", "code-alias")], &accounts).unwrap_err();
    assert_eq!(
        err,
        [ActivationError::SharedPeerAccount {
            listener: n("a"),
            uid: 1000,
            callers: vec![n("cli"), n("cli2")],
        }]
    );
    assert_eq!(
        err[0].to_string(),
        "callers cli, cli2 on listener a name accounts with uid 1000, so one account would identify more than one caller"
    );
}

#[test]
fn two_names_for_one_uid_on_different_listeners_are_accepted() {
    let accounts = FakeAccounts::with(&[("code-alias", 1000)]);
    let map = resolved(&[("cli", "a", "code"), ("cli2", "b", "code-alias")], &accounts).unwrap();
    assert_eq!(uids(&map), [("cli", 1000), ("cli2", 1000)]);
}

#[test]
fn a_refused_account_is_not_also_reported_as_shared() {
    let accounts = FakeAccounts::with(&[("toor", 0)]);
    let err = resolved(&[("cli", "a", "root"), ("cli2", "a", "toor")], &accounts).unwrap_err();
    assert!(
        err.iter().all(|e| matches!(e, ActivationError::PrivilegedAccount { .. })) && err.len() == 2,
        "{err:?}"
    );
}

#[test]
fn every_refusal_is_reported_unknown_and_privileged_before_shared() {
    let accounts = FakeAccounts::with(&[("code-alias", 1000)]);
    let peers = [
        ("a1", "a", "code"),
        ("a2", "a", "code-alias"),
        ("b1", "b", "ghost"),
        ("b2", "b", "root"),
    ];
    let err = resolved(&peers, &accounts).unwrap_err();
    let expected = [
        ActivationError::UnknownAccount {
            caller: n("b1"),
            user: n("ghost"),
        },
        ActivationError::PrivilegedAccount {
            caller: n("b2"),
            user: n("root"),
        },
        ActivationError::SharedPeerAccount {
            listener: n("a"),
            uid: 1000,
            callers: vec![n("a1"), n("a2")],
        },
    ];
    assert_eq!(err, expected);
}

#[test]
fn the_resolved_map_is_identical_across_runs() {
    let peers = [("zeta", "b", "fx-other"), ("alpha", "a", "fx-mcp"), ("mid", "a", "code")];
    let first = resolved(&peers, &FakeAccounts::host()).unwrap();
    let again: Vec<_> = (0..8).map(|_| resolved(&peers, &FakeAccounts::host()).unwrap()).collect();
    assert!(again.iter().all(|map| uids(map) == uids(&first)));
    assert_eq!(uids(&first), [("alpha", 1001), ("mid", 1000), ("zeta", 1002)]);
}

/// Records which names are looked up, to show only peer callers' accounts are.
struct Recording(RefCell<Vec<String>>);

impl AccountDirectory for Recording {
    fn uid(&self, name: &AccountName) -> Option<u32> {
        self.0.borrow_mut().push(name.as_str().to_owned());
        Some(1000)
    }

    fn service_account_uid(&self) -> u32 {
        SERVICE_UID
    }
}

#[test]
fn only_peer_callers_are_looked_up() {
    let accounts = Recording(RefCell::default());
    assert!(resolve(&config(&[("cli", "a", "code")]), &accounts).is_ok());
    assert_eq!(*accounts.0.borrow(), ["code"]);
}
