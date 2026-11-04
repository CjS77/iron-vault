//! Activation: checking a validated config against facts only the running service knows (spec §2, §3.3, §3.4, §3.9).
//!
//! The configuration cannot know which credential records exist, which hosts they permit, whether this machine can
//! confirm a touch, or which uid each peer account has. The service supplies those facts as [`Capabilities`], a
//! [`CredentialCatalog`] and an [`AccountDirectory`]; activation then either refuses the whole configuration or
//! produces the [`ActivePolicy`] that requests are served under.

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;

use crate::account_name::AccountName;
use crate::confirmation::Confirmation;
use crate::credential_kind::CredentialKind;
use crate::display::joined;
use crate::host::Host;
use crate::name::{CallerName, CredentialName, ListenerName, RouteName};
use crate::port::Port;
use crate::route::RouteConfig;
use crate::validated::ValidatedConfig;

/// What this service installation can do that some routes depend on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Capabilities {
    /// Whether a supported touch-confirmation provider exists; v0 never has one (spec §2).
    pub touch_provider: bool,
}

/// The service's view of the vault's credential records, as activation needs it.
///
/// The service implements this over the store, so this crate checks records without reading them itself.
pub trait CredentialCatalog {
    /// What the vault holds under `name`.
    fn entry(&self, name: &CredentialName) -> CatalogEntry;
}

/// The host's local accounts, as activation needs them to resolve each peer caller's `user` (spec §3.4).
///
/// The service implements this over the host's account database, so this crate resolves accounts without reading it.
pub trait AccountDirectory {
    /// The uid of the account named `name`, or none when no such account exists.
    fn uid(&self, name: &AccountName) -> Option<u32>;

    /// The uid the service runs as, which no peer caller may name.
    fn service_account_uid(&self) -> u32;

    /// The uid the kernel reports for a peer whose uid has no mapping in the service's user namespace, which no peer
    /// caller may name: every unmapped process shares it, so it cannot identify one account.
    fn overflow_uid(&self) -> u32;
}

/// One credential name's standing in the vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogEntry {
    /// No record has this name.
    Unknown,
    /// A record has this name but is damaged or needs login, so its routes are unavailable (spec §3.9).
    ///
    /// It carries no origins: a damaged record cannot be trusted to report them.
    Unusable,
    /// A record has this name and can serve requests.
    Usable {
        /// The kind the record declares, which decides the slots its routes may use (spec §5.2).
        kind: CredentialKind,
        /// The exact host and port pairs the record permits its secret to reach (spec §3.3).
        origins: BTreeSet<(Host, Port)>,
    },
}

/// A validated config activated against the service's capabilities, credential catalog and account directory.
///
/// Only [`activate`] builds one. Unavailable routes stay listed so the service can answer for them, each with its
/// causes; every other route may serve requests.
///
/// Each peer caller's account is resolved to a uid once, here, so identifying a caller is a uid comparison and a
/// missing, privileged or overflow account refuses the config rather than a request. The uids are a snapshot: an
/// account renamed, deleted or recreated with another uid takes effect at the next activation, which a reload performs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivePolicy {
    config: ValidatedConfig,
    unavailable: BTreeMap<RouteName, BTreeSet<UnavailableCause>>,
    peer_uids: BTreeMap<CallerName, u32>,
}

/// Why a route of an active policy serves no request (glossary: *Unavailable route*). A route may have both.
///
/// Neither cause refuses the policy: each is a fault local to its routes, which the owner fixes and then reloads (§3.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UnavailableCause {
    /// The route's credential record is damaged or needs login.
    CredentialUnusable,
    /// The route's pinned CA could not be loaded (§3.7).
    PinnedCaUnavailable,
}

/// Why a validated config cannot be activated.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ActivationError {
    /// The route requires touch confirmation, which this service cannot provide; it is never silently downgraded.
    #[error("route {route} sets confirm = \"touch\", but no touch confirmation provider is available")]
    TouchUnavailable {
        /// The route.
        route: RouteName,
    },
    /// The route names a credential the vault does not hold, which invalidates the whole config (spec §3.9).
    #[error("route {route} uses credential {credential}, which the vault does not hold")]
    UnknownCredential {
        /// The route.
        route: RouteName,
        /// The missing credential.
        credential: CredentialName,
    },
    /// The route's upstream is not a host and port its credential record permits.
    #[error("route {route} sends credential {credential} to {host}:{}, which its record does not permit", .port.get())]
    OriginNotPermitted {
        /// The route.
        route: RouteName,
        /// The route's credential.
        credential: CredentialName,
        /// The route's upstream host.
        host: Host,
        /// The route's upstream port.
        port: Port,
    },
    /// The route's slot cannot be filled by its credential's kind, so every request to it would fail (spec §5.2).
    #[error("route {route} uses a {} credential, {credential}, on a slot that kind cannot fill", .kind.as_str())]
    SlotMismatch {
        /// The route.
        route: RouteName,
        /// The route's credential.
        credential: CredentialName,
        /// The credential's kind.
        kind: CredentialKind,
    },
    /// The peer caller's `user` names no account on this host (spec §3.4).
    #[error("caller {caller} names user {user}, which is not an account on this host")]
    UnknownAccount {
        /// The peer caller.
        caller: CallerName,
        /// The account it names.
        user: AccountName,
    },
    /// The peer caller's `user` resolves to root or to the service account, which are never peer accounts (spec §3.4).
    ///
    /// Root is already a host administrator, outside the threat model (spec §1.2), so it needs no caller identity;
    /// a program run as root to use a route holds far more than that route. The service account connecting to its own
    /// request socket is never legitimate: a process doing so is the service misbehaving or something running with
    /// its privileges.
    #[error("caller {caller} names user {user}, which is root or the service account; neither may be a peer account")]
    PrivilegedAccount {
        /// The peer caller.
        caller: CallerName,
        /// The account it names.
        user: AccountName,
    },
    /// The peer caller's `user` resolves to the kernel's overflow uid, `nobody` by default (spec §3.4).
    ///
    /// The kernel reports that uid for every peer whose uid has no mapping in the service's user namespace, so in a
    /// container or sandbox it would match many unrelated processes rather than one account.
    #[error("caller {caller} names user {user}, the overflow uid; the kernel reports this uid for processes outside this user namespace")]
    OverflowAccount {
        /// The peer caller.
        caller: CallerName,
        /// The account it names.
        user: AccountName,
    },
    /// Peer callers on one listener name accounts with the same uid, as `passwd` aliases can, so a connection from that
    /// uid would identify more than one caller (spec §3.4).
    #[error("callers {} on listener {listener} name accounts with uid {uid}, so one account would identify more than one caller", joined(.callers))]
    SharedPeerAccount {
        /// The listener.
        listener: ListenerName,
        /// The uid the accounts share.
        uid: u32,
        /// The callers whose accounts have it, in name order.
        callers: Vec<CallerName>,
    },
}

impl ActivePolicy {
    /// The validated configuration this policy serves.
    ///
    /// Its routes include unavailable ones; serve requests through [`ActivePolicy::route`], which omits them.
    pub fn config(&self) -> &ValidatedConfig {
        &self.config
    }

    /// The route named `route`, if it exists and is available.
    ///
    /// This is the lookup for serving a request, so an unavailable route, whatever its cause, can never be reached by
    /// forgetting to check [`ActivePolicy::is_available`].
    pub fn route(&self, route: &RouteName) -> Option<&RouteConfig> {
        self.config.routes().get(route).filter(|_| !self.unavailable.contains_key(route))
    }

    /// The unavailable routes, in name order, each with its causes.
    pub fn unavailable_routes(&self) -> &BTreeMap<RouteName, BTreeSet<UnavailableCause>> {
        &self.unavailable
    }

    /// Whether `route` is unavailable for `cause`, whatever other cause it also has.
    pub fn is_unavailable_for(&self, route: &RouteName, cause: UnavailableCause) -> bool {
        self.unavailable.get(route).is_some_and(|causes| causes.contains(&cause))
    }

    /// This policy with each of `routes` also unavailable because its pinned CA could not be loaded.
    ///
    /// Only the service can load a CA file, so it marks these after activation, before the policy serves anything. A
    /// name the config does not hold is ignored. It can only take routes away, never make one available.
    pub fn with_pinned_ca_unavailable<'a>(mut self, routes: impl IntoIterator<Item = &'a RouteName>) -> Self {
        routes
            .into_iter()
            .filter(|route| self.config.routes().contains_key(*route))
            .for_each(|route| {
                self.unavailable
                    .entry(route.clone())
                    .or_default()
                    .insert(UnavailableCause::PinnedCaUnavailable);
            });
        self
    }

    /// Whether `route` exists and may serve requests.
    pub fn is_available(&self, route: &RouteName) -> bool {
        self.route(route).is_some()
    }

    /// The uid each peer caller's account had when this policy was activated, in caller name order.
    pub fn peer_uids(&self) -> &BTreeMap<CallerName, u32> {
        &self.peer_uids
    }
}

/// Activates `config`, or returns every reason it cannot be: route errors in route name order, then peer account errors.
///
/// The catalog is asked once per credential. An unusable record makes only its routes unavailable; activation runs
/// again once the record is repaired, and checks its origins then. The directory is asked once per peer caller.
pub fn activate(
    config: &ValidatedConfig,
    capabilities: &Capabilities,
    catalog: &impl CredentialCatalog,
    accounts: &impl AccountDirectory,
) -> Result<ActivePolicy, Vec<ActivationError>> {
    let credentials: BTreeSet<_> = config.routes().values().map(RouteConfig::credential).collect();
    let entries: BTreeMap<_, _> = credentials
        .into_iter()
        .map(|credential| (credential, catalog.entry(credential)))
        .collect();
    let routes = config
        .routes()
        .iter()
        .filter_map(|(name, route)| entries.get(route.credential()).map(|entry| (name, route, entry)));
    let errors: Vec<_> = routes
        .clone()
        .flat_map(|(name, route, entry)| route_errors(name, route, capabilities, entry))
        .collect();
    match (errors.is_empty(), peer_accounts::resolve(config, accounts)) {
        (true, Ok(peer_uids)) => {
            let unavailable = routes
                .filter(|(_, _, entry)| !is_usable(entry))
                .map(|(name, _, _)| (name.clone(), BTreeSet::from([UnavailableCause::CredentialUnusable])))
                .collect();
            Ok(ActivePolicy {
                config: config.clone(),
                unavailable,
                peer_uids,
            })
        }
        (_, peer_uids) => Err(errors.into_iter().chain(peer_uids.err().into_iter().flatten()).collect()),
    }
}

fn route_errors(name: &RouteName, route: &RouteConfig, capabilities: &Capabilities, entry: &CatalogEntry) -> Vec<ActivationError> {
    let touch = (route.confirm() == Confirmation::Touch && !capabilities.touch_provider)
        .then(|| ActivationError::TouchUnavailable { route: name.clone() });
    touch
        .into_iter()
        .chain(credential_error(name, route, entry))
        .chain(slot_error(name, route, entry))
        .collect()
}

fn slot_error(name: &RouteName, route: &RouteConfig, entry: &CatalogEntry) -> Option<ActivationError> {
    match entry {
        CatalogEntry::Usable { kind, .. } if !kind.fills(route.slot()) => Some(ActivationError::SlotMismatch {
            route: name.clone(),
            credential: route.credential().clone(),
            kind: *kind,
        }),
        _ => None,
    }
}

fn credential_error(name: &RouteName, route: &RouteConfig, entry: &CatalogEntry) -> Option<ActivationError> {
    let upstream = route.upstream();
    match entry {
        CatalogEntry::Unknown => Some(ActivationError::UnknownCredential {
            route: name.clone(),
            credential: route.credential().clone(),
        }),
        CatalogEntry::Usable { origins, .. } if !origins.iter().any(|(h, p)| h == upstream.host() && *p == upstream.port()) => {
            Some(ActivationError::OriginNotPermitted {
                route: name.clone(),
                credential: route.credential().clone(),
                host: upstream.host().clone(),
                port: upstream.port(),
            })
        }
        CatalogEntry::Usable { .. } | CatalogEntry::Unusable => None,
    }
}

fn is_usable(entry: &CatalogEntry) -> bool {
    matches!(entry, CatalogEntry::Usable { .. })
}

mod peer_accounts;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ParsedConfig;
    use crate::spec_example::SPEC_EXAMPLE;
    use crate::test_accounts::{FakeAccounts, SERVICE_UID};

    const NO_TOUCH: Capabilities = Capabilities { touch_provider: false };

    /// A catalog held in memory: names map to entries, and any other name is unknown.
    struct FakeCatalog(BTreeMap<CredentialName, CatalogEntry>);

    impl CredentialCatalog for FakeCatalog {
        fn entry(&self, name: &CredentialName) -> CatalogEntry {
            self.0.get(name).cloned().unwrap_or(CatalogEntry::Unknown)
        }
    }

    fn n<T: std::str::FromStr<Err: std::fmt::Debug>>(s: &str) -> T {
        s.parse().unwrap()
    }

    fn usable(hosts: &[(&str, u16)]) -> CatalogEntry {
        let origins = hosts.iter().map(|(h, p)| (n(h), Port::try_from(*p).unwrap())).collect();
        CatalogEntry::Usable {
            kind: CredentialKind::Static,
            origins,
        }
    }

    /// A catalog that permits each §3.3 route's upstream, with `overrides` replacing individual entries.
    fn spec_catalog(overrides: &[(&str, CatalogEntry)]) -> FakeCatalog {
        let healthy = [
            ("fx_key", "api.fx.example"),
            ("venice", "api.venice.ai"),
            ("brave", "api.search.brave.com"),
        ];
        let mut entries: BTreeMap<_, _> = healthy.iter().map(|(name, host)| (n(name), usable(&[(host, 443)]))).collect();
        entries.extend(overrides.iter().map(|(name, entry)| (n(name), entry.clone())));
        FakeCatalog(entries)
    }

    fn config(doc: &str) -> ValidatedConfig {
        ValidatedConfig::try_from(ParsedConfig::from_toml(doc.as_bytes()).unwrap()).unwrap()
    }

    /// The §3.3 example with the `[routes.fx]` line `from` replaced by `to`.
    fn spec_with(from: &str, to: &str) -> ValidatedConfig {
        assert!(SPEC_EXAMPLE.contains(from), "{from}");
        config(&SPEC_EXAMPLE.replacen(from, to, 1))
    }

    /// Counts lookups, to show a credential shared by several routes is looked up once.
    struct CountingCatalog(std::cell::RefCell<Vec<CredentialName>>);

    impl CredentialCatalog for CountingCatalog {
        fn entry(&self, name: &CredentialName) -> CatalogEntry {
            self.0.borrow_mut().push(name.clone());
            usable(&[("api.fx.example", 443), ("api.venice.ai", 443), ("api.search.brave.com", 443)])
        }
    }

    #[test]
    fn each_credential_is_looked_up_once() {
        let shared = config(&SPEC_EXAMPLE.replace("credential = \"brave\"", "credential = \"venice\""));
        let catalog = CountingCatalog(std::cell::RefCell::default());
        assert!(activate(&shared, &NO_TOUCH, &catalog, &FakeAccounts::host()).is_ok());
        assert_eq!(
            catalog.0.borrow().iter().map(CredentialName::as_str).collect::<Vec<_>>(),
            ["fx_key", "venice"]
        );
    }

    #[test]
    fn spec_example_activates() {
        let policy = activate(&config(SPEC_EXAMPLE), &NO_TOUCH, &spec_catalog(&[]), &FakeAccounts::host()).unwrap();
        assert!(policy.unavailable_routes().is_empty());
        assert!(["fx", "venice", "brave"].iter().all(|route| policy.is_available(&n(route))));
        assert!(!policy.is_available(&n("missing")));
        assert_eq!(policy.config(), &config(SPEC_EXAMPLE));
    }

    #[test]
    fn the_policy_holds_each_peer_callers_uid() {
        let policy = activate(&config(SPEC_EXAMPLE), &NO_TOUCH, &spec_catalog(&[]), &FakeAccounts::host()).unwrap();
        assert_eq!(policy.peer_uids(), &[(n("fx-mcp"), 1001)].into());
    }

    #[test]
    fn peer_account_errors_follow_route_errors() {
        let catalog = spec_catalog(&[("brave", CatalogEntry::Unknown)]);
        let err = activate(&config(SPEC_EXAMPLE), &NO_TOUCH, &catalog, &FakeAccounts::with(&[("fx-mcp", 0)])).unwrap_err();
        let expected = [
            ActivationError::UnknownCredential {
                route: n("brave"),
                credential: n("brave"),
            },
            ActivationError::PrivilegedAccount {
                caller: n("fx-mcp"),
                user: n("fx-mcp"),
            },
        ];
        assert_eq!(err, expected);
    }

    #[test]
    fn a_peer_account_error_alone_refuses_the_config() {
        let err = activate(&config(SPEC_EXAMPLE), &NO_TOUCH, &spec_catalog(&[]), &FakeAccounts::with(&[])).map(|_| ());
        assert_eq!(err, Ok(()));
        let accounts = FakeAccounts::with(&[("fx-mcp", SERVICE_UID)]);
        let err = activate(&config(SPEC_EXAMPLE), &NO_TOUCH, &spec_catalog(&[]), &accounts).unwrap_err();
        assert!(matches!(&err[..], [ActivationError::PrivilegedAccount { .. }]), "{err:?}");
    }

    #[test]
    fn touch_route_is_refused_without_a_provider() {
        let touch = spec_with("credential = \"fx_key\"", "credential = \"fx_key\"\nconfirm = \"touch\"");
        let err = activate(&touch, &NO_TOUCH, &spec_catalog(&[]), &FakeAccounts::host()).unwrap_err();
        assert_eq!(err, [ActivationError::TouchUnavailable { route: n("fx") }]);
        assert!(
            activate(
                &touch,
                &Capabilities { touch_provider: true },
                &spec_catalog(&[]),
                &FakeAccounts::host()
            )
            .is_ok()
        );
    }

    #[test]
    fn unknown_credential_is_refused() {
        let catalog = spec_catalog(&[("brave", CatalogEntry::Unknown)]);
        let err = activate(&config(SPEC_EXAMPLE), &NO_TOUCH, &catalog, &FakeAccounts::host()).unwrap_err();
        assert_eq!(
            err,
            [ActivationError::UnknownCredential {
                route: n("brave"),
                credential: n("brave")
            }]
        );
    }

    #[test]
    fn damaged_credential_disables_only_its_route() {
        let catalog = spec_catalog(&[("venice", CatalogEntry::Unusable)]);
        let policy = activate(&config(SPEC_EXAMPLE), &NO_TOUCH, &catalog, &FakeAccounts::host()).unwrap();
        let causes = BTreeSet::from([UnavailableCause::CredentialUnusable]);
        assert_eq!(policy.unavailable_routes(), &BTreeMap::from([(n("venice"), causes)]));
        assert!(!policy.is_available(&n("venice")));
        assert!(policy.is_available(&n("fx")) && policy.is_available(&n("brave")));
    }

    #[test]
    fn route_lookup_omits_unavailable_and_missing_routes() {
        let catalog = spec_catalog(&[("venice", CatalogEntry::Unusable)]);
        let policy = activate(&config(SPEC_EXAMPLE), &NO_TOUCH, &catalog, &FakeAccounts::host()).unwrap();
        assert_eq!(policy.route(&n("fx")), policy.config().routes().get(&n("fx")));
        assert!(policy.route(&n("fx")).is_some() && policy.route(&n("brave")).is_some());
        assert_eq!(policy.route(&n("venice")), None);
        assert!(policy.config().routes().contains_key(&n("venice")));
        assert_eq!(policy.route(&n("missing")), None);
    }

    #[test]
    fn a_pinned_ca_route_is_unavailable_and_keeps_its_credential_cause() {
        let catalog = spec_catalog(&[("venice", CatalogEntry::Unusable)]);
        let policy = activate(&config(SPEC_EXAMPLE), &NO_TOUCH, &catalog, &FakeAccounts::host()).unwrap();
        let policy = policy.with_pinned_ca_unavailable(&[n("fx"), n("venice"), n("missing")]);
        let both = BTreeSet::from([UnavailableCause::CredentialUnusable, UnavailableCause::PinnedCaUnavailable]);
        let expected = BTreeMap::from([
            (n("fx"), BTreeSet::from([UnavailableCause::PinnedCaUnavailable])),
            (n("venice"), both),
        ]);
        assert_eq!(policy.unavailable_routes(), &expected);
        assert_eq!(policy.route(&n("fx")), None);
        assert!(policy.is_unavailable_for(&n("fx"), UnavailableCause::PinnedCaUnavailable));
        assert!(!policy.is_unavailable_for(&n("fx"), UnavailableCause::CredentialUnusable));
        assert!(policy.is_available(&n("brave")));
    }

    #[test]
    fn upstream_host_must_be_permitted_exactly() {
        let evil = spec_with("https://api.fx.example", "https://api.fx.example.evil.com");
        let err = activate(&evil, &NO_TOUCH, &spec_catalog(&[]), &FakeAccounts::host()).unwrap_err();
        let host = n("api.fx.example.evil.com");
        let expected = ActivationError::OriginNotPermitted {
            route: n("fx"),
            credential: n("fx_key"),
            host,
            port: Port::HTTPS,
        };
        assert_eq!(err, [expected]);
        assert_eq!(
            err[0].to_string(),
            "route fx sends credential fx_key to api.fx.example.evil.com:443, which its record does not permit"
        );
    }

    #[test]
    fn upstream_port_must_be_permitted() {
        let other_port = spec_with("https://api.fx.example", "https://api.fx.example:8443");
        let err = activate(&other_port, &NO_TOUCH, &spec_catalog(&[]), &FakeAccounts::host()).unwrap_err();
        assert!(
            matches!(&err[..], [ActivationError::OriginNotPermitted { port, .. }] if port.get() == 8443),
            "{err:?}"
        );
        let catalog = spec_catalog(&[("fx_key", usable(&[("api.fx.example", 443), ("api.fx.example", 8443)]))]);
        assert!(activate(&other_port, &NO_TOUCH, &catalog, &FakeAccounts::host()).is_ok());
    }

    #[test]
    fn every_error_is_reported_in_route_order() {
        let touch = spec_with("credential = \"fx_key\"", "credential = \"fx_key\"\nconfirm = \"touch\"");
        let catalog = spec_catalog(&[("brave", CatalogEntry::Unknown), ("fx_key", usable(&[("api.fx.example", 8443)]))]);
        let err = activate(&touch, &NO_TOUCH, &catalog, &FakeAccounts::host()).unwrap_err();
        let expected = [
            ActivationError::UnknownCredential {
                route: n("brave"),
                credential: n("brave"),
            },
            ActivationError::TouchUnavailable { route: n("fx") },
            ActivationError::OriginNotPermitted {
                route: n("fx"),
                credential: n("fx_key"),
                host: n("api.fx.example"),
                port: Port::HTTPS,
            },
        ];
        assert_eq!(err, expected);
    }

    fn with_kind(entry: CatalogEntry, kind: CredentialKind) -> CatalogEntry {
        match entry {
            CatalogEntry::Usable { origins, .. } => CatalogEntry::Usable { kind, origins },
            other => other,
        }
    }

    #[test]
    fn static_credential_on_basic_slot_is_refused() {
        let basic = spec_with("slot = { query = \"access_key\" }", "slot = \"basic\"");
        let err = activate(&basic, &NO_TOUCH, &spec_catalog(&[]), &FakeAccounts::host()).unwrap_err();
        assert_eq!(
            err,
            [ActivationError::SlotMismatch {
                route: n("fx"),
                credential: n("fx_key"),
                kind: CredentialKind::Static
            }]
        );
        assert_eq!(
            err[0].to_string(),
            "route fx uses a static credential, fx_key, on a slot that kind cannot fill"
        );
    }

    #[test]
    fn basic_credential_on_header_slot_is_reported_with_other_errors() {
        let brave = with_kind(usable(&[("api.search.brave.com", 443)]), CredentialKind::Basic);
        let catalog = spec_catalog(&[("brave", brave), ("fx_key", CatalogEntry::Unknown)]);
        let err = activate(&config(SPEC_EXAMPLE), &NO_TOUCH, &catalog, &FakeAccounts::host()).unwrap_err();
        let expected = [
            ActivationError::SlotMismatch {
                route: n("brave"),
                credential: n("brave"),
                kind: CredentialKind::Basic,
            },
            ActivationError::UnknownCredential {
                route: n("fx"),
                credential: n("fx_key"),
            },
        ];
        assert_eq!(err, expected);
    }
}
