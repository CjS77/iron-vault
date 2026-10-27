//! Activation: checking a validated config against facts only the running service knows (spec §2, §3.3, §3.9).
//!
//! The configuration cannot know which credential records exist, which hosts they permit, or whether this machine
//! can confirm a touch. The service supplies those facts as [`Capabilities`] and a [`CredentialCatalog`]; activation
//! then either refuses the whole configuration or produces the [`ActivePolicy`] that requests are served under.

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;

use crate::confirmation::Confirmation;
use crate::host::Host;
use crate::name::{CredentialName, RouteName};
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
        /// The exact host and port pairs the record permits its secret to reach (spec §3.3).
        origins: BTreeSet<(Host, Port)>,
    },
}

/// A validated config activated against the service's capabilities and credential catalog.
///
/// Only [`activate`] builds one. Routes whose record is unusable stay listed so the service can answer for them, but
/// are unavailable; every other route may serve requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivePolicy {
    config: ValidatedConfig,
    unavailable: BTreeSet<RouteName>,
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
    /// This is the lookup for serving a request, so a route whose record is unusable can never be reached by forgetting
    /// to check [`ActivePolicy::is_available`].
    pub fn route(&self, route: &RouteName) -> Option<&RouteConfig> {
        self.config.routes().get(route).filter(|_| !self.unavailable.contains(route))
    }

    /// Routes whose credential record is unusable, in name order.
    pub fn unavailable_routes(&self) -> &BTreeSet<RouteName> {
        &self.unavailable
    }

    /// Whether `route` exists and may serve requests.
    pub fn is_available(&self, route: &RouteName) -> bool {
        self.route(route).is_some()
    }
}

/// Activates `config`, or returns every reason it cannot be, in route name order.
///
/// The catalog is asked once per credential. An unusable record makes only its routes unavailable; activation runs
/// again once the record is repaired, and checks its origins then.
pub fn activate(
    config: &ValidatedConfig,
    capabilities: &Capabilities,
    catalog: &impl CredentialCatalog,
) -> Result<ActivePolicy, Vec<ActivationError>> {
    let credentials: BTreeSet<_> = config.routes().values().map(RouteConfig::credential).collect();
    let entries: BTreeMap<_, _> = credentials.into_iter().map(|credential| (credential, catalog.entry(credential))).collect();
    let routes = config.routes().iter().filter_map(|(name, route)| entries.get(route.credential()).map(|entry| (name, route, entry)));
    let errors: Vec<_> = routes.clone().flat_map(|(name, route, entry)| route_errors(name, route, capabilities, entry)).collect();
    match errors.is_empty() {
        true => {
            let unavailable = routes.filter(|(_, _, entry)| !is_usable(entry)).map(|(name, _, _)| name.clone()).collect();
            Ok(ActivePolicy { config: config.clone(), unavailable })
        }
        false => Err(errors),
    }
}

fn route_errors(name: &RouteName, route: &RouteConfig, capabilities: &Capabilities, entry: &CatalogEntry) -> Vec<ActivationError> {
    let touch = (route.confirm() == Confirmation::Touch && !capabilities.touch_provider)
        .then(|| ActivationError::TouchUnavailable { route: name.clone() });
    touch.into_iter().chain(credential_error(name, route, entry)).collect()
}

fn credential_error(name: &RouteName, route: &RouteConfig, entry: &CatalogEntry) -> Option<ActivationError> {
    let upstream = route.upstream();
    match entry {
        CatalogEntry::Unknown => Some(ActivationError::UnknownCredential { route: name.clone(), credential: route.credential().clone() }),
        CatalogEntry::Usable { origins } if !origins.iter().any(|(h, p)| h == upstream.host() && *p == upstream.port()) => {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ParsedConfig;
    use crate::spec_example::SPEC_EXAMPLE;

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
        CatalogEntry::Usable { origins: hosts.iter().map(|(h, p)| (n(h), Port::try_from(*p).unwrap())).collect() }
    }

    /// A catalog that permits each §3.3 route's upstream, with `overrides` replacing individual entries.
    fn spec_catalog(overrides: &[(&str, CatalogEntry)]) -> FakeCatalog {
        let healthy = [("fx_key", "api.fx.example"), ("venice", "api.venice.ai"), ("brave", "api.search.brave.com")];
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
        assert!(activate(&shared, &NO_TOUCH, &catalog).is_ok());
        assert_eq!(catalog.0.borrow().iter().map(CredentialName::as_str).collect::<Vec<_>>(), ["fx_key", "venice"]);
    }

    #[test]
    fn spec_example_activates() {
        let policy = activate(&config(SPEC_EXAMPLE), &NO_TOUCH, &spec_catalog(&[])).unwrap();
        assert!(policy.unavailable_routes().is_empty());
        assert!(["fx", "venice", "brave"].iter().all(|route| policy.is_available(&n(route))));
        assert!(!policy.is_available(&n("missing")));
        assert_eq!(policy.config(), &config(SPEC_EXAMPLE));
    }

    #[test]
    fn touch_route_is_refused_without_a_provider() {
        let touch = spec_with("credential = \"fx_key\"", "credential = \"fx_key\"\nconfirm = \"touch\"");
        let err = activate(&touch, &NO_TOUCH, &spec_catalog(&[])).unwrap_err();
        assert_eq!(err, [ActivationError::TouchUnavailable { route: n("fx") }]);
        assert!(activate(&touch, &Capabilities { touch_provider: true }, &spec_catalog(&[])).is_ok());
    }

    #[test]
    fn unknown_credential_is_refused() {
        let catalog = spec_catalog(&[("brave", CatalogEntry::Unknown)]);
        let err = activate(&config(SPEC_EXAMPLE), &NO_TOUCH, &catalog).unwrap_err();
        assert_eq!(err, [ActivationError::UnknownCredential { route: n("brave"), credential: n("brave") }]);
    }

    #[test]
    fn damaged_credential_disables_only_its_route() {
        let catalog = spec_catalog(&[("venice", CatalogEntry::Unusable)]);
        let policy = activate(&config(SPEC_EXAMPLE), &NO_TOUCH, &catalog).unwrap();
        assert_eq!(policy.unavailable_routes().iter().map(RouteName::as_str).collect::<Vec<_>>(), ["venice"]);
        assert!(!policy.is_available(&n("venice")));
        assert!(policy.is_available(&n("fx")) && policy.is_available(&n("brave")));
    }

    #[test]
    fn route_lookup_omits_unavailable_and_missing_routes() {
        let catalog = spec_catalog(&[("venice", CatalogEntry::Unusable)]);
        let policy = activate(&config(SPEC_EXAMPLE), &NO_TOUCH, &catalog).unwrap();
        assert_eq!(policy.route(&n("fx")), policy.config().routes().get(&n("fx")));
        assert!(policy.route(&n("fx")).is_some() && policy.route(&n("brave")).is_some());
        assert_eq!(policy.route(&n("venice")), None);
        assert!(policy.config().routes().contains_key(&n("venice")));
        assert_eq!(policy.route(&n("missing")), None);
    }

    #[test]
    fn upstream_host_must_be_permitted_exactly() {
        let evil = spec_with("https://api.fx.example", "https://api.fx.example.evil.com");
        let err = activate(&evil, &NO_TOUCH, &spec_catalog(&[])).unwrap_err();
        let host = n("api.fx.example.evil.com");
        let expected = ActivationError::OriginNotPermitted { route: n("fx"), credential: n("fx_key"), host, port: Port::HTTPS };
        assert_eq!(err, [expected]);
        assert_eq!(err[0].to_string(), "route fx sends credential fx_key to api.fx.example.evil.com:443, which its record does not permit");
    }

    #[test]
    fn upstream_port_must_be_permitted() {
        let other_port = spec_with("https://api.fx.example", "https://api.fx.example:8443");
        let err = activate(&other_port, &NO_TOUCH, &spec_catalog(&[])).unwrap_err();
        assert!(matches!(&err[..], [ActivationError::OriginNotPermitted { port, .. }] if port.get() == 8443), "{err:?}");
        let catalog = spec_catalog(&[("fx_key", usable(&[("api.fx.example", 443), ("api.fx.example", 8443)]))]);
        assert!(activate(&other_port, &NO_TOUCH, &catalog).is_ok());
    }

    #[test]
    fn every_error_is_reported_in_route_order() {
        let touch = spec_with("credential = \"fx_key\"", "credential = \"fx_key\"\nconfirm = \"touch\"");
        let catalog = spec_catalog(&[("brave", CatalogEntry::Unknown), ("fx_key", usable(&[("api.fx.example", 8443)]))]);
        let err = activate(&touch, &NO_TOUCH, &catalog).unwrap_err();
        let expected = [
            ActivationError::UnknownCredential { route: n("brave"), credential: n("brave") },
            ActivationError::TouchUnavailable { route: n("fx") },
            ActivationError::OriginNotPermitted { route: n("fx"), credential: n("fx_key"), host: n("api.fx.example"), port: Port::HTTPS },
        ];
        assert_eq!(err, expected);
    }
}
