//! Cross-reference checks that turn a parsed config into one the rest of the system can trust (spec §3.3–§3.6).
//!
//! Each section already passed its own rules when parsed; every check here needs two or more sections at once. All
//! checks run and every failure is reported, in a fixed order, so an operator can fix a configuration in one pass and
//! the same document always yields the same report.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};

use thiserror::Error;

use crate::caller::{CallerAuth, CallerConfig};
use crate::config::ParsedConfig;
use crate::header_name::HeaderName;
use crate::limits::Limits;
use crate::listener::{Endpoint, ListenerConfig};
use crate::name::{CallerName, ListenerName, RouteName};
use crate::rate_limit::RateLimit;
use crate::route::RouteConfig;
use crate::route_prefix::RoutePrefix;
use crate::token_hash::TOKEN_DIGEST_LEN;

/// A parsed config whose references resolve and whose sections cannot conflict.
///
/// [`ValidatedConfig::try_from`] is the only constructor, so holding one proves every check below passed. Facts the
/// configuration cannot know, such as which credential records exist, are checked at activation instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedConfig(ParsedConfig);

/// One way in which the sections of a parsed config contradict each other.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ValidationError {
    /// A caller names a listener that is not defined.
    #[error("caller {caller} names listener {listener}, which is not defined")]
    UnknownListener {
        /// The caller.
        caller: CallerName,
        /// The missing listener.
        listener: ListenerName,
    },
    /// A caller is granted a route that is not defined.
    #[error("caller {caller} is granted route {route}, which is not defined")]
    UnknownRoute {
        /// The caller.
        caller: CallerName,
        /// The missing route.
        route: RouteName,
    },
    /// A per-caller limit refills faster than its route's aggregate limit, so it could never be the stricter one.
    #[error("caller {caller} rate limit for route {route} allows a higher request rate than the route's own limit")]
    CallerRateLooser {
        /// The caller.
        caller: CallerName,
        /// The route.
        route: RouteName,
    },
    /// A per-caller limit has a larger burst than its route's aggregate limit.
    #[error("caller {caller} rate limit for route {route} allows a larger burst than the route's own limit")]
    CallerBurstLooser {
        /// The caller.
        caller: CallerName,
        /// The route.
        route: RouteName,
    },
    /// A caller identified by its listener uses a listener of the wrong kind.
    #[error("caller {caller} uses auth = \"{auth}\", which needs {required}; listener {listener} is not one")]
    WrongListenerKind {
        /// The caller.
        caller: CallerName,
        /// The caller's `auth` value.
        auth: &'static str,
        /// The listener.
        listener: ListenerName,
        /// The kind of listener the `auth` value needs.
        required: &'static str,
    },
    /// An `isolated-network` caller's listener binds an address that is not confined to one network.
    ///
    /// The caller has no token, so the listener address is its whole identity: a loopback bind hands its routes to every
    /// local process, and a wildcard bind to every host that can reach any interface (spec §3.4).
    #[error(
        "caller {caller} uses auth = \"isolated-network\", so listener {listener} must bind a dedicated non-loopback, \
         non-wildcard address; {address} would let any local process or reachable host use its routes"
    )]
    UndedicatedAddress {
        /// The caller.
        caller: CallerName,
        /// The listener.
        listener: ListenerName,
        /// The listener's address.
        address: SocketAddr,
    },
    /// A caller identified by its listener shares that listener, so the listener no longer identifies it.
    #[error(
        "caller {caller} uses auth = \"{auth}\", so it must be the only caller on listener {listener}, which {} also use; \
         callers that share a listener must use tokens",
        joined(.others)
    )]
    SharedListener {
        /// The caller.
        caller: CallerName,
        /// The caller's `auth` value.
        auth: &'static str,
        /// The listener.
        listener: ListenerName,
        /// The other callers on the listener, in name order.
        others: Vec<CallerName>,
    },
    /// Callers on one listener share a token hash, so one token would resolve to several identities.
    #[error("callers {} on listener {listener} share a token_hash, so one token would identify more than one caller", joined(.callers))]
    SharedTokenHash {
        /// The listener.
        listener: ListenerName,
        /// The callers sharing the hash, in name order.
        callers: Vec<CallerName>,
    },
    /// Two route prefixes are equal or one is a segment prefix of the other, so a request path could select either.
    #[error("route {route} prefix {prefix} overlaps route {other} prefix {other_prefix}; a request path could match both")]
    AmbiguousPrefix {
        /// The route first in name order.
        route: RouteName,
        /// Its prefix.
        prefix: RoutePrefix,
        /// The other route.
        other: RouteName,
        /// Its prefix.
        other_prefix: RoutePrefix,
    },
    /// A listener's caller-token header is the header a reachable route writes its credential to.
    #[error("listener {listener} token_header {header} is the credential slot of route {route}, which its callers can use")]
    TokenHeaderIsSlot {
        /// The listener.
        listener: ListenerName,
        /// The token header.
        header: HeaderName,
        /// The route whose slot writes that header.
        route: RouteName,
    },
}

/// One cross-section check; each returns all of its failures.
type Check = fn(&ParsedConfig) -> Vec<ValidationError>;

/// The checks in report order.
const CHECKS: [Check; 6] =
    [check_references, check_caller_limits, check_listener_auth, check_token_hashes, check_prefixes, check_token_headers];

impl TryFrom<ParsedConfig> for ValidatedConfig {
    type Error = Vec<ValidationError>;

    /// Runs every check and returns every failure, never just the first.
    fn try_from(config: ParsedConfig) -> Result<Self, Self::Error> {
        let errors: Vec<_> = CHECKS.iter().flat_map(|check| check(&config)).collect();
        match errors.is_empty() {
            true => Ok(Self(config)),
            false => Err(errors),
        }
    }
}

impl ValidatedConfig {
    /// Listeners by name.
    pub fn listeners(&self) -> &BTreeMap<ListenerName, ListenerConfig> {
        self.0.listeners()
    }

    /// Callers by name; every listener and route a caller names exists.
    pub fn callers(&self) -> &BTreeMap<CallerName, CallerConfig> {
        self.0.callers()
    }

    /// Routes by name; no two prefixes overlap.
    pub fn routes(&self) -> &BTreeMap<RouteName, RouteConfig> {
        self.0.routes()
    }

    /// Operational limits.
    pub fn limits(&self) -> &Limits {
        self.0.limits()
    }
}

/// Every caller's listener and granted routes exist.
fn check_references(config: &ParsedConfig) -> Vec<ValidationError> {
    config.callers().iter().flat_map(|(name, caller)| caller_references(config, name, caller)).collect()
}

fn caller_references(config: &ParsedConfig, name: &CallerName, caller: &CallerConfig) -> Vec<ValidationError> {
    let listener = (!config.listeners().contains_key(caller.listener()))
        .then(|| ValidationError::UnknownListener { caller: name.clone(), listener: caller.listener().clone() });
    let routes = caller
        .routes()
        .iter()
        .filter(|route| !config.routes().contains_key(*route))
        .map(|route| ValidationError::UnknownRoute { caller: name.clone(), route: route.clone() });
    listener.into_iter().chain(routes).collect()
}

/// Per-caller limits are no looser than their route's limit, in rate or burst (spec §3.5).
///
/// A missing route is already reported by [`check_references`], so its limit is skipped here.
fn check_caller_limits(config: &ParsedConfig) -> Vec<ValidationError> {
    config
        .callers()
        .iter()
        .flat_map(|(name, caller)| caller.rate_limits().iter().map(move |(route, limit)| (name, route, *limit)))
        .filter_map(|(name, route, limit)| config.routes().get(route).map(|r| (name, route, limit, r.rate_limit())))
        .flat_map(|(caller, route, limit, route_limit)| looser_limits(caller, route, limit, route_limit))
        .collect()
}

fn looser_limits(caller: &CallerName, route: &RouteName, limit: RateLimit, route_limit: RateLimit) -> Vec<ValidationError> {
    let rate = higher_rate(limit, route_limit)
        .then(|| ValidationError::CallerRateLooser { caller: caller.clone(), route: route.clone() });
    let burst = (limit.burst() > route_limit.burst())
        .then(|| ValidationError::CallerBurstLooser { caller: caller.clone(), route: route.clone() });
    rate.into_iter().chain(burst).collect()
}

/// Whether `a` refills faster than `b`, compared exactly by cross-multiplying; two `u32`s always fit in a `u64`.
fn higher_rate(a: RateLimit, b: RateLimit) -> bool {
    u64::from(a.requests().get()) * u64::from(b.per_seconds().get()) > u64::from(b.requests().get()) * u64::from(a.per_seconds().get())
}

/// Callers identified by their listener use the right kind of listener and are its only caller (spec §3.4).
///
/// An `isolated-network` caller needs a TLS listener on a dedicated, non-loopback, non-wildcard address, bound to its
/// own network; a `socket` caller needs a Unix socket whose permissions admit only it. Either way a second caller on
/// the listener would be indistinguishable.
fn check_listener_auth(config: &ParsedConfig) -> Vec<ValidationError> {
    config.callers().iter().flat_map(|(name, caller)| listener_auth(config, name, caller)).collect()
}

fn listener_auth(config: &ParsedConfig, name: &CallerName, caller: &CallerConfig) -> Vec<ValidationError> {
    let Some(listener) = config.listeners().get(caller.listener()) else { return Vec::new() };
    let (auth, fault) = match caller.auth() {
        CallerAuth::Token(_) => return Vec::new(),
        CallerAuth::IsolatedNetwork => ("isolated-network", isolated_network_fault(name, caller.listener(), listener)),
        CallerAuth::Socket => ("socket", socket_fault(name, caller.listener(), listener)),
    };
    let others: Vec<_> = callers_on(config, caller.listener()).map(|(other, _)| other).filter(|other| *other != name).cloned().collect();
    let shared = (!others.is_empty())
        .then(|| ValidationError::SharedListener { caller: name.clone(), auth, listener: caller.listener().clone(), others });
    fault.into_iter().chain(shared).collect()
}

/// Why `listener` cannot identify an `isolated-network` caller, if it cannot.
fn isolated_network_fault(caller: &CallerName, name: &ListenerName, listener: &ListenerConfig) -> Option<ValidationError> {
    match listener.endpoint() {
        Endpoint::Tcp { address, tls: Some(_) } if !is_dedicated(address.ip()) => {
            Some(ValidationError::UndedicatedAddress { caller: caller.clone(), listener: name.clone(), address: *address })
        }
        Endpoint::Tcp { tls: Some(_), .. } => None,
        Endpoint::Tcp { tls: None, .. } | Endpoint::UnixSocket(_) => {
            Some(wrong_kind(caller, "isolated-network", name, "an address listener with TLS"))
        }
    }
}

/// Why `listener` cannot identify a `socket` caller, if it cannot.
fn socket_fault(caller: &CallerName, name: &ListenerName, listener: &ListenerConfig) -> Option<ValidationError> {
    (!matches!(listener.endpoint(), Endpoint::UnixSocket(_))).then(|| wrong_kind(caller, "socket", name, "a unix_socket listener"))
}

fn wrong_kind(caller: &CallerName, auth: &'static str, listener: &ListenerName, required: &'static str) -> ValidationError {
    ValidationError::WrongListenerKind { caller: caller.clone(), auth, listener: listener.clone(), required }
}

/// Whether a bind on `ip` admits only the hosts of one network: it is neither loopback (every local process) nor
/// unspecified (every interface).
///
/// The address is canonicalized first, so `::ffff:127.0.0.1` counts as loopback here. The listener's TLS rule treats
/// that same address as non-loopback; each rule takes the reading that rejects more.
fn is_dedicated(ip: IpAddr) -> bool {
    let ip = ip.to_canonical();
    !ip.is_loopback() && !ip.is_unspecified()
}

/// No two token callers on one listener share a token hash.
fn check_token_hashes(config: &ParsedConfig) -> Vec<ValidationError> {
    let groups = config
        .callers()
        .iter()
        .filter_map(|(name, caller)| match caller.auth() {
            CallerAuth::Token(hash) => Some(((caller.listener(), hash.digest()), name)),
            CallerAuth::IsolatedNetwork | CallerAuth::Socket => None,
        })
        .fold(BTreeMap::<(&ListenerName, &[u8; TOKEN_DIGEST_LEN]), Vec<CallerName>>::new(), |mut groups, (key, name)| {
            groups.entry(key).or_default().push(name.clone());
            groups
        });
    groups
        .into_iter()
        .filter(|(_, callers)| callers.len() > 1)
        .map(|((listener, _), callers)| ValidationError::SharedTokenHash { listener: listener.clone(), callers })
        .collect()
}

/// No route prefix equals or is a segment prefix of another, across all routes (spec §3.3).
///
/// Overlap is rejected outright rather than resolved by longest match, so which route serves a path never depends on
/// a rule the operator has to remember.
fn check_prefixes(config: &ParsedConfig) -> Vec<ValidationError> {
    let routes: Vec<_> = config.routes().iter().collect();
    routes
        .iter()
        .enumerate()
        .flat_map(|(i, a)| routes.iter().skip(i + 1).map(move |b| (*a, *b)))
        .filter(|((_, a), (_, b))| overlaps(a.prefix(), b.prefix()))
        .map(|((route, a), (other, b))| ValidationError::AmbiguousPrefix {
            route: route.clone(),
            prefix: a.prefix().clone(),
            other: other.clone(),
            other_prefix: b.prefix().clone(),
        })
        .collect()
}

fn overlaps(a: &RoutePrefix, b: &RoutePrefix) -> bool {
    a.segments().starts_with(b.segments()) || b.segments().starts_with(a.segments())
}

/// A listener's `token_header` is not the slot header of any route its callers can use (spec §3.6).
///
/// The service strips caller authentication before writing the slot, so a shared header would carry either the token
/// or the credential, never both. The default `Proxy-Authorization` is reserved and can never be a slot.
fn check_token_headers(config: &ParsedConfig) -> Vec<ValidationError> {
    config
        .listeners()
        .iter()
        .filter_map(|(name, listener)| listener.token_header().map(|header| (name, header)))
        .flat_map(|(listener, header)| token_header_collisions(config, listener, header))
        .collect()
}

fn token_header_collisions(config: &ParsedConfig, listener: &ListenerName, header: &HeaderName) -> Vec<ValidationError> {
    let reachable: BTreeSet<_> = callers_on(config, listener).flat_map(|(_, caller)| caller.routes()).collect();
    reachable
        .into_iter()
        .filter(|route| config.routes().get(*route).is_some_and(|r| r.slot().header_written() == Some(header.lowercase())))
        .map(|route| ValidationError::TokenHeaderIsSlot { listener: listener.clone(), header: header.clone(), route: route.clone() })
        .collect()
}

/// The callers configured on `listener`, in name order.
fn callers_on<'a>(config: &'a ParsedConfig, listener: &'a ListenerName) -> impl Iterator<Item = (&'a CallerName, &'a CallerConfig)> {
    config.callers().iter().filter(move |(_, caller)| caller.listener() == listener)
}

/// Names separated by ", ", for error messages.
fn joined(names: &[CallerName]) -> String {
    names.iter().map(CallerName::as_str).collect::<Vec<_>>().join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec_example::SPEC_EXAMPLE;

    const LOCAL: &str = "[listeners.local]\nunix_socket = \"/run/iron-vault/proxy.sock\"\n";
    const NET: &str = "[listeners.net]\naddress = \"10.20.0.2:7878\"\ntls_certificate = \"/etc/c.pem\"\ntls_key = \"/etc/k.pem\"\n";
    const LOOPBACK: &str = "[listeners.lo]\naddress = \"127.0.0.1:7878\"\n";
    const LIMIT: &str = "{ requests = 60, per_seconds = 60, burst = 10 }";

    fn validate(doc: &str) -> Result<ValidatedConfig, Vec<ValidationError>> {
        ValidatedConfig::try_from(ParsedConfig::from_toml(doc.as_bytes()).unwrap())
    }

    /// The errors for a document assembled from `sections`.
    fn errors(sections: &[&str]) -> Vec<ValidationError> {
        validate(&doc(sections)).unwrap_err()
    }

    fn doc(sections: &[&str]) -> String {
        format!("schema_version = 1\n{}", sections.join("\n"))
    }

    fn n<T: std::str::FromStr<Err: std::fmt::Debug>>(s: &str) -> T {
        s.parse().unwrap()
    }

    fn hash(digit: char) -> String {
        format!("blake2b:{}", digit.to_string().repeat(64))
    }

    fn route(name: &str, prefix: &str, slot: &str) -> String {
        format!(
            "[routes.{name}]\nprefix = \"{prefix}\"\nupstream = \"https://api.{name}.example\"\ncredential = \"{name}\"\nslot = {slot}\n\
             methods = [\"GET\"]\npaths = [\"/**\"]\nrate_limit = {LIMIT}\n"
        )
    }

    fn fx() -> String {
        route("fx", "/fx", "{ query = \"access_key\" }")
    }

    fn token_caller(name: &str, listener: &str, digit: char, routes: &str) -> String {
        format!("[callers.{name}]\nlistener = \"{listener}\"\ntoken_hash = \"{}\"\nroutes = [{routes}]\n", hash(digit))
    }

    fn caller(name: &str, listener: &str, auth: &str) -> String {
        format!("[callers.{name}]\nlistener = \"{listener}\"\nauth = \"{auth}\"\nroutes = [\"fx\"]\n")
    }

    fn limited_caller(limit: &str) -> String {
        format!("{}[callers.a.rate_limits]\nfx = {limit}\n", token_caller("a", "local", '1', "\"fx\""))
    }

    #[test]
    fn spec_example_validates() {
        let config = validate(SPEC_EXAMPLE).unwrap();
        assert_eq!(config.routes().len(), 3);
        assert_eq!(config.callers().len(), 2);
        assert_eq!(config.listeners().len(), 2);
        assert_eq!(config.limits(), &Limits::default());
    }

    #[test]
    fn duplicate_names_are_rejected_by_the_parser() {
        let twice = doc(&[LOCAL, &fx(), &fx()]);
        assert!(ParsedConfig::from_toml(twice.as_bytes()).is_err());
    }

    #[test]
    fn unknown_listener_is_rejected() {
        let err = errors(&[LOCAL, &fx(), &token_caller("a", "missing", '1', "\"fx\"")]);
        assert_eq!(err, [ValidationError::UnknownListener { caller: n("a"), listener: n("missing") }]);
    }

    #[test]
    fn unknown_routes_are_rejected() {
        let err = errors(&[LOCAL, &fx(), &token_caller("a", "local", '1', "\"fx\", \"gone\", \"lost\"")]);
        let unknown = |route: &str| ValidationError::UnknownRoute { caller: n("a"), route: n(route) };
        assert_eq!(err, [unknown("gone"), unknown("lost")]);
    }

    #[test]
    fn caller_limit_must_be_no_looser_than_route_limit() {
        ["{ requests = 60, per_seconds = 60, burst = 10 }", "{ requests = 1, per_seconds = 2, burst = 1 }"]
            .iter()
            .for_each(|limit| assert!(validate(&doc(&[LOCAL, &fx(), &limited_caller(limit)])).is_ok(), "{limit}"));
        let rate = ValidationError::CallerRateLooser { caller: n("a"), route: n("fx") };
        let burst = ValidationError::CallerBurstLooser { caller: n("a"), route: n("fx") };
        let cases = [
            ("{ requests = 61, per_seconds = 60, burst = 10 }", vec![rate.clone()]),
            ("{ requests = 2, per_seconds = 1, burst = 10 }", vec![rate.clone()]),
            ("{ requests = 60, per_seconds = 60, burst = 11 }", vec![burst.clone()]),
            ("{ requests = 4294967295, per_seconds = 1, burst = 4294967295 }", vec![rate, burst]),
        ];
        cases.into_iter().for_each(|(limit, expected)| assert_eq!(errors(&[LOCAL, &fx(), &limited_caller(limit)]), expected, "{limit}"));
    }

    #[test]
    fn isolated_network_caller_needs_a_tls_address_listener() {
        assert!(validate(&doc(&[NET, &fx(), &caller("a", "net", "isolated-network")])).is_ok());
        [(LOCAL, "local"), (LOOPBACK, "lo")].iter().for_each(|(listener, name)| {
            let err = errors(&[listener, &fx(), &caller("a", name, "isolated-network")]);
            assert!(matches!(&err[..], [ValidationError::WrongListenerKind { auth: "isolated-network", .. }]), "{err:?}");
        });
    }

    #[test]
    fn isolated_network_caller_needs_a_dedicated_address() {
        ["127.0.0.1:7878", "[::1]:7878", "0.0.0.0:7878", "[::]:7878", "[::ffff:127.0.0.1]:7878", "[::ffff:0.0.0.0]:7878"].iter().for_each(
            |address| {
                let listener = NET.replace("10.20.0.2:7878", address);
                let err = errors(&[&listener, &fx(), &caller("a", "net", "isolated-network")]);
                let expected = ValidationError::UndedicatedAddress { caller: n("a"), listener: n("net"), address: n(address) };
                assert_eq!(err, [expected], "{address}");
            },
        );
        let err = errors(&[&NET.replace("10.20.0.2", "0.0.0.0"), &fx(), &caller("a", "net", "isolated-network")]);
        assert!(err[0].to_string().contains("must bind a dedicated non-loopback, non-wildcard address; 0.0.0.0:7878"), "{}", err[0]);
    }

    #[test]
    fn socket_caller_needs_a_unix_socket_listener() {
        assert!(validate(&doc(&[LOCAL, &fx(), &caller("a", "local", "socket")])).is_ok());
        [(NET, "net"), (LOOPBACK, "lo")].iter().for_each(|(listener, name)| {
            let err = errors(&[listener, &fx(), &caller("a", name, "socket")]);
            assert!(matches!(&err[..], [ValidationError::WrongListenerKind { auth: "socket", .. }]), "{err:?}");
        });
    }

    #[test]
    fn listener_identified_callers_must_not_share_their_listener() {
        let err = errors(&[NET, &fx(), &caller("a", "net", "isolated-network"), &token_caller("b", "net", '1', "\"fx\"")]);
        let expected =
            ValidationError::SharedListener { caller: n("a"), auth: "isolated-network", listener: n("net"), others: vec![n("b")] };
        assert_eq!(err, [expected]);
        let err = errors(&[LOCAL, &fx(), &caller("a", "local", "socket"), &caller("b", "local", "socket")]);
        let shared = |caller: &str, other: &str| ValidationError::SharedListener {
            caller: n(caller),
            auth: "socket",
            listener: n("local"),
            others: vec![n(other)],
        };
        assert_eq!(err, [shared("a", "b"), shared("b", "a")]);
        assert!(err[0].to_string().contains("callers that share a listener must use tokens"), "{}", err[0]);
    }

    #[test]
    fn token_callers_may_share_a_listener_with_distinct_hashes() {
        let callers = [token_caller("a", "local", '1', "\"fx\""), token_caller("b", "local", '2', "\"fx\"")];
        assert!(validate(&doc(&[LOCAL, &fx(), &callers[0], &callers[1]])).is_ok());
    }

    #[test]
    fn token_callers_on_one_listener_must_not_share_a_hash() {
        let callers = ["a", "b", "c"].map(|name| token_caller(name, "local", '1', "\"fx\""));
        let err = errors(&[LOCAL, &fx(), &callers[0], &callers[1], &callers[2]]);
        assert_eq!(err, [ValidationError::SharedTokenHash { listener: n("local"), callers: vec![n("a"), n("b"), n("c")] }]);
        assert!(err[0].to_string().starts_with("callers a, b, c on listener local share a token_hash"), "{}", err[0]);
        let other_listener = [LOCAL, LOOPBACK, &fx(), &token_caller("a", "local", '1', "\"fx\""), &token_caller("b", "lo", '1', "\"fx\"")];
        assert!(validate(&doc(&other_listener)).is_ok());
    }

    #[test]
    fn overlapping_prefixes_are_rejected() {
        let v2 = route("fxtwo", "/fx/v2", "{ query = \"access_key\" }");
        let err = errors(&[LOCAL, &fx(), &v2, &token_caller("a", "local", '1', "\"fx\"")]);
        let expected =
            ValidationError::AmbiguousPrefix { route: n("fx"), prefix: n("/fx"), other: n("fxtwo"), other_prefix: n("/fx/v2") };
        assert_eq!(err, [expected]);
        let same = route("again", "/fx", "{ query = \"access_key\" }");
        let err = errors(&[LOCAL, &fx(), &same, &token_caller("a", "local", '1', "\"fx\"")]);
        assert!(matches!(&err[..], [ValidationError::AmbiguousPrefix { .. }]), "{err:?}");
    }

    #[test]
    fn prefixes_match_on_whole_segments() {
        let fxv2 = route("fxtwo", "/fxv2", "{ query = \"access_key\" }");
        let nested = route("nested", "/api/fx", "{ query = \"access_key\" }");
        assert!(validate(&doc(&[LOCAL, &fx(), &fxv2, &nested, &token_caller("a", "local", '1', "\"fx\"")])).is_ok());
    }

    #[test]
    fn token_header_must_not_be_a_reachable_slot() {
        let listener = format!("{LOCAL}token_header = \"x-api-key\"\n");
        let keyed = route("keyed", "/keyed", "{ header = \"X-API-Key\" }");
        let caller = token_caller("a", "local", '1', "\"fx\", \"keyed\"");
        let err = errors(&[&listener, &fx(), &keyed, &caller]);
        assert_eq!(err, [ValidationError::TokenHeaderIsSlot { listener: n("local"), header: n("x-api-key"), route: n("keyed") }]);
        let unreachable = token_caller("a", "local", '1', "\"fx\"");
        assert!(validate(&doc(&[&listener, &fx(), &keyed, &unreachable])).is_ok());
    }

    #[test]
    fn authorization_token_header_collides_with_basic_and_bearer_slots() {
        let listener = format!("{LOCAL}token_header = \"Authorization\"\n");
        let basic = route("basic", "/basic", "\"basic\"");
        let bearer = route("bearer", "/bearer", "{ header = \"authorization\", format = \"Bearer {}\" }");
        let err = errors(&[&listener, &fx(), &basic, &bearer, &token_caller("a", "local", '1', "\"basic\", \"bearer\", \"fx\"")]);
        let routes: Vec<_> = err
            .iter()
            .map(|e| match e {
                ValidationError::TokenHeaderIsSlot { route, .. } => route.as_str(),
                other => panic!("{other}"),
            })
            .collect();
        assert_eq!(routes, ["basic", "bearer"]);
    }

    #[test]
    fn every_error_is_reported_in_check_order() {
        let listener = format!("{LOCAL}token_header = \"X-Key\"\n");
        let keyed = route("keyed", "/fx/keyed", "{ header = \"X-Key\" }");
        let limit = "[callers.a.rate_limits]\nfx = { requests = 61, per_seconds = 60, burst = 10 }\n";
        let first = format!("{}{limit}", token_caller("a", "local", '1', "\"fx\", \"keyed\", \"gone\""));
        let (second, third) = (token_caller("b", "local", '1', "\"fx\""), caller("c", "nowhere", "socket"));
        let err = errors(&[&listener, &fx(), &keyed, &first, &second, &third]);
        let kinds: Vec<_> = err.iter().map(|e| format!("{e:?}").split([' ', '{']).next().unwrap().to_owned()).collect();
        let expected = ["UnknownRoute", "UnknownListener", "CallerRateLooser", "SharedTokenHash", "AmbiguousPrefix", "TokenHeaderIsSlot"];
        assert_eq!(kinds, expected);
        assert_eq!(validate(&doc(&[&listener, &fx(), &keyed, &first])).unwrap_err().len(), 4);
    }
}
