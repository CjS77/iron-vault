//! A `[callers.<name>]` section: one caller's listener, identity mechanism and route grants (spec §6, §7, §8).

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use thiserror::Error;

use crate::account_name::AccountName;
use crate::name::{ListenerName, RouteName};
use crate::rate_limit::RateLimit;
use crate::token_hash::TokenHash;

/// A validated caller.
///
/// TOML forms:
///
/// ```toml
/// [callers.fx-mcp]
/// listener = "local"
/// auth = "peer"
/// user = "fx-mcp"
/// routes = ["fx"]
///
/// [callers.fx-mcp.rate_limits]
/// fx = { requests = 10, per_seconds = 60, burst = 2 }
///
/// [callers.brave-cli]
/// listener = "loopback"
/// token_hash = "blake2b:<64 lowercase hex digits>"
/// routes = ["brave"]
///
/// [callers.naomi-backoffice]
/// listener = "naomi-backoffice"
/// auth = "isolated-network"
/// routes = ["venice", "brave"]
/// ```
///
/// Only rules local to the section are checked here. That `listener` and every route exist, that a per-caller rate
/// limit is no looser than its route's, and that the listener suits the caller's `auth` (a sole caller on a TLS TCP
/// listener for `isolated-network`; a Unix socket shared only with peer callers of other accounts for `peer`) need the
/// whole configuration and are checked by [`ValidatedConfig`](crate::ValidatedConfig).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "RawCaller")]
pub struct CallerConfig {
    listener: ListenerName,
    auth: CallerAuth,
    routes: Vec<RouteName>,
    rate_limits: BTreeMap<RouteName, RateLimit>,
}

/// How the service establishes that a connection is this caller (spec §7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallerAuth {
    /// The caller presents a token whose hash matches this one.
    Token(TokenHash),
    /// The listener's address identifies the caller's isolated Docker network.
    IsolatedNetwork,
    /// The OS account the kernel reports for the process connecting to the listener's Unix socket identifies the
    /// caller. It proves which account connected, never which program, so every process of that account shares the
    /// caller's routes.
    Peer(AccountName),
}

/// Why a caller section was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CallerError {
    /// `auth = "token"`, or no `auth`, without a `token_hash`.
    #[error("caller uses token authentication but has no token_hash")]
    MissingTokenHash,
    /// A `token_hash` on a caller that does not authenticate by token, where it would never be checked.
    #[error("caller sets token_hash but uses auth = \"{auth}\"; token_hash applies only to auth = \"token\"")]
    UnusedTokenHash {
        /// The configured `auth` value.
        auth: &'static str,
    },
    /// `auth = "peer"` without a `user`.
    #[error("caller uses auth = \"peer\" but has no user")]
    MissingUser,
    /// A `user` on a caller that is not identified by its peer account, where it would never be checked.
    #[error("caller sets user but uses auth = \"{auth}\"; user applies only to auth = \"peer\"")]
    UnusedUser {
        /// The configured `auth` value.
        auth: &'static str,
    },
    /// `routes` is empty.
    #[error("caller must be granted at least one route")]
    NoRoutes,
    /// A route appears more than once in `routes`.
    #[error("caller lists route {route} more than once")]
    DuplicateRoute {
        /// The repeated route.
        route: RouteName,
    },
    /// A per-caller rate limit names a route the caller is not granted.
    #[error("caller sets a rate limit for route {route}, which is not in its routes")]
    RateLimitForUngrantedRoute {
        /// The route named in `rate_limits`.
        route: RouteName,
    },
}

impl CallerConfig {
    /// The listener this caller connects through.
    pub fn listener(&self) -> &ListenerName {
        &self.listener
    }

    /// How the caller is identified.
    pub fn auth(&self) -> &CallerAuth {
        &self.auth
    }

    /// The granted routes, in configured order, without duplicates.
    pub fn routes(&self) -> &[RouteName] {
        &self.routes
    }

    /// Per-route limits for this caller, applied in addition to each route's aggregate limit (spec §8).
    pub fn rate_limits(&self) -> &BTreeMap<RouteName, RateLimit> {
        &self.rate_limits
    }
}

/// The `auth` key as written.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum AuthKind {
    #[default]
    Token,
    IsolatedNetwork,
    Peer,
}

/// The `[callers.<name>]` table as written.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCaller {
    listener: ListenerName,
    #[serde(default)]
    auth: AuthKind,
    token_hash: Option<TokenHash>,
    user: Option<AccountName>,
    routes: Vec<RouteName>,
    #[serde(default)]
    rate_limits: BTreeMap<RouteName, RateLimit>,
}

impl TryFrom<RawCaller> for CallerConfig {
    type Error = CallerError;

    fn try_from(raw: RawCaller) -> Result<Self, Self::Error> {
        let auth = caller_auth(raw.auth, raw.token_hash, raw.user)?;
        check_routes(&raw.routes)?;
        check_rate_limit_routes(&raw.routes, &raw.rate_limits)?;
        Ok(Self {
            listener: raw.listener,
            auth,
            routes: raw.routes,
            rate_limits: raw.rate_limits,
        })
    }
}

/// Pairs `auth` with the one key it needs: `token_hash` for token authentication, `user` for `peer`. A key that the
/// `auth` value never checks is refused rather than ignored, so a typo in `auth` cannot silently drop it.
fn caller_auth(kind: AuthKind, token_hash: Option<TokenHash>, user: Option<AccountName>) -> Result<CallerAuth, CallerError> {
    match kind {
        AuthKind::Token => {
            refuse_user(user, "token")?;
            token_hash.map(CallerAuth::Token).ok_or(CallerError::MissingTokenHash)
        }
        AuthKind::IsolatedNetwork => {
            refuse_token_hash(token_hash, "isolated-network")?;
            refuse_user(user, "isolated-network").map(|()| CallerAuth::IsolatedNetwork)
        }
        AuthKind::Peer => {
            refuse_token_hash(token_hash, "peer")?;
            user.map(CallerAuth::Peer).ok_or(CallerError::MissingUser)
        }
    }
}

fn refuse_token_hash(token_hash: Option<TokenHash>, auth: &'static str) -> Result<(), CallerError> {
    token_hash.map_or(Ok(()), |_| Err(CallerError::UnusedTokenHash { auth }))
}

fn refuse_user(user: Option<AccountName>, auth: &'static str) -> Result<(), CallerError> {
    user.map_or(Ok(()), |_| Err(CallerError::UnusedUser { auth }))
}

/// Rejects an empty grant list or a route listed twice.
fn check_routes(routes: &[RouteName]) -> Result<(), CallerError> {
    if routes.is_empty() {
        return Err(CallerError::NoRoutes);
    }
    let mut seen = BTreeSet::new();
    routes
        .iter()
        .find(|route| !seen.insert(*route))
        .map_or(Ok(()), |route| Err(CallerError::DuplicateRoute { route: route.clone() }))
}

/// Rejects a per-caller limit for a route the caller cannot use, which would be a silent no-op.
fn check_rate_limit_routes(routes: &[RouteName], rate_limits: &BTreeMap<RouteName, RateLimit>) -> Result<(), CallerError> {
    rate_limits.keys().find(|route| !routes.contains(route)).map_or(Ok(()), |route| {
        Err(CallerError::RateLimitForUngrantedRoute { route: route.clone() })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal peer caller; tests append keys to it.
    const PEER: &str = "listener = \"local\"\nauth = \"peer\"\nuser = \"code\"\nroutes = [\"fx\"]";

    const HASH: &str = "blake2b:0123456789abcdef00112233445566778899aabbccddeeff0f1e2d3c4b5a6978";

    fn parse(s: &str) -> Result<CallerConfig, toml::de::Error> {
        toml::from_str(s)
    }

    fn rejected(s: &str, expected: &str) {
        let err = parse(s).unwrap_err().to_string();
        assert!(err.contains(expected), "{s}: {err}");
    }

    fn route_names(c: &CallerConfig) -> Vec<&str> {
        c.routes().iter().map(RouteName::as_str).collect()
    }

    #[test]
    fn spec_token_caller_parses() {
        // §6 writes `token_hash = "blake2b:..."`; a placeholder digest is not a valid hash, so a real one stands in.
        let c = parse(&format!("listener = \"local\"\ntoken_hash = \"{HASH}\"\nroutes = [\"fx\"]")).unwrap();
        assert_eq!(c.listener().as_str(), "local");
        assert_eq!(c.auth(), &CallerAuth::Token(HASH.parse().unwrap()));
        assert_eq!(route_names(&c), ["fx"]);
        assert!(c.rate_limits().is_empty());
    }

    #[test]
    fn spec_isolated_network_caller_parses() {
        let c = parse("listener = \"naomi-backoffice\"\nauth = \"isolated-network\"\nroutes = [\"venice\", \"brave\"]").unwrap();
        assert_eq!(c.auth(), &CallerAuth::IsolatedNetwork);
        assert_eq!(route_names(&c), ["venice", "brave"]);
    }

    #[test]
    fn spec_listener_and_caller_sections_parse_together() {
        #[derive(Deserialize)]
        struct Config {
            listeners: BTreeMap<ListenerName, crate::listener::ListenerConfig>,
            callers: BTreeMap<crate::name::CallerName, CallerConfig>,
        }
        let toml = format!(
            r#"
            [listeners.local]
            unix_socket = "/run/iron-vault/proxy.sock"

            [callers.fx-mcp]
            listener = "local"
            token_hash = "{HASH}"
            routes = ["fx"]

            [callers.naomi-backoffice]
            listener = "naomi-backoffice"
            auth = "isolated-network"
            routes = ["venice", "brave"]

            [listeners.naomi-backoffice]
            address = "10.20.0.2:7878"
            tls_certificate = "/etc/iron-vault/tls/server.crt"
            tls_key = "/etc/iron-vault/tls/server.key"
            "#
        );
        let config: Config = toml::from_str(&toml).unwrap();
        assert_eq!(
            config.listeners.keys().map(ListenerName::as_str).collect::<Vec<_>>(),
            ["local", "naomi-backoffice"]
        );
        assert_eq!(config.callers.len(), 2);
    }

    #[test]
    fn peer_caller_parses() {
        assert_eq!(
            parse(PEER).unwrap().auth(),
            &CallerAuth::Peer(AccountName::try_from("code").unwrap())
        );
    }

    #[test]
    fn peer_needs_a_user_and_no_token_hash() {
        rejected(
            "listener = \"local\"\nauth = \"peer\"\nroutes = [\"fx\"]",
            "auth = \"peer\" but has no user",
        );
        rejected(
            &format!("{PEER}\ntoken_hash = \"{HASH}\""),
            "token_hash applies only to auth = \"token\"",
        );
        rejected(&PEER.replace("\"code\"", "\"Code\""), "invalid account name \"Code\"");
    }

    #[test]
    fn user_is_refused_without_peer_auth() {
        rejected(
            &format!("listener = \"local\"\ntoken_hash = \"{HASH}\"\nuser = \"code\"\nroutes = [\"fx\"]"),
            "user applies only to auth = \"peer\"",
        );
        rejected(
            "listener = \"n\"\nauth = \"isolated-network\"\nuser = \"code\"\nroutes = [\"fx\"]",
            "uses auth = \"isolated-network\"",
        );
    }

    #[test]
    fn socket_auth_is_an_unknown_variant() {
        rejected(
            "listener = \"local\"\nauth = \"socket\"\nroutes = [\"fx\"]",
            "unknown variant `socket`",
        );
    }

    #[test]
    fn per_route_rate_limit_parses() {
        let limit = "[rate_limits]\nfx = { requests = 10, per_seconds = 60, burst = 2 }";
        let s = format!("listener = \"local\"\ntoken_hash = \"{HASH}\"\nroutes = [\"fx\"]\n{limit}");
        let c = parse(&s).unwrap();
        let fx = c.rate_limits().get(&RouteName::try_from("fx").unwrap()).unwrap();
        assert_eq!((fx.requests().get(), fx.per_seconds().get(), fx.burst().get()), (10, 60, 2));
    }

    #[test]
    fn token_hash_is_required_iff_token_auth() {
        rejected("listener = \"local\"\nroutes = [\"fx\"]", "has no token_hash");
        rejected("listener = \"local\"\nauth = \"token\"\nroutes = [\"fx\"]", "has no token_hash");
        rejected(
            &format!("listener = \"n\"\nauth = \"isolated-network\"\ntoken_hash = \"{HASH}\"\nroutes = [\"fx\"]"),
            "isolated-network",
        );
    }

    #[test]
    fn bad_token_hashes_are_rejected() {
        rejected(
            "listener = \"local\"\ntoken_hash = \"blake2b:...\"\nroutes = [\"fx\"]",
            "must be 64 lowercase hex digits",
        );
        rejected(
            &format!(
                "listener = \"local\"\ntoken_hash = \"{}\"\nroutes = [\"fx\"]",
                HASH.to_ascii_uppercase()
            ),
            "must start with",
        );
        let upper = format!("blake2b:{}", HASH[8..].to_ascii_uppercase());
        rejected(
            &format!("listener = \"local\"\ntoken_hash = \"{upper}\"\nroutes = [\"fx\"]"),
            "other than 0-9 or a-f",
        );
    }

    #[test]
    fn unknown_auth_is_rejected() {
        ["\"Token\"", "\"isolated_network\"", "\"Peer\"", "\"socket\"", "\"\""]
            .iter()
            .for_each(|a| {
                assert!(
                    parse(&format!("listener = \"local\"\nauth = {a}\nroutes = [\"fx\"]")).is_err(),
                    "{a}"
                )
            });
    }

    #[test]
    fn routes_must_be_non_empty_and_unique() {
        rejected(
            "listener = \"local\"\nauth = \"peer\"\nuser = \"code\"\nroutes = []",
            "at least one route",
        );
        rejected(
            "listener = \"local\"\nauth = \"peer\"\nuser = \"code\"\nroutes = [\"fx\", \"brave\", \"fx\"]",
            "lists route fx more than once",
        );
        rejected("listener = \"local\"\nauth = \"peer\"\nuser = \"code\"", "missing field `routes`");
        rejected(
            "listener = \"local\"\nauth = \"peer\"\nuser = \"code\"\nroutes = [\"Fx\"]",
            "invalid route name",
        );
    }

    #[test]
    fn rate_limit_must_name_a_granted_route() {
        let limit = "[rate_limits]\nbrave = { requests = 1, per_seconds = 1, burst = 1 }";
        let s = &format!("listener = \"local\"\nauth = \"peer\"\nuser = \"code\"\nroutes = [\"fx\"]\n{limit}");
        rejected(s, "rate limit for route brave, which is not in its routes");
    }

    #[test]
    fn listener_is_required_and_validated() {
        rejected("auth = \"peer\"\nuser = \"code\"\nroutes = [\"fx\"]", "missing field `listener`");
        rejected(
            "listener = \"Local\"\nauth = \"peer\"\nuser = \"code\"\nroutes = [\"fx\"]",
            "invalid listener name",
        );
    }

    #[test]
    fn unknown_fields_are_rejected() {
        rejected(
            "listener = \"local\"\nauth = \"peer\"\nuser = \"code\"\nroutes = [\"fx\"]\ntoken = \"x\"",
            "unknown field",
        );
    }
}
