//! A `[routes.<name>]` section: one upstream mapping with its credential, slot and restrictions (spec §3.3, §3.7).

use std::collections::BTreeSet;

use serde::Deserialize;
use thiserror::Error;

use crate::config_path::ConfigPath;
use crate::confirmation::Confirmation;
use crate::method::Method;
use crate::name::CredentialName;
use crate::path_pattern::PathPatterns;
use crate::rate_limit::RateLimit;
use crate::route_prefix::RoutePrefix;
use crate::slot::Slot;
use crate::upstream::UpstreamUrl;

/// A validated route.
///
/// TOML form:
///
/// ```toml
/// [routes.fx]
/// prefix = "/fx"
/// upstream = "https://api.fx.example"
/// credential = "fx_key"
/// slot = { query = "access_key" }
/// methods = ["GET"]
/// paths = ["/latest", "/historical/**"]
/// rate_limit = { requests = 60, per_seconds = 60, burst = 10 }
/// confirm = "none"                         # optional; "none" when omitted
/// ca_file = "/etc/iron-vault/ca/fx.pem"    # optional administrator-installed CA (spec §3.7)
/// ```
///
/// Methods, paths and the rate limit are required so a missing restriction never widens into "allow all" (spec §3.3).
/// Whether `credential` exists and permits `upstream`, whether prefixes overlap, and whether `confirm = "touch"` can
/// be honoured need the whole configuration or the vault, so they are checked elsewhere (K-11).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "RawRoute")]
pub struct RouteConfig {
    prefix: RoutePrefix,
    upstream: UpstreamUrl,
    credential: CredentialName,
    slot: Slot,
    methods: Vec<Method>,
    paths: PathPatterns,
    rate_limit: RateLimit,
    confirm: Confirmation,
    ca_file: Option<ConfigPath>,
}

/// Why a route section was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RouteError {
    /// `methods` is empty.
    #[error("route must allow at least one method")]
    NoMethods,
    /// A method appears more than once in `methods`.
    #[error("route lists method {method} more than once")]
    DuplicateMethod {
        /// The repeated method.
        method: Method,
    },
}

impl RouteConfig {
    /// The request-path prefix that selects this route.
    pub fn prefix(&self) -> &RoutePrefix {
        &self.prefix
    }

    /// Where matching requests are forwarded.
    pub fn upstream(&self) -> &UpstreamUrl {
        &self.upstream
    }

    /// The credential this route injects.
    pub fn credential(&self) -> &CredentialName {
        &self.credential
    }

    /// Where the credential is written.
    pub fn slot(&self) -> &Slot {
        &self.slot
    }

    /// The allowed methods, in configured order, without duplicates; never empty.
    pub fn methods(&self) -> &[Method] {
        &self.methods
    }

    /// The upstream paths this route may reach.
    pub fn paths(&self) -> &PathPatterns {
        &self.paths
    }

    /// The route's aggregate rate limit across all callers.
    pub fn rate_limit(&self) -> RateLimit {
        self.rate_limit
    }

    /// The owner-confirmation policy.
    pub fn confirm(&self) -> Confirmation {
        self.confirm
    }

    /// An administrator-installed CA file that replaces the built-in roots for this upstream, if any.
    pub fn ca_file(&self) -> Option<&ConfigPath> {
        self.ca_file.as_ref()
    }
}

/// The `[routes.<name>]` table as written.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRoute {
    prefix: RoutePrefix,
    upstream: UpstreamUrl,
    credential: CredentialName,
    slot: Slot,
    methods: Vec<Method>,
    paths: PathPatterns,
    rate_limit: RateLimit,
    #[serde(default)]
    confirm: Confirmation,
    ca_file: Option<ConfigPath>,
}

impl TryFrom<RawRoute> for RouteConfig {
    type Error = RouteError;

    fn try_from(raw: RawRoute) -> Result<Self, Self::Error> {
        check_methods(&raw.methods)?;
        Ok(Self {
            prefix: raw.prefix,
            upstream: raw.upstream,
            credential: raw.credential,
            slot: raw.slot,
            methods: raw.methods,
            paths: raw.paths,
            rate_limit: raw.rate_limit,
            confirm: raw.confirm,
            ca_file: raw.ca_file,
        })
    }
}

/// Rejects an empty method list or a method listed twice.
fn check_methods(methods: &[Method]) -> Result<(), RouteError> {
    if methods.is_empty() {
        return Err(RouteError::NoMethods);
    }
    let mut seen = BTreeSet::new();
    methods.iter().find(|method| !seen.insert(**method)).map_or(Ok(()), |method| Err(RouteError::DuplicateMethod { method: *method }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FX: &str = r#"
prefix = "/fx"
upstream = "https://api.fx.example"
credential = "fx_key"
slot = { query = "access_key" }
methods = ["GET"]
paths = ["/latest", "/historical/**"]
rate_limit = { requests = 60, per_seconds = 60, burst = 10 }
"#;

    fn parse(s: &str) -> Result<RouteConfig, toml::de::Error> {
        toml::from_str(s)
    }

    fn rejected(s: &str, expected: &str) {
        let err = parse(s).unwrap_err().to_string();
        assert!(err.contains(expected), "{s}: {err}");
    }

    fn without(key: &str) -> String {
        FX.lines().filter(|line| !line.starts_with(&format!("{key} ="))).collect::<Vec<_>>().join("\n")
    }

    #[test]
    fn spec_route_parses() {
        let r = parse(FX).unwrap();
        assert_eq!(r.prefix().as_str(), "/fx");
        assert_eq!(r.upstream().to_string(), "https://api.fx.example/");
        assert_eq!(r.credential().as_str(), "fx_key");
        assert!(matches!(r.slot(), Slot::Query(name) if name.as_str() == "access_key"));
        assert_eq!(r.methods(), [Method::Get]);
        assert!(r.paths().matches(&["historical", "2024"]));
        assert_eq!(r.rate_limit().burst().get(), 10);
        assert_eq!(r.confirm(), Confirmation::None);
        assert_eq!(r.ca_file(), None);
    }

    #[test]
    fn optional_fields_parse() {
        let r = parse(&format!("{FX}confirm = \"touch\"\nca_file = \"/etc/iron-vault/ca/fx.pem\"")).unwrap();
        assert_eq!(r.confirm(), Confirmation::Touch);
        assert_eq!(r.ca_file().map(ToString::to_string).as_deref(), Some("/etc/iron-vault/ca/fx.pem"));
    }

    #[test]
    fn required_fields_are_enforced() {
        ["prefix", "upstream", "credential", "slot", "methods", "paths", "rate_limit"]
            .iter()
            .for_each(|key| rejected(&without(key), &format!("missing field `{key}`")));
    }

    #[test]
    fn unknown_fields_are_rejected() {
        rejected(&format!("{FX}hosts = [\"evil.example\"]"), "unknown field `hosts`");
    }

    #[test]
    fn methods_must_be_non_empty_and_unique() {
        rejected(&format!("{}\nmethods = []", without("methods")), "at least one method");
        rejected(&format!("{}\nmethods = [\"GET\", \"POST\", \"GET\"]", without("methods")), "method GET more than once");
        rejected(&format!("{}\nmethods = [\"CONNECT\"]", without("methods")), "CONNECT");
    }

    #[test]
    fn relative_ca_file_is_rejected() {
        rejected(&format!("{FX}ca_file = \"ca/fx.pem\""), "must be absolute");
    }

    #[test]
    fn bad_prefixes_are_rejected() {
        rejected(&format!("{}\nprefix = \"/\"", without("prefix")), "must not be \"/\"");
        rejected(&format!("{}\nprefix = \"/fx/\"", without("prefix")), "trailing slash");
        rejected(&format!("{}\nprefix = \"/fx/*\"", without("prefix")), "wildcard");
    }
}
