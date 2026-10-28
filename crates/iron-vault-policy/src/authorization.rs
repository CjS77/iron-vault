//! Route selection and request authorization (spec §3.5 steps 3–4, §3.6, §3.12).
//!
//! [`authorize`] decides, once, which route an authenticated caller's request belongs to and whether the caller may use
//! it with this method and path. Its result, an [`AuthorizedRequest`], is the immutable request plan that rate limiting,
//! credential resolution and URL construction consume without deciding any of this again.

use thiserror::Error;

use crate::activation::ActivePolicy;
use crate::method::Method;
use crate::name::{CallerName, RouteName};
use crate::request_target::{NormalizedPath, RawQuery};
use crate::route::RouteConfig;

/// A request that passed route selection, the caller's grant, and the route's method and path restrictions.
///
/// Only [`authorize`] builds one, so holding one is proof that those checks passed; later steps take it rather than
/// a raw path so they cannot forward a path other than the one that was authorized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedRequest {
    route: RouteName,
    method: Method,
    upstream_segments: Vec<String>,
    trailing_slash: bool,
    query: Option<RawQuery>,
}

impl AuthorizedRequest {
    /// The selected route; look up its upstream, credential and slot through [`ActivePolicy::route`].
    pub fn route(&self) -> &RouteName {
        &self.route
    }

    /// The authorized method.
    pub fn method(&self) -> Method {
        self.method
    }

    /// The upstream path's segments: the upstream base segments followed by the request segments after the prefix.
    ///
    /// Segments are percent-encoded in the [`NormalizedPath`] representation, so they must be forwarded without being
    /// encoded again. Empty for the upstream root path.
    pub fn upstream_segments(&self) -> &[String] {
        &self.upstream_segments
    }

    /// Whether the upstream path ends in `/` after its last segment; never true for the root path.
    pub fn has_trailing_slash(&self) -> bool {
        self.trailing_slash
    }

    /// The caller's query, unchanged; path patterns never see it.
    pub fn query(&self) -> Option<&RawQuery> {
        self.query.as_ref()
    }
}

/// Why a request was not authorized; each variant names the status the request interface returns (spec §3.12).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AuthzError {
    /// No route's prefix matches the path: `404`.
    ///
    /// It carries nothing, so the response cannot disclose which routes exist or what other callers are granted.
    #[error("no route matches the request path")]
    NotFound,
    /// The caller may not make this request on the route its path selected: `403`, with no upstream request.
    #[error("request on route {route} is forbidden: {reason}")]
    Forbidden {
        /// The route the path selected.
        route: RouteName,
        /// Which check failed.
        reason: Refusal,
    },
    /// The caller is granted the route, but its credential record is unusable: `503`, while other routes keep serving.
    #[error("route {route} is unavailable because its credential cannot be used")]
    Unavailable {
        /// The unavailable route.
        route: RouteName,
    },
}

/// Which restriction refused a request on a matched route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum Refusal {
    /// The caller is not granted the route.
    #[error("the caller is not granted this route")]
    NotGranted,
    /// The method is not in the route's `methods`.
    #[error("the method is not allowed")]
    Method,
    /// The upstream path matches none of the route's `paths`.
    #[error("the upstream path is not allowed")]
    Path,
}

/// Selects the route for `path` and checks that `caller` may send `method` there.
///
/// Checks run in an order that discloses as little as possible: a caller learns that a route is unavailable only after
/// its grant to that route is confirmed, so an ungranted caller gets `Forbidden` whether or not the route is available.
/// The query is carried through unchecked, because path patterns match the upstream path excluding its query (§3.3).
pub fn authorize(
    policy: &ActivePolicy,
    caller: &CallerName,
    method: &Method,
    path: &NormalizedPath,
    query: Option<RawQuery>,
) -> Result<AuthorizedRequest, AuthzError> {
    let name = select_route(policy, path).ok_or(AuthzError::NotFound)?;
    let forbidden = |reason| AuthzError::Forbidden { route: name.clone(), reason };
    if !is_granted(policy, caller, name) {
        return Err(forbidden(Refusal::NotGranted));
    }
    let route = policy.route(name).ok_or_else(|| AuthzError::Unavailable { route: name.clone() })?;
    if !route.methods().contains(method) {
        return Err(forbidden(Refusal::Method));
    }
    let request = plan(name, *method, route, path, query);
    let segments: Vec<&str> = request.upstream_segments.iter().map(String::as_str).collect();
    match route.paths().matches(&segments) {
        true => Ok(request),
        false => Err(forbidden(Refusal::Path)),
    }
}

/// The route whose prefix covers the leading complete segments of `path`, available or not.
///
/// Whole-segment comparison is what keeps `/fx` from matching `/fx.evil.example` or `/fx@evil.example` (§3.6).
/// Validation guarantees that no two prefixes overlap, so at most one route matches.
fn select_route<'a>(policy: &'a ActivePolicy, path: &NormalizedPath) -> Option<&'a RouteName> {
    let routes = policy.config().routes().iter();
    routes.filter(|(_, route)| path.segments().starts_with(route.prefix().segments())).map(|(name, _)| name).next()
}

/// Whether `caller` lists `route` among its grants; an unknown caller has none.
fn is_granted(policy: &ActivePolicy, caller: &CallerName, route: &RouteName) -> bool {
    policy.config().callers().get(caller).is_some_and(|config| config.routes().contains(route))
}

/// Builds the plan for `path` on `route`: the upstream base segments, then the request segments after the prefix.
///
/// A trailing slash is kept, except on the root path, which has no segment for it to follow.
fn plan(name: &RouteName, method: Method, route: &RouteConfig, path: &NormalizedPath, query: Option<RawQuery>) -> AuthorizedRequest {
    let remainder = path.segments().iter().skip(route.prefix().segments().len());
    let upstream_segments: Vec<String> = route.upstream().base_segments().iter().chain(remainder).cloned().collect();
    let trailing_slash = path.has_trailing_slash() && !upstream_segments.is_empty();
    AuthorizedRequest { route: name.clone(), method, upstream_segments, trailing_slash, query }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::activation::{Capabilities, CatalogEntry, CredentialCatalog, activate};
    use crate::config::ParsedConfig;
    use crate::name::CredentialName;
    use crate::port::Port;
    use crate::request_target::RequestTarget;
    use crate::spec_example::SPEC_EXAMPLE;
    use crate::validated::ValidatedConfig;

    /// Permits every §3.3 credential on its route's upstream, except those named as unusable.
    struct Catalog(&'static [&'static str]);

    impl CredentialCatalog for Catalog {
        fn entry(&self, name: &CredentialName) -> CatalogEntry {
            let host = match name.as_str() {
                "fx_key" => "api.fx.example",
                "venice" => "api.venice.ai",
                _ => "api.search.brave.com",
            };
            match self.0.contains(&name.as_str()) {
                true => CatalogEntry::Unusable,
                false => {
                    CatalogEntry::Usable { kind: crate::CredentialKind::Static, origins: [(host.parse().unwrap(), Port::HTTPS)].into() }
                }
            }
        }
    }

    fn n<T: std::str::FromStr<Err: std::fmt::Debug>>(s: &str) -> T {
        s.parse().unwrap()
    }

    fn policy_from(doc: &str, unusable: &'static [&'static str]) -> ActivePolicy {
        let config = ValidatedConfig::try_from(ParsedConfig::from_toml(doc.as_bytes()).unwrap()).unwrap();
        activate(&config, &Capabilities::default(), &Catalog(unusable)).unwrap()
    }

    fn policy(unusable: &'static [&'static str]) -> ActivePolicy {
        policy_from(SPEC_EXAMPLE, unusable)
    }

    fn request(policy: &ActivePolicy, caller: &str, method: Method, target: &str) -> Result<AuthorizedRequest, AuthzError> {
        let (path, query) = RequestTarget::parse(target).unwrap().into_parts();
        authorize(policy, &n(caller), &method, &path, query)
    }

    fn forbidden(route: &str, reason: Refusal) -> AuthzError {
        AuthzError::Forbidden { route: n(route), reason }
    }

    fn upstream_path(request: &AuthorizedRequest) -> String {
        let trailing = if request.has_trailing_slash() { "/" } else { "" };
        format!("/{}{trailing}", request.upstream_segments().join("/"))
    }

    #[test]
    fn fx_latest_is_authorized() {
        let ok = request(&policy(&[]), "fx-mcp", Method::Get, "/fx/latest?base=USD").unwrap();
        assert_eq!(ok.route().as_str(), "fx");
        assert_eq!(ok.method(), Method::Get);
        assert_eq!(upstream_path(&ok), "/latest");
        assert_eq!(ok.query().map(RawQuery::as_str), Some("base=USD"));
    }

    #[test]
    fn upstream_path_starts_with_the_base_path() {
        let ok = request(&policy(&[]), "naomi-backoffice", Method::Post, "/venice/chat/completions").unwrap();
        assert_eq!(ok.upstream_segments(), ["api", "v1", "chat", "completions"]);
        assert_eq!(ok.query(), None);
    }

    #[test]
    fn method_and_path_restrictions_apply() {
        let p = policy(&[]);
        assert_eq!(upstream_path(&request(&p, "fx-mcp", Method::Get, "/fx/historical/2024/01").unwrap()), "/historical/2024/01");
        assert_eq!(request(&p, "fx-mcp", Method::Get, "/fx/convert"), Err(forbidden("fx", Refusal::Path)));
        assert_eq!(request(&p, "fx-mcp", Method::Post, "/fx/latest"), Err(forbidden("fx", Refusal::Method)));
    }

    #[test]
    fn prefixes_match_complete_segments_only() {
        let p = policy(&[]);
        ["/fx.evil.example/latest", "/fx@evil.example", "/fxlatest", "/nothing", "/", "/FX/latest"]
            .iter()
            .for_each(|target| assert_eq!(request(&p, "fx-mcp", Method::Get, target), Err(AuthzError::NotFound), "{target}"));
    }

    #[test]
    fn decoded_unreserved_escapes_select_the_route() {
        let ok = request(&policy(&[]), "fx-mcp", Method::Get, "/f%78/l%61test").unwrap();
        assert_eq!(upstream_path(&ok), "/latest");
    }

    #[test]
    fn ungranted_route_is_forbidden() {
        let p = policy(&[]);
        assert_eq!(request(&p, "fx-mcp", Method::Get, "/brave/res/v1/web/search"), Err(forbidden("brave", Refusal::NotGranted)));
        assert_eq!(request(&p, "naomi-backoffice", Method::Get, "/fx/latest"), Err(forbidden("fx", Refusal::NotGranted)));
        assert_eq!(request(&p, "nobody", Method::Get, "/fx/latest"), Err(forbidden("fx", Refusal::NotGranted)));
    }

    #[test]
    fn unavailable_route_answers_503_and_others_still_serve() {
        let p = policy(&["venice"]);
        let unavailable = Err(AuthzError::Unavailable { route: n("venice") });
        assert_eq!(request(&p, "naomi-backoffice", Method::Post, "/venice/chat/completions"), unavailable);
        assert!(request(&p, "naomi-backoffice", Method::Get, "/brave/res/v1/web/search").is_ok());
        assert!(request(&p, "fx-mcp", Method::Get, "/fx/latest").is_ok());
    }

    #[test]
    fn ungranted_caller_never_learns_a_route_is_unavailable() {
        let p = policy(&["venice"]);
        assert_eq!(request(&p, "fx-mcp", Method::Post, "/venice/chat/completions"), Err(forbidden("venice", Refusal::NotGranted)));
    }

    #[test]
    fn trailing_slash_is_preserved_except_at_the_root() {
        let doc = SPEC_EXAMPLE.replace("paths = [\"/latest\", \"/historical/**\"]", "paths = [\"/**\"]");
        let p = policy_from(&doc, &[]);
        let path = |target| upstream_path(&request(&p, "fx-mcp", Method::Get, target).unwrap());
        assert_eq!(path("/fx/latest/"), "/latest/");
        assert_eq!(path("/fx"), "/");
        assert_eq!(path("/fx/"), "/");
        let venice = request(&policy(&[]), "naomi-backoffice", Method::Post, "/venice/chat/completions/").unwrap();
        assert!(venice.has_trailing_slash());
        assert_eq!(upstream_path(&venice), "/api/v1/chat/completions/");
    }

    #[test]
    fn not_found_discloses_nothing() {
        assert_eq!(AuthzError::NotFound.to_string(), "no route matches the request path");
    }
}
