//! The upstream target: the URL an authorized request is sent to (spec §3.5 step 7, §3.6).
//!
//! The URL is built through the `url` API from the configured [`UpstreamUrl`] and an [`AuthorizedRequest`], never by
//! accepting caller text as a URL, so a caller cannot supply a scheme, an authority or a path the authorizer did not
//! see. The `url` crate rewrites some input silently, so every built URL is read back and compared with what was
//! authorized; a mismatch is a construction error rather than a request to a different path.

use thiserror::Error;
use url::Url;

use crate::authorization::AuthorizedRequest;
use crate::upstream::UpstreamUrl;

/// The URL the service will send an authorized request to: the configured upstream's scheme, host and port, the
/// authorized upstream path, and the caller's query.
///
/// Only [`UpstreamTarget::build`] creates one, and nothing changes its scheme, host or port afterwards, so the URL always
/// has the upstream's origin and the authorized path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamTarget {
    url: Url,
}

/// Why an upstream target could not be built.
///
/// Every variant means the `url` crate would send something other than what was authorized, which is a construction
/// defect, so the request must be refused. Variants carry no URL text, because the query may hold caller secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum UpstreamTargetError {
    /// The configured upstream's canonical form did not parse as a URL.
    #[error("the configured upstream does not parse as a URL")]
    Upstream,
    /// The built URL's scheme, host or port differs from the configured upstream.
    #[error("the built URL's origin differs from the configured upstream")]
    Origin,
    /// The built URL's path segments differ from the authorized upstream path.
    #[error("the built URL's path differs from the authorized path")]
    Path,
    /// The built URL's query differs from the caller's query.
    #[error("the built URL's query differs from the authorized query")]
    Query,
}

impl UpstreamTarget {
    /// Builds the target for `request` on `upstream`, which must be the selected route's configured upstream.
    ///
    /// The upstream path segments are already percent-encoded ([`NormalizedPath`](crate::NormalizedPath) form), so
    /// they reach the URL through `Url::set_path`, which keeps existing escapes; `path_segments_mut().push` would encode
    /// `%` again and turn `a%20b` into `a%2520b`.
    pub fn build(upstream: &UpstreamUrl, request: &AuthorizedRequest) -> Result<Self, UpstreamTargetError> {
        let mut url = Url::parse(&upstream.to_string()).map_err(|_| UpstreamTargetError::Upstream)?;
        url.set_path(&authorized_path(request));
        url.set_query(request.query().map(|query| query.as_str()));
        check_origin(&url, upstream)?;
        check_path(&url, request)?;
        check_query(&url, request)?;
        Ok(Self { url })
    }

    /// The URL to send to; read-only, so its origin and path stay the ones that were checked.
    pub fn as_url(&self) -> &Url {
        &self.url
    }

    /// The query without its leading `?`, for the query slot filler to rebuild; `None` when there is no query.
    pub fn query(&self) -> Option<&str> {
        self.url.query()
    }
}

/// `/`, the segments joined by `/`, and the trailing slash when the request had one.
fn authorized_path(request: &AuthorizedRequest) -> String {
    let trailing = if request.has_trailing_slash() { "/" } else { "" };
    format!("/{}{trailing}", request.upstream_segments().join("/"))
}

fn check_origin(url: &Url, upstream: &UpstreamUrl) -> Result<(), UpstreamTargetError> {
    let same = url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.host_str() == Some(upstream.host().as_str())
        && url.port_or_known_default() == Some(upstream.port().get());
    same.then_some(()).ok_or(UpstreamTargetError::Origin)
}

/// The segments `url` reports: the authorized ones, then an empty one for a trailing slash; the root path is one
/// empty segment.
fn check_path(url: &Url, request: &AuthorizedRequest) -> Result<(), UpstreamTargetError> {
    let segments = request.upstream_segments().iter().map(String::as_str);
    let empty = (request.upstream_segments().is_empty() || request.has_trailing_slash()).then_some("");
    let expected: Vec<&str> = segments.chain(empty).collect();
    let actual: Option<Vec<&str>> = url.path_segments().map(Iterator::collect);
    (actual.as_ref() == Some(&expected)).then_some(()).ok_or(UpstreamTargetError::Path)
}

fn check_query(url: &Url, request: &AuthorizedRequest) -> Result<(), UpstreamTargetError> {
    (url.query() == request.query().map(|query| query.as_str())).then_some(()).ok_or(UpstreamTargetError::Query)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::activation::{ActivePolicy, Capabilities, CatalogEntry, CredentialCatalog, activate};
    use crate::authorization::authorize;
    use crate::config::ParsedConfig;
    use crate::method::Method;
    use crate::name::CredentialName;
    use crate::port::Port;
    use crate::request_target::RequestTarget;
    use crate::spec_example::SPEC_EXAMPLE;
    use crate::validated::ValidatedConfig;

    /// Permits every §3.3 credential on its route's host, on both 443 and 8443.
    struct Catalog;

    impl CredentialCatalog for Catalog {
        fn entry(&self, name: &CredentialName) -> CatalogEntry {
            let host = match name.as_str() {
                "fx_key" => "api.fx.example",
                "venice" => "api.venice.ai",
                _ => "api.search.brave.com",
            };
            let port = |p: &str| p.parse::<Port>().unwrap();
            CatalogEntry::Usable { origins: [(host.parse().unwrap(), port("443")), (host.parse().unwrap(), port("8443"))].into() }
        }
    }

    /// The §3.3 example with every route opened to every path, so any request target can be built.
    fn open_example() -> String {
        ["[\"/latest\", \"/historical/**\"]", "[\"/api/v1/chat/completions\"]", "[\"/res/v1/web/search\"]"]
            .iter()
            .fold(SPEC_EXAMPLE.to_owned(), |doc, paths| doc.replace(paths, "[\"/**\"]"))
    }

    fn policy(doc: &str) -> ActivePolicy {
        let config = ValidatedConfig::try_from(ParsedConfig::from_toml(doc.as_bytes()).unwrap()).unwrap();
        activate(&config, &Capabilities::default(), &Catalog).unwrap()
    }

    /// Authorizes `target` for the caller granted its route, builds the target, and checks the round trip.
    fn build_in(doc: &str, method: Method, target: &str) -> UpstreamTarget {
        let policy = policy(doc);
        let caller = if target.starts_with("/fx") { "fx-mcp" } else { "naomi-backoffice" };
        let (path, query) = RequestTarget::parse(target).unwrap().into_parts();
        let request = authorize(&policy, &caller.parse().unwrap(), &method, &path, query).unwrap();
        let upstream = policy.config().routes()[request.route()].upstream();
        let built = UpstreamTarget::build(upstream, &request).unwrap();
        assert_round_trip(&built, &request);
        built
    }

    fn assert_round_trip(built: &UpstreamTarget, request: &AuthorizedRequest) {
        let segments: Vec<&str> = built.as_url().path_segments().unwrap().collect();
        let trailing = request.upstream_segments().is_empty() || request.has_trailing_slash();
        let expected: Vec<&str> = request.upstream_segments().iter().map(String::as_str).chain(trailing.then_some("")).collect();
        assert_eq!(segments, expected);
        assert_eq!(built.query(), request.query().map(|q| q.as_str()));
    }

    fn url(method: Method, target: &str) -> String {
        build_in(&open_example(), method, target).as_url().to_string()
    }

    #[test]
    fn spec_example_routes_build_their_upstream_urls() {
        let fx = build_in(SPEC_EXAMPLE, Method::Get, "/fx/latest?base=USD");
        assert_eq!(fx.as_url().as_str(), "https://api.fx.example/latest?base=USD");
        assert_eq!(fx.query(), Some("base=USD"));
        let venice = build_in(SPEC_EXAMPLE, Method::Post, "/venice/chat/completions");
        assert_eq!(venice.as_url().as_str(), "https://api.venice.ai/api/v1/chat/completions");
        assert_eq!(venice.query(), None);
    }

    #[test]
    fn encoded_segments_are_not_encoded_again() {
        assert_eq!(url(Method::Get, "/fx/a%20b"), "https://api.fx.example/a%20b");
        assert_eq!(url(Method::Get, "/fx/a%3Bb/c;d"), "https://api.fx.example/a%3Bb/c;d");
        assert_eq!(url(Method::Get, "/fx/caf%c3%a9"), "https://api.fx.example/caf%C3%A9");
        assert_eq!(url(Method::Get, "/fx/x%40y"), "https://api.fx.example/x%40y");
    }

    #[test]
    fn trailing_slash_and_root_are_preserved() {
        assert_eq!(url(Method::Get, "/fx/latest/"), "https://api.fx.example/latest/");
        assert_eq!(url(Method::Get, "/fx"), "https://api.fx.example/");
        assert_eq!(url(Method::Get, "/fx/"), "https://api.fx.example/");
        assert_eq!(url(Method::Post, "/venice"), "https://api.venice.ai/api/v1");
        assert_eq!(url(Method::Post, "/venice/"), "https://api.venice.ai/api/v1/");
    }

    #[test]
    fn query_is_kept_exactly() {
        assert_eq!(url(Method::Get, "/fx/latest?a=1&b=%2f/?x&a=2"), "https://api.fx.example/latest?a=1&b=%2f/?x&a=2");
        assert_eq!(url(Method::Get, "/fx/latest?k=%7B%22v%22%7D"), "https://api.fx.example/latest?k=%7B%22v%22%7D");
    }

    #[test]
    fn explicit_port_is_kept_and_443_is_omitted() {
        let doc = open_example().replace("https://api.fx.example", "https://api.fx.example:8443");
        let fx = build_in(&doc, Method::Get, "/fx/latest");
        assert_eq!(fx.as_url().as_str(), "https://api.fx.example:8443/latest");
        assert_eq!(fx.as_url().port(), Some(8443));
        let doc = open_example().replace("https://api.fx.example", "https://api.fx.example:443");
        assert_eq!(build_in(&doc, Method::Get, "/fx/latest").as_url().as_str(), "https://api.fx.example/latest");
    }

    fn fx_request(target: &str) -> AuthorizedRequest {
        let (path, query) = RequestTarget::parse(target).unwrap().into_parts();
        authorize(&policy(&open_example()), &"fx-mcp".parse().unwrap(), &Method::Get, &path, query).unwrap()
    }

    #[test]
    fn a_double_encoded_path_is_a_path_error() {
        let request = fx_request("/fx/a%20b");
        let mut pushed = Url::parse("https://api.fx.example/").unwrap();
        pushed.path_segments_mut().unwrap().clear().push("a%20b");
        assert_eq!(pushed.path(), "/a%2520b");
        assert_eq!(check_path(&pushed, &request), Err(UpstreamTargetError::Path));
    }

    #[test]
    fn a_changed_query_is_a_query_error() {
        let request = fx_request("/fx/latest?a=1");
        let changed = Url::parse("https://api.fx.example/latest?a=2").unwrap();
        assert_eq!(check_query(&changed, &request), Err(UpstreamTargetError::Query));
        let dropped = Url::parse("https://api.fx.example/latest").unwrap();
        assert_eq!(check_query(&dropped, &request), Err(UpstreamTargetError::Query));
    }

    #[test]
    fn a_changed_origin_is_an_origin_error() {
        let upstream: UpstreamUrl = "https://api.fx.example".parse().unwrap();
        ["http://api.fx.example/", "https://api.fx.example:8443/", "https://evil.example/", "https://u@api.fx.example/"]
            .into_iter()
            .for_each(|raw| assert_eq!(check_origin(&Url::parse(raw).unwrap(), &upstream), Err(UpstreamTargetError::Origin), "{raw}"));
        assert_eq!(check_origin(&Url::parse("https://api.fx.example:443/").unwrap(), &upstream), Ok(()));
        let ipv6: UpstreamUrl = "https://[::1]:8443".parse().unwrap();
        assert_eq!(check_origin(&Url::parse("https://[::1]:8443/").unwrap(), &ipv6), Ok(()));
    }
}
