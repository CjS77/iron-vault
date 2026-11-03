//! The request form gate (spec §3.5 step 2): only an origin-form request that asks for no protocol change goes on.
//!
//! A `CONNECT` tunnel, an absolute-form target or an upgrade would carry a request around route selection and the final
//! outgoing-request check, so each is refused before authentication. The check is a pure function over the parts of
//! the request head it reads, so it allocates nothing and costs no token lookup.

use hyper::header::{CONNECTION, UPGRADE};
use hyper::{HeaderMap, Method, Uri, Version};

/// The rule a request head broke. Its text names the rule and never the target, which may hold a secret in its query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FormViolation {
    /// The method is `CONNECT`.
    #[error("CONNECT is not supported")]
    Connect,
    /// The target is absolute-form, authority-form or `*`.
    #[error("the request target must be origin-form")]
    NotOriginForm,
    /// The request asks to switch protocols.
    #[error("protocol upgrades are not supported")]
    Upgrade,
    /// The HTTP version is neither 1.0 nor 1.1.
    #[error("only HTTP/1.0 and HTTP/1.1 are supported")]
    Version,
}

/// Checks the request line and headers against the form gate, returning the first rule broken.
pub fn check_form(method: &Method, uri: &Uri, version: Version, headers: &HeaderMap) -> Result<(), FormViolation> {
    if method == Method::CONNECT {
        return Err(FormViolation::Connect);
    }
    // hyper parses `*` as a path-only `Uri`, so it is told apart by its path.
    if uri.scheme().is_some() || uri.authority().is_some() || uri.path() == "*" {
        return Err(FormViolation::NotOriginForm);
    }
    if headers.contains_key(UPGRADE) || connection_asks_upgrade(headers) {
        return Err(FormViolation::Upgrade);
    }
    match version {
        Version::HTTP_10 | Version::HTTP_11 => Ok(()),
        _ => Err(FormViolation::Version),
    }
}

/// Whether any `Connection` header lists the `upgrade` token, in any case and among other tokens.
fn connection_asks_upgrade(headers: &HeaderMap) -> bool {
    headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
}

#[cfg(test)]
mod tests {
    use hyper::header::HeaderValue;

    use super::*;

    fn check(method: &str, target: &str, version: Version, headers: &[(&str, &str)]) -> Result<(), FormViolation> {
        let headers = headers
            .iter()
            .map(|(name, value)| (name.parse().unwrap(), HeaderValue::from_str(value).unwrap()))
            .collect();
        check_form(&method.parse().unwrap(), &target.parse().unwrap(), version, &headers)
    }

    #[test]
    fn origin_form_requests_pass() {
        assert_eq!(check("GET", "/fx/latest?x=1", Version::HTTP_11, &[]), Ok(()));
        assert_eq!(check("POST", "/v1/chat", Version::HTTP_10, &[("connection", "keep-alive")]), Ok(()));
    }

    #[test]
    fn each_refused_form_names_its_rule() {
        let v = Version::HTTP_11;
        assert_eq!(check("CONNECT", "example.com:443", v, &[]), Err(FormViolation::Connect));
        assert_eq!(check("GET", "https://evil/x", v, &[]), Err(FormViolation::NotOriginForm));
        assert_eq!(
            check("GET", "//evil/x", v, &[]),
            Ok(()),
            "a double slash is a path, left to RequestTarget::parse"
        );
        assert_eq!(check("OPTIONS", "*", v, &[]), Err(FormViolation::NotOriginForm));
        assert_eq!(check("GET", "/", v, &[("upgrade", "websocket")]), Err(FormViolation::Upgrade));
        assert_eq!(check("GET", "/", v, &[("upgrade", "h2c")]), Err(FormViolation::Upgrade));
        assert_eq!(check("GET", "/", v, &[("connection", "Upgrade")]), Err(FormViolation::Upgrade));
        assert_eq!(
            check("GET", "/", v, &[("connection", "keep-alive, UPGRADE")]),
            Err(FormViolation::Upgrade)
        );
        assert_eq!(check("GET", "/", Version::HTTP_2, &[]), Err(FormViolation::Version));
        assert_eq!(check("GET", "/", Version::HTTP_09, &[]), Err(FormViolation::Version));
    }
}
