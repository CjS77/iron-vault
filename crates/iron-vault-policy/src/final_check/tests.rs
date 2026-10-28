use secrecy::SecretString;

use super::*;
use crate::activation::{ActivePolicy, Capabilities, CatalogEntry, CredentialCatalog, activate};
use crate::authorization::authorize;
use crate::config::ParsedConfig;
use crate::header_value::HeaderValue;
use crate::name::CredentialName;
use crate::request_target::RequestTarget;
use crate::slot_value::SlotValue;
use crate::spec_example::SPEC_EXAMPLE;
use crate::upstream_target::UpstreamTarget;
use crate::validated::ValidatedConfig;

const SECRET: &str = "S3CR3T";

/// Permits every §3.3 credential on its route's host at 443.
struct Catalog;

impl CredentialCatalog for Catalog {
    fn entry(&self, name: &CredentialName) -> CatalogEntry {
        CatalogEntry::Usable {
            kind: crate::CredentialKind::Static,
            origins: origins(route_host(name.as_str()), 443),
        }
    }
}

fn route_host(credential: &str) -> &'static str {
    match credential {
        "fx_key" => "api.fx.example",
        "venice" => "api.venice.ai",
        _ => "api.search.brave.com",
    }
}

fn origins(host: &str, port: u16) -> BTreeSet<(Host, Port)> {
    [(host.parse().unwrap(), Port::try_from(port).unwrap())].into()
}

/// The §3.3 example with every route opened to every path.
fn policy() -> ActivePolicy {
    let doc = [
        "[\"/latest\", \"/historical/**\"]",
        "[\"/api/v1/chat/completions\"]",
        "[\"/res/v1/web/search\"]",
    ]
    .iter()
    .fold(SPEC_EXAMPLE.to_owned(), |doc, paths| doc.replace(paths, "[\"/**\"]"));
    let config = ValidatedConfig::try_from(ParsedConfig::from_toml(doc.as_bytes()).unwrap()).unwrap();
    activate(&config, &Capabilities::default(), &Catalog).unwrap()
}

/// Everything `final_check` takes, starting from a valid assembled request; tests change exactly one fact.
struct Case {
    request: OutgoingRequest,
    authorized: AuthorizedRequest,
    upstream: UpstreamUrl,
    slot: Slot,
    value: SlotValue,
    permitted: BTreeSet<(Host, Port)>,
}

impl Case {
    /// `target` authorized for the caller granted its route and assembled with the route's slot filled with `SECRET`.
    fn new(target: &str) -> Self {
        Self::with_slot(target, None)
    }

    /// Like [`Case::new`], but with a Basic slot in place of the route's.
    fn basic(target: &str) -> Self {
        Self::with_slot(target, Some(Slot::Basic))
    }

    fn with_slot(target: &str, slot: Option<Slot>) -> Self {
        let policy = policy();
        let caller = if target.starts_with("/fx") { "fx-mcp" } else { "naomi-backoffice" };
        let method = if target.starts_with("/venice") { Method::Post } else { Method::Get };
        let (path, query) = RequestTarget::parse(target).unwrap().into_parts();
        let authorized = authorize(&policy, &caller.parse().unwrap(), &method, &path, query).unwrap();
        let route = &policy.config().routes()[authorized.route()];
        let slot = slot.unwrap_or_else(|| route.slot().clone());
        let built = UpstreamTarget::build(route.upstream(), &authorized).unwrap();
        let value = secret_value(SECRET);
        let request = OutgoingRequest::assemble(&authorized, built, OutgoingHeaders::new(), &slot, route.credential(), &value).unwrap();
        let permitted = origins(route_host(route.credential().as_str()), 443);
        Self {
            request,
            authorized,
            upstream: route.upstream().clone(),
            slot,
            value,
            permitted,
        }
    }

    fn with_url(self, change: impl FnOnce(&mut Url)) -> Self {
        let (method, mut url, headers) = self.request.into_parts();
        change(&mut url);
        Self {
            request: OutgoingRequest::unchecked(method, url, headers),
            ..self
        }
    }

    fn with_method(self, method: Method) -> Self {
        let (_, url, headers) = self.request.into_parts();
        Self {
            request: OutgoingRequest::unchecked(method, url, headers),
            ..self
        }
    }

    /// Appends a header without the reserved-header refusal `OutgoingHeaders::insert` applies.
    fn with_header(self, name: &str, value: &str) -> Self {
        let (method, url, mut headers) = self.request.into_parts();
        headers.push_unchecked(name.parse().unwrap(), HeaderValue::try_from(value).unwrap());
        Self {
            request: OutgoingRequest::unchecked(method, url, headers),
            ..self
        }
    }

    fn check(self) -> Result<CheckedRequest, FinalCheckError> {
        final_check(
            self.request,
            &self.authorized,
            &self.upstream,
            &self.slot,
            &self.value,
            &self.permitted,
        )
    }
}

fn secret_value(secret: &str) -> SlotValue {
    SlotValue::new(SecretString::from(secret)).unwrap()
}

/// The case fails with `expected`, and the error's text names no secret, query or header value.
fn assert_refused(case: Case, expected: FinalCheckError) {
    let error = case.check().unwrap_err();
    assert_eq!(error, expected);
    let text = format!("{error} {error:?}");
    ["S3CR3T", "access_key", "USD", "evil", "8443"]
        .iter()
        .for_each(|leak| assert!(!text.contains(leak), "{text}"));
}

fn header_list(checked: &CheckedRequest) -> Vec<(String, Vec<u8>)> {
    checked
        .headers()
        .iter()
        .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
        .collect()
}

#[test]
fn spec_example_routes_pass() {
    let fx = Case::new("/fx/latest?base=USD").check().unwrap();
    assert_eq!(fx.url().as_str(), "https://api.fx.example/latest?base=USD&access_key=S3CR3T");
    assert_eq!((fx.method(), fx.host().as_str()), (Method::Get, "api.fx.example"));
    assert!(header_list(&fx).is_empty());

    let venice = Case::new("/venice/chat/completions").check().unwrap();
    assert_eq!(venice.url().as_str(), "https://api.venice.ai/api/v1/chat/completions");
    assert_eq!((venice.method(), venice.host().as_str()), (Method::Post, "api.venice.ai"));
    assert_eq!(header_list(&venice), [("Authorization".to_owned(), b"Bearer S3CR3T".to_vec())]);

    let brave = Case::new("/brave/res/v1/web/search?q=rust").check().unwrap();
    assert_eq!(brave.url().as_str(), "https://api.search.brave.com/res/v1/web/search?q=rust");
    assert_eq!(brave.host().as_str(), "api.search.brave.com");
    assert_eq!(
        header_list(&brave),
        [("X-Subscription-Token".to_owned(), SECRET.as_bytes().to_vec())]
    );
}

#[test]
fn basic_slot_passes() {
    let basic = Case::basic("/brave/res/v1/web/search").check().unwrap();
    assert_eq!(header_list(&basic), [("Authorization".to_owned(), b"Basic S3CR3T".to_vec())]);
}

#[test]
fn explicit_port_passes_when_upstream_and_record_agree() {
    let case = Case::new("/fx/latest").with_url(|url| url.set_port(Some(8443)).unwrap());
    let case = Case {
        upstream: "https://api.fx.example:8443".parse().unwrap(),
        permitted: origins("api.fx.example", 8443),
        ..case
    };
    let checked = case.check().unwrap();
    assert_eq!((checked.host().as_str(), checked.url().port()), ("api.fx.example", Some(8443)));
}

#[test]
fn an_http_scheme_is_refused() {
    assert_refused(
        Case::new("/fx/latest?base=USD").with_url(|url| url.set_scheme("http").unwrap()),
        FinalCheckError::Scheme,
    );
}

#[test]
fn user_info_is_refused() {
    assert_refused(
        Case::new("/fx/latest").with_url(|url| url.set_username("evil").unwrap()),
        FinalCheckError::UserInfo,
    );
    assert_refused(
        Case::new("/fx/latest").with_url(|url| url.set_password(Some("p")).unwrap()),
        FinalCheckError::UserInfo,
    );
}

#[test]
fn a_fragment_is_refused() {
    assert_refused(
        Case::new("/fx/latest").with_url(|url| url.set_fragment(Some("f"))),
        FinalCheckError::Fragment,
    );
}

#[test]
fn a_host_other_than_the_upstreams_is_refused() {
    let case = Case::new("/fx/latest").with_url(|url| url.set_host(Some("api.fx.example.evil.com")).unwrap());
    assert_refused(case, FinalCheckError::Host);
}

#[test]
fn a_host_the_record_does_not_permit_is_refused_without_suffix_matching() {
    let case = Case::new("/fx/latest").with_url(|url| url.set_host(Some("api.fx.example.evil.com")).unwrap());
    assert_refused(
        Case {
            upstream: "https://api.fx.example.evil.com".parse().unwrap(),
            ..case
        },
        FinalCheckError::Origin,
    );
}

#[test]
fn a_port_other_than_the_upstreams_is_refused() {
    assert_refused(
        Case::new("/fx/latest").with_url(|url| url.set_port(Some(8443)).unwrap()),
        FinalCheckError::Port,
    );
}

#[test]
fn a_port_the_upstream_allows_but_the_record_does_not_is_refused() {
    let case = Case::new("/fx/latest").with_url(|url| url.set_port(Some(8443)).unwrap());
    assert_refused(
        Case {
            upstream: "https://api.fx.example:8443".parse().unwrap(),
            ..case
        },
        FinalCheckError::Origin,
    );
}

#[test]
fn a_path_outside_the_base_path_is_refused() {
    let outside = Case::new("/venice/chat/completions").with_url(|url| url.set_path("/api/v2/chat/completions"));
    assert_refused(outside, FinalCheckError::Path);
    let above = Case::new("/venice/chat/completions").with_url(|url| url.set_path("/chat/completions"));
    assert_refused(above, FinalCheckError::Path);
}

#[test]
fn an_authorized_path_outside_this_upstreams_base_is_refused() {
    let case = Case::new("/venice/chat/completions");
    assert_refused(
        Case {
            upstream: "https://api.venice.ai/api/v2".parse().unwrap(),
            ..case
        },
        FinalCheckError::Path,
    );
}

#[test]
fn a_path_other_than_the_authorized_one_is_refused() {
    let other = Case::new("/venice/chat/completions").with_url(|url| url.set_path("/api/v1/models"));
    assert_refused(other, FinalCheckError::Path);
    let trailing = Case::new("/fx/latest").with_url(|url| url.set_path("/latest/"));
    assert_refused(trailing, FinalCheckError::Path);
}

#[test]
fn a_method_other_than_the_authorized_one_is_refused() {
    assert_refused(
        Case::new("/venice/chat/completions").with_method(Method::Get),
        FinalCheckError::Method,
    );
}

#[test]
fn a_host_header_is_refused() {
    assert_refused(
        Case::new("/brave/res/v1/web/search").with_header("Host", "evil.example"),
        FinalCheckError::ReservedHeader,
    );
}

#[test]
fn a_slot_written_twice_is_refused() {
    let query = Case::new("/fx/latest?base=USD").with_url(|url| url.set_query(Some("base=USD&access_key=S3CR3T&access%5Fkey=S3CR3T")));
    assert_refused(query, FinalCheckError::Slot);
    assert_refused(
        Case::new("/brave/res/v1/web/search").with_header("x-subscription-token", SECRET),
        FinalCheckError::Slot,
    );
    assert_refused(
        Case::basic("/brave/res/v1/web/search").with_header("authorization", "Basic S3CR3T"),
        FinalCheckError::Slot,
    );
}

#[test]
fn a_missing_slot_is_refused() {
    assert_refused(
        Case::new("/fx/latest?base=USD").with_url(|url| url.set_query(Some("base=USD"))),
        FinalCheckError::Slot,
    );
    assert_refused(Case::new("/fx/latest").with_url(|url| url.set_query(None)), FinalCheckError::Slot);
}

#[test]
fn debug_never_shows_the_credential() {
    let fx = Case::new("/fx/latest?base=USD").check().unwrap();
    let brave = Case::new("/brave/res/v1/web/search").check().unwrap();
    [format!("{fx:?}"), format!("{brave:?}")]
        .iter()
        .for_each(|debug| assert!(!debug.contains(SECRET), "{debug}"));
    assert!(format!("{fx:?}").contains("https://api.fx.example/latest"));
}

#[test]
fn a_slot_holding_anything_but_the_credential_is_refused() {
    let query = Case::new("/fx/latest?base=USD").with_url(|url| url.set_query(Some("base=USD&access_key=evil")));
    assert_refused(query, FinalCheckError::SlotValue);
    let header = Case::new("/venice/chat/completions");
    assert_refused(
        Case {
            value: secret_value("evil"),
            ..header
        },
        FinalCheckError::SlotValue,
    );
    let basic = Case::basic("/brave/res/v1/web/search");
    assert_refused(
        Case {
            value: secret_value("evil"),
            ..basic
        },
        FinalCheckError::SlotValue,
    );
}

#[test]
fn the_credential_must_hold_its_formatted_and_encoded_form() {
    let unformatted = Case::new("/venice/chat/completions");
    let (method, url, mut headers) = unformatted.request.into_parts();
    headers.remove_all(&"Authorization".parse().unwrap());
    headers.push_unchecked("Authorization".parse().unwrap(), HeaderValue::try_from(SECRET).unwrap());
    let unformatted = Case {
        request: OutgoingRequest::unchecked(method, url, headers),
        ..unformatted
    };
    assert_refused(unformatted, FinalCheckError::SlotValue);

    let fx = Case::new("/fx/latest").with_url(|url| url.set_query(Some("access_key=S3CR3T+x")));
    assert_refused(
        Case {
            value: secret_value("S3CR3T x"),
            ..fx
        },
        FinalCheckError::SlotValue,
    );
    let encoded = Case::new("/fx/latest").with_url(|url| url.set_query(Some("access_key=S3CR3T%20x")));
    assert!(
        Case {
            value: secret_value("S3CR3T x"),
            ..encoded
        }
        .check()
        .is_ok()
    );
}

#[test]
fn the_credential_outside_the_slot_is_refused() {
    let in_param = Case::new("/fx/latest?base=USD").with_url(|url| url.set_query(Some("base=S3CR3T&access_key=S3CR3T")));
    assert_refused(in_param, FinalCheckError::CredentialOutsideSlot);
    let in_header = Case::new("/fx/latest").with_header("X-Custom", "x S3CR3T");
    assert_refused(in_header, FinalCheckError::CredentialOutsideSlot);
    let in_url = Case::new("/brave/res/v1/web/search").with_url(|url| url.set_query(Some("q=S3CR3T")));
    assert_refused(in_url, FinalCheckError::CredentialOutsideSlot);
    let encoded = Case::new("/fx/latest").with_url(|url| url.set_query(Some("base=S3CR3T%20x&access_key=S3CR3T%20x")));
    assert_refused(
        Case {
            value: secret_value("S3CR3T x"),
            ..encoded
        },
        FinalCheckError::CredentialOutsideSlot,
    );
}

#[test]
fn the_credential_in_the_wrong_route_slot_is_refused() {
    let fx = Case::new("/fx/latest").with_header("X-Subscription-Token", "evil.example");
    let brave_slot = Case::new("/brave/res/v1/web/search").slot;
    assert_refused(Case { slot: brave_slot, ..fx }, FinalCheckError::SlotValue);
}
