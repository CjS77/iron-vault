use secrecy::SecretString;

use super::*;
use crate::activation::{ActivePolicy, Capabilities, CatalogEntry, CredentialCatalog, activate};
use crate::authorization::authorize;
use crate::config::ParsedConfig;
use crate::port::Port;
use crate::request_target::RequestTarget;
use crate::spec_example::SPEC_EXAMPLE;
use crate::validated::ValidatedConfig;

const SECRET: &str = "S3CR3T";

/// Permits every §3.3 credential on its route's host.
struct Catalog;

impl CredentialCatalog for Catalog {
    fn entry(&self, name: &CredentialName) -> CatalogEntry {
        let host = match name.as_str() {
            "fx_key" => "api.fx.example",
            "venice" => "api.venice.ai",
            _ => "api.search.brave.com",
        };
        CatalogEntry::Usable {
            kind: crate::CredentialKind::Static,
            origins: [(host.parse().unwrap(), Port::HTTPS)].into(),
        }
    }
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

/// Authorizes `target` for the caller granted its route and assembles it with the caller's `headers`, filling the
/// route's slot, or `slot` when given, with `value`.
fn assemble_with(target: &str, headers: &[(&str, &str)], slot: Option<&Slot>, value: &str) -> Result<OutgoingRequest, AssembleError> {
    let policy = policy();
    let caller = if target.starts_with("/fx") { "fx-mcp" } else { "naomi-backoffice" };
    let method = if target.starts_with("/venice") { Method::Post } else { Method::Get };
    let (path, query) = RequestTarget::parse(target).unwrap().into_parts();
    let request = authorize(&policy, &caller.parse().unwrap(), &method, &path, query).unwrap();
    let route = &policy.config().routes()[request.route()];
    let upstream_target = UpstreamTarget::build(route.upstream(), &request).unwrap();
    let mut outgoing = OutgoingHeaders::new();
    headers.iter().for_each(|(name, value)| {
        outgoing
            .insert(name.parse().unwrap(), HeaderValue::try_from(*value).unwrap())
            .unwrap()
    });
    let value = SlotValue::new(SecretString::from(value)).unwrap();
    OutgoingRequest::assemble(
        &request,
        upstream_target,
        outgoing,
        slot.unwrap_or(route.slot()),
        route.credential(),
        &value,
    )
}

fn assemble(target: &str, headers: &[(&str, &str)]) -> Result<OutgoingRequest, AssembleError> {
    assemble_with(target, headers, None, SECRET)
}

fn url(request: &OutgoingRequest) -> &str {
    request.target().as_url().as_str()
}

/// Every header as `(spelling, value)`, in order.
fn header_list(request: &OutgoingRequest) -> Vec<(String, String)> {
    let text = |value: &HeaderValue| String::from_utf8_lossy(value.as_bytes()).into_owned();
    request
        .headers()
        .iter()
        .map(|(name, value)| (name.as_str().to_owned(), text(value)))
        .collect()
}

fn pair(name: &str, value: &str) -> (String, String) {
    (name.to_owned(), value.to_owned())
}

#[test]
fn fx_query_marker_is_replaced() {
    let fx = assemble("/fx/latest?base=USD&access_key=%7Biv:fx_key%7D", &[]).unwrap();
    assert_eq!(url(&fx), "https://api.fx.example/latest?base=USD&access_key=S3CR3T");
    assert_eq!(fx.method(), Method::Get);
}

#[test]
fn query_slot_is_written_once_without_a_caller_occurrence() {
    assert_eq!(
        url(&assemble("/fx/latest?base=USD", &[]).unwrap()),
        "https://api.fx.example/latest?base=USD&access_key=S3CR3T"
    );
    assert_eq!(
        url(&assemble("/fx/latest", &[]).unwrap()),
        "https://api.fx.example/latest?access_key=S3CR3T"
    );
}

#[test]
fn encoded_slot_names_are_removed_too() {
    let fx = assemble("/fx/latest?access%5Fkey=x&access_key=y&acc%65ss_key=z", &[]).unwrap();
    assert_eq!(url(&fx), "https://api.fx.example/latest?access_key=S3CR3T");
}

#[test]
fn other_parameters_are_kept_byte_for_byte_and_in_order() {
    let fx = assemble("/fx/latest?b=%2f/?x&ACCESS_KEY=1&&q=%7Biv:venice%7D&access_key=2&a+b=%7Biv:", &[]).unwrap();
    assert_eq!(
        url(&fx),
        "https://api.fx.example/latest?b=%2f/?x&ACCESS_KEY=1&&q=%7Biv:venice%7D&a+b=%7Biv:&access_key=S3CR3T"
    );
}

#[test]
fn query_value_parses_back_to_the_exact_value() {
    let value = "a&b=c+d%e f/?#\u{e9}\u{2028}";
    let fx = assemble_with("/fx/latest?base=USD", &[], None, value).unwrap();
    let pairs: Vec<(String, String)> = fx
        .target()
        .as_url()
        .query_pairs()
        .map(|(n, v)| (n.into_owned(), v.into_owned()))
        .collect();
    assert_eq!(pairs, [pair("base", "USD"), pair("access_key", value)]);
}

#[test]
fn brave_duplicate_placeholders_become_one_header() {
    let headers = [
        ("x-subscription-token", "placeholder"),
        ("Accept", "application/json"),
        ("X-Subscription-Token", "placeholder"),
    ];
    let brave = assemble("/brave/res/v1/web/search?q=rust", &headers).unwrap();
    assert_eq!(
        header_list(&brave),
        [pair("Accept", "application/json"), pair("X-Subscription-Token", SECRET)]
    );
    assert_eq!(url(&brave), "https://api.search.brave.com/res/v1/web/search?q=rust");
}

#[test]
fn header_slot_is_written_once_without_a_caller_occurrence() {
    assert_eq!(
        header_list(&assemble("/brave/res/v1/web/search", &[]).unwrap()),
        [pair("X-Subscription-Token", SECRET)]
    );
}

#[test]
fn venice_marker_is_replaced_through_the_format() {
    let venice = assemble("/venice/chat/completions", &[("Authorization", "Bearer {iv:venice}")]).unwrap();
    assert_eq!(header_list(&venice), [pair("Authorization", "Bearer S3CR3T")]);
    assert_eq!(venice.method(), Method::Post);
}

#[test]
fn basic_slot_replaces_every_authorization_header() {
    let headers = [
        ("Authorization", "Basic {iv:brave}"),
        ("authorization", "Bearer x"),
        ("Accept", "*/*"),
    ];
    let basic = assemble_with("/brave/res/v1/web/search", &headers, Some(&Slot::Basic), "dTpw").unwrap();
    assert_eq!(header_list(&basic), [pair("Accept", "*/*"), pair("Authorization", "Basic dTpw")]);
}

#[test]
fn foreign_marker_in_the_slot_is_refused() {
    let foreign = Err(AssembleError::ForeignMarker);
    assert_eq!(assemble("/fx/latest?access_key=%7Biv:venice%7D", &[]).map(|_| ()), foreign);
    assert_eq!(
        assemble("/fx/latest?access%5Fkey=%7Biv:venice%7D&access_key=%7Biv:fx_key%7D", &[]).map(|_| ()),
        foreign
    );
    assert_eq!(
        assemble("/brave/res/v1/web/search", &[("X-Subscription-Token", "{iv:fx_key}")]).map(|_| ()),
        foreign
    );
    assert_eq!(
        assemble("/venice/chat/completions", &[("Authorization", "Bearer {iv:venice}{iv:brave}")]).map(|_| ()),
        foreign
    );
    let basic = assemble_with(
        "/brave/res/v1/web/search",
        &[("authorization", "Basic {iv:venice}")],
        Some(&Slot::Basic),
        "dTpw",
    );
    assert_eq!(basic.map(|_| ()), foreign);
}

#[test]
fn malformed_marker_in_the_slot_is_refused() {
    let malformed = Err(AssembleError::MalformedMarker);
    assert_eq!(assemble("/fx/latest?access_key=%7Biv:", &[]).map(|_| ()), malformed);
    assert_eq!(assemble("/fx/latest?access_key=%7Biv:FX%7D", &[]).map(|_| ()), malformed);
    ["{iv:Brave}", "{iv:brave", "{iv:}"].iter().for_each(|value| {
        assert_eq!(
            assemble("/brave/res/v1/web/search", &[("X-Subscription-Token", value)]).map(|_| ()),
            malformed,
            "{value}"
        );
    });
}

#[test]
fn markers_outside_the_slot_stay_inert() {
    let headers = [
        ("X-Other", "{iv:fx_key}"),
        ("X-Broken", "{iv:"),
        ("X-Subscription-Token", "{iv:brave}"),
    ];
    let brave = assemble("/brave/res/v1/web/search?title=%7Biv:venice%7D", &headers).unwrap();
    assert_eq!(
        header_list(&brave),
        [
            pair("X-Other", "{iv:fx_key}"),
            pair("X-Broken", "{iv:"),
            pair("X-Subscription-Token", SECRET)
        ]
    );
    assert_eq!(url(&brave), "https://api.search.brave.com/res/v1/web/search?title=%7Biv:venice%7D");
}

#[test]
fn non_ascii_values_are_refused_for_header_and_basic_slots() {
    ["k\u{e9}y", "k\u{2028}y"].iter().for_each(|value| {
        let header = assemble_with("/brave/res/v1/web/search", &[], None, value);
        assert_eq!(header.map(|_| ()), Err(AssembleError::NonAsciiSlotValue), "{value:?}");
        let basic = assemble_with("/brave/res/v1/web/search", &[], Some(&Slot::Basic), value);
        assert_eq!(basic.map(|_| ()), Err(AssembleError::NonAsciiSlotValue), "{value:?}");
        assert!(assemble_with("/fx/latest", &[], None, value).is_ok(), "{value:?}");
    });
}

#[test]
fn debug_never_shows_the_credential() {
    let fx = assemble("/fx/latest?base=USD", &[]).unwrap();
    let brave = assemble("/brave/res/v1/web/search", &[]).unwrap();
    [format!("{fx:?}"), format!("{brave:?}")]
        .iter()
        .for_each(|debug| assert!(!debug.contains(SECRET), "{debug}"));
}

#[test]
fn error_text_never_shows_slot_contents() {
    let error = assemble("/brave/res/v1/web/search", &[("X-Subscription-Token", "QZJW {iv:fx_key}")]).unwrap_err();
    let text = format!("{error} {error:?}");
    assert!(!text.contains("QZJW") && !text.contains("fx_key"), "{text}");
}
