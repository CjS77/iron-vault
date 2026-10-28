//! Property tests for the destination invariant (specification §3.6, §8; threats R-4, R-7).
//!
//! The destination invariant: a credential leaves only for its route upstream's host and port, only when its
//! credential record permits that pair, only inside the upstream base path, and only in the route's one slot. Each case
//! runs a hostile caller request through every policy step, from [`RequestTarget::parse`] to [`final_check`], and the
//! properties hold for whatever comes out.
//!
//! Most cases wire the steps as the service does: the selected route's upstream builds the URL and the selected route's
//! slot is filled. The rest build the URL or fill the slot from another route of the config, as a construction defect
//! would. The final check exists to catch exactly those defects, and an honestly wired pipeline never reaches its host,
//! port or slot rules, so without miswired cases weakening one of those rules would go unnoticed.

// Workspace lints deny `unwrap` outside tests, and clippy treats only `#[test]` functions as tests here; these helpers
// run only under the test harness, where a panic is a test failure.
#![allow(clippy::unwrap_used)]

mod common;

use std::collections::BTreeSet;

use common::{POLICY, QUERIES, config, fragment, join_path, prefix, route_origins, sample};
use iron_vault_policy::{
    AuthorizedRequest, CheckedRequest, FinalCheckError, HeaderName, HeaderValue, Host, Method, OutgoingRequest, Port, RequestTarget,
    RouteConfig, RouteName, Slot, SlotValue, UpstreamTarget, authorize, final_check, sanitize,
};
use proptest::bool::weighted;
use proptest::collection::vec;
use proptest::prelude::*;
use proptest::sample::select;
use proptest::test_runner::TestCaseError;
use secrecy::SecretString;

/// Cases for each property. About one in seven generated cases gets past the hostile path to the final check; this
/// many cases puts several hundred through it per property, across every route, slot shape and wiring, in about a
/// second.
const CASES: u32 = 4096;

/// Cases for panic freedom over arbitrary input, which is mostly rejected at the first step.
const PANIC_CASES: u32 = 4096;

/// Every generated slot value starts with this text, and no generated caller input contains it, so counting it in the
/// URL and headers counts the copies of the credential that would leave the service.
const SECRET_MARK: &str = "IVs3cr3t";

/// Text that tries to supply a scheme, user-info, a port or a second host inside a path segment, including look-alikes
/// of a route's host.
const AUTHORITY_PIECES: &[&str] = &[
    "@",
    ":",
    "//",
    "@evil.example",
    ":443",
    ":8443@evil.example",
    "evil.example:443@",
    "http:",
    "https:",
    "http://evil.example",
    "//evil.example",
    "%40",
    "%3A",
    "%3a443",
    "%2F%2Fevil.example",
    "api.fx.example.evil.example",
    "api.fx.example.",
    "api.fx.example%2e",
    "api%E2%80%A4fx.example",
    "xn--api-fx-example",
];

/// Starts of absolute-form, scheme-relative and authority-form targets, which must never be accepted.
const LEADS: &[&str] = &[
    "http://evil.example",
    "https://evil.example",
    "https://api.fx.example",
    "//evil.example",
    "evil.example:443",
    "http:",
    "@evil.example",
];

/// Spellings of query parameter names: the query slot's name, escaped or `+`-spaced variants of it that a form decoder
/// may or may not read as the same name, and header slot names.
const PARAM_NAMES: &[&str] = &[
    "access_key",
    "ACCESS_KEY",
    "access%5Fkey",
    "access%5fkey",
    "%61ccess_key",
    "%61%63%63%65%73%73%5F%6B%65%79",
    "access+key",
    "access_key+",
    "+access_key",
    "access%2Bkey",
    "access%20key",
    "access_key%00",
    "access_key%3D",
    "X-Api-Key",
    "Authorization",
    "api_key",
    "",
];

/// Query parameter values: markers for each credential, malformed markers, smuggled parameters and hosts, and text the
/// request target rejects.
const PARAM_VALUES: &[&str] = &[
    "",
    "1",
    "%7Biv:fx_key%7D",
    "%7Biv%3Afx_key%7D",
    "%7biv:fxa_key%7d",
    "%7Biv:other%7D",
    "%7Biv:",
    "%7Biv:fx_key",
    "{iv:fx_key}",
    "a%26access_key%3Dx",
    "http://evil.example/",
    "@evil.example",
    "%2F%2Fevil.example",
    "a+b",
    "x=y",
    "%23f",
    "%",
];

/// Caller header names: authority, forwarding, override and framing headers, and every slot header in several cases.
const HEADER_NAMES: &[&str] = &[
    "Host",
    "host",
    "X-Forwarded-Host",
    "X-Forwarded-For",
    "Forwarded",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-HTTP-Method-Override",
    "X-Host",
    "Proxy-Authorization",
    "Connection",
    "X-Api-Key",
    "x-api-key",
    "X-API-KEY",
    "Authorization",
    "authorization",
    "AUTHORIZATION",
    "Accept",
    "X-Custom",
    "access_key",
    "Content-Length",
    "Transfer-Encoding",
];

/// Caller header values: other hosts, markers for each credential, malformed markers, and `Connection` lists naming
/// the slot headers.
const HEADER_VALUES: &[&str] = &[
    "evil.example",
    "evil.example:443",
    "api.fx.example.evil.example",
    "api.fx.example.",
    "https://evil.example/",
    "{iv:fx_key}",
    "{iv:fxa_key}",
    "{iv:deep}",
    "{iv:venice}",
    "Bearer {iv:venice}",
    "Basic {iv:basic_login}",
    "{iv:other}",
    "{iv:",
    "Bearer x",
    "keep-alive, X-Api-Key, Authorization",
    "5",
    "chunked",
    "",
];

/// Host and port pairs a credential record might permit beside the routes' own: look-alikes of them, the same hosts
/// on other ports, and other hosts. Spellings that convert to a route's host, such as a trailing dot or capitals, are
/// that route's origin.
const OTHER_ORIGINS: &[(&str, u16)] = &[
    ("api.fx.example.", 443),
    ("API.DEEP.EXAMPLE", 443),
    ("api.fxa.example", 8443),
    ("api.venice.ai", 8443),
    ("evil.example", 443),
    ("api.fx.example.evil.example", 443),
    ("fx.example", 443),
];

/// Lowercase names of headers that would let a caller choose the authority, the forwarded-for chain, the URL or the
/// method the upstream acts on; none may be in a checked request.
const CONTROL_HEADERS: &[&str] = &[
    "host",
    "x-forwarded-host",
    "x-forwarded-for",
    "forwarded",
    "x-host",
    "x-original-url",
    "x-rewrite-url",
    "x-http-method-override",
];

/// The listener's caller-token header; the default when a listener names none.
const TOKEN_HEADER: &str = "Proxy-Authorization";

// The pipeline.

/// Which route each construction step takes its input from; `None` is the route the request selected.
#[derive(Debug, Clone)]
struct Wiring {
    /// The route whose upstream builds the URL.
    upstream: Option<RouteName>,
    /// The route whose slot and credential fill the request.
    slot: Option<RouteName>,
}

/// One generated request: everything the caller controls, the slot value, how the steps are wired, and the origins
/// the credential record permits.
#[derive(Debug, Clone)]
struct Case {
    target: String,
    headers: Vec<(&'static str, &'static str)>,
    secret: String,
    wiring: Wiring,
    permitted: BTreeSet<(Host, Port)>,
}

/// A case that reached the final check.
struct Run {
    authorized: AuthorizedRequest,
    /// Whether the selected route's upstream built the URL.
    own_upstream: bool,
    /// Whether the selected route's slot and credential filled the request.
    own_slot: bool,
    checked: Result<CheckedRequest, FinalCheckError>,
}

impl Case {
    fn run(&self) -> Option<Run> {
        run(&self.target, &typed(&self.headers), &self.secret, &self.wiring, &self.permitted)
    }
}

/// Runs every step from parsing to the final check, or stops with `None` where a step refuses the request, as each may
/// for hostile input.
fn run(
    target: &str,
    headers: &[(HeaderName, HeaderValue)],
    secret: &str,
    wiring: &Wiring,
    permitted: &BTreeSet<(Host, Port)>,
) -> Option<Run> {
    let (path, query) = RequestTarget::parse(target).ok()?.into_parts();
    let authorized = authorize(&POLICY, &"agent".parse().unwrap(), &Method::Get, &path, query).ok()?;
    let selected = authorized.route();
    let route = POLICY.route(selected).unwrap();
    let (upstream_route, slot_route) = (wired(&wiring.upstream, selected), wired(&wiring.slot, selected));
    let target = UpstreamTarget::build(POLICY.route(upstream_route)?.upstream(), &authorized).ok()?;
    let outgoing = sanitize(headers, &TOKEN_HEADER.parse().unwrap()).ok()?;
    let filler = POLICY.route(slot_route)?;
    let value = SlotValue::new(SecretString::from(secret)).ok()?;
    let request = OutgoingRequest::assemble(&authorized, target, outgoing, filler.slot(), filler.credential(), &value).ok()?;
    let checked = final_check(request, &authorized, route.upstream(), route.slot(), &value, permitted);
    let (own_upstream, own_slot) = (upstream_route == selected, slot_route == selected);
    Some(Run {
        authorized,
        own_upstream,
        own_slot,
        checked,
    })
}

fn wired<'a>(wiring: &'a Option<RouteName>, selected: &'a RouteName) -> &'a RouteName {
    wiring.as_ref().unwrap_or(selected)
}

fn selected_route(authorized: &AuthorizedRequest) -> &'static RouteConfig {
    POLICY.route(authorized.route()).unwrap()
}

fn upstream_origin(route: &RouteConfig) -> (Host, Port) {
    (route.upstream().host().clone(), route.upstream().port())
}

// Generators.

fn authority_piece() -> impl Strategy<Value = String> {
    select(AUTHORITY_PIECES).prop_map(String::from)
}

/// One to three of the shared hostile path fragments and authority pieces run together.
fn destination_segment() -> impl Strategy<Value = String> {
    vec(prop_oneof![4 => fragment(), 1 => authority_piece()], 1..4).prop_map(|pieces| pieces.concat())
}

fn query_param() -> impl Strategy<Value = String> {
    prop_oneof![
        4 => (select(PARAM_NAMES), select(PARAM_VALUES)).prop_map(|(name, value)| format!("{name}={value}")),
        1 => select(PARAM_NAMES).prop_map(String::from),
        1 => "[a-z]{1,4}=[a-z0-9]{0,4}",
        1 => Just(String::new()),
    ]
}

/// No query, one of the shared queries, or up to four parameters, some of them empty so `&&` appears.
fn hostile_query() -> impl Strategy<Value = String> {
    prop_oneof![
        1 => Just(String::new()),
        1 => select(QUERIES).prop_map(String::from),
        4 => vec(query_param(), 1..5).prop_map(|params| format!("?{}", params.join("&"))),
    ]
}

/// An origin-form target under a route prefix, decoy or none, sometimes behind an absolute-form or authority-form start.
fn destination_target() -> impl Strategy<Value = String> {
    let lead = prop_oneof![12 => Just(""), 1 => select(LEADS)];
    (lead, prefix(), vec(destination_segment(), 0..4), any::<bool>(), hostile_query())
        .prop_map(|(lead, prefix, segments, slash, query)| format!("{lead}{}{query}", join_path(prefix, segments, slash)))
}

fn caller_headers() -> impl Strategy<Value = Vec<(&'static str, &'static str)>> {
    vec((select(HEADER_NAMES), select(HEADER_VALUES)), 0..6)
}

/// A printable ASCII slot value starting with [`SECRET_MARK`], with characters that query encoding must escape.
fn secret() -> impl Strategy<Value = String> {
    "IVs3cr3t[A-Za-z0-9+/=&%._~ -]{0,10}[A-Za-z0-9]"
}

fn route_names() -> Vec<RouteName> {
    POLICY.config().routes().keys().cloned().collect()
}

/// The selected route most of the time; otherwise any route of the config, which may happen to be the selected one.
fn wired_route() -> impl Strategy<Value = Option<RouteName>> {
    prop_oneof![5 => Just(None), 1 => select(route_names()).prop_map(Some)]
}

fn wiring() -> impl Strategy<Value = Wiring> {
    (wired_route(), wired_route()).prop_map(|(upstream, slot)| Wiring { upstream, slot })
}

/// Every route's origin and every other origin, each kept with probability three in four.
fn permitted() -> impl Strategy<Value = BTreeSet<(Host, Port)>> {
    let others = OTHER_ORIGINS
        .iter()
        .map(|(host, port)| (host.parse().unwrap(), Port::try_from(*port).unwrap()));
    let universe: Vec<(Host, Port)> = route_origins(POLICY.config()).into_iter().chain(others).collect();
    vec(weighted(0.75), universe.len()).prop_map(move |keep| {
        universe
            .iter()
            .zip(keep)
            .filter(|(_, keep)| *keep)
            .map(|(origin, _)| origin.clone())
            .collect()
    })
}

fn case() -> impl Strategy<Value = Case> {
    (destination_target(), caller_headers(), secret(), wiring(), permitted()).prop_map(|(target, headers, secret, wiring, permitted)| {
        Case {
            target,
            headers,
            secret,
            wiring,
            permitted,
        }
    })
}

// Properties, shared by the property tests and the regression examples.

/// Property 1: a checked request goes over `https`, without user-info, to the selected route upstream's host and port,
/// which the record permits, and its path starts with the upstream base segments. No header can redirect it: none is
/// an authority, forwarding, URL-rewrite or method-override header, and none is a pseudo-header such as `:authority`.
fn check_destination(case: &Case) -> Result<(), TestCaseError> {
    let Some(Run {
        authorized,
        checked: Ok(checked),
        ..
    }) = case.run()
    else {
        return Ok(());
    };
    let upstream = selected_route(&authorized).upstream();
    let url = checked.url();
    prop_assert_eq!(url.scheme(), "https", "{:?}", case);
    prop_assert!(url.username().is_empty() && url.password().is_none(), "{case:?} sent user-info");
    prop_assert_eq!(url.host_str(), Some(upstream.host().as_str()), "{:?}", case);
    prop_assert_eq!(checked.host(), upstream.host(), "{:?}", case);
    prop_assert_eq!(url.port_or_known_default(), Some(upstream.port().get()), "{:?}", case);
    let port = url.port_or_known_default().and_then(|port| Port::try_from(port).ok());
    let origin = url.host_str().and_then(|host| host.parse::<Host>().ok()).zip(port);
    prop_assert!(
        origin.is_some_and(|origin| case.permitted.contains(&origin)),
        "{case:?} went to an origin the record does not permit"
    );
    let segments: Vec<&str> = url.path_segments().map(Iterator::collect).unwrap_or_default();
    let base: Vec<&str> = upstream.base_segments().iter().map(String::as_str).collect();
    prop_assert!(segments.starts_with(&base), "{case:?} left the base path: {segments:?}");
    let control = checked
        .headers()
        .iter()
        .map(|(name, _)| name)
        .find(|name| is_control_header(name.lowercase()));
    prop_assert!(control.is_none(), "{case:?} forwarded {control:?}");
    Ok(())
}

fn is_control_header(lowercase: &str) -> bool {
    CONTROL_HEADERS.contains(&lowercase) || lowercase.starts_with(':')
}

/// Property 2: a checked request writes the selected route's slot once, holding the rendered slot value, and the slot
/// value appears nowhere else in the URL or headers. Slot filling removes every caller copy of the slot, so an honestly
/// wired request whose origin is permitted always passes the final check rather than failing it for a second copy.
///
/// Requests filled through another route's slot are checked too: the final check confirms that the selected slot holds
/// the slot value, so one whose selected slot holds only a caller copy never passes
/// ([`slot_filled_through_another_route_is_refused`]).
fn check_single_slot(case: &Case) -> Result<(), TestCaseError> {
    let Some(run) = case.run() else { return Ok(()) };
    let route = selected_route(&run.authorized);
    let checked = match run.checked {
        Ok(checked) => checked,
        Err(error) => {
            let permitted = case.permitted.contains(&upstream_origin(route));
            let honest = run.own_upstream && run.own_slot && permitted;
            prop_assert!(!honest, "{case:?} was honestly built but failed the final check: {error}");
            return Ok(());
        }
    };
    prop_assert_eq!(
        slot_entries(&checked, route.slot()),
        vec![rendered(route.slot(), &case.secret)],
        "{:?}",
        case
    );
    let headers = checked
        .headers()
        .iter()
        .map(|(_, value)| String::from_utf8_lossy(value.as_bytes()).into_owned());
    let copies: usize = headers
        .chain([checked.url().to_string()])
        .map(|text| text.matches(SECRET_MARK).count())
        .sum();
    prop_assert_eq!(copies, 1, "{:?} holds the slot value {} times", case, copies);
    Ok(())
}

/// Every value written to `slot`: matching headers in any case, or query parameters whose form-decoded name matches.
fn slot_entries(checked: &CheckedRequest, slot: &Slot) -> Vec<String> {
    match slot {
        Slot::Query(name) => {
            let params = checked.url().query_pairs().filter(|(param, _)| param == name.as_str());
            params.map(|(_, value)| value.into_owned()).collect()
        }
        Slot::Header(_) | Slot::Basic => {
            let written = slot.header_written().unwrap_or_default();
            let values = checked.headers().iter().filter(|(name, _)| name.lowercase() == written);
            values
                .map(|(_, value)| String::from_utf8_lossy(value.as_bytes()).into_owned())
                .collect()
        }
    }
}

/// What `slot` holds for `secret`, decoded: the formatted header value, `Basic` and the value, or the value itself.
fn rendered(slot: &Slot, secret: &str) -> String {
    match slot {
        Slot::Header(header) => format!("{}{secret}{}", header.format().prefix(), header.format().suffix()),
        Slot::Basic => format!("Basic {secret}"),
        Slot::Query(_) => secret.to_owned(),
    }
}

/// Property 3: when the record does not permit the selected route upstream's origin, no checked request is produced.
fn check_permitted_origins(case: &Case) -> Result<(), TestCaseError> {
    let Some(run) = case.run() else { return Ok(()) };
    let permitted = case.permitted.contains(&upstream_origin(selected_route(&run.authorized)));
    prop_assert!(
        permitted || run.checked.is_err(),
        "{case:?} produced a checked request for an origin the record omits"
    );
    Ok(())
}

proptest! {
    #![proptest_config(config(CASES))]

    #[test]
    fn checked_requests_go_only_to_the_route_upstream(case in case()) {
        check_destination(&case)?;
    }

    #[test]
    fn checked_requests_write_the_slot_exactly_once(case in case()) {
        check_single_slot(&case)?;
    }

    #[test]
    fn omitted_origins_never_produce_a_checked_request(case in case()) {
        check_permitted_origins(&case)?;
    }
}

/// Arbitrary header names and values, of which only those a caller could send are kept.
fn arbitrary_headers() -> impl Strategy<Value = Vec<(HeaderName, HeaderValue)>> {
    let header = (any::<String>(), vec(any::<u8>(), 0..24));
    vec(header, 0..6).prop_map(|headers| {
        headers
            .into_iter()
            .filter_map(|(name, value)| Some((name.parse().ok()?, HeaderValue::try_from(value).ok()?)))
            .collect()
    })
}

proptest! {
    #![proptest_config(config(PANIC_CASES))]

    /// Property 4: no step panics, on generated hostile input or on arbitrary text.
    #[test]
    fn no_step_panics_on_arbitrary_input(
        target in prop_oneof![destination_target(), any::<String>().prop_map(|text| format!("/fx/{text}")), any::<String>()],
        headers in prop_oneof![caller_headers().prop_map(|headers| typed(&headers)), arbitrary_headers()],
        secret in prop_oneof![secret(), any::<String>()],
        wiring in wiring(),
        permitted in permitted(),
    ) {
        let _ = run(&target, &headers, &secret, &wiring, &permitted);
    }
}

fn typed(headers: &[(&str, &str)]) -> Vec<(HeaderName, HeaderValue)> {
    headers
        .iter()
        .map(|(name, value)| (name.parse().unwrap(), HeaderValue::try_from(*value).unwrap()))
        .collect()
}

/// The properties above are vacuous if few cases reach a checked request; this keeps the generators honest as the
/// policy's rules change. Each slot shape, miswired cases and omitted origins must all reach the final check.
#[test]
fn generated_cases_reach_the_final_check() {
    let runs: Vec<(Case, Run)> = sample(case(), 2000)
        .into_iter()
        .filter_map(|case| case.run().map(|run| (case, run)))
        .collect();
    let checked: Vec<&Run> = runs.iter().map(|(_, run)| run).filter(|run| run.checked.is_ok()).collect();
    let shape = |run: &&Run| match selected_route(&run.authorized).slot() {
        Slot::Query(_) => 0,
        Slot::Header(_) => 1,
        Slot::Basic => 2,
    };
    let shapes: Vec<usize> = (0..3).map(|n| checked.iter().filter(|run| shape(run) == n).count()).collect();
    let miswired = runs.iter().filter(|(_, run)| !run.own_upstream).count();
    let omitted = runs
        .iter()
        .filter(|(case, run)| !case.permitted.contains(&upstream_origin(selected_route(&run.authorized))))
        .count();
    assert!(runs.len() >= 200, "only {} of 2000 reached the final check", runs.len());
    assert!(
        shapes.iter().all(|&count| count >= 20),
        "checked requests per slot shape (query, header, Basic): {shapes:?}"
    );
    assert!(
        miswired >= 25 && omitted >= 25,
        "{miswired} miswired and {omitted} omitted-origin cases reached the final check"
    );
}

fn origin(host: &str, port: u16) -> (Host, Port) {
    (host.parse().unwrap(), Port::try_from(port).unwrap())
}

fn route(name: &str) -> Option<RouteName> {
    Some(name.parse().unwrap())
}

fn honest(target: &str, headers: &[(&'static str, &'static str)], permitted: (Host, Port)) -> Case {
    let wiring = Wiring {
        upstream: None,
        slot: None,
    };
    Case {
        target: target.to_owned(),
        headers: headers.to_vec(),
        secret: "IVs3cr3ta".to_owned(),
        wiring,
        permitted: [permitted].into(),
    }
}

fn built_upstream_from(name: &str, target: &str, permitted: (Host, Port)) -> Case {
    Case {
        wiring: Wiring {
            upstream: route(name),
            slot: None,
        },
        ..honest(target, &[], permitted)
    }
}

/// Minimal counterexamples the properties shrank to when one rule was deliberately weakened: the final check's host
/// equality (a URL built from `fx`'s upstream for an `fxa` or `deep` request, whose record permits only `fx`'s origin),
/// and slot filling's removal of caller copies (a caller `X-Api-Key` header, a bare `access_key` parameter, and an
/// escaped `access%5Fkey` that decodes to the slot name). Each must keep every property.
#[test]
fn shrunk_counterexamples_keep_every_property() {
    let fx = origin("api.fx.example", 443);
    let cases = [
        built_upstream_from("fx", "/fxa", fx.clone()),
        built_upstream_from("fx", "/a/b", fx.clone()),
        honest("/fxa", &[("X-Api-Key", "evil.example")], origin("api.fxa.example", 443)),
        honest("/fx?access_key=", &[], fx.clone()),
        honest("/fx?access%5Fkey", &[], fx),
    ];
    cases.iter().for_each(|case| {
        [check_destination, check_single_slot, check_permitted_origins]
            .into_iter()
            .for_each(|check| check(case).unwrap_or_else(|e| panic!("{case:?}: {e}")));
    });
}

/// The minimal counterexample property 1 shrank to when both header defences were deliberately disabled, the strip of
/// reserved headers in sanitizing and the final check's reserved-header rule: a caller `Host` header naming another
/// host on an honestly built `fx` request. It must keep every property.
#[test]
fn caller_host_header_keeps_every_property() {
    let case = honest("/fx", &[("Host", "evil.example")], origin("api.fx.example", 443));
    [check_destination, check_single_slot, check_permitted_origins]
        .into_iter()
        .for_each(|check| check(&case).unwrap_or_else(|e| panic!("{case:?}: {e}")));
    assert!(
        case.run().is_some_and(|run| run.checked.is_ok()),
        "{case:?} did not reach a checked request"
    );
}

/// A record that spells the `basic` route's host with a trailing dot, as its upstream does, permits that route: both
/// spellings convert to one host, and the URL carries the converted form.
#[test]
fn trailing_dot_spellings_are_one_origin() {
    let run = honest("/basic/x", &[], origin("api.fx.example.", 8443)).run().unwrap();
    let checked = run.checked.unwrap();
    assert_eq!(checked.url().host_str(), Some("api.fx.example"));
    assert_eq!(checked.url().port(), Some(8443));
}

/// The shrunk counterexample that keeps slot-filler miswiring out of [`check_single_slot`]: the `deep` route's request
/// is filled through `fx`'s query slot, so the credential leaves in an `access_key` parameter the route never names,
/// while the caller's own `X-Api-Key` header fills the slot the final check reads. The slot is written once, so only
/// confirming that it holds the slot value refuses the request.
#[test]
fn slot_filled_through_another_route_is_refused() {
    let case = Case {
        target: "/a/b".to_owned(),
        headers: vec![("X-Api-Key", "evil.example")],
        secret: "IVs3cr3ta".to_owned(),
        wiring: Wiring {
            upstream: None,
            slot: route("fx"),
        },
        permitted: [origin("api.deep.example", 443)].into(),
    };
    assert!(
        case.run().is_some_and(|run| run.checked.is_err()),
        "{case:?} passed the final check"
    );
}
