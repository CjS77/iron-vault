use proptest::prelude::*;

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

/// A header-slot route with a non-root base path, for the base-path rules.
const SVC: &str = r#"
prefix = "/svc"
upstream = "https://api.svc.example/v1"
credential = "svc_key"
slot = { header = "X-Key" }
methods = ["GET"]
paths = ["/v1/**"]
rate_limit = { requests = 60, per_seconds = 60, burst = 10 }
"#;

const SECRET: &str = "s3cr3t-PLANTED-k3y";

fn route(toml_text: &str) -> RouteConfig {
    toml::from_str(toml_text).unwrap()
}

fn url(text: &str) -> Url {
    Url::parse(text).unwrap()
}

fn rewrite(route_text: &str, request: &str, location: &str) -> LocationRewrite {
    rewrite_location(&route(route_text), &url(request), location.as_bytes())
}

fn rewritten_text(outcome: &LocationRewrite) -> Option<String> {
    match outcome {
        LocationRewrite::Rewritten(value) => Some(String::from_utf8(value.as_bytes().to_vec()).unwrap()),
        _ => None,
    }
}

fn expect_rewrite(route_text: &str, request: &str, location: &str, expected: &str) {
    let outcome = rewrite(route_text, request, location);
    assert_eq!(rewritten_text(&outcome).as_deref(), Some(expected), "{location:?}: {outcome:?}");
}

fn expect(route_text: &str, request: &str, location: &str, expected: &LocationRewrite) {
    assert_eq!(&rewrite(route_text, request, location), expected, "{location:?}");
}

const SVC_REQUEST: &str = "https://api.svc.example/v1/items/list?page=1";

#[test]
fn relative_references_resolve_against_the_request_url() {
    [
        ("next", "/svc/items/next"),
        ("../x", "/svc/x"),
        ("./x/", "/svc/items/x/"),
        ("?page=2", "/svc/items/list?page=2"),
        ("", "/svc/items/list?page=1"),
        ("#f", "/svc/items/list?page=1#f"),
    ]
    .into_iter()
    .for_each(|(location, expected)| expect_rewrite(SVC, SVC_REQUEST, location, expected));
}

#[test]
fn same_origin_destinations_in_the_base_return_under_the_prefix() {
    [
        ("/v1/a/b", "/svc/a/b"),
        ("/v1", "/svc"),
        ("/v1/", "/svc/"),
        ("/v1/a?q=1#frag", "/svc/a?q=1#frag"),
        ("https://api.svc.example/v1/a", "/svc/a"),
        ("https://api.svc.example:443/v1/a", "/svc/a"),
        ("HTTPS://API.svc.example./v1/a", "/svc/a"),
        ("//api.svc.example/v1/a", "/svc/a"),
        ("/v1/caf%c3%a9/%41", "/svc/caf%C3%A9/A"),
    ]
    .into_iter()
    .for_each(|(location, expected)| expect_rewrite(SVC, SVC_REQUEST, location, expected));
}

#[test]
fn a_root_base_maps_its_root_to_the_prefix() {
    let request = "https://api.fx.example/latest";
    expect_rewrite(FX, request, "/", "/fx/");
    expect_rewrite(FX, request, "/historical/2024", "/fx/historical/2024");
}

#[test]
fn other_origins_pass_through() {
    [
        "https://api.svc.example:8443/v1/a",
        "http://api.svc.example/v1/a",
        "https://other.example/v1/a",
        "https://api.svc.example.evil/v1/a",
        "HTTP://other.example",
        "mailto://other.example/x",
    ]
    .into_iter()
    .for_each(|location| expect(SVC, SVC_REQUEST, location, &LocationRewrite::PassThrough));
}

#[test]
fn other_origins_without_an_absolute_url_are_refused() {
    [
        "//other.example/v1/a",
        "//api.svc.example:8443/v1/a",
        "http:foo",
        "http:/other/x",
        "http:other.example/x",
    ]
    .into_iter()
    .for_each(|location| {
        expect(
            SVC,
            SVC_REQUEST,
            location,
            &LocationRewrite::Refused(LocationRefusal::RelativeCrossOrigin),
        )
    });
}

#[test]
fn backslashes_are_refused_anywhere() {
    [
        "\\other.example/x",
        "/\\other.example/x",
        "https://other.example\\@api.svc.example/",
        "/v1/a\\b",
        "/\\api.svc.example/v1/a",
        "/v1/a?q=\\",
    ]
    .into_iter()
    .for_each(|location| expect(SVC, SVC_REQUEST, location, &LocationRewrite::Refused(LocationRefusal::Malformed)));
}

#[test]
fn same_origin_user_info_is_refused() {
    ["https://u:p@api.svc.example/v1/a", "//u@api.svc.example/v1/a"]
        .into_iter()
        .for_each(|location| expect(SVC, SVC_REQUEST, location, &LocationRewrite::Refused(LocationRefusal::UserInfo)));
}

#[test]
fn out_of_base_redirects_are_refused() {
    ["/v2/a", "/v10", "/v10/a", "/", "/v", "../../x", "https://api.svc.example/other"]
        .into_iter()
        .for_each(|location| expect(SVC, SVC_REQUEST, location, &LocationRewrite::Refused(LocationRefusal::OutOfBase)));
}

#[test]
fn ambiguous_paths_inside_the_base_are_refused() {
    [
        "/v1/a%2Fb",
        "/v1/a%2fb",
        "/v1/a/%2e%2e/b",
        "/v1/%2E%2E/v2",
        "/v1/.%2e/x",
        "/v1/a%5Cb",
        "/v1/a//b",
        "/v1/..;x",
        "/v1/a%00",
        "/v1/a%25",
        "/v1/a|b",
        "/v1/a\"b",
        "/v1/%zz",
    ]
    .into_iter()
    .for_each(|location| {
        expect(
            SVC,
            SVC_REQUEST,
            location,
            &LocationRewrite::Refused(LocationRefusal::AmbiguousPath),
        )
    });
}

#[test]
fn malformed_values_are_refused() {
    let refused = LocationRewrite::Refused(LocationRefusal::Malformed);
    [
        &b"/v1/a b"[..],
        b"/v1/a\tb",
        b"/v1/\x00",
        b"/v1/\xc3\xa9",
        b"https://[::1",
        b"//",
        b" /v1/a",
    ]
    .into_iter()
    .for_each(|location| assert_eq!(rewrite_location(&route(SVC), &url(SVC_REQUEST), location), refused, "{location:?}"));
}

#[test]
fn query_slot_parameters_never_reach_a_rewritten_value() {
    let request = format!("https://api.fx.example/latest?base=USD&access_key={SECRET}");
    [
        ("", "/fx/latest?base=USD"),
        ("#f", "/fx/latest?base=USD#f"),
        ("?page=2", "/fx/latest?page=2"),
        ("?access_key=x&page=2&access%5Fkey=y&access+key=z", "/fx/latest?page=2&access+key=z"),
    ]
    .into_iter()
    .for_each(|(location, expected)| expect_rewrite(FX, &request, location, expected));
    expect_rewrite(FX, &format!("https://api.fx.example/latest?access_key={SECRET}"), "", "/fx/latest");
}

#[test]
fn header_slot_routes_keep_the_query_untouched() {
    let request = "https://api.svc.example/v1/items?access_key=abc&page=1";
    expect_rewrite(SVC, request, "", "/svc/items?access_key=abc&page=1");
    expect_rewrite(SVC, request, "?x=%2F&access_key=1", "/svc/items?x=%2F&access_key=1");
}

#[test]
fn refusals_hold_no_input_bytes() {
    [
        LocationRefusal::Malformed,
        LocationRefusal::UserInfo,
        LocationRefusal::OutOfBase,
        LocationRefusal::AmbiguousPath,
        LocationRefusal::RelativeCrossOrigin,
    ]
    .into_iter()
    .flat_map(|refusal| {
        [
            refusal.to_string(),
            format!("{refusal:?}"),
            format!("{:?}", LocationRewrite::Refused(refusal)),
        ]
    })
    .for_each(|message| {
        ["s3cr3t", "api.", "/v1", "/fx", "svc", "%"]
            .into_iter()
            .for_each(|input| assert!(!message.contains(input), "{message}"));
    });
}

/// Pieces that combine into the URI references most likely to probe the rules.
const PIECES: &[&str] = &[
    "/",
    "//",
    ".",
    "..",
    "%2e",
    "%2F",
    "%5c",
    "\\",
    "?",
    "#",
    "&",
    "=",
    ";",
    "@",
    ":",
    ":443",
    "+",
    "%",
    "%41",
    "a",
    "fx",
    "v1",
    "v10",
    "latest",
    "access_key",
    "access%5Fkey",
    "access_key=",
    "https:",
    "http:",
    "https://",
    "http://",
    "api.fx.example",
    "api.svc.example",
    "API.FX.EXAMPLE.",
    "u:p@",
    "other.example",
];

/// Schemes for values written as `scheme://...`, the only shape that may pass through.
const SCHEMES: &[&str] = &["https:", "http:", "HTTPS:", "ftp:", "x-y.z+1:"];

fn location_bytes() -> impl Strategy<Value = Vec<u8>> {
    let pieces = || proptest::collection::vec(proptest::sample::select(PIECES), 0..12).prop_map(|pieces| pieces.concat());
    prop_oneof![
        pieces().prop_map(String::into_bytes),
        (proptest::sample::select(SCHEMES), pieces()).prop_map(|(scheme, rest)| format!("{scheme}//{rest}").into_bytes()),
        proptest::collection::vec(any::<u8>(), 0..48),
    ]
}

fn request_url() -> impl Strategy<Value = (&'static str, String)> {
    prop_oneof![
        Just((FX, format!("https://api.fx.example/latest?access_key={SECRET}"))),
        Just((FX, format!("https://api.fx.example/historical/2024?base=USD&access_key={SECRET}"))),
        Just((FX, format!("https://api.fx.example/?access_key={SECRET}&base=EUR"))),
        Just((SVC, "https://api.svc.example/v1/items/list?page=1".to_owned())),
    ]
}

/// The prefix, then the end of the value or a path, query or fragment delimiter.
fn starts_on_prefix_boundary(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(prefix)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with(['/', '?', '#']))
}

proptest! {
    // Most arbitrary values are refused, so more cases are needed to reach enough rewrites and pass-throughs.
    #![proptest_config(ProptestConfig::with_cases(1024))]

    #[test]
    fn rewritten_values_hold_no_secret_and_start_with_the_prefix(
        location in location_bytes(),
        (route_text, request) in request_url(),
    ) {
        let route = route(route_text);
        let outcome = rewrite_location(&route, &url(&request), &location);
        if let Some(value) = rewritten_text(&outcome) {
            prop_assert!(!value.contains(SECRET), "{value}");
            prop_assert!(starts_on_prefix_boundary(&value, route.prefix().as_str()), "{value}");
        }
    }

    #[test]
    fn passed_through_values_mean_the_same_against_any_base(
        location in location_bytes(),
        (route_text, request) in request_url(),
    ) {
        let request = url(&request);
        if rewrite_location(&route(route_text), &request, &location) == LocationRewrite::PassThrough {
            let text = std::str::from_utf8(&location).unwrap();
            let absolute = Url::parse(text).unwrap();
            prop_assert_eq!(&request.join(text).unwrap(), &absolute);
            prop_assert_eq!(&url("http://127.0.0.1:8080/fx/a/b").join(text).unwrap(), &absolute);
        }
    }
}
