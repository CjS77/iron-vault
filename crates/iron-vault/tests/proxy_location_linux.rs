//! Redirect `Location` handling through the proxy handler end to end: a caller on a Unix request socket, the real
//! request server and pipeline, an FX route with a query slot and a Brave route with a header slot, each in front of a
//! recording TLS test upstream (specification §3.5, §3.8, §3.12, R-13).

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::mock_upstream::{MockUpstream, Reply, TestCa};
use common::proxy_harness::{CallerRequest, Credential, Proxy, Response, Setup, TOKEN_BYTES, Via, token_hash};
use iron_vault::scrub::SCRUB_REPLACEMENT;
use iron_vault_kinds::CredentialMaterial;

const FX_SECRET: &str = "fx/key+9=zq";
const FX_SECRET_ENCODED: &str = "fx%2Fkey%2B9%3Dzq";
const BRAVE_SECRET: &str = "brave-secret-77";

fn routes(fx: u16, brave: u16) -> String {
    let hash = token_hash(TOKEN_BYTES);
    format!(
        r#"[callers.agent]
listener = "local"
token_hash = "{hash}"
routes = ["fx", "brave"]

[routes.fx]
prefix = "/fx"
upstream = "https://localhost:{fx}"
ca_file = "/etc/iron-vault/ca/test.pem"
credential = "fx_key"
slot = {{ query = "access_key" }}
methods = ["GET"]
paths = ["/**"]
rate_limit = {{ requests = 60, per_seconds = 60, burst = 10 }}

[routes.brave]
prefix = "/brave"
upstream = "https://localhost:{brave}/api"
ca_file = "/etc/iron-vault/ca/test.pem"
credential = "brave"
slot = {{ header = "X-Subscription-Token" }}
methods = ["GET"]
paths = ["/api/**"]
rate_limit = {{ requests = 60, per_seconds = 60, burst = 10 }}
"#
    )
}

/// The proxy over an FX upstream answering `fx` and a Brave upstream answering `brave`.
async fn start(ca: &TestCa, fx: &MockUpstream, brave: &MockUpstream) -> Proxy {
    let key = |name, key: &str, port| Credential {
        name,
        material: CredentialMaterial::Static { key: key.into() },
        port,
    };
    Proxy::start(Setup {
        ca,
        callers_and_routes: routes(fx.port(), brave.port()),
        credentials: vec![key("fx_key", FX_SECRET, fx.port()), key("brave", BRAVE_SECRET, brave.port())],
        tcp_port: None,
        request_timeout_secs: 30,
    })
    .await
}

async fn get(proxy: &Proxy, target: &str) -> Response {
    let request = CallerRequest::get(target).signed(Via::Unix);
    proxy.endpoints().send(Via::Unix, &request).await
}

fn redirect(location: &str) -> Reply {
    Reply::Respond {
        status: 302,
        headers: vec![("location".to_owned(), location.to_owned())],
        body: b"upstream-redirect-body".to_vec(),
    }
}

/// Nothing the caller received holds a secret, raw or URL-encoded, or the upstream's body.
fn assert_no_secret(response: &Response) {
    let raw = format!("{}{:?}", response.body, response.headers);
    [FX_SECRET, FX_SECRET_ENCODED, BRAVE_SECRET, "access_key"]
        .iter()
        .for_each(|needle| assert!(!raw.contains(needle), "{needle} reached the caller: {raw}"));
}

/// The `Location` the caller sees for the FX upstream answering `302` to `location`.
async fn fx_location(location: &str) -> Response {
    let ca = TestCa::new("location test CA");
    let (fx, brave) = (
        MockUpstream::start(&ca, redirect(location)).await,
        MockUpstream::start(&ca, Reply::ok("ok")).await,
    );
    let proxy = start(&ca, &fx, &brave).await;
    let response = get(&proxy, "/fx/latest").await;
    assert_no_secret(&response);
    response
}

/// Whether the FX redirect to `location` is relayed as `expected`.
async fn assert_fx_location(location: &str, expected: &str) {
    let response = fx_location(location).await;
    assert_eq!((response.status, response.header("location")), (302, Some(expected)), "{location}");
}

#[tokio::test]
async fn a_relative_location_is_rewritten_under_the_route_prefix() {
    assert_fx_location("/latest?page=2", "/fx/latest?page=2").await;
}

#[tokio::test]
async fn an_empty_location_inherits_the_request_without_the_secret() {
    assert_fx_location("", "/fx/latest").await;
}

#[tokio::test]
async fn a_same_origin_absolute_location_is_rewritten() {
    // `{origin}` is the mock upstream's own `https://localhost:port`.
    assert_fx_location("{origin}/historical/1?x=1", "/fx/historical/1?x=1").await;
}

#[tokio::test]
async fn a_cross_origin_location_passes_through_with_a_secret_in_its_query_scrubbed() {
    assert_fx_location("https://other.example/next?a=1", "https://other.example/next?a=1").await;
    let response = fx_location(&format!("https://other.example/next?k={FX_SECRET_ENCODED}")).await;
    assert_eq!(
        response.header("location"),
        Some(format!("https://other.example/next?k={}", std::str::from_utf8(SCRUB_REPLACEMENT).unwrap()).as_str())
    );
}

#[tokio::test]
async fn an_out_of_base_redirect_is_502_and_is_not_followed() {
    let ca = TestCa::new("location test CA");
    let fx = MockUpstream::start(&ca, Reply::ok("ok")).await;
    let brave = MockUpstream::start(&ca, redirect("/elsewhere")).await;
    let proxy = start(&ca, &fx, &brave).await;

    let response = get(&proxy, "/brave/api/web").await;

    assert_eq!((response.status, response.body.as_str()), (502, "bad gateway"));
    assert_eq!(response.header("location"), None);
    assert_no_secret(&response);
    assert_eq!(brave.requests().len(), 1);
    assert!(fx.requests().is_empty());
}

#[tokio::test]
async fn a_header_slot_route_rewrites_inside_its_base() {
    let ca = TestCa::new("location test CA");
    let fx = MockUpstream::start(&ca, Reply::ok("ok")).await;
    let brave = MockUpstream::start(&ca, redirect("/api/next")).await;
    let proxy = start(&ca, &fx, &brave).await;

    let response = get(&proxy, "/brave/api/web").await;

    assert_eq!((response.status, response.header("location")), (302, Some("/brave/next")));
    assert_no_secret(&response);
}

#[tokio::test]
async fn two_location_headers_are_502() {
    let ca = TestCa::new("location test CA");
    let two = Reply::Respond {
        status: 302,
        headers: vec![
            ("location".to_owned(), "/latest".to_owned()),
            ("location".to_owned(), "/latest?b=1".to_owned()),
        ],
        body: b"upstream-redirect-body".to_vec(),
    };
    let (fx, brave) = (MockUpstream::start(&ca, two).await, MockUpstream::start(&ca, Reply::ok("ok")).await);
    let proxy = start(&ca, &fx, &brave).await;

    let response = get(&proxy, "/fx/latest").await;

    assert_eq!((response.status, response.body.as_str()), (502, "bad gateway"));
    assert_eq!(response.header("location"), None);
    assert_eq!(fx.requests().len(), 1);
}
