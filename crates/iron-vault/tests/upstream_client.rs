//! The upstream client against a recording TLS test upstream (specification §3.5 step 9, §3.6, §3.7, §3.12).
//!
//! Each test sends a checked request built through the public policy API and asserts on what the upstream actually
//! received, not on the request the client was given.
//!
//! Linux only: the test upstream terminates TLS with `tokio-rustls`, which this crate depends on only on Linux.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::panic)]

mod common;

use std::time::Duration;

use common::checked::checked;
use common::mock_upstream::{MockUpstream, RecordedRequest, Reply, TestCa, UPSTREAM_HOST};
use iron_vault::upstream::client::{TransportLimits, UpstreamClient, UpstreamResponse};
use iron_vault::upstream::request_body::RequestBody;
use iron_vault::upstream::transport_error::TransportError;
use iron_vault::upstream::trust::UpstreamTrust;
use iron_vault_policy::Method;
use reqwest::StatusCode;

/// The credential every test injects; it must never appear in an error.
const SECRET: &str = "IVmarker5ecret";

fn client(trust: &UpstreamTrust) -> UpstreamClient {
    UpstreamClient::new(trust, TransportLimits::default()).unwrap()
}

fn sorted(mut headers: Vec<(String, String)>) -> Vec<(String, String)> {
    headers.sort();
    headers
}

fn pairs(headers: &[(&str, &str)]) -> Vec<(String, String)> {
    sorted(headers.iter().map(|(name, value)| (name.to_string(), value.to_string())).collect())
}

/// The only request `upstream` recorded.
fn only_request(upstream: &MockUpstream) -> RecordedRequest {
    let requests = upstream.requests();
    assert_eq!(requests.len(), 1, "{requests:?}");
    requests.into_iter().next().unwrap()
}

async fn body(mut response: UpstreamResponse) -> Vec<u8> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.unwrap() {
        body.extend_from_slice(&chunk);
    }
    body
}

/// Sends a GET for `target` through the query-slot route with the credential marker in the query, expecting failure.
async fn failure(trust: &UpstreamTrust, limits: TransportLimits, origin: &str) -> TransportError {
    let request = checked(origin, Method::Get, "/query/rates?base=USD", &[], SECRET);
    UpstreamClient::new(trust, limits)
        .unwrap()
        .send(request, RequestBody::empty())
        .await
        .unwrap_err()
}

#[tokio::test]
async fn the_upstream_receives_exactly_the_checked_method_target_and_headers() {
    let ca = TestCa::new("Test CA");
    let upstream = MockUpstream::start(&ca, Reply::ok("hello")).await;
    let caller_headers = [
        ("Accept", "application/json"),
        ("X-Custom", "one"),
        ("Proxy-Authorization", "Bearer ivt_caller"),
    ];
    let request = checked(&upstream.origin(), Method::Get, "/header/rates?base=USD", &caller_headers, SECRET);

    let response = client(&ca.trust()).send(request, RequestBody::empty()).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body(response).await, b"hello");
    let received = only_request(&upstream);
    assert_eq!(
        received.server_name.as_deref(),
        Some(UPSTREAM_HOST),
        "SNI names the checked upstream"
    );
    assert_eq!(received.request_line(), "GET /v1/rates?base=USD HTTP/1.1");
    let host = format!("{UPSTREAM_HOST}:{}", upstream.port());
    assert_eq!(
        sorted(received.headers()),
        pairs(&[
            ("accept", "application/json"),
            ("host", &host),
            ("x-api-key", SECRET),
            ("x-custom", "one")
        ]),
        "no Accept-Encoding, cookie, Referer or proxy header may be added"
    );
}

#[tokio::test]
async fn a_query_slot_reaches_the_upstream_in_the_query() {
    let ca = TestCa::new("Test CA");
    let upstream = MockUpstream::start(&ca, Reply::ok("")).await;
    let request = checked(
        &upstream.origin(),
        Method::Post,
        "/query/rates?base=USD",
        &[("Accept", "*/*")],
        SECRET,
    );

    client(&ca.trust()).send(request, RequestBody::empty()).await.unwrap();

    let received = only_request(&upstream);
    assert_eq!(
        received.request_line(),
        format!("POST /v1/rates?base=USD&access_key={SECRET} HTTP/1.1")
    );
    let host = format!("{UPSTREAM_HOST}:{}", upstream.port());
    assert_eq!(sorted(received.headers()), pairs(&[("accept", "*/*"), ("host", &host)]));
}

/// reqwest adds `Accept: */*` to a request that has none, and its builder cannot stop it. This pins that behaviour, so
/// a reqwest upgrade that changes it is noticed.
#[tokio::test]
async fn reqwest_adds_only_accept_to_a_request_without_one() {
    let ca = TestCa::new("Test CA");
    let upstream = MockUpstream::start(&ca, Reply::ok("")).await;
    let request = checked(&upstream.origin(), Method::Get, "/header/x", &[], SECRET);

    client(&ca.trust()).send(request, RequestBody::empty()).await.unwrap();

    let host = format!("{UPSTREAM_HOST}:{}", upstream.port());
    assert_eq!(
        sorted(only_request(&upstream).headers()),
        pairs(&[("accept", "*/*"), ("host", &host), ("x-api-key", SECRET)])
    );
}

#[tokio::test]
async fn a_redirect_is_returned_and_never_followed() {
    let ca = TestCa::new("Test CA");
    let elsewhere = MockUpstream::start(&ca, Reply::ok("followed")).await;
    let location = format!("{}/v1/elsewhere", elsewhere.origin());
    let upstream = MockUpstream::start(&ca, Reply::redirect(&location)).await;
    let request = checked(&upstream.origin(), Method::Get, "/header/x", &[], SECRET);

    let response = client(&ca.trust()).send(request, RequestBody::empty()).await.unwrap();

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(response.headers()["location"], location.as_str());
    assert_eq!(upstream.requests().len(), 1);
    assert_eq!(elsewhere.connections(), 0, "the redirect target saw a connection");
}

#[tokio::test]
async fn a_stalled_upstream_times_out_with_504() {
    let ca = TestCa::new("Test CA");
    let upstream = MockUpstream::start(&ca, Reply::Stall).await;
    let limits = TransportLimits {
        response_headers: Duration::from_millis(200),
        ..TransportLimits::default()
    };

    let error = failure(&ca.trust(), limits, &upstream.origin()).await;

    assert_eq!(error, TransportError::Timeout);
    assert_eq!(error.status(), StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(upstream.requests().len(), 1);
}

#[tokio::test]
async fn an_upstream_certificate_from_another_ca_is_a_tls_failure() {
    let upstream = MockUpstream::start(&TestCa::new("Upstream CA"), Reply::ok("")).await;

    let error = failure(&TestCa::new("Pinned CA").trust(), TransportLimits::default(), &upstream.origin()).await;

    assert_eq!(error, TransportError::Tls);
    assert_eq!(error.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(upstream.requests(), []);
}

#[tokio::test]
async fn the_built_in_roots_refuse_a_private_ca() {
    let upstream = MockUpstream::start(&TestCa::new("Private CA"), Reply::ok("")).await;

    let error = failure(&UpstreamTrust::BuiltIn, TransportLimits::default(), &upstream.origin()).await;

    assert_eq!(error, TransportError::Tls);
    assert_eq!(upstream.requests(), []);
}

#[tokio::test]
async fn a_closed_port_is_a_connect_failure() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("https://{UPSTREAM_HOST}:{}", listener.local_addr().unwrap().port());
    drop(listener);

    let error = failure(&UpstreamTrust::BuiltIn, TransportLimits::default(), &origin).await;

    assert_eq!(error, TransportError::Connect);
    assert_eq!(error.status(), StatusCode::BAD_GATEWAY);
}

/// Every failure above, sent with the credential in the query, formats without the credential or any part of the URL.
#[tokio::test]
async fn transport_errors_show_neither_the_credential_nor_the_url() {
    let ca = TestCa::new("Test CA");
    let stalled = MockUpstream::start(&ca, Reply::Stall).await;
    let foreign = MockUpstream::start(&TestCa::new("Other CA"), Reply::ok("")).await;
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let closed_origin = format!("https://{UPSTREAM_HOST}:{}", closed.local_addr().unwrap().port());
    drop(closed);
    let short = TransportLimits {
        response_headers: Duration::from_millis(200),
        ..TransportLimits::default()
    };
    let errors = [
        failure(&ca.trust(), short, &stalled.origin()).await,
        failure(&ca.trust(), short, &foreign.origin()).await,
        failure(&ca.trust(), short, &closed_origin).await,
    ];
    assert_eq!(errors, [TransportError::Timeout, TransportError::Tls, TransportError::Connect]);

    errors.iter().for_each(|error| {
        [error.to_string(), format!("{error:?}"), format!("{error:#?}")]
            .iter()
            .for_each(|text| {
                [SECRET, UPSTREAM_HOST, "https", "/v1", "access_key", "base=USD"]
                    .iter()
                    .for_each(|forbidden| assert!(!text.contains(forbidden), "{text:?} contains {forbidden:?}"));
            });
    });
}

#[test]
fn only_a_timeout_maps_to_504() {
    let statuses = [
        TransportError::Timeout,
        TransportError::Connect,
        TransportError::Tls,
        TransportError::Protocol,
        TransportError::Body,
    ]
    .map(TransportError::status);
    assert_eq!(
        statuses,
        [
            StatusCode::GATEWAY_TIMEOUT,
            StatusCode::BAD_GATEWAY,
            StatusCode::BAD_GATEWAY,
            StatusCode::BAD_GATEWAY,
            StatusCode::BAD_GATEWAY
        ]
    );
}
