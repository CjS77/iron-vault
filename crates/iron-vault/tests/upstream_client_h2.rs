//! The upstream client over HTTP/2 against a recording test upstream that offers only ALPN `h2` (specification §3.6,
//! §3.7, §3.12).
//!
//! The HTTP/1.1 tests in `upstream_client.rs` cover the rest of the client; these cover what only HTTP/2 has:
//! `:authority`, HPACK's never-indexed literals, failures signalled by RST_STREAM and GOAWAY, and that a request the
//! upstream refused unprocessed is not re-sent (§7).
//!
//! Linux only: the test upstream terminates TLS with `tokio-rustls`, which this crate depends on only on Linux.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::panic)]

mod common;

use common::body_stream::{body as body_of, eventually, failing_body};
use common::checked::checked;
use common::h2_refusal::Refusal;
use common::hpack_fields::{FieldName, Representation};
use common::mock_upstream::{TestCa, UPSTREAM_HOST};
use common::mock_upstream_h2::{H2Reply, MockH2Upstream, RecordedH2Request};
use h2::Reason;
use iron_vault::upstream::client::{TransportLimits, UpstreamClient, UpstreamResponse};
use iron_vault::upstream::request_body::UpstreamBody;
use iron_vault::upstream::transport_error::TransportError;
use iron_vault_policy::Method;
use reqwest::StatusCode;

/// The credential every test injects; it must never appear in an error.
const SECRET: &str = "IVmarker5ecret";

/// Caller headers that all survive sanitizing, so each reaches the upstream marked sensitive.
const CALLER_HEADERS: [(&str, &str); 2] = [("Accept", "application/json"), ("X-Custom", "one")];

fn client(ca: &TestCa) -> UpstreamClient {
    UpstreamClient::new(&ca.trust(), TransportLimits::default()).unwrap()
}

fn sorted(mut headers: Vec<(String, String)>) -> Vec<(String, String)> {
    headers.sort();
    headers
}

/// The only request `upstream` recorded.
fn only_request(upstream: &MockH2Upstream) -> RecordedH2Request {
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

/// Sends a GET through the query-slot route, with the credential in the query, to an upstream answering `reply`.
async fn failure(reply: H2Reply) -> (TransportError, MockH2Upstream) {
    let ca = TestCa::new("Test CA");
    let upstream = MockH2Upstream::start(&ca, reply).await;
    let request = checked(&upstream.origin(), Method::Get, "/query/rates?base=USD", &CALLER_HEADERS, SECRET);
    let error = client(&ca).send(request, UpstreamBody::empty()).await.unwrap_err();
    (error, upstream)
}

/// `error` is a 502 of a class an HTTP/2 failure may take, and formats with nothing from the request.
fn assert_safe_502(error: TransportError) {
    assert!(matches!(error, TransportError::Protocol | TransportError::Connect), "{error:?}");
    assert_eq!(error.status(), StatusCode::BAD_GATEWAY);
    [error.to_string(), format!("{error:?}"), format!("{error:#?}")]
        .iter()
        .for_each(|text| {
            [SECRET, UPSTREAM_HOST, "https", "/v1", "access_key", "base=USD", "application/json"]
                .iter()
                .for_each(|forbidden| assert!(!text.contains(forbidden), "{text:?} contains {forbidden:?}"));
        });
}

#[tokio::test]
async fn http2_carries_exactly_the_checked_authority_path_and_headers() {
    let ca = TestCa::new("Test CA");
    let upstream = MockH2Upstream::start(&ca, H2Reply::ok("hello")).await;
    let request = checked(&upstream.origin(), Method::Get, "/header/rates?base=USD", &CALLER_HEADERS, SECRET);

    let response = client(&ca).send(request, UpstreamBody::empty()).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body(response).await, b"hello");
    let received = only_request(&upstream);
    assert_eq!(received.alpn.as_deref(), Some(&b"h2"[..]), "ALPN settled on HTTP/2");
    assert_eq!(received.server_name.as_deref(), Some(UPSTREAM_HOST));
    assert_eq!(received.method, "GET");
    assert_eq!(received.scheme.as_deref(), Some("https"));
    let authority = format!("{UPSTREAM_HOST}:{}", upstream.port());
    assert_eq!(
        received.authority.as_deref(),
        Some(authority.as_str()),
        ":authority names the checked upstream"
    );
    assert_eq!(received.path.as_deref(), Some("/v1/rates?base=USD"));
    let expected = [("accept", "application/json"), ("x-api-key", SECRET), ("x-custom", "one")]
        .map(|(name, value)| (name.to_owned(), value.to_owned()));
    assert_eq!(
        sorted(received.headers),
        expected,
        "no Host, cookie, Referer or proxy header may be added"
    );
}

#[tokio::test]
async fn a_query_slot_reaches_the_upstream_in_path() {
    let ca = TestCa::new("Test CA");
    let upstream = MockH2Upstream::start(&ca, H2Reply::ok("")).await;
    let request = checked(&upstream.origin(), Method::Post, "/query/rates?base=USD", &CALLER_HEADERS, SECRET);

    client(&ca).send(request, UpstreamBody::empty()).await.unwrap();

    let received = only_request(&upstream);
    assert_eq!(received.method, "POST");
    assert_eq!(received.path, Some(format!("/v1/rates?base=USD&access_key={SECRET}")));
}

/// A never-indexed literal keeps a value out of both ends' HPACK dynamic tables, where it would outlive the request,
/// and tells any intermediary to do the same (RFC 7541 §7.1.3).
#[tokio::test]
async fn every_checked_header_is_a_never_indexed_literal() {
    let ca = TestCa::new("Test CA");
    let upstream = MockH2Upstream::start(&ca, H2Reply::ok("")).await;
    let request = checked(&upstream.origin(), Method::Get, "/header/rates?base=USD", &CALLER_HEADERS, SECRET);

    client(&ca).send(request, UpstreamBody::empty()).await.unwrap();

    let received = only_request(&upstream);
    assert!(received.fields.is_some(), "the raw header block could not be read");
    let regular = received.regular_fields();
    assert_eq!(regular.len(), received.headers.len(), "one field per received header: {regular:?}");
    assert!(
        regular.iter().all(|field| field.representation == Representation::NeverIndexed),
        "{regular:?}"
    );
}

/// The control for the test above: reqwest's own `Accept: */*` is not marked sensitive, so it is indexed, which shows the
/// recording tells the representations apart rather than reporting every field as never-indexed.
#[tokio::test]
async fn reqwest_indexes_the_accept_it_adds() {
    let ca = TestCa::new("Test CA");
    let upstream = MockH2Upstream::start(&ca, H2Reply::ok("")).await;
    let request = checked(&upstream.origin(), Method::Get, "/header/rates?base=USD", &[], SECRET);

    client(&ca).send(request, UpstreamBody::empty()).await.unwrap();

    let representations: Vec<_> = only_request(&upstream)
        .regular_fields()
        .iter()
        .map(|field| (field.name, field.representation))
        .collect();
    assert_eq!(
        representations,
        [
            (FieldName::Literal, Representation::NeverIndexed),
            (FieldName::Static("accept"), Representation::IncrementalIndexing)
        ],
        "x-api-key is sensitive; the added Accept is not"
    );
}

/// h2 never adds `:path` to the dynamic table, so a filled query slot stays out of it (`design/secret-handling.md`).
#[tokio::test]
async fn a_path_with_a_query_slot_never_enters_the_dynamic_table() {
    let ca = TestCa::new("Test CA");
    let upstream = MockH2Upstream::start(&ca, H2Reply::ok("")).await;
    let request = checked(&upstream.origin(), Method::Get, "/query/rates?base=USD", &CALLER_HEADERS, SECRET);

    client(&ca).send(request, UpstreamBody::empty()).await.unwrap();

    let fields = only_request(&upstream).fields.unwrap();
    let paths: Vec<_> = fields.iter().filter(|field| field.name == FieldName::Static(":path")).collect();
    assert_eq!(paths.len(), 1, "{fields:?}");
    assert_ne!(paths[0].representation, Representation::IncrementalIndexing);
}

#[tokio::test]
async fn a_reset_stream_is_a_safe_502() {
    let (error, upstream) = failure(H2Reply::Reset(Reason::INTERNAL_ERROR)).await;

    assert_safe_502(error);
    assert_eq!(upstream.requests().len(), 1);
}

#[tokio::test]
async fn a_stream_reset_for_a_protocol_error_is_a_safe_502() {
    let (error, upstream) = failure(H2Reply::Reset(Reason::PROTOCOL_ERROR)).await;

    assert_safe_502(error);
    assert_eq!(upstream.requests().len(), 1);
}

#[tokio::test]
async fn goaway_before_a_response_is_a_safe_502() {
    let (error, upstream) = failure(H2Reply::GoAway(Reason::INTERNAL_ERROR)).await;

    assert_safe_502(error);
    assert_eq!(upstream.requests().len(), 1);
}

#[tokio::test]
async fn goaway_for_a_protocol_error_is_a_safe_502() {
    let (error, upstream) = failure(H2Reply::GoAway(Reason::PROTOCOL_ERROR)).await;

    assert_safe_502(error);
    assert_eq!(upstream.requests().len(), 1);
}

/// The client sends a refused request once and reports the refusal, however safe reqwest would judge a re-send.
/// `reqwest_retry_control.rs` shows that reqwest's default policy does re-send both refusals.
async fn assert_sent_once(refusal: Refusal) {
    let (error, upstream) = failure(H2Reply::Refuse(refusal)).await;

    assert_safe_502(error);
    assert_eq!(upstream.connections(), 1, "a retry over a new connection");
    assert!(upstream.request_heads() <= 1, "{} request heads", upstream.request_heads());
}

#[tokio::test]
async fn a_refused_stream_is_not_retried() {
    assert_sent_once(Refusal::RefusedStream).await;
}

#[tokio::test]
async fn goaway_before_the_request_was_processed_is_not_retried() {
    assert_sent_once(Refusal::GoAwayUnprocessed).await;
}

/// The only request `upstream` records, waited for, since an aborted request is recorded after `send` has failed.
async fn recorded(upstream: &MockH2Upstream) -> RecordedH2Request {
    eventually(|| upstream.requests().into_iter().next()).await
}

fn header<'a>(request: &'a RecordedH2Request, name: &str) -> Option<&'a str> {
    request
        .headers
        .iter()
        .find(|(found, _)| found == name)
        .map(|(_, value)| value.as_str())
}

const CHAT: &str = "/header/chat";

#[tokio::test]
async fn a_fixed_length_body_arrives_byte_for_byte_over_http2() {
    let ca = TestCa::new("Test CA");
    let upstream = MockH2Upstream::start(&ca, H2Reply::ok("done")).await;
    let request = checked(&upstream.origin(), Method::Post, CHAT, &[], SECRET);
    let chunks = ["{\"prompt\":", "\"h\u{e9}llo ", "w\u{f6}rld\"}"];
    let sent = chunks.concat();

    let response = client(&ca).send(request, body_of(Some(sent.len() as u64), &chunks)).await.unwrap();

    assert_eq!(body(response).await, b"done");
    let received = only_request(&upstream);
    assert_eq!(received.alpn.as_deref(), Some(&b"h2"[..]));
    assert_eq!(received.method, "POST");
    assert_eq!(header(&received, "content-length"), Some(sent.len().to_string().as_str()));
    assert_eq!(received.body, sent.as_bytes());
    assert!(received.body_complete);
}

#[tokio::test]
async fn a_body_of_unknown_length_arrives_byte_for_byte_over_http2() {
    let ca = TestCa::new("Test CA");
    let upstream = MockH2Upstream::start(&ca, H2Reply::ok("done")).await;
    let request = checked(&upstream.origin(), Method::Post, CHAT, &[], SECRET);
    let chunks = ["one,", "two,", "three"];

    client(&ca).send(request, body_of(None, &chunks)).await.unwrap();

    let received = only_request(&upstream);
    assert_eq!(header(&received, "content-length"), None, "HTTP/2 frames by END_STREAM");
    assert_eq!(header(&received, "transfer-encoding"), None);
    assert_eq!(received.body, chunks.concat().as_bytes());
    assert!(received.body_complete);
}

#[tokio::test]
async fn a_body_stream_that_fails_partway_resets_the_http2_stream() {
    for length in [None, Some(100)] {
        let ca = TestCa::new("Test CA");
        let upstream = MockH2Upstream::start(&ca, H2Reply::ok("done")).await;
        let request = checked(&upstream.origin(), Method::Post, CHAT, &[], SECRET);

        let error = client(&ca)
            .send(request, failing_body(length, &["partial ", "body"]))
            .await
            .unwrap_err();

        assert_eq!(error.status(), StatusCode::BAD_GATEWAY, "{length:?}: {error:?}");
        let received = recorded(&upstream).await;
        assert!(
            !received.body_complete,
            "{length:?}: the upstream saw a complete request: {received:?}"
        );
        assert_eq!(
            received.body, b"partial body",
            "{length:?}: the chunks before the failure were forwarded"
        );
    }
}

#[tokio::test]
async fn a_body_stream_that_ends_short_of_its_declared_length_is_not_completed_over_http2() {
    let ca = TestCa::new("Test CA");
    let upstream = MockH2Upstream::start(&ca, H2Reply::ok("done")).await;
    let request = checked(&upstream.origin(), Method::Post, CHAT, &[], SECRET);

    let error = client(&ca).send(request, body_of(Some(100), &["short"])).await.unwrap_err();

    assert_eq!(error.status(), StatusCode::BAD_GATEWAY);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(upstream.requests().iter().all(|received| !received.body_complete));
}

#[tokio::test]
async fn a_body_stream_longer_than_its_declared_length_is_not_completed_over_http2() {
    let ca = TestCa::new("Test CA");
    let upstream = MockH2Upstream::start(&ca, H2Reply::ok("done")).await;
    let request = checked(&upstream.origin(), Method::Post, CHAT, &[], SECRET);

    let error = client(&ca).send(request, body_of(Some(5), &["toolong"])).await.unwrap_err();

    assert_eq!(error.status(), StatusCode::BAD_GATEWAY);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(upstream.requests().iter().all(|received| !received.body_complete));
}

#[tokio::test]
async fn a_get_without_a_body_sends_no_body_over_http2() {
    let ca = TestCa::new("Test CA");
    let upstream = MockH2Upstream::start(&ca, H2Reply::ok("")).await;
    let request = checked(&upstream.origin(), Method::Get, "/header/rates", &[], SECRET);

    client(&ca).send(request, UpstreamBody::empty()).await.unwrap();

    let received = only_request(&upstream);
    assert_eq!(header(&received, "content-length"), None);
    assert_eq!(header(&received, "transfer-encoding"), None);
    assert_eq!(received.body, b"");
    assert!(received.body_complete);
}
