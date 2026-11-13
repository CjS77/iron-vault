//! The proxy handler end to end: a caller on a Unix request socket, the real request server and pipeline, and a
//! recording TLS test upstream (specification §8 steps 9-10, §15).
//!
//! The service account is the test's own uid, and the caller authenticates with a token in a dedicated header, so an
//! upstream echoing that header back is the case the relay must strip.

#![cfg(target_os = "linux")]

use crate::common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::mock_upstream::{MockUpstream, Reply, TestCa};
use common::proxy_harness::{CallerRequest, Credential, Proxy, Response, Setup, UNLOADABLE_CA, Via, WAIT, token_hash};
use iron_vault_kinds::CredentialMaterial;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const SECRET: &str = "fx-secret-9c2e";

/// One token caller on a Unix listener, granted the `fx` route to `localhost:port` under `/v1`, its key in `X-Api-Key`.
fn callers_and_routes(port: u16) -> String {
    let hash = token_hash(common::proxy_harness::TOKEN_BYTES);
    format!(
        r#"[callers.agent]
listener = "local"
token_hash = "{hash}"
routes = ["fx"]

[routes.fx]
prefix = "/fx"
upstream = "https://localhost:{port}/v1"
ca_file = "/etc/iron-vault/ca/test.pem"
credential = "fx_key"
slot = {{ header = "X-Api-Key" }}
methods = ["GET"]
paths = ["/**"]
rate_limit = {{ requests = 60, per_seconds = 60, burst = 10 }}
"#
    )
}

/// The proxy serving the `fx` route to the upstream at `localhost:port`, pinning `ca`.
async fn start(ca: &TestCa, port: u16, request_timeout_secs: u64) -> Proxy {
    Proxy::start(Setup {
        ca,
        callers_and_routes: callers_and_routes(port),
        credentials: vec![Credential {
            name: "fx_key",
            material: CredentialMaterial::Static { key: SECRET.into() },
            port,
        }],
        tcp: false,
        request_timeout_secs,
        limits: "",
    })
    .await
}

/// The token caller's `GET target`.
fn get(target: &str) -> String {
    String::from_utf8(CallerRequest::get(target).signed(Via::Unix).to_bytes()).unwrap()
}

fn reply(status: u16, headers: &[(&str, &str)], body: &str) -> Reply {
    Reply::Respond {
        status,
        headers: headers.iter().map(|(n, v)| ((*n).to_owned(), (*v).to_owned())).collect(),
        body: body.as_bytes().to_vec(),
    }
}

#[tokio::test]
async fn a_granted_get_carries_the_credential_and_gets_the_upstreams_response() {
    let ca = TestCa::new("proxy test CA");
    let upstream = MockUpstream::start(
        &ca,
        reply(201, &[("content-type", "application/json"), ("x-rate", "59")], r#"{"ok":1}"#),
    )
    .await;
    let proxy = start(&ca, upstream.port(), 30).await;

    let response = proxy.get("/fx/latest?base=USD").await;

    assert_eq!(response.status, 201);
    assert_eq!(response.header("content-type"), Some("application/json"));
    assert_eq!(response.header("x-rate"), Some("59"));
    // Scrubbing may change the length, so the upstream's `Content-Length` is dropped and the body is sent chunked.
    assert_eq!(response.header("content-length"), None);
    assert_eq!(response.header("transfer-encoding"), Some("chunked"));
    assert_eq!(response.body, "8\r\n{\"ok\":1}\r\n0\r\n\r\n");
    let sent = upstream.requests();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].request_line(), "GET /v1/latest?base=USD HTTP/1.1");
    let headers = sent[0].headers();
    assert!(headers.contains(&("x-api-key".to_owned(), SECRET.to_owned())), "{headers:?}");
    assert!(headers.iter().all(|(name, _)| name != "x-iron-vault-token"), "{headers:?}");
}

#[tokio::test]
async fn hop_by_hop_and_caller_auth_headers_from_the_upstream_never_reach_the_caller() {
    let ca = TestCa::new("proxy test CA");
    let echoed = [
        ("connection", "x-hop"),
        ("x-hop", "1"),
        ("proxy-authenticate", "Basic realm=\"upstream\""),
        ("x-iron-vault-token", "ivt_echoed"),
        ("x-kept", "1"),
    ];
    let upstream = MockUpstream::start(&ca, reply(200, &echoed, "ok")).await;
    let proxy = start(&ca, upstream.port(), 30).await;

    let response = proxy.get("/fx/latest").await;

    assert_eq!(response.status, 200);
    assert_eq!(response.header("x-kept"), Some("1"));
    ["x-hop", "proxy-authenticate", "x-iron-vault-token"]
        .iter()
        .for_each(|name| assert_eq!(response.header(name), None, "{name} reached the caller"));
    // hyper's own `Connection: close`, answering the caller's, is the only one, and names nothing from the upstream.
    assert!(
        response
            .headers
            .iter()
            .filter(|(n, _)| n == "connection")
            .all(|(_, v)| v == "close"),
        "{:?}",
        response.headers
    );
    assert_eq!(response.body, "2\r\nok\r\n0\r\n\r\n");
}

#[tokio::test]
async fn an_unreachable_upstream_is_502_without_its_url() {
    let ca = TestCa::new("proxy test CA");
    // A port nothing listens on: bound, read and closed.
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let proxy = start(&ca, port, 30).await;

    let response = proxy.get("/fx/latest?base=USD").await;

    assert_eq!(response.status, 502);
    assert_eq!(response.body, "bad gateway");
    assert_no_upstream_detail(&response, port);
}

#[tokio::test]
async fn an_upstream_that_never_sends_headers_is_504_at_the_request_deadline() {
    let ca = TestCa::new("proxy test CA");
    let upstream = MockUpstream::start(&ca, Reply::Stall).await;
    let proxy = start(&ca, upstream.port(), 1).await;

    let start = Instant::now();
    let response = proxy.get("/fx/latest?base=USD").await;

    assert_eq!(response.status, 504);
    assert_eq!(response.body, "gateway timeout");
    assert!(start.elapsed() >= Duration::from_secs(1), "answered after {:?}", start.elapsed());
    assert_eq!(upstream.requests().len(), 1, "the request did reach the upstream");
    assert_no_upstream_detail(&response, upstream.port());
}

#[tokio::test]
async fn a_streamed_body_reaches_the_caller_chunk_by_chunk() {
    let ca = TestCa::new("proxy test CA");
    let gate = Arc::new(tokio::sync::Notify::new());
    let chunks = Reply::TwoChunks {
        first: "data: first\n\n".to_owned(),
        second: "data: second\n\n".to_owned(),
        gate: Arc::clone(&gate),
    };
    let upstream = MockUpstream::start(&ca, chunks).await;
    let proxy = start(&ca, upstream.port(), 30).await;
    let mut stream = proxy.connect().await;
    stream.write_all(get("/fx/stream").as_bytes()).await.unwrap();

    // The upstream sends the second chunk only after this sees the first, so a buffering relay would stall here.
    let mut raw = tokio::time::timeout(WAIT, read_until(&mut stream, "data: first\n\n"))
        .await
        .unwrap();
    assert!(!raw.contains("data: second"), "{raw}");
    gate.notify_one();
    let mut rest = Vec::new();
    tokio::time::timeout(WAIT, stream.read_to_end(&mut rest)).await.unwrap().unwrap();
    raw.push_str(&String::from_utf8(rest).unwrap());

    let response = Response::parse(&raw);
    assert_eq!(response.status, 200);
    assert_eq!(response.header("transfer-encoding"), Some("chunked"));
    assert!(response.body.contains("data: second\n\n"), "{raw}");
    assert!(response.body.ends_with("0\r\n\r\n"), "the chunked body did not end cleanly: {raw}");
}

#[tokio::test]
async fn a_body_cut_short_upstream_reaches_the_caller_cut_short_not_complete() {
    let ca = TestCa::new("proxy test CA");
    let truncated = Reply::Truncated {
        sent: "partial".to_owned(),
    };
    let upstream = MockUpstream::start(&ca, truncated).await;
    let proxy = start(&ca, upstream.port(), 30).await;

    let response = proxy.get("/fx/latest").await;

    // The head and the chunk that arrived went out; the connection then closed without the last chunk.
    assert_eq!(response.status, 200);
    assert_eq!(response.header("transfer-encoding"), Some("chunked"));
    assert!(response.body.contains("partial"), "{:?}", response.body);
    assert!(
        !response.body.ends_with("0\r\n\r\n"),
        "the cut-short body ended cleanly: {:?}",
        response.body
    );
}

/// Reads from `stream` until what has arrived contains `wanted`, and returns all of it.
async fn read_until(stream: &mut UnixStream, wanted: &str) -> String {
    let mut raw = Vec::new();
    while !String::from_utf8_lossy(&raw).contains(wanted) {
        let mut buf = [0u8; 256];
        let read = stream.read(&mut buf).await.unwrap();
        assert!(read > 0, "the connection closed before {wanted:?} arrived");
        raw.extend_from_slice(&buf[..read]);
    }
    String::from_utf8(raw).unwrap()
}

/// The response names neither the upstream's origin nor the query the caller sent, and its body not even the port.
fn assert_no_upstream_detail(response: &Response, port: u16) {
    let text = format!("{:?}{}", response.headers, response.body);
    ["localhost", "https://", "base=USD"]
        .iter()
        .for_each(|detail| assert!(!text.contains(detail), "{detail} in {text}"));
    assert!(!response.body.contains(&port.to_string()), "{}", response.body);
}

/// The `fx` route pinning a CA that does not load, and the `fx_plain` route on the same credential pinning the test CA.
fn pinned_ca_unavailable(port: u16) -> String {
    let fx = callers_and_routes(port)
        .replace("routes = [\"fx\"]", "routes = [\"fx\", \"fx_plain\"]")
        .replace("/etc/iron-vault/ca/test.pem", UNLOADABLE_CA);
    format!(
        r#"{fx}
[routes.fx_plain]
prefix = "/fx-plain"
upstream = "https://localhost:{port}/v1"
ca_file = "/etc/iron-vault/ca/test.pem"
credential = "fx_key"
slot = {{ header = "X-Api-Key" }}
methods = ["GET"]
paths = ["/**"]
rate_limit = {{ requests = 60, per_seconds = 60, burst = 10 }}
"#
    )
}

#[tokio::test]
async fn a_route_whose_pinned_ca_did_not_load_is_503_and_reaches_no_upstream() {
    let ca = TestCa::new("proxy test CA");
    let upstream = MockUpstream::start(&ca, reply(200, &[], "ok")).await;
    let proxy = Proxy::start(Setup {
        ca: &ca,
        callers_and_routes: pinned_ca_unavailable(upstream.port()),
        credentials: vec![Credential {
            name: "fx_key",
            material: CredentialMaterial::Static { key: SECRET.into() },
            port: upstream.port(),
        }],
        tcp: false,
        request_timeout_secs: 30,
        limits: "",
    })
    .await;

    let response = proxy.get("/fx/latest").await;

    assert_eq!((response.status, response.body.as_str()), (503, "service unavailable"));
    assert_eq!(upstream.connections(), 0);
    assert!(upstream.requests().is_empty());
    // The same credential's other route pins a CA that loaded, so it keeps serving.
    assert_eq!(proxy.get("/fx-plain/latest").await.status, 200);
    assert_eq!(upstream.requests().len(), 1);
}

/// The proxy's [`Setup`] for the `fx` route with a 30-second request timeout and these extra `[limits]`.
fn setup_with_limits<'a>(ca: &'a TestCa, port: u16, limits: &'static str) -> Setup<'a> {
    Setup {
        ca,
        callers_and_routes: callers_and_routes(port),
        credentials: vec![Credential {
            name: "fx_key",
            material: CredentialMaterial::Static { key: SECRET.into() },
            port,
        }],
        tcp: false,
        request_timeout_secs: 30,
        limits,
    }
}

#[tokio::test]
async fn the_approved_upstream_timeout_bounds_the_wait_for_response_headers() {
    let ca = TestCa::new("proxy test CA");
    let delayed = Reply::Delayed {
        delay: Duration::from_secs(3),
        body: "late".into(),
    };
    let upstream = MockUpstream::start(&ca, delayed).await;
    let proxy = Proxy::start(setup_with_limits(&ca, upstream.port(), "upstream_timeout_secs = 1")).await;

    let started = Instant::now();
    let response = proxy.get("/fx/latest").await;

    assert_eq!(response.status, 504);
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_secs(1) && waited < Duration::from_secs(3),
        "waited {waited:?}"
    );

    // A newly served config raises the limit for the next request, with no restart.
    proxy
        .holder()
        .serve(proxy.snapshot(setup_with_limits(&ca, upstream.port(), "upstream_timeout_secs = 10")));
    let response = proxy.get("/fx/latest").await;

    assert_eq!(response.status, 200);
    assert!(response.body.contains("late"), "{}", response.body);
}
