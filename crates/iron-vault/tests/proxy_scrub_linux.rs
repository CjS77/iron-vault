//! Response scrubbing through the proxy handler end to end: a caller on a Unix request socket, the real request server
//! and pipeline, a Basic credential and a recording TLS test upstream that echoes it back (specification §11, §15).
//!
//! The credential is Basic so one body can echo three of its forms at once: the password as stored, the `Basic` token
//! and the URL-encoded password. The password holds `/`, `+` and `=`, so its URL-encoded form differs from it.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::time::Duration;

use common::approval_harness::{Captured, assert_audit_record, captured_logs};
use common::mock_upstream::{MockUpstream, Reply, TestCa};
use common::proxy_harness::{CallerRequest, Credential, Proxy, Response, Setup, TOKEN_BYTES, Via, WAIT, token_hash};
use iron_vault::scrub::SCRUB_REPLACEMENT;
use iron_vault_kinds::CredentialMaterial;

const USERNAME: &str = "agent-user";
const PASSWORD: &str = "pa/ss+word=9f3e";
const PASSWORD_ENCODED: &str = "pa%2Fss%2Bword%3D9f3e";

/// One token caller granted `route`, which sends the Basic credential `fx_basic` to `localhost:port` under `/v1`.
fn callers_and_routes(route: &str, port: u16) -> String {
    let hash = token_hash(TOKEN_BYTES);
    format!(
        r#"[callers.agent]
listener = "local"
token_hash = "{hash}"
routes = ["{route}"]

[routes.{route}]
prefix = "/{route}"
upstream = "https://localhost:{port}/v1"
ca_file = "/etc/iron-vault/ca/test.pem"
credential = "fx_basic"
slot = "basic"
methods = ["GET", "HEAD"]
paths = ["/**"]
rate_limit = {{ requests = 60, per_seconds = 60, burst = 10 }}
"#
    )
}

/// The proxy serving `route` in front of `upstream`.
async fn start(ca: &TestCa, upstream: &MockUpstream, route: &str) -> Proxy {
    let material = CredentialMaterial::Basic {
        username: USERNAME.into(),
        password: PASSWORD.into(),
    };
    Proxy::start(Setup {
        ca,
        callers_and_routes: callers_and_routes(route, upstream.port()),
        credentials: vec![Credential {
            name: "fx_basic",
            material,
            port: upstream.port(),
        }],
        tcp: false,
        request_timeout_secs: 30,
        limits: "",
    })
    .await
}

/// The caller's `method target`, asking for gzip, so a test can see the upstream is asked for the service's codings
/// instead.
async fn send(proxy: &Proxy, method: &str, target: &str) -> Response {
    let request = CallerRequest::new(method, target)
        .header("Accept-Encoding", "gzip")
        .signed(Via::Unix);
    proxy.endpoints().send(Via::Unix, &request).await
}

/// `body` with its chunked framing removed, or `None` if it does not end with the last chunk.
fn dechunked(body: &str) -> Option<String> {
    let mut rest = body;
    let mut out = String::new();
    loop {
        let (size, after) = rest.split_once("\r\n")?;
        let size = usize::from_str_radix(size, 16).ok()?;
        if size == 0 {
            return (after == "\r\n").then_some(out);
        }
        out.push_str(after.get(..size)?);
        rest = after.get(size..)?.strip_prefix("\r\n")?;
    }
}

fn reply(headers: &[(&str, &str)], body: &[u8]) -> Reply {
    Reply::Respond {
        status: 200,
        headers: headers.iter().map(|(n, v)| ((*n).to_owned(), (*v).to_owned())).collect(),
        body: body.to_vec(),
    }
}

/// Every form of the credential the test could see leak: the password, its URL-encoded form and `user:pass`.
fn leaked_forms() -> [String; 3] {
    [PASSWORD.to_owned(), PASSWORD_ENCODED.to_owned(), format!("{USERNAME}:{PASSWORD}")]
}

/// The `Basic` token the proxy injects for the test credential, learnt from one exchange with a plain upstream.
async fn injected_token(ca: &TestCa) -> String {
    let upstream = MockUpstream::start(ca, Reply::ok("ok")).await;
    let proxy = start(ca, &upstream, "fx").await;
    send(&proxy, "GET", "/fx/latest").await;
    let headers = upstream.requests()[0].headers();
    let (_, value) = headers.iter().find(|(name, _)| name == "authorization").unwrap();
    value.strip_prefix("Basic ").unwrap().to_owned()
}

/// An upstream whose body and `X-Echo` header both echo the credential. The mock cannot know the `Basic` token ahead of
/// the request, so the body echoes `token` from a first exchange: the token is the same every time.
async fn echoing_upstream(ca: &TestCa, token: &str) -> MockUpstream {
    let body = format!("raw={PASSWORD} auth=Basic {token} enc={PASSWORD_ENCODED} end");
    MockUpstream::start(ca, reply(&[("x-echo", PASSWORD), ("content-type", "text/plain")], body.as_bytes())).await
}

fn replacement() -> &'static str {
    std::str::from_utf8(SCRUB_REPLACEMENT).unwrap()
}

#[tokio::test]
async fn the_secret_its_basic_token_and_its_url_encoded_form_are_all_replaced() {
    let ca = TestCa::new("scrub test CA");
    let token = injected_token(&ca).await;
    let upstream = echoing_upstream(&ca, &token).await;
    let proxy = start(&ca, &upstream, "fx").await;

    let response = send(&proxy, "GET", "/fx/latest").await;

    let r = replacement();
    assert_eq!(response.status, 200);
    assert_eq!(dechunked(&response.body).unwrap(), format!("raw={r} auth={r} enc={r} end"));
    assert_eq!(response.header("x-echo"), Some(r));
    let raw = format!("{}{:?}", response.body, response.headers);
    leaked_forms()
        .iter()
        .chain([&token])
        .for_each(|form| assert!(!raw.contains(form.as_str()), "{form} reached the caller: {raw}"));
}

/// Answers `502` with the fixed body, and the upstream was asked for the service's codings, not the caller's.
async fn assert_refused(reply: Reply) {
    let ca = TestCa::new("scrub test CA");
    let upstream = MockUpstream::start(&ca, reply).await;
    let proxy = start(&ca, &upstream, "fx").await;

    let response = send(&proxy, "GET", "/fx/latest").await;

    assert_eq!((response.status, response.body.as_str()), (502, "bad gateway"));
    assert_eq!(response.header("content-encoding"), None);
    let sent = upstream.requests()[0].headers();
    let asked: Vec<_> = sent
        .iter()
        .filter(|(name, _)| name == "accept-encoding")
        .map(|(_, value)| value)
        .collect();
    assert_eq!(asked, ["gzip, deflate, br"], "{sent:?}");
}

#[tokio::test]
async fn an_unsupported_content_coding_that_connection_names_is_still_502() {
    // Stripping drops every header `Connection` names, so the coding must be judged before it.
    let headers = [("connection", "content-encoding"), ("content-encoding", "zstd")];
    assert_refused(reply(&headers, b"\x28\xb5\x2f\xfdupstream-body")).await;
}

#[tokio::test]
async fn a_transfer_coding_other_than_chunked_is_502() {
    // hyper removes the chunked framing and leaves the gzip coding under it. The mock also sends `Content-Length`,
    // which `Transfer-Encoding` overrides (RFC 9112 §6.3).
    let framed = b"11\r\n\x1f\x8b\x08\x00upstream-body\r\n0\r\n\r\n";
    assert_refused(reply(&[("transfer-encoding", "gzip, chunked")], framed)).await;
}

#[tokio::test]
async fn a_reply_without_the_secret_comes_back_unchanged_but_for_its_framing_integrity_and_etag_headers() {
    let ca = TestCa::new("scrub test CA");
    let body = "{\"rates\":{\"EUR\":0.91},\"note\":\"pa/ss but not the password; Basic realm\"}\n\u{e9}\u{1f600}";
    let kept = [
        ("content-type", "application/json; charset=utf-8"),
        ("cache-control", "max-age=60"),
        ("x-request-id", "req-77"),
    ];
    let removed = [
        ("content-digest", "sha-256=:AAAA:"),
        ("repr-digest", "sha-256=:AAAA:"),
        ("digest", "SHA-256=AAAA"),
    ];
    let headers: Vec<_> = kept.iter().chain(&removed).chain(&[("etag", "\"v1\"")]).copied().collect();
    let upstream = MockUpstream::start(&ca, reply(&headers, body.as_bytes())).await;
    let proxy = start(&ca, &upstream, "fx").await;

    let response = send(&proxy, "GET", "/fx/latest").await;

    assert_eq!(response.status, 200);
    assert_eq!(dechunked(&response.body).unwrap(), body);
    kept.iter()
        .for_each(|(name, value)| assert_eq!(response.header(name), Some(*value), "{name}"));
    // A scrub may replace bytes, so the strong `ETag` no longer promises byte identity.
    assert_eq!(response.header("etag"), Some("W/\"v1\""));
    // Besides the kept headers and the `ETag`, only the request server's own framing and date headers.
    let own = ["etag", "transfer-encoding", "connection", "date"];
    response
        .headers
        .iter()
        .filter(|(name, _)| !kept.iter().any(|(kept, _)| kept == name))
        .for_each(|(name, _)| assert!(own.contains(&name.as_str()), "{name} reached the caller"));
}

#[tokio::test]
async fn a_head_response_has_the_headers_of_its_get_so_no_content_length() {
    // The `GET` body is scrubbed, which may change its length, so it is sent chunked without one.
    let ca = TestCa::new("scrub test CA");
    let upstream = MockUpstream::start(&ca, Reply::ok("hello")).await;
    let proxy = start(&ca, &upstream, "fx").await;

    let response = send(&proxy, "HEAD", "/fx/latest").await;

    assert_eq!(response.status, 200);
    assert_eq!(response.header("content-length"), None);
    assert_eq!(response.header("transfer-encoding"), None);
    assert!(response.body.is_empty());
}

#[tokio::test]
async fn a_body_cut_short_never_releases_a_held_secret_prefix() {
    let ca = TestCa::new("scrub test CA");
    let prefix = &PASSWORD[..PASSWORD.len() - 1];
    let truncated = Reply::Truncated {
        sent: format!("partial {prefix}"),
    };
    let upstream = MockUpstream::start(&ca, truncated).await;
    let proxy = start(&ca, &upstream, "fx").await;

    let response = send(&proxy, "GET", "/fx/latest").await;

    assert_eq!(response.status, 200);
    assert!(response.body.contains("partial "), "{:?}", response.body);
    assert!(
        !response.body.contains("pa/"),
        "the held prefix reached the caller: {:?}",
        response.body
    );
    assert!(
        dechunked(&response.body).is_none(),
        "the cut-short body ended cleanly: {:?}",
        response.body
    );
}

#[tokio::test]
async fn the_scrub_event_names_the_route_and_credential_and_holds_no_secret_form() {
    // Its own route, so its event is told apart from those the other tests raise into the same global subscriber.
    let captured = captured_logs();
    let ca = TestCa::new("scrub test CA");
    let token = injected_token(&ca).await;
    let upstream = echoing_upstream(&ca, &token).await;
    let proxy = start(&ca, &upstream, "scrubev").await;

    let response = send(&proxy, "GET", "/scrubev/latest").await;
    // The event is raised when the server drops the body, which may come just after the caller reads the end.
    let event = tokio::time::timeout(WAIT, async {
        loop {
            if let Some(event) = scrub_events(&captured).into_iter().next() {
                return event;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();

    assert_eq!(response.status, 200);
    assert_eq!(scrub_events(&captured).len(), 1, "{}", captured.text());
    assert_eq!(
        (event["level"].as_str(), event["credential"].as_str(), event["matches"].as_u64()),
        (Some("WARN"), Some("fx_basic"), Some(4))
    );
    assert_audit_record(&event, "WARN", &["credential", "matches", "request_id", "route"]);
    let logged = captured.text();
    leaked_forms()
        .iter()
        .chain([&token])
        .for_each(|form| assert!(!logged.contains(form.as_str()), "{form} was logged: {logged}"));
}

/// The `response.scrubbed` records of this test's own route.
fn scrub_events(captured: &Captured) -> Vec<serde_json::Value> {
    captured
        .events("response.scrubbed")
        .into_iter()
        .filter(|record| record["route"] == "scrubev")
        .collect()
}
