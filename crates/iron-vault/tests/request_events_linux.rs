//! The request event of each request that ends before a response head is relayed, end to end: the real request server,
//! pipeline and proxy handler in front of a recording test upstream (specification §3.15; `design/audit-logging.md`,
//! "Request event").
//!
//! The harness runs on a current-thread runtime, so the log captured on the test's thread holds every record.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeSet;

use common::mock_upstream::{MockUpstream, Reply, TestCa};
use common::proxy_harness::{CallerRequest, Credential, Proxy, Setup, TOKEN_BYTES, UNLOADABLE_CA, Via, token, token_hash};
use common::request_log::capture;
use iron_vault::service_state::UnavailableReason;
use iron_vault_kinds::CredentialMaterial;

const SECRET: &str = "fx-secret-9c2e";

/// One token caller granted `fx`, `slow` (one request, then a wait), `narrow` (one path) and `broken` (a pinned CA that does
/// not load); `other` exists but is not granted.
fn callers_and_routes(port: u16) -> String {
    let hash = token_hash(TOKEN_BYTES);
    let route = |name: &str, methods: &str, paths: &str, ca: &str, rate: &str| {
        format!(
            "[routes.{name}]\nprefix = \"/{name}\"\nupstream = \"https://localhost:{port}/v1\"\nca_file = \"{ca}\"\n\
             credential = \"fx_key\"\nslot = {{ header = \"X-Api-Key\" }}\n\
             methods = [{methods}]\npaths = [{paths}]\nrate_limit = {rate}\n\n"
        )
    };
    let fast = "{ requests = 1000, per_seconds = 1, burst = 1000 }";
    let ca = "/etc/iron-vault/ca/test.pem";
    let routes = [
        route("fx", "\"GET\"", "\"/v1/**\"", ca, fast),
        route("slow", "\"GET\"", "\"/v1/**\"", ca, "{ requests = 2, per_seconds = 60, burst = 1 }"),
        route("narrow", "\"GET\"", "\"/v1/latest\"", ca, fast),
        route("broken", "\"GET\"", "\"/v1/**\"", UNLOADABLE_CA, fast),
        route("other", "\"GET\"", "\"/v1/**\"", ca, fast),
    ]
    .concat();
    format!(
        "[callers.agent]\nlistener = \"local\"\ntoken_hash = \"{hash}\"\nroutes = [\"fx\", \"slow\", \"narrow\", \"broken\"]\n\n{routes}"
    )
}

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

fn signed(method: &str, target: &str) -> CallerRequest {
    CallerRequest::new(method, target).signed(Via::Unix)
}

fn keys(event: &serde_json::Value) -> BTreeSet<&str> {
    event.as_object().unwrap().keys().map(String::as_str).collect()
}

/// Checks the fields every failure event has, and returns the event.
fn assert_failure(event: &serde_json::Value, status: u64, reason: &str) {
    assert_eq!(event["event"], "request.completed", "{event}");
    assert_eq!(event["level"], "INFO", "{event}");
    assert_eq!(
        (event["outcome"].as_str(), event["reason"].as_str()),
        (Some("failure"), Some(reason)),
        "{event}"
    );
    assert_eq!(event["status"].as_u64(), Some(status), "{event}");
    assert_eq!(event["listener"], "local", "{event}");
    assert!(
        event["request_id"].is_string() && event["request_bytes"].is_u64() && event["duration_ms"].is_u64(),
        "{event}"
    );
}

/// The fields that name who asked for what; each present only once it is known.
fn identity(event: &serde_json::Value) -> [Option<&str>; 4] {
    ["caller", "route", "credential", "upstream_host"].map(|key| event[key].as_str())
}

#[tokio::test]
async fn an_admission_refusal_names_the_unavailable_reason_and_nothing_about_the_caller() {
    let (_guard, log) = capture();
    let ca = TestCa::new("proxy test CA");
    let upstream = MockUpstream::start(&ca, Reply::Stall).await;
    let proxy = start(&ca, upstream.port(), 30).await;
    let expected = [
        (UnavailableReason::Locked, "locked"),
        (UnavailableReason::PolicyInvalid, "policy_invalid"),
        (UnavailableReason::Checking, "checking"),
        (UnavailableReason::RecoveryNeeded, "recovery_needed"),
    ];
    for (reason, label) in expected {
        proxy.holder().refuse(reason);
        assert_eq!(proxy.get("/fx/latest").await.status, 503);
        let event = log.the_request_event().await;
        assert_failure(&event, 503, label);
        assert_eq!(identity(&event), [None; 4], "{event}");
        assert_eq!(event["http_method"], "GET");
        log.clear();
    }
}

#[tokio::test]
async fn pipeline_refusals_name_the_reason_and_what_was_known_by_then() {
    let (_guard, log) = capture();
    let ca = TestCa::new("proxy test CA");
    let upstream = MockUpstream::start(&ca, Reply::Stall).await;
    let proxy = start(&ca, upstream.port(), 30).await;
    let endpoints = proxy.endpoints();
    let anonymous = CallerRequest::get("/fx/latest");
    let cases = [
        (anonymous, 401, "unauthenticated", [None; 4]),
        (signed("GET", "/nowhere"), 404, "no_route", [Some("agent"), None, None, None]),
        (
            signed("GET", "/other/latest"),
            403,
            "not_granted",
            [Some("agent"), Some("other"), Some("fx_key"), Some("localhost")],
        ),
        (
            signed("POST", "/fx/latest"),
            403,
            "method_not_allowed",
            [Some("agent"), Some("fx"), Some("fx_key"), Some("localhost")],
        ),
        (
            signed("GET", "/narrow/elsewhere"),
            403,
            "path_not_allowed",
            [Some("agent"), Some("narrow"), Some("fx_key"), Some("localhost")],
        ),
        (signed("GET", "/fx/../narrow"), 400, "bad_target", [Some("agent"), None, None, None]),
        (
            signed("GET", "/broken/latest"),
            503,
            "route_unavailable",
            [Some("agent"), Some("broken"), Some("fx_key"), Some("localhost")],
        ),
    ];
    for (request, status, reason, who) in cases {
        endpoints.send(Via::Unix, &request).await;
        let event = log.the_request_event().await;
        assert_failure(&event, status, reason);
        assert_eq!(identity(&event), who, "{reason}: {event}");
        log.clear();
    }
    assert!(upstream.requests().is_empty());
}

#[tokio::test]
async fn a_rate_limited_request_is_recorded_with_its_route() {
    let (_guard, log) = capture();
    let ca = TestCa::new("proxy test CA");
    let upstream = MockUpstream::start(
        &ca,
        Reply::Respond {
            status: 200,
            headers: vec![],
            body: b"ok".to_vec(),
        },
    )
    .await;
    let proxy = start(&ca, upstream.port(), 30).await;
    assert_eq!(proxy.get("/slow/latest").await.status, 200);
    log.clear();

    assert_eq!(proxy.get("/slow/latest").await.status, 429);

    let event = log.the_request_event().await;
    assert_failure(&event, 429, "rate_limited");
    assert_eq!(identity(&event), [Some("agent"), Some("slow"), Some("fx_key"), Some("localhost")]);
}

#[tokio::test]
async fn an_unreachable_upstream_is_upstream_connect_with_the_enrolled_host_only() {
    let (_guard, log) = capture();
    let ca = TestCa::new("proxy test CA");
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let proxy = start(&ca, port, 30).await;

    assert_eq!(proxy.get("/fx/latest?base=USD").await.status, 502);

    let event = log.the_request_event().await;
    assert_failure(&event, 502, "upstream_connect");
    assert_eq!(identity(&event), [Some("agent"), Some("fx"), Some("fx_key"), Some("localhost")]);
    assert!(
        !log.text().contains(&port.to_string()),
        "the upstream port reached the log: {}",
        log.text()
    );
}

#[tokio::test]
async fn an_upstream_that_never_answers_is_upstream_timeout() {
    let (_guard, log) = capture();
    let ca = TestCa::new("proxy test CA");
    let upstream = MockUpstream::start(&ca, Reply::Stall).await;
    let proxy = start(&ca, upstream.port(), 1).await;

    assert_eq!(proxy.get("/fx/latest").await.status, 504);

    assert_failure(&log.the_request_event().await, 504, "upstream_timeout");
}

#[tokio::test]
async fn a_snapshot_withdrawn_before_the_head_is_withdrawn() {
    let (_guard, log) = capture();
    let ca = TestCa::new("proxy test CA");
    let upstream = MockUpstream::start(&ca, Reply::Stall).await;
    let proxy = start(&ca, upstream.port(), 30).await;
    let endpoints = proxy.endpoints();
    let waiting = tokio::spawn(async move { endpoints.send(Via::Unix, &signed("GET", "/fx/latest")).await });
    while upstream.requests().is_empty() {
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }

    proxy.holder().refuse(UnavailableReason::Locked);
    assert_eq!(waiting.await.unwrap().status, 503);

    let event = log.the_request_event().await;
    assert_failure(&event, 503, "withdrawn");
    assert_eq!(identity(&event), [Some("agent"), Some("fx"), Some("fx_key"), Some("localhost")]);
}

#[tokio::test]
async fn two_requests_get_different_ids() {
    let (_guard, log) = capture();
    let ca = TestCa::new("proxy test CA");
    let upstream = MockUpstream::start(&ca, Reply::Stall).await;
    let proxy = start(&ca, upstream.port(), 30).await;

    proxy.get("/nowhere").await;
    proxy.get("/nowhere").await;

    let ids: BTreeSet<_> = log
        .request_events()
        .iter()
        .map(|event| event["request_id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(ids.len(), 2);
}

#[tokio::test]
async fn no_token_query_or_header_value_reaches_the_record() {
    let (_guard, log) = capture();
    let ca = TestCa::new("proxy test CA");
    let upstream = MockUpstream::start(&ca, Reply::Stall).await;
    let proxy = start(&ca, upstream.port(), 30).await;
    let request = signed("GET", "/narrow/elsewhere?key=QUERYSECRET").header("X-Custom", "HEADERVALUE");

    proxy.endpoints().send(Via::Unix, &request).await;

    let event = log.the_request_event().await;
    assert_failure(&event, 403, "path_not_allowed");
    let text = log.text();
    [
        token().as_str(),
        "QUERYSECRET",
        "HEADERVALUE",
        "elsewhere",
        "/v1",
        "https://",
        SECRET,
    ]
    .iter()
    .for_each(|forbidden| assert!(!text.contains(forbidden), "{forbidden} reached the log: {text}"));
    let expected = [
        "timestamp",
        "level",
        "target",
        "message",
        "event",
        "service",
        "service_version",
        "schema_version",
        "deployment_profile",
        "request_id",
        "listener",
        "http_method",
        "caller",
        "route",
        "credential",
        "upstream_host",
        "status",
        "request_bytes",
        "response_bytes",
        "duration_ms",
        "outcome",
        "reason",
    ];
    assert_eq!(keys(&event), expected.into_iter().collect(), "{event}");
}

#[tokio::test]
async fn a_request_body_is_never_logged() {
    let (_guard, log) = capture();
    let ca = TestCa::new("proxy test CA");
    let upstream = MockUpstream::start(&ca, Reply::Stall).await;
    let proxy = start(&ca, upstream.port(), 30).await;
    let request = CallerRequest::post("/fx/latest", b"BODYSECRET").signed(Via::Unix);

    proxy.endpoints().send(Via::Unix, &request).await;

    let event = log.the_request_event().await;
    assert_failure(&event, 403, "method_not_allowed");
    assert!(!log.text().contains("BODYSECRET"));
    assert!(log.audit_events("request.defect").is_empty());
}
