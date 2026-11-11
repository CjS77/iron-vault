//! What leaves the service, observed at a recording TLS upstream (specification §19 first two v0 release checks, implementation spec §2).
//!
//! The real request server, pipeline and upstream client run behind a Unix request socket and a loopback TCP listener,
//! configured from the §6 FX/Brave/Venice example plus a Basic route, each with a recognisable test secret. Checking
//! only the constructed URL is not enough (implementation spec §2), so each test reads the request head and body the upstream received.
//!
//! A refused request must leave no trace upstream: the negative tests assert the upstream accepted no TCP connection at
//! all, which is stronger than recording no request.
//!
//! A mismatched final URL cannot be produced through the public API, because the pipeline builds the URL structurally
//! and re-checks it. The final check's refusals are covered by `a_final_check_failure_raises_a_high_severity_event_without_secrets`
//! and `every_variant_has_its_status_body_and_headers` in `src/pipeline/tests/refusal.rs` (K-100), and by the
//! `a_host_other_than_the_upstreams_is_refused` family in `iron-vault-policy/src/final_check/tests.rs`.

#![cfg(target_os = "linux")]

use crate::common;

use std::sync::Arc;

use common::mock_upstream::{MockUpstream, RecordedRequest, Reply, TestCa};
use common::mock_upstream_h2::{H2Reply, MockH2Upstream};
use common::proxy_harness::{CallerRequest, Credential, Proxy, RefusingPort, Response, Setup, TOKEN_BYTES, Via, token_hash};
use iron_vault_kinds::CredentialMaterial;

const FX_SECRET: &str = "fx-secret-3a7d91";
const BRAVE_SECRET: &str = "brave-secret-51c9e2";
const VENICE_SECRET: &str = "venice-secret-b20e44";
const BILLING_USER: &str = "alice";
const BILLING_PASSWORD: &str = "billing-pw-77";
/// `base64("alice:billing-pw-77")`.
const BILLING_BASIC: &str = "YWxpY2U6YmlsbGluZy1wdy03Nw==";
const ALL_SECRETS: [&str; 4] = [FX_SECRET, BRAVE_SECRET, VENICE_SECRET, BILLING_PASSWORD];

/// The token of `brave-only`, which holds a grant of one route.
const NARROW_TOKEN: [u8; 32] = [8; 32];
/// The §6 `burst` of the `quota` route, and how many requests beyond it a test sends.
const QUOTA_BURST: usize = 5;
const EXTRA_REQUESTS: usize = 7;

/// The §6 example's routes with each upstream moved to its test port, plus `billing` (Basic) and `quota`. `quota`
/// refills a token every ten seconds, so a test that spends its burst sees no refill; it shares `fx`'s upstream.
fn callers_and_routes(ports: &Ports) -> String {
    let (hash, narrow, ca) = (token_hash(TOKEN_BYTES), token_hash(NARROW_TOKEN), "/etc/iron-vault/ca/test.pem");
    let Ports {
        fx,
        brave,
        venice,
        billing,
    } = ports;
    format!(
        r#"[callers.agent]
listener = "local"
token_hash = "{hash}"
routes = ["fx", "venice", "brave", "billing", "quota"]

[callers.brave-only]
listener = "local"
token_hash = "{narrow}"
routes = ["brave"]

[callers.brave-cli]
listener = "loopback"
token_hash = "{hash}"
routes = ["brave", "fx"]

[routes.fx]
prefix = "/fx"
upstream = "https://localhost:{fx}"
ca_file = "{ca}"
credential = "fx_key"
slot = {{ query = "access_key" }}
methods = ["GET"]
paths = ["/latest", "/historical/**"]
rate_limit = {{ requests = 60, per_seconds = 60, burst = 10 }}

[routes.venice]
prefix = "/venice"
upstream = "https://localhost:{venice}/api/v1"
ca_file = "{ca}"
credential = "venice"
slot = {{ header = "Authorization", format = "Bearer {{}}" }}
methods = ["POST"]
paths = ["/chat/completions"]
rate_limit = {{ requests = 120, per_seconds = 60, burst = 20 }}

[routes.brave]
prefix = "/brave"
upstream = "https://localhost:{brave}"
ca_file = "{ca}"
credential = "brave"
slot = {{ header = "X-Subscription-Token" }}
methods = ["GET"]
paths = ["/res/v1/web/search"]
rate_limit = {{ requests = 60, per_seconds = 60, burst = 10 }}

[routes.billing]
prefix = "/billing"
upstream = "https://localhost:{billing}"
ca_file = "{ca}"
credential = "billing"
slot = "basic"
methods = ["GET"]
paths = ["/**"]
rate_limit = {{ requests = 60, per_seconds = 60, burst = 10 }}

[routes.quota]
prefix = "/quota"
upstream = "https://localhost:{fx}"
ca_file = "{ca}"
credential = "fx_key"
slot = {{ query = "access_key" }}
methods = ["GET"]
paths = ["/latest"]
rate_limit = {{ requests = 6, per_seconds = 60, burst = {QUOTA_BURST} }}
"#
    )
}

/// The port each upstream listens on.
#[derive(Clone, Copy)]
struct Ports {
    fx: u16,
    brave: u16,
    venice: u16,
    billing: u16,
}

fn credentials(ports: &Ports) -> Vec<Credential> {
    let static_key = |name, key: &str, port| Credential {
        name,
        material: CredentialMaterial::Static { key: key.into() },
        port,
    };
    let basic = CredentialMaterial::Basic {
        username: BILLING_USER.into(),
        password: BILLING_PASSWORD.into(),
    };
    vec![
        static_key("fx_key", FX_SECRET, ports.fx),
        static_key("brave", BRAVE_SECRET, ports.brave),
        static_key("venice", VENICE_SECRET, ports.venice),
        Credential {
            name: "billing",
            material: basic,
            port: ports.billing,
        },
    ]
}

/// The proxy over the four upstreams at `ports`, with a loopback TCP listener.
async fn proxy(ca: &TestCa, ports: Ports) -> Proxy {
    Proxy::start(Setup {
        ca,
        callers_and_routes: callers_and_routes(&ports),
        credentials: credentials(&ports),
        tcp: true,
        request_timeout_secs: 30,
        limits: "",
    })
    .await
}

/// One recording upstream for each provider.
struct Upstreams {
    fx: MockUpstream,
    brave: MockUpstream,
    venice: MockUpstream,
    billing: MockUpstream,
}

impl Upstreams {
    /// All four answer `200 ok`, except Venice, which answers with `venice`.
    async fn start(ca: &TestCa, venice: Reply) -> Self {
        Self {
            fx: MockUpstream::start(ca, Reply::ok("ok")).await,
            brave: MockUpstream::start(ca, Reply::ok("ok")).await,
            venice: MockUpstream::start(ca, venice).await,
            billing: MockUpstream::start(ca, Reply::ok("ok")).await,
        }
    }

    fn ports(&self) -> Ports {
        Ports {
            fx: self.fx.port(),
            brave: self.brave.port(),
            venice: self.venice.port(),
            billing: self.billing.port(),
        }
    }

    fn all(&self) -> [(&'static str, &MockUpstream); 4] {
        [
            ("fx", &self.fx),
            ("brave", &self.brave),
            ("venice", &self.venice),
            ("billing", &self.billing),
        ]
    }

    /// Asserts that `only` was the sole upstream the service contacted, and returns the one request it received.
    fn sole_request(&self, only: &str) -> RecordedRequest {
        self.all()
            .iter()
            .filter(|(name, _)| *name != only)
            .for_each(|(name, upstream)| assert_eq!(upstream.connections(), 0, "{name} was contacted"));
        let mut requests = self.all().iter().find(|(name, _)| *name == only).unwrap().1.requests();
        assert_eq!(requests.len(), 1, "{only} received {requests:?}");
        requests.remove(0)
    }

    /// Asserts that no upstream accepted a connection.
    fn assert_untouched(&self, what: &str) {
        self.all()
            .iter()
            .for_each(|(name, upstream)| assert_eq!(upstream.connections(), 0, "{what}: {name} was contacted"));
    }
}

async fn start_all() -> (TestCa, Upstreams, Proxy) {
    let ca = TestCa::new("egress test CA");
    let upstreams = Upstreams::start(&ca, Reply::ok("ok")).await;
    let proxy = proxy(&ca, upstreams.ports()).await;
    (ca, upstreams, proxy)
}

/// How many times `text` holds `needle`.
fn count(text: &str, needle: &str) -> usize {
    text.matches(needle).count()
}

/// The request head, then the body, as one text: everything the upstream received.
fn wire_text(request: &RecordedRequest) -> String {
    format!("{}\r\n\r\n{}", request.head, String::from_utf8_lossy(&request.body))
}

fn header_values<'a>(headers: &'a [(String, String)], name: &str) -> Vec<&'a str> {
    headers.iter().filter(|(n, _)| n == name).map(|(_, v)| v.as_str()).collect()
}

/// A refused response names no provider secret.
fn assert_no_secret(response: &Response) {
    let text = format!("{:?}{}", response.headers, response.body);
    ALL_SECRETS
        .iter()
        .for_each(|secret| assert!(!text.contains(secret), "{secret} in {text}"));
}

// Positive: the credential goes to the enrolled origin and the selected slot, and nowhere else.

#[tokio::test]
async fn fx_query_slot_sends_the_credential_in_the_query_only() {
    let (_ca, upstreams, proxy) = start_all().await;

    let response = proxy.get("/fx/latest?base=USD").await;

    // Scrubbing may change the length, so the relayed body is chunked rather than framed by the upstream's length.
    assert_eq!((response.status, response.body.as_str()), (200, "2\r\nok\r\n0\r\n\r\n"));
    let sent = upstreams.sole_request("fx");
    assert_eq!(sent.request_line(), format!("GET /latest?base=USD&access_key={FX_SECRET} HTTP/1.1"));
    assert_eq!(count(&wire_text(&sent), FX_SECRET), 1, "{}", sent.head);
    assert_eq!(sent.server_name.as_deref(), Some("localhost"));
    assert_eq!(
        header_values(&sent.headers(), "host"),
        [format!("localhost:{}", upstreams.fx.port())]
    );
}

#[tokio::test]
async fn query_slot_replaces_every_caller_supplied_occurrence_of_the_parameter() {
    let (_ca, upstreams, proxy) = start_all().await;
    // The second value is the route's own marker, percent-encoded because a raw `{` is not valid in a request target.
    let target = "/fx/latest?access_key=stale&base=USD&access_key=%7Biv%3Afx_key%7D";

    let response = proxy.get(target).await;

    assert_eq!(response.status, 200);
    let sent = upstreams.sole_request("fx");
    assert_eq!(sent.request_line(), format!("GET /latest?base=USD&access_key={FX_SECRET} HTTP/1.1"));
    assert_eq!(count(&sent.head, "access_key"), 1, "{}", sent.head);
    assert!(!sent.head.contains("stale"), "{}", sent.head);
}

#[tokio::test]
async fn brave_header_slot_sends_the_credential_in_its_header_exactly_once() {
    let (_ca, upstreams, proxy) = start_all().await;
    // Both caller-supplied copies go, whatever their case: the first is the route's own marker, the second a stale value.
    let request = CallerRequest::get("/brave/res/v1/web/search?q=rust")
        .header("X-Subscription-Token", "{iv:brave}")
        .header("x-subscription-token", "stale-copy")
        .signed(Via::Unix);

    let response = proxy.endpoints().send(Via::Unix, &request).await;

    assert_eq!(response.status, 200);
    let sent = upstreams.sole_request("brave");
    assert_eq!(sent.request_line(), "GET /res/v1/web/search?q=rust HTTP/1.1");
    assert_eq!(header_values(&sent.headers(), "x-subscription-token"), [BRAVE_SECRET]);
    assert_eq!(count(&wire_text(&sent), BRAVE_SECRET), 1, "{}", sent.head);
    assert!(!sent.head.contains("stale-copy"), "{}", sent.head);
    assert!(sent.headers().iter().all(|(name, _)| name != "x-iron-vault-token"), "{}", sent.head);
}

#[tokio::test]
async fn a_token_caller_on_the_loopback_listener_reaches_its_route() {
    let (_ca, upstreams, proxy) = start_all().await;
    let request = CallerRequest::get("/brave/res/v1/web/search?q=rust").signed(Via::Tcp);

    let response = proxy.endpoints().send(Via::Tcp, &request).await;

    assert_eq!(response.status, 200);
    let sent = upstreams.sole_request("brave");
    assert_eq!(header_values(&sent.headers(), "x-subscription-token"), [BRAVE_SECRET]);
    assert!(
        sent.headers().iter().all(|(name, _)| name != "proxy-authorization"),
        "{}",
        sent.head
    );
}

#[tokio::test]
async fn brave_over_http2_sends_the_credential_to_the_enrolled_authority_only() {
    let ca = TestCa::new("egress test CA");
    let brave = MockH2Upstream::start(&ca, H2Reply::ok("ok")).await;
    // The other upstreams are never reached; their ports refuse connections and are held so nothing else can take them.
    let [fx, venice, billing] = std::array::from_fn(|_| RefusingPort::bind());
    let ports = Ports {
        fx: fx.port(),
        brave: brave.port(),
        venice: venice.port(),
        billing: billing.port(),
    };
    let proxy = proxy(&ca, ports).await;

    let response = proxy.get("/brave/res/v1/web/search?q=rust").await;

    assert_eq!(response.status, 200);
    let [sent] = <[_; 1]>::try_from(brave.requests()).unwrap();
    assert_eq!(sent.alpn.as_deref(), Some(&b"h2"[..]));
    assert_eq!(sent.authority.as_deref(), Some(format!("localhost:{}", brave.port()).as_str()));
    assert_eq!(sent.path.as_deref(), Some("/res/v1/web/search?q=rust"));
    assert_eq!(header_values(&sent.headers, "x-subscription-token"), [BRAVE_SECRET]);
    let carriers = sent.headers.iter().filter(|(_, value)| value.contains(BRAVE_SECRET)).count();
    assert_eq!(carriers, 1, "{:?}", sent.headers);
    assert!(!sent.path.unwrap().contains(BRAVE_SECRET));
}

#[tokio::test]
async fn venice_bearer_slot_forwards_the_post_body_byte_for_byte_and_streams_the_reply() {
    let ca = TestCa::new("egress test CA");
    let gate = Arc::new(tokio::sync::Notify::new());
    let streamed = Reply::TwoChunks {
        first: "data: {\"delta\":\"he\"}\n\n".to_owned(),
        second: "data: [DONE]\n\n".to_owned(),
        gate: Arc::clone(&gate),
    };
    // The permit is stored, so the upstream's second chunk is not held back; the relay still sends it as its own chunk.
    gate.notify_one();
    let upstreams = Upstreams::start(&ca, streamed).await;
    let proxy = proxy(&ca, upstreams.ports()).await;
    // Odd spacing, a non-ASCII character, and a marker for another credential in the body: nothing here may change.
    let body =
        "{ \"model\" : \"m\",\n\t\"messages\":[{\"role\":\"user\",\"content\":\"caf\u{e9} {iv:other} {iv:venice}\"}],\"stream\":true }\n";
    let request = CallerRequest::post("/venice/chat/completions", body.as_bytes())
        .header("Content-Type", "application/json")
        .header("Authorization", "Bearer placeholder")
        .signed(Via::Unix);

    let response = proxy.endpoints().send(Via::Unix, &request).await;

    assert_eq!(response.status, 200);
    assert_eq!(response.header("transfer-encoding"), Some("chunked"));
    assert!(response.body.contains("data: {\"delta\":\"he\"}\n\n"), "{}", response.body);
    assert!(response.body.contains("data: [DONE]\n\n"), "{}", response.body);
    assert!(response.body.ends_with("0\r\n\r\n"), "{}", response.body);
    let sent = upstreams.sole_request("venice");
    assert_eq!(sent.request_line(), "POST /api/v1/chat/completions HTTP/1.1");
    assert_eq!(sent.body, body.as_bytes());
    assert!(sent.body_complete);
    assert_eq!(header_values(&sent.headers(), "authorization"), [format!("Bearer {VENICE_SECRET}")]);
    assert_eq!(header_values(&sent.headers(), "content-type"), ["application/json"]);
    assert_eq!(count(&wire_text(&sent), VENICE_SECRET), 1, "{}", sent.head);
}

#[tokio::test]
async fn basic_slot_replaces_the_callers_authorization_with_one_basic_value() {
    let (_ca, upstreams, proxy) = start_all().await;
    let request = CallerRequest::get("/billing/v1/invoices")
        .header("Authorization", "Bearer callers-own-credential")
        .header("authorization", "Basic cGxhY2Vob2xkZXI6cGxhY2Vob2xkZXI=")
        .signed(Via::Unix);

    let response = proxy.endpoints().send(Via::Unix, &request).await;

    assert_eq!(response.status, 200);
    let sent = upstreams.sole_request("billing");
    assert_eq!(sent.request_line(), "GET /v1/invoices HTTP/1.1");
    assert_eq!(header_values(&sent.headers(), "authorization"), [format!("Basic {BILLING_BASIC}")]);
    ["callers-own-credential", "cGxhY2Vob2xkZXI", BILLING_PASSWORD]
        .iter()
        .for_each(|text| {
            assert!(!wire_text(&sent).contains(text), "{text} in {}", sent.head);
        });
}

// Negative: no credentialed egress, and no connection to any upstream at all.

#[tokio::test]
async fn a_missing_or_wrong_token_is_401() {
    let (_ca, upstreams, proxy) = start_all().await;
    let target = "/brave/res/v1/web/search?q=rust";
    let (unix, tcp) = (Via::Unix, Via::Tcp);
    let requests = [
        (unix, CallerRequest::get(target)),
        (unix, CallerRequest::get(target).with_token(unix, [9; 32])),
        (unix, CallerRequest::get(target).header("X-Iron-Vault-Token", "not-a-token")),
        (unix, CallerRequest::get(target).header("X-Iron-Vault-Token", "")),
        // The Unix listener reads its dedicated header only; a bearer token there is not its credential.
        (unix, CallerRequest::get(target).with_token(tcp, TOKEN_BYTES)),
        (tcp, CallerRequest::get(target)),
        (tcp, CallerRequest::get(target).with_token(tcp, [9; 32])),
        (tcp, CallerRequest::get(target).with_token(unix, TOKEN_BYTES)),
    ];

    let endpoints = proxy.endpoints();
    for (via, request) in &requests {
        let response = endpoints.send(*via, request).await;
        assert_eq!((response.status, response.body.as_str()), (401, "unauthorized"), "{request:?}");
        assert_no_secret(&response);
    }

    upstreams.assert_untouched("unauthenticated");
}

#[tokio::test]
async fn a_route_the_caller_is_not_granted_is_403() {
    let (_ca, upstreams, proxy) = start_all().await;
    let narrow = |target: &str| CallerRequest::get(target).with_token(Via::Unix, NARROW_TOKEN);
    let requests = [
        narrow("/fx/latest?base=USD"),
        narrow("/venice/chat/completions"),
        narrow("/billing/v1/invoices"),
        // Granted route, but a path outside its allowlist.
        narrow("/brave/res/v1/web/other"),
        // Granted route and path, but a method outside its allowlist.
        CallerRequest::new("POST", "/brave/res/v1/web/search").with_token(Via::Unix, NARROW_TOKEN),
        CallerRequest::new("DELETE", "/brave/res/v1/web/search").with_token(Via::Unix, NARROW_TOKEN),
    ];

    for request in &requests {
        let response = proxy.endpoints().send(Via::Unix, request).await;
        assert_eq!((response.status, response.body.as_str()), (403, "forbidden"), "{request:?}");
        assert_no_secret(&response);
    }

    upstreams.assert_untouched("ungranted");
}

#[tokio::test]
async fn a_prefix_no_route_has_is_404() {
    let (_ca, upstreams, proxy) = start_all().await;
    // Lookalikes of `/fx` match on whole segments only (§9).
    let targets = [
        "/nowhere/latest",
        "/",
        "/fx.evil.example/latest",
        "/fx@evil.example/latest",
        "/fxa/latest",
        "/FX/latest",
    ];

    for target in targets {
        let response = proxy.get(target).await;
        assert_eq!((response.status, response.body.as_str()), (404, "not found"), "{target}");
        assert_no_secret(&response);
    }

    upstreams.assert_untouched("unknown prefix");
}

#[tokio::test]
async fn hostile_paths_are_400_before_any_upstream_work() {
    let (_ca, upstreams, proxy) = start_all().await;
    // A handful of the `hostile_paths.rs` families: dot segments, mixed-case and double-encoded dots, encoded and raw
    // separators, NUL, a malformed escape and repeated empty segments, each under a granted prefix.
    let targets = [
        "/fx/../brave/res/v1/web/search",
        "/fx/./latest",
        "/fx/%2e%2e/latest",
        "/fx/%2E%2e/latest",
        "/fx/%252e%252e/latest",
        "/fx/historical/..%2Flatest",
        "/fx/historical/%2f%2e%2e%2flatest",
        "/fx/historical/..%5Clatest",
        "/fx/historical/a%5cb",
        "/fx/historical/a%00b",
        "/fx/historical/%zz",
        "/fx/historical//a//b",
        "/brave/res/v1/web/search/..;/x",
    ];

    for target in targets {
        let response = proxy.get(target).await;
        assert_eq!((response.status, response.body.as_str()), (400, "bad request"), "{target}");
        assert_no_secret(&response);
    }

    upstreams.assert_untouched("hostile path");
}

#[tokio::test]
async fn an_absolute_form_or_authority_form_target_is_refused_before_any_upstream_work() {
    let (_ca, upstreams, proxy) = start_all().await;
    let requests = [
        CallerRequest::get("http://evil.example/fx/latest"),
        CallerRequest::get("https://localhost/brave/res/v1/web/search"),
        CallerRequest::new("CONNECT", "evil.example:443"),
    ];

    for request in requests {
        let response = proxy.endpoints().send(Via::Unix, &request.signed(Via::Unix)).await;
        assert_eq!(response.status, 400);
        assert_no_secret(&response);
    }

    upstreams.assert_untouched("non-origin-form target");
}

#[tokio::test]
async fn override_rewrite_and_forwarding_headers_are_stripped_not_refused() {
    let (_ca, upstreams, proxy) = start_all().await;
    let stripped = [
        ("X-HTTP-Method-Override", "DELETE"),
        ("X-Method-Override", "DELETE"),
        ("X-HTTP-Method", "DELETE"),
        ("X-Original-URL", "/admin"),
        ("X-Rewrite-URL", "/admin"),
        ("Forwarded", "for=203.0.113.9;host=evil.example"),
        ("X-Forwarded-For", "203.0.113.9"),
        ("X-Forwarded-Host", "evil.example"),
        ("X-Hop", "1"),
        ("Connection", "x-hop"),
    ];
    let request = stripped
        .iter()
        .fold(CallerRequest::get("/brave/res/v1/web/search?q=rust"), |request, (name, value)| {
            request.header(name, value)
        })
        .header("Host", "evil.example")
        .signed(Via::Unix);

    let response = proxy.endpoints().send(Via::Unix, &request).await;

    assert_eq!(response.status, 200);
    let sent = upstreams.sole_request("brave");
    assert_eq!(sent.request_line(), "GET /res/v1/web/search?q=rust HTTP/1.1");
    let names: Vec<_> = sent.headers().into_iter().map(|(name, _)| name).collect();
    stripped.iter().filter(|(name, _)| *name != "Connection").for_each(|(name, _)| {
        assert!(
            !names.contains(&name.to_ascii_lowercase()),
            "{name} reached the upstream: {}",
            sent.head
        )
    });
    assert!(
        !sent.head.contains("evil.example") && !sent.head.contains("203.0.113.9"),
        "{}",
        sent.head
    );
    assert_eq!(
        header_values(&sent.headers(), "host"),
        [format!("localhost:{}", upstreams.brave.port())]
    );
}

#[tokio::test]
async fn a_marker_naming_another_credential_in_the_slot_is_400() {
    let (_ca, upstreams, proxy) = start_all().await;
    let requests = [
        // Header slot, header slot with a format, query slot (percent-encoded), and a marker that does not parse.
        CallerRequest::get("/brave/res/v1/web/search").header("X-Subscription-Token", "{iv:other}"),
        CallerRequest::get("/brave/res/v1/web/search").header("X-Subscription-Token", "{iv:fx_key}"),
        CallerRequest::get("/brave/res/v1/web/search").header("X-Subscription-Token", "{iv:brave} {iv:other}"),
        CallerRequest::get("/brave/res/v1/web/search").header("X-Subscription-Token", "{iv:"),
        CallerRequest::post("/venice/chat/completions", b"{}").header("Authorization", "Bearer {iv:other}"),
        CallerRequest::get("/fx/latest?access_key=%7Biv%3Aother%7D"),
    ];

    for request in requests {
        let response = proxy.endpoints().send(Via::Unix, &request.clone().signed(Via::Unix)).await;
        assert_eq!((response.status, response.body.as_str()), (400, "bad request"), "{request:?}");
        assert_no_secret(&response);
    }

    upstreams.assert_untouched("foreign marker");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_requests_cannot_exceed_a_bucket() {
    let (_ca, upstreams, proxy) = start_all().await;
    let endpoints = proxy.endpoints();
    let request = CallerRequest::get("/quota/latest").signed(Via::Unix);

    let sends = (0..QUOTA_BURST + EXTRA_REQUESTS).map(|_| {
        let (endpoints, request) = (endpoints.clone(), request.clone());
        tokio::spawn(async move { endpoints.send(Via::Unix, &request).await })
    });
    let mut responses = Vec::new();
    for send in sends.collect::<Vec<_>>() {
        responses.push(send.await.unwrap());
    }

    let statuses = |wanted: u16| responses.iter().filter(|response| response.status == wanted).collect::<Vec<_>>();
    assert_eq!(
        statuses(200).len(),
        QUOTA_BURST,
        "{:?}",
        responses.iter().map(|r| r.status).collect::<Vec<_>>()
    );
    let limited = statuses(429);
    assert_eq!(limited.len(), EXTRA_REQUESTS);
    limited.iter().for_each(|response| {
        assert!(
            response
                .header("retry-after")
                .is_some_and(|secs| secs.parse::<u64>().is_ok_and(|s| s > 0)),
            "{:?}",
            response.headers
        );
        assert_no_secret(response);
    });
    // The upstream saw exactly the admitted requests: a refused one is stopped before the credential is resolved.
    assert_eq!(upstreams.fx.requests().len(), QUOTA_BURST);
    assert_eq!(upstreams.fx.connections(), QUOTA_BURST);
    assert!(upstreams.fx.requests().iter().all(|sent| count(&sent.head, FX_SECRET) == 1));
}
