// SPDX-License-Identifier: MPL-2.0
//! The fourth v0 release check (specification §19): "Rate limits and path/method restrictions apply under concurrency;
//! unavailable touch requirements never degrade to unconfirmed access."
//!
//! Requests race on one route, two callers share one route's bucket, and an approval narrows a route while requests run.
//! A recording upstream shows what left the service: each request target carries an index, so every recorded request is
//! matched to the request the test sent and to the answer that caller got. A config with a touch route goes through
//! `config approve` and through a start; it is refused when read, and its route never reaches the upstream.
//!
//! The first two tests serve a snapshot from [`Proxy`], whose buckets start full; the last three run the service from
//! [`Fixture`], whose buckets start empty at each config check, as a real service's do.

#![cfg(target_os = "linux")]

use crate::common;

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use common::approval_harness::{APPROVAL_PASSPHRASE, Fixture, approve, get, identity, send_request, state_dir_lock, versions};
use common::mock_upstream::{MockUpstream, Reply, TestCa};
use common::proxy_harness::{CallerRequest, Credential, Proxy, Response, Setup, TOKEN_BYTES, TOKEN_HEADER, Via, token_hash};
use iron_vault::admin::protocol::{AdminResponse, ErrorCode};
use iron_vault::service_state::{FailureReason, ServiceState};
use iron_vault_kinds::CredentialMaterial;
use iron_vault_store::{OsFs, Vault};

const CA_FILE: &str = "/etc/iron-vault/ca/test.pem";
/// A bucket no test can spend for long: it refills 100 000 tokens a second. In the [`Fixture`] tests it starts empty
/// after each approval, so a request in the first moments after one can still be limited.
const GENEROUS: &str = "{ requests = 100000, per_seconds = 1, burst = 100000 }";

/// One request a caller sends: a method and a path below the route prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Case {
    method: &'static str,
    path: &'static str,
}

impl Case {
    const fn new(method: &'static str, path: &'static str) -> Self {
        Self { method, path }
    }

    /// The caller's request on `prefix`, its target ending in `tag` so the upstream's record names it.
    fn request(self, prefix: &str, tag: &str) -> CallerRequest {
        CallerRequest::new(self.method, &format!("/{prefix}/{}/{tag}", self.path)).signed(Via::Unix)
    }

    /// The request line the upstream records for this case sent with `tag`, the prefix stripped.
    fn upstream_line(self, tag: &str) -> String {
        format!("{} /{}/{tag} HTTP/1.1", self.method, self.path)
    }
}

/// A proxy over one recording upstream, serving `callers_and_routes`, whose routes forward to `https://localhost:{port}`
/// with the credential `api_key`.
async fn proxy_over(ca: &TestCa, upstream: &MockUpstream, callers_and_routes: String) -> Proxy {
    let credentials = vec![Credential {
        name: "api_key",
        material: CredentialMaterial::Static { key: "api-secret".into() },
        port: upstream.port(),
    }];
    Proxy::start(Setup {
        ca,
        callers_and_routes,
        credentials,
        tcp: false,
        request_timeout_secs: 30,
        limits: "",
    })
    .await
}

/// The route `name` at `/{name}` on the upstream at `port`.
fn route(name: &str, port: u16, methods: &str, paths: &str, rate_limit: &str) -> String {
    format!(
        r#"
[routes.{name}]
prefix = "/{name}"
upstream = "https://localhost:{port}"
ca_file = "{CA_FILE}"
credential = "api_key"
slot = {{ header = "X-Api-Key" }}
methods = {methods}
paths = {paths}
rate_limit = {rate_limit}
"#
    )
}

/// The token caller `name` on the Unix listener `local`, granted `routes`.
fn caller(name: &str, token: [u8; 32], routes: &str) -> String {
    format!(
        "\n[callers.{name}]\nlistener = \"local\"\ntoken_hash = \"{}\"\nroutes = {routes}\n",
        token_hash(token)
    )
}

/// How many connections the tests hold open at once. More than this many concurrent connects can find the request
/// socket's accept queue full, which a Unix socket answers with `EAGAIN` rather than a wait.
const LANES: usize = 8;

/// Sends `requests` from [`LANES`] tasks at once, lane `n` taking every `LANES`th request in turn, and returns each
/// request's index and answer.
async fn send_all(proxy: &Proxy, requests: Vec<CallerRequest>) -> Vec<(usize, Response)> {
    let requests = Arc::new(requests);
    let lanes: Vec<_> = (0..LANES)
        .map(|lane| {
            let (endpoints, requests) = (proxy.endpoints(), Arc::clone(&requests));
            tokio::spawn(async move {
                let mut answers = Vec::new();
                for i in (lane..requests.len()).step_by(LANES) {
                    answers.push((i, endpoints.send(Via::Unix, &requests[i]).await));
                }
                answers
            })
        })
        .collect();
    let mut answers = Vec::new();
    for lane in lanes {
        answers.extend(lane.await.unwrap());
    }
    answers
}

/// The mixed test's cases: one allowed, then a forbidden path, a forbidden method, and both.
const MIXED: [Case; 4] = [
    Case::new("GET", "allowed"),
    Case::new("GET", "denied"),
    Case::new("DELETE", "allowed"),
    Case::new("POST", "denied"),
];
/// How many requests the mixed test sends: sixteen of each case.
const MIXED_REQUESTS: usize = 64;

/// §19: "Rate limits and path/method restrictions apply under concurrency; unavailable touch requirements never degrade
/// to unconfirmed access."
///
/// Sixty-four requests in a shuffled mix of one allowed case and three forbidden ones race on one route, eight at a
/// time. Each forbidden request is refused with `403` (§15) and never reaches the upstream; the upstream records exactly
/// the allowed requests, one for each `200`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn allowed_and_forbidden_requests_racing_on_one_route_reach_the_upstream_only_when_allowed() {
    let ca = TestCa::new("restrictions test CA");
    let upstream = MockUpstream::start(&ca, Reply::ok("ok")).await;
    let routes = route("api", upstream.port(), r#"["GET"]"#, r#"["/allowed/**"]"#, GENEROUS);
    let proxy = proxy_over(&ca, &upstream, caller("agent", TOKEN_BYTES, r#"["api"]"#) + &routes).await;
    // 37 is coprime to 64, so `i * 37 % 64` permutes the indices; each quarter of the permutation is one case, so every case
    // is sent sixteen times, in no regular order.
    let quarter = MIXED_REQUESTS / MIXED.len();
    let cases: Vec<Case> = (0..MIXED_REQUESTS).map(|i| MIXED[(i * 37) % MIXED_REQUESTS / quarter]).collect();
    let requests = cases
        .iter()
        .enumerate()
        .map(|(i, case)| case.request("api", &i.to_string()))
        .collect();

    let answers = send_all(&proxy, requests).await;

    answers.iter().for_each(|(i, answer)| {
        let wanted = match cases[*i] == MIXED[0] {
            true => (200, "2\r\nok\r\n0\r\n\r\n"),
            false => (403, "forbidden"),
        };
        assert_eq!((answer.status, answer.body.as_str()), wanted, "{:?}", cases[*i]);
    });
    let allowed: BTreeSet<String> = (0..MIXED_REQUESTS)
        .filter(|i| cases[*i] == MIXED[0])
        .map(|i| MIXED[0].upstream_line(&i.to_string()))
        .collect();
    let recorded: Vec<String> = upstream.requests().iter().map(|sent| sent.request_line().to_owned()).collect();
    assert_eq!(recorded.len(), answers.iter().filter(|(_, answer)| answer.status == 200).count());
    assert_eq!(recorded.iter().cloned().collect::<BTreeSet<_>>(), allowed);
}

/// The token of the second caller on the shared route.
const SECOND_TOKEN: [u8; 32] = [9; 32];
/// The shared route's burst. It refills `SHARED_BURST` tokens a minute, so the proxy's minute of accounting fills it and
/// the next token comes thirty seconds after the first is spent: past [`WAIT`](common::WAIT), which bounds every request here.
const SHARED_BURST: usize = 2;
/// How many requests each caller sends.
const PER_CALLER: usize = 6;

/// §19: "Rate limits and path/method restrictions apply under concurrency; unavailable touch requirements never degrade
/// to unconfirmed access."
///
/// Two callers granted one route send at once. §8: "Rate limits apply to each route in aggregate across its callers",
/// and the configuration reference: "All the route's callers share its bucket." So the two together get the route's
/// burst, not one burst each, and the upstream receives no more requests than the bucket holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_callers_on_one_route_share_its_bucket() {
    let ca = TestCa::new("restrictions test CA");
    let upstream = MockUpstream::start(&ca, Reply::ok("ok")).await;
    let rate = format!("{{ requests = {SHARED_BURST}, per_seconds = 60, burst = {SHARED_BURST} }}");
    let config = [
        caller("first", TOKEN_BYTES, r#"["shared"]"#),
        caller("second", SECOND_TOKEN, r#"["shared"]"#),
        route("shared", upstream.port(), r#"["GET"]"#, r#"["/**"]"#, &rate),
    ]
    .concat();
    let proxy = proxy_over(&ca, &upstream, config).await;
    // The callers alternate, so neither can spend the bucket before the other starts.
    let requests = (0..2 * PER_CALLER)
        .map(|i| {
            let request = CallerRequest::get(&format!("/shared/r/{i}"));
            match i % 2 {
                0 => request.signed(Via::Unix),
                _ => request.with_token(Via::Unix, SECOND_TOKEN),
            }
        })
        .collect();

    let answers = send_all(&proxy, requests).await;

    let statuses: Vec<u16> = answers.iter().map(|(_, answer)| answer.status).collect();
    assert_eq!(
        statuses.iter().filter(|status| **status == 200).count(),
        SHARED_BURST,
        "{statuses:?}"
    );
    assert_eq!(
        statuses.iter().filter(|status| **status == 429).count(),
        2 * PER_CALLER - SHARED_BURST,
        "{statuses:?}"
    );
    assert_eq!(upstream.requests().len(), SHARED_BURST);
}

/// A route the reload test never narrows: its bucket refills one token an hour, so a burst it held could only have come
/// from the config check that built it.
const METERED: &str = "{ requests = 1, per_seconds = 3600, burst = 5 }";

/// The reload test's config: the token caller granted `api`, with `methods` and `paths`, and `metered`.
fn reload_config(fixture: &Fixture, methods: &str, paths: &str) -> String {
    let port = fixture.upstream().port();
    format!(
        "schema_version = 1\n\n[listeners.local]\nunix_socket = \"{}\"\ntoken_header = \"{TOKEN_HEADER}\"\n{}{}{}",
        fixture.socket().display(),
        caller("agent", TOKEN_BYTES, r#"["api", "metered"]"#),
        route("api", port, methods, paths, GENEROUS),
        route("metered", port, r#"["GET"]"#, r#"["/**"]"#, METERED),
    )
    .replace("credential = \"api_key\"", "credential = \"fx_key\"")
}

/// The reload test's cases: the old policy allows all but the last, the new one only the first, and neither the last.
const RELOAD: [Case; 5] = [
    NEW_ALLOWS,
    Case::new("POST", "a"),
    Case::new("GET", "b"),
    Case::new("POST", "b"),
    BOTH_FORBID,
];
/// The one reload case the new policy allows.
const NEW_ALLOWS: Case = Case::new("GET", "a");
/// The reload case neither policy allows: a method outside both.
const BOTH_FORBID: Case = Case::new("DELETE", "a");
const RELOAD_TASKS: usize = 4;

/// One request of the reload test: its case, its tag, whether it was sent after the approval returned, and its status.
struct Sent {
    case: Case,
    tag: String,
    after: bool,
    status: u16,
}

/// The statuses a reload case may get, sent `after` the approval returned or before it.
///
/// After it, only the new policy answers. Before it, the old policy, the admission pause's `503` or the new policy may:
/// the narrowing approval builds the `api` bucket empty, so a request admitted just after the pause may get `429`. A
/// case both policies forbid is refused at authorization, which runs before the charge, so it is never `200` or `429`.
fn permitted(case: Case, after: bool) -> &'static [u16] {
    match (after, case == NEW_ALLOWS, case == BOTH_FORBID) {
        (true, true, _) => &[200],
        (true, false, _) => &[403],
        (false, true, _) => &[200, 429, 503],
        (false, false, false) => &[200, 403, 429, 503],
        (false, false, true) => &[403, 503],
    }
}

/// Task `task` sends the reload cases in rounds, signalling `started` after its first round, until a round that began
/// after `reloaded` was set has ended. A request is tagged `post` when the flag was set before it was sent.
async fn send_rounds(socket: &Path, task: usize, reloaded: &AtomicBool, started: tokio::sync::mpsc::Sender<()>) -> Vec<Sent> {
    let mut sent = Vec::new();
    for round in 0.. {
        let last = reloaded.load(Ordering::SeqCst);
        for case in RELOAD {
            let after = reloaded.load(Ordering::SeqCst);
            let tag = format!("{task}-{round}-{}", if after { "post" } else { "pre" });
            let status = send_request(socket, &case.request("api", &tag)).await.status;
            sent.push(Sent { case, tag, after, status });
        }
        if round == 0 {
            started.send(()).await.unwrap();
        }
        if last {
            break;
        }
    }
    sent
}

/// §19: "Rate limits and path/method restrictions apply under concurrency; unavailable touch requirements never degrade
/// to unconfirmed access."
///
/// Four callers' tasks send allowed and forbidden requests while `config approve` narrows the route from `GET` and
/// `POST` on `/a/**` and `/b/**` to `GET` on `/a/**`. §12: "Never admit new requests under the previous policy after that
/// commit." Every request is answered by the old policy or the new one, a request both forbid is never admitted, every
/// request sent after the approval returned is answered by the new one, and the upstream saw one request for each `200`.
///
/// The configuration reference: "Every bucket starts empty each time the service becomes Ready, and fills from there:
/// after `unlock`, an approval, a SIGHUP reload [...] Neither a restart nor a reload ever hands out a fresh burst." So
/// `metered`, with a burst of five and a token an hour, starts empty after the first approval, and the narrowing approval
/// gives it no fresh burst: it refuses its first request after each.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_approval_that_narrows_a_route_while_requests_run_admits_nothing_the_new_policy_forbids() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    let old = reload_config(&fixture, r#"["GET", "POST"]"#, r#"["/a/**", "/b/**"]"#);
    let new = reload_config(&fixture, r#"["GET"]"#, r#"["/a/**"]"#);
    let approved = approve(&service, &old, &["yes", APPROVAL_PASSPHRASE]).await;
    assert!(
        matches!(approved.response, AdminResponse::ConfigApprove(_)),
        "{:?}",
        approved.response
    );
    let metered = CallerRequest::get("/metered/meter").signed(Via::Unix);
    assert_eq!(
        send_request(&fixture.socket(), &metered).await.status,
        429,
        "a fresh burst after the first approval"
    );

    let reloaded = Arc::new(AtomicBool::new(false));
    let (started, mut rounds) = tokio::sync::mpsc::channel(RELOAD_TASKS);
    let tasks: Vec<_> = (0..RELOAD_TASKS)
        .map(|task| {
            let (socket, reloaded, started) = (fixture.socket(), Arc::clone(&reloaded), started.clone());
            tokio::spawn(async move { send_rounds(&socket, task, &reloaded, started).await })
        })
        .collect();
    // Every task has had answers under the old policy before the approval starts.
    for _ in 0..RELOAD_TASKS {
        rounds.recv().await.unwrap();
    }
    let narrowed = approve(&service, &new, &["yes", APPROVAL_PASSPHRASE]).await;
    assert!(
        matches!(narrowed.response, AdminResponse::ConfigApprove(_)),
        "{:?}",
        narrowed.response
    );
    reloaded.store(true, Ordering::SeqCst);
    let mut sent = Vec::new();
    for task in tasks {
        sent.extend(task.await.unwrap());
    }

    sent.iter().for_each(|request| {
        assert!(
            permitted(request.case, request.after).contains(&request.status),
            "{:?} {}: {}",
            request.case,
            request.tag,
            request.status
        );
    });
    let recorded: BTreeSet<String> = fixture.upstream().requests().iter().map(|r| r.request_line().to_owned()).collect();
    let answered: BTreeSet<String> = sent
        .iter()
        .filter(|request| request.status == 200)
        .map(|request| request.case.upstream_line(&request.tag))
        .collect();
    assert_eq!(recorded, answered);
    assert_eq!(fixture.upstream().requests().len(), answered.len());
    assert!(sent.iter().any(|request| request.after), "no request was sent after the approval");
    assert_eq!(
        send_request(&fixture.socket(), &metered).await.status,
        429,
        "a fresh burst after the narrowing approval"
    );
    assert!(recorded.iter().all(|line| !line.contains("/meter")), "{recorded:?}");
}

/// The fixture's own config, with the route `gated` beside `fx`, which requires touch confirmation.
fn touch_config(fixture: &Fixture) -> String {
    let gated = format!(
        r#"
[routes.gated]
prefix = "/gated"
upstream = "https://localhost:{}/v1"
ca_file = "{CA_FILE}"
credential = "fx_key"
slot = {{ header = "X-Api-Key" }}
methods = ["GET"]
paths = ["/**"]
rate_limit = {GENEROUS}
confirm = "touch"
"#,
        fixture.upstream().port()
    );
    fixture.config("fx").replace(r#"routes = ["fx"]"#, r#"routes = ["fx", "gated"]"#) + &gated
}

/// The `config-invalid` message for `config`, refused at its `confirm = "touch"` value. A parse fault is reported by
/// position only (configuration reference, "Reading a refusal"); the policy crate's tests show the parser's own message
/// there is the fixed "not yet available" refusal.
fn touch_refusal(config: &str) -> String {
    let line = config.lines().position(|line| line == r#"confirm = "touch""#).unwrap() + 1;
    format!("the proposed config is invalid: config is invalid at line {line}, column 11")
}

/// §19: "Rate limits and path/method restrictions apply under concurrency; unavailable touch requirements never degrade
/// to unconfirmed access."
///
/// §6: "v0 refuses a config that sets `confirm = "touch"` when it is read, because no confirmation provider exists
/// yet." `config approve` refuses the config before any prompt, at the touch value, and reserves no version. The service keeps
/// serving the config it had: `fx` still answers, and the touch route's prefix is unknown, so its request never reaches
/// the upstream.
#[tokio::test]
async fn config_approve_refuses_a_touch_route_and_keeps_serving_the_previous_config() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;

    let config = touch_config(&fixture);
    let refused = approve(&service, &config, &["yes", APPROVAL_PASSPHRASE]).await;

    match &refused.response {
        AdminResponse::Error {
            code: ErrorCode::ConfigInvalid,
            message,
        } => assert_eq!(message, &touch_refusal(&config)),
        other => panic!("expected config-invalid, got {other:?}"),
    }
    assert!(refused.prompts.is_empty());
    assert_eq!(versions(&service).await, (Some(1), 1));
    assert_eq!(service.status().await.state, ServiceState::Ready);
    assert_eq!(get(&fixture, "gated").await.status, 404);
    assert_eq!(fixture.upstream().connections(), 0);
    assert_eq!(get(&fixture, "fx").await.status, 200);
    let lines: Vec<String> = fixture.upstream().requests().iter().map(|r| r.request_line().to_owned()).collect();
    assert_eq!(lines, ["GET /v1/latest HTTP/1.1"]);
}

/// §19: "Rate limits and path/method restrictions apply under concurrency; unavailable touch requirements never degrade
/// to unconfirmed access."
///
/// A signed and committed config with a touch route, such as one an older build wrote, fails the config check at start:
/// it does not parse, so no route of it is served. `status` reports Unavailable with an invalid policy. An unparsable
/// config names no listener either, so no request listener is bound, as for any unparsable config (§15): no request
/// gets past the service, and the upstream sees no connection.
#[tokio::test]
async fn a_committed_touch_route_leaves_the_service_unavailable_with_no_upstream_connection() {
    let fixture = Fixture::new().await;
    let mut state = {
        let lock = state_dir_lock(&fixture.path("state"));
        let (vault, _) = Vault::open(&lock, &OsFs, identity()).unwrap();
        vault.load_approval_state(&lock, &OsFs).unwrap()
    };
    fixture.approve_through_store(&mut state, &touch_config(&fixture));

    let service = fixture.start().await;

    assert_eq!(
        service.status().await.state,
        ServiceState::Unavailable(FailureReason::PolicyInvalid)
    );
    assert!(
        tokio::net::UnixStream::connect(fixture.socket()).await.is_err(),
        "a request listener is bound"
    );
    assert_eq!(fixture.upstream().connections(), 0);
}
