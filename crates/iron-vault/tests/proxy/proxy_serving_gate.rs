// SPDX-License-Identifier: MPL-2.0
//! The serving gate end to end: a request refused at admission, the admission pause around a snapshot swap, and the
//! withdrawal of a snapshot from the requests still running on it (specification §12, §15).
//!
//! The harness serves one snapshot; a test builds another with [`Proxy::snapshot`] and swaps it in through the holder, the
//! way the config check will.

#![cfg(target_os = "linux")]

use crate::common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use common::mock_upstream::{MockUpstream, Reply, TestCa};
use common::proxy_harness::{CallerRequest, Credential, Proxy, Response, Setup, TOKEN_BYTES, Via, WAIT, token_hash};
use iron_vault::service_state::{FailureReason, UnavailableReason};
use iron_vault_kinds::CredentialMaterial;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const SECRET: &str = "fx-secret-9c2e";

/// The reasons a request can be refused with, each with the text its `503` carries.
const REASONS: [UnavailableReason; 4] = [
    UnavailableReason::Locked,
    UnavailableReason::PolicyInvalid,
    UnavailableReason::Checking,
    UnavailableReason::RecoveryNeeded,
];

/// One token caller on a Unix listener, granted `route`, which sends `fx_key` to `localhost:port` under `/v1`.
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
credential = "fx_key"
slot = {{ header = "X-Api-Key" }}
methods = ["GET"]
paths = ["/**"]
rate_limit = {{ requests = 100000, per_seconds = 1, burst = 100000 }}
"#
    )
}

/// A setup serving `route` to the upstream at `localhost:port`.
fn setup<'a>(ca: &'a TestCa, route: &str, port: u16) -> Setup<'a> {
    Setup {
        ca,
        callers_and_routes: callers_and_routes(route, port),
        credentials: vec![Credential {
            name: "fx_key",
            material: CredentialMaterial::Static { key: SECRET.into() },
            port,
        }],
        tcp: false,
        request_timeout_secs: 30,
        limits: "",
    }
}

fn ok_reply() -> Reply {
    Reply::Respond {
        status: 200,
        headers: Vec::new(),
        body: b"ok".to_vec(),
    }
}

/// A two-chunk reply whose second chunk is sent when the returned gate opens.
fn gated_reply() -> (Reply, Arc<tokio::sync::Notify>) {
    let gate = Arc::new(tokio::sync::Notify::new());
    let reply = Reply::TwoChunks {
        first: "data: first\n\n".to_owned(),
        second: "data: second\n\n".to_owned(),
        gate: Arc::clone(&gate),
    };
    (reply, gate)
}

fn signed_get(target: &str) -> CallerRequest {
    CallerRequest::get(target).signed(Via::Unix)
}

/// Opens a connection, sends the token caller's `GET target` and reads until `wanted` has arrived.
async fn start_streaming(proxy: &Proxy, target: &str, wanted: &str) -> (UnixStream, String) {
    let mut stream = proxy.connect().await;
    stream.write_all(&signed_get(target).to_bytes()).await.unwrap();
    let mut raw = Vec::new();
    while !String::from_utf8_lossy(&raw).contains(wanted) {
        let mut buf = [0u8; 256];
        let read = tokio::time::timeout(WAIT, stream.read(&mut buf)).await.unwrap().unwrap();
        assert!(read > 0, "the connection closed before {wanted:?} arrived");
        raw.extend_from_slice(&buf[..read]);
    }
    (stream, String::from_utf8(raw).unwrap())
}

/// Reads to the end of the connection, whether it ends cleanly or is reset.
async fn read_to_close(stream: &mut UnixStream) -> String {
    let mut raw = Vec::new();
    let _ = tokio::time::timeout(WAIT, stream.read_to_end(&mut raw)).await.unwrap();
    String::from_utf8_lossy(&raw).into_owned()
}

/// Waits until the upstream has seen `count` requests.
async fn wait_for_requests(upstream: &MockUpstream, count: usize) {
    tokio::time::timeout(WAIT, async {
        while upstream.requests().len() < count {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_refused_admission_is_503_with_the_reason_and_sends_nothing_upstream() {
    let ca = TestCa::new("proxy test CA");
    let upstream = MockUpstream::start(&ca, ok_reply()).await;
    let proxy = Proxy::start(setup(&ca, "fx", upstream.port())).await;

    for reason in REASONS {
        proxy.holder().refuse(reason);
        let granted = proxy.get("/fx/latest").await;
        // No snapshot, so no policy to identify a caller against: a caller with no token is refused the same way.
        let anonymous = proxy.endpoints().send(Via::Unix, &CallerRequest::get("/fx/latest")).await;
        for response in [granted, anonymous] {
            assert_eq!(response.status, 503, "{reason:?}");
            assert_eq!(response.body, reason.as_str(), "{reason:?}");
            assert_eq!(response.header("content-type"), Some("text/plain; charset=utf-8"));
        }
    }

    assert!(upstream.requests().is_empty(), "{:?}", upstream.requests());
}

#[tokio::test]
async fn serving_again_after_a_refusal_admits_requests() {
    let ca = TestCa::new("proxy test CA");
    let upstream = MockUpstream::start(&ca, ok_reply()).await;
    let proxy = Proxy::start(setup(&ca, "fx", upstream.port())).await;
    proxy.holder().refuse(UnavailableReason::Locked);
    assert_eq!(proxy.get("/fx/latest").await.status, 503);

    proxy.holder().serve(proxy.snapshot(setup(&ca, "fx", upstream.port())));

    assert_eq!(proxy.get("/fx/latest").await.status, 200);
    assert_eq!(upstream.requests().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_request_is_admitted_under_the_old_policy_once_the_swap_returns() {
    let ca = TestCa::new("proxy test CA");
    let upstream = MockUpstream::start(&ca, ok_reply()).await;
    let proxy = Proxy::start(setup(&ca, "fx", upstream.port())).await;
    let holder = proxy.holder();
    // The new config no longer has the `fx` route.
    let replacement = proxy.snapshot(setup(&ca, "other", upstream.port()));
    assert_eq!(proxy.get("/fx/latest").await.status, 200);

    let swapped = Arc::new(AtomicBool::new(false));
    let after_swap = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let callers: Vec<_> = (0..4)
        .map(|_| {
            tokio::spawn(hammer(
                proxy.endpoints(),
                Arc::clone(&swapped),
                Arc::clone(&after_swap),
                Arc::clone(&stop),
            ))
        })
        .collect();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let pause = holder.pause();
    let during = proxy.get("/fx/latest").await;
    assert_eq!((during.status, during.body.as_str()), (503, "checking"));
    tokio::time::sleep(Duration::from_millis(50)).await;
    pause.resume(replacement);
    swapped.store(true, Ordering::SeqCst);

    tokio::time::timeout(WAIT, async {
        while after_swap.load(Ordering::SeqCst) < 8 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    stop.store(true, Ordering::SeqCst);
    let seen: Vec<_> = futures_join(callers).await.into_iter().flatten().collect();

    let late: Vec<_> = seen.iter().filter(|(after_swap, _)| *after_swap).collect();
    assert!(late.len() >= 8, "{} requests started after the swap", late.len());
    assert!(
        late.iter().all(|(_, response)| response.status == 404),
        "a request used the old policy after the swap"
    );
    let mut refusals = seen.iter().filter(|(_, response)| response.status == 503);
    assert!(refusals.all(|(_, response)| response.body == "checking"));
    // Everything admitted before the pause has finished by now, so the old route reaches the upstream no more.
    let sent = upstream.requests().len();
    assert_eq!(proxy.get("/fx/latest").await.status, 404);
    assert_eq!(upstream.requests().len(), sent);
}

/// Sends `GET /fx/latest` until `stop`, returning each response with whether the swap had returned before it was sent.
async fn hammer(
    endpoints: common::proxy_harness::Endpoints,
    swapped: Arc<AtomicBool>,
    after_swap: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
) -> Vec<(bool, Response)> {
    let mut seen = Vec::new();
    while !stop.load(Ordering::SeqCst) {
        let started_after_swap = swapped.load(Ordering::SeqCst);
        let response = endpoints.send(Via::Unix, &signed_get("/fx/latest")).await;
        if started_after_swap {
            after_swap.fetch_add(1, Ordering::SeqCst);
        }
        seen.push((started_after_swap, response));
    }
    seen
}

/// Awaits every task, in order.
async fn futures_join<T>(tasks: Vec<tokio::task::JoinHandle<T>>) -> Vec<T> {
    let mut out = Vec::new();
    for task in tasks {
        out.push(task.await.unwrap());
    }
    out
}

#[tokio::test]
async fn a_request_admitted_before_a_pause_that_ends_in_ready_finishes_on_the_old_snapshot() {
    let ca = TestCa::new("proxy test CA");
    let (reply, gate) = gated_reply();
    let upstream = MockUpstream::start(&ca, reply).await;
    let proxy = Proxy::start(setup(&ca, "fx", upstream.port())).await;
    let (mut stream, mut raw) = start_streaming(&proxy, "/fx/stream", "data: first\n\n").await;

    proxy.holder().pause().resume(proxy.snapshot(setup(&ca, "other", upstream.port())));
    gate.notify_one();
    raw.push_str(&read_to_close(&mut stream).await);

    assert!(raw.contains("data: second\n\n"), "{raw}");
    assert!(raw.ends_with("0\r\n\r\n"), "the body did not end cleanly: {raw}");
}

#[tokio::test]
async fn a_request_streaming_when_the_check_fails_has_its_connection_aborted() {
    let ca = TestCa::new("proxy test CA");
    let (reply, _gate) = gated_reply();
    let upstream = MockUpstream::start(&ca, reply).await;
    let proxy = Proxy::start(setup(&ca, "fx", upstream.port())).await;
    let (mut stream, mut raw) = start_streaming(&proxy, "/fx/stream", "data: first\n\n").await;

    proxy.holder().pause().fail(FailureReason::PolicyInvalid);
    raw.push_str(&read_to_close(&mut stream).await);

    // The caller got the head and the first chunk; the connection then ended without the last chunk.
    assert!(!raw.ends_with("0\r\n\r\n"), "the withdrawn body ended cleanly: {raw}");
    assert!(!raw.contains("data: second"), "{raw}");
    let after = proxy.get("/fx/stream").await;
    assert_eq!((after.status, after.body.as_str()), (503, "policy invalid"));
}

#[tokio::test]
async fn a_request_still_waiting_for_the_upstream_is_answered_503_when_its_snapshot_is_withdrawn() {
    let ca = TestCa::new("proxy test CA");
    let upstream = MockUpstream::start(&ca, Reply::Stall).await;
    let proxy = Proxy::start(setup(&ca, "fx", upstream.port())).await;
    let endpoints = proxy.endpoints();
    let waiting = tokio::spawn(async move { endpoints.send(Via::Unix, &signed_get("/fx/latest")).await });
    wait_for_requests(&upstream, 1).await;

    let started = Instant::now();
    proxy.holder().refuse(UnavailableReason::Locked);
    let response = waiting.await.unwrap();

    assert_eq!((response.status, response.body.as_str()), (503, "service unavailable"));
    assert!(started.elapsed() < Duration::from_secs(5), "answered after {:?}", started.elapsed());
}
