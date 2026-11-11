//! The request event of each request answered by relaying an upstream response, end to end: written once when the
//! relayed body ends, cleanly or not, or when the relay refuses the upstream's head (specification §18;
//! `design/audit-logging.md`, "Request event").
//!
//! The harness runs on a current-thread runtime, so the log captured on the test's thread holds every record.

#![cfg(target_os = "linux")]

use crate::common;

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use common::WAIT;
use common::mock_upstream::{MockUpstream, Reply, TestCa};
use common::proxy_harness::{CallerRequest, Credential, Proxy, Setup, TOKEN_BYTES, Via, token_hash};
use common::request_log::{RequestLog, capture};
use iron_vault::service_state::UnavailableReason;
use iron_vault_kinds::CredentialMaterial;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::Notify;

const KEY: &str = "sk-relayed-5d1c8e2f7a90";

/// One token caller granted the route `fx`, which sends the static key `fx_key` in `X-Api-Key` to `localhost:port`.
fn callers_and_routes(port: u16) -> String {
    let hash = token_hash(TOKEN_BYTES);
    format!(
        "[callers.agent]\nlistener = \"local\"\ntoken_hash = \"{hash}\"\nroutes = [\"fx\"]\n\n[routes.fx]\nprefix = \"/fx\"\n\
         upstream = \"https://localhost:{port}/v1\"\nca_file = \"/etc/iron-vault/ca/test.pem\"\ncredential = \"fx_key\"\n\
         slot = {{ header = \"X-Api-Key\" }}\nmethods = [\"GET\", \"HEAD\"]\npaths = [\"/**\"]\n\
         rate_limit = {{ requests = 1000, per_seconds = 1, burst = 1000 }}\n"
    )
}

/// The proxy, with this request timeout, in front of an upstream that answers every request with `reply`.
async fn start(ca: &TestCa, reply: Reply, request_timeout_secs: u64) -> (MockUpstream, Proxy) {
    start_with(ca, reply, request_timeout_secs, "").await
}

/// As [`start`], with further `[limits]` keys.
async fn start_with(ca: &TestCa, reply: Reply, request_timeout_secs: u64, limits: &'static str) -> (MockUpstream, Proxy) {
    let upstream = MockUpstream::start(ca, reply).await;
    let proxy = Proxy::start(Setup {
        ca,
        callers_and_routes: callers_and_routes(upstream.port()),
        credentials: vec![Credential {
            name: "fx_key",
            material: CredentialMaterial::Static { key: KEY.into() },
            port: upstream.port(),
        }],
        tcp: false,
        request_timeout_secs,
        limits,
    })
    .await;
    (upstream, proxy)
}

fn reply(status: u16, headers: &[(&str, &str)], body: Vec<u8>) -> Reply {
    Reply::Respond {
        status,
        headers: headers.iter().map(|(n, v)| ((*n).to_owned(), (*v).to_owned())).collect(),
        body,
    }
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

/// The caller's `method /fx/latest` with these extra headers: every byte it received once the connection closed.
async fn send(proxy: &Proxy, method: &str, headers: &[(&str, &str)]) -> Vec<u8> {
    let request = headers
        .iter()
        .fold(CallerRequest::new(method, "/fx/latest"), |request, (name, value)| {
            request.header(name, value)
        })
        .signed(Via::Unix);
    proxy.endpoints().send_raw(Via::Unix, &request).await
}

/// The status of a raw response, if a head arrived.
fn status_of(raw: &[u8]) -> Option<u16> {
    std::str::from_utf8(raw.get(9..12)?).ok()?.parse().ok()
}

/// The body of a chunked response with its framing removed, and whether it ended with the last chunk.
fn dechunked(raw: &[u8]) -> (Vec<u8>, bool) {
    let start = raw.windows(4).position(|window| window == b"\r\n\r\n").unwrap() + 4;
    let mut rest = &raw[start..];
    let mut out = Vec::new();
    while let Some(line_end) = rest.windows(2).position(|pair| pair == b"\r\n") {
        let size = usize::from_str_radix(std::str::from_utf8(&rest[..line_end]).unwrap(), 16).unwrap();
        let Some(chunk) = rest.get(line_end + 2..line_end + 2 + size) else {
            break;
        };
        if size == 0 {
            return (out, true);
        }
        out.extend_from_slice(chunk);
        rest = &rest[line_end + 4 + size..];
    }
    (out, false)
}

/// The one request event. The proxy is stopped first, which joins every connection task, so no second event can follow the
/// count.
async fn the_only_event(log: &RequestLog, proxy: Proxy) -> serde_json::Value {
    let event = log.the_request_event().await;
    proxy.stop().await;
    assert_eq!(log.request_events().len(), 1, "{}", log.text());
    event
}

/// Checks `event` is a failure with `reason` after a `200` head, naming the route.
fn assert_cut(event: &serde_json::Value, reason: &str) {
    assert_eq!(
        (event["outcome"].as_str(), event["reason"].as_str(), event["status"].as_u64()),
        (Some("failure"), Some(reason), Some(200)),
        "{event}"
    );
    assert_eq!(
        (event["route"].as_str(), event["scrubbed"].as_bool()),
        (Some("fx"), Some(false)),
        "{event}"
    );
    assert!(event["response_bytes"].is_u64() && event["duration_ms"].is_u64(), "{event}");
}

#[tokio::test]
async fn a_clean_relayed_response_is_one_success_with_its_size_and_whole_duration() {
    let (_guard, log) = capture();
    let ca = TestCa::new("relay events CA");
    let gate = Arc::new(Notify::new());
    let (_upstream, proxy) = start(&ca, two_chunks(&gate), 30).await;
    let mut stream = first_chunk(&proxy).await;

    tokio::time::sleep(Duration::from_millis(300)).await;
    gate.notify_one();
    let _ = tokio::time::timeout(WAIT, stream.read_to_end(&mut Vec::new())).await.unwrap();

    let event = the_only_event(&log, proxy).await;
    assert_eq!(
        (
            event["outcome"].as_str(),
            event["status"].as_u64(),
            event["response_bytes"].as_u64()
        ),
        (Some("success"), Some(200), Some(11)),
        "{event}"
    );
    assert_eq!(event["scrubbed"], false, "{event}");
    assert!(event.get("reason").is_none(), "{event}");
    assert!(event["duration_ms"].as_u64().unwrap() >= 300, "{event}");
    assert!(log.audit_events("response.scrubbed").is_empty());
}

#[tokio::test]
async fn a_head_answer_hyper_never_polls_is_a_success() {
    let (_guard, log) = capture();
    let ca = TestCa::new("relay events CA");
    let (_upstream, proxy) = start(&ca, reply(200, &[], b"body".to_vec()), 30).await;

    assert_eq!(status_of(&send(&proxy, "HEAD", &[]).await), Some(200));

    let event = the_only_event(&log, proxy).await;
    assert_eq!(
        (event["outcome"].as_str(), event["response_bytes"].as_u64()),
        (Some("success"), Some(0)),
        "{event}"
    );
}

#[tokio::test]
async fn a_compressed_scrubbed_response_counts_the_bytes_sent_and_writes_one_scrub_event() {
    let (_guard, log) = capture();
    let ca = TestCa::new("relay events CA");
    let body = gzip(format!("{{\"key\":\"{KEY}\"}}").as_bytes());
    let (_upstream, proxy) = start(&ca, reply(200, &[("content-encoding", "gzip")], body), 30).await;

    let raw = send(&proxy, "GET", &[("Accept-Encoding", "gzip, identity;q=0")]).await;

    let (sent, ended) = dechunked(&raw);
    assert!(ended);
    let event = the_only_event(&log, proxy).await;
    assert_eq!(
        (
            event["outcome"].as_str(),
            event["scrubbed"].as_bool(),
            event["response_bytes"].as_u64()
        ),
        (Some("success"), Some(true), Some(u64::try_from(sent.len()).unwrap())),
        "{event}"
    );
    let scrubs = log.audit_events("response.scrubbed");
    assert_eq!(scrubs.len(), 1, "{scrubs:?}");
    assert_eq!(
        (&scrubs[0]["request_id"], scrubs[0]["matches"].as_u64()),
        (&event["request_id"], Some(1))
    );
    assert!(!log.text().contains(KEY));
}

#[tokio::test]
async fn a_body_past_the_size_limit_is_one_body_size_limit_event() {
    let (_guard, log) = capture();
    let ca = TestCa::new("relay events CA");
    let (_upstream, proxy) = start_with(&ca, reply(200, &[], vec![b'a'; 4096]), 30, "max_decompressed_response_bytes = 1000").await;

    let raw = send(&proxy, "GET", &[]).await;

    assert!(raw.is_empty() || !dechunked(&raw).1, "the body ended cleanly");
    assert_cut(&the_only_event(&log, proxy).await, "body_size_limit");
}

#[tokio::test]
async fn each_relay_failure_after_the_head_is_one_event_with_its_reason() {
    let (_guard, log) = capture();
    let gzipped = gzip(&[b'a'; 4096]);
    let bomb = gzip(&vec![0; 16 << 20]);
    let coded = [("content-encoding", "gzip")];
    let cases = [
        (reply(200, &coded, b"not gzip at all".to_vec()), "body_corrupt"),
        (reply(200, &coded, gzipped[..gzipped.len() - 4].to_vec()), "body_truncated"),
        (reply(200, &coded, bomb), "body_ratio_limit"),
        (
            Reply::Truncated {
                sent: "partial".to_owned(),
            },
            "upstream_body",
        ),
    ];
    for (upstream_reply, reason) in cases {
        let ca = TestCa::new("relay events CA");
        let (_upstream, proxy) = start(&ca, upstream_reply, 30).await;
        let raw = send(&proxy, "GET", &[]).await;
        assert!(raw.is_empty() || !dechunked(&raw).1, "{reason}: the body ended cleanly");
        assert_cut(&the_only_event(&log, proxy).await, reason);
        log.clear();
    }
}

#[tokio::test]
async fn a_refused_coding_or_redirect_is_one_event_with_its_reason() {
    let (_guard, log) = capture();
    let cases = [
        (reply(200, &[("content-encoding", "zstd")], b"zz".to_vec()), "unsupported_coding"),
        (reply(302, &[("location", "/elsewhere")], Vec::new()), "redirect_refused"),
    ];
    for (upstream_reply, reason) in cases {
        let ca = TestCa::new("relay events CA");
        let (_upstream, proxy) = start(&ca, upstream_reply, 30).await;
        assert_eq!(status_of(&send(&proxy, "GET", &[]).await), Some(502));
        let event = the_only_event(&log, proxy).await;
        assert_eq!(
            (event["outcome"].as_str(), event["reason"].as_str(), event["status"].as_u64()),
            (Some("failure"), Some(reason), Some(502)),
            "{event}"
        );
        assert!(event.get("scrubbed").is_none(), "{event}");
        assert!(!log.text().contains("elsewhere"), "{}", log.text());
        log.clear();
    }
}

/// Opens a connection, sends the caller's `GET /fx/latest` and reads until the first chunk of a two-chunk reply arrived.
async fn first_chunk(proxy: &Proxy) -> UnixStream {
    let mut stream = proxy.connect().await;
    let request = CallerRequest::get("/fx/latest").signed(Via::Unix);
    stream.write_all(&request.to_bytes()).await.unwrap();
    let mut raw = Vec::new();
    while !String::from_utf8_lossy(&raw).contains("first") {
        let mut buf = [0u8; 256];
        let read = tokio::time::timeout(WAIT, stream.read(&mut buf)).await.unwrap().unwrap();
        assert!(read > 0, "the connection closed before the first chunk");
        raw.extend_from_slice(&buf[..read]);
    }
    stream
}

fn two_chunks(gate: &Arc<Notify>) -> Reply {
    Reply::TwoChunks {
        first: "first".to_owned(),
        second: "second".to_owned(),
        gate: Arc::clone(gate),
    }
}

#[tokio::test]
async fn a_withdrawal_after_the_head_is_one_withdrawn_event_with_the_heads_status() {
    let (_guard, log) = capture();
    let ca = TestCa::new("relay events CA");
    let gate = Arc::new(Notify::new());
    let (_upstream, proxy) = start(&ca, two_chunks(&gate), 30).await;
    let mut stream = first_chunk(&proxy).await;

    proxy.holder().refuse(UnavailableReason::Locked);

    let _ = tokio::time::timeout(WAIT, stream.read_to_end(&mut Vec::new())).await.unwrap();
    let event = the_only_event(&log, proxy).await;
    assert_cut(&event, "withdrawn");
    assert_eq!(event["response_bytes"], 5, "{event}");
}

#[tokio::test]
async fn a_caller_that_hangs_up_mid_body_is_one_caller_gone_event() {
    let (_guard, log) = capture();
    let ca = TestCa::new("relay events CA");
    let gate = Arc::new(Notify::new());
    let (_upstream, proxy) = start(&ca, two_chunks(&gate), 30).await;

    // The gate stays shut: the second chunk never exists, so the cut can only be the caller's hang-up.
    drop(first_chunk(&proxy).await);

    assert_cut(&the_only_event(&log, proxy).await, "caller_gone");
}

#[tokio::test]
async fn a_body_still_streaming_at_the_deadline_is_one_deadline_event() {
    let (_guard, log) = capture();
    let ca = TestCa::new("relay events CA");
    let gate = Arc::new(Notify::new());
    let (_upstream, proxy) = start(&ca, two_chunks(&gate), 1).await;
    let mut stream = first_chunk(&proxy).await;

    let _ = tokio::time::timeout(WAIT, stream.read_to_end(&mut Vec::new())).await.unwrap();

    let event = the_only_event(&log, proxy).await;
    assert_cut(&event, "deadline");
    assert!(event["duration_ms"].as_u64().unwrap() >= 1000, "{event}");
}
