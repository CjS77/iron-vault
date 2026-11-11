//! Release checks for compressed responses on the assembled service (specification §11, §19, implementation spec §3 "Streamed response
//! compatibility"): a caller on the Unix request socket, the real request server and pipeline, and a test upstream that
//! sends scripted, already compressed chunks. `design/secret-handling.md` ("Compressed responses") quotes the numbers
//! the measuring tests print. The refused codings are covered in `proxy_coding_linux.rs`.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::mock_upstream::{MockUpstream, Reply, Script, Step, TestCa};
use common::proxy_harness::{CallerRequest, Via};
use common::scrub_stream::{Cred, Streamed, basic, body_with_every_form, edge, fx, replacement, start};
use iron_vault::content_coding::PIECE_SIZE;
use tokio::sync::Notify;

type Encode = fn(&[u8]) -> Vec<u8>;

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn deflate(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn br(data: &[u8]) -> Vec<u8> {
    let mut encoder = brotli::CompressorWriter::new(Vec::new(), 4096, 5, 22);
    encoder.write_all(data).unwrap();
    encoder.into_inner()
}

/// Whatever of a possibly unfinished gzip stream decodes so far.
fn gunzip_prefix(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    // A stream cut short is an error after the bytes that did decode, which `read_to_end` keeps.
    let _ = flate2::read::GzDecoder::new(data).read_to_end(&mut out);
    out
}

/// A script that sends `coded` as two chunks split at the offset the request target ends with, `coding` declared.
fn split_script(coded: Vec<u8>, coding: &str) -> Script {
    Script::by_target("text/plain", move |target| {
        let at: usize = target.rsplit('-').next().unwrap().parse().unwrap();
        let (head, tail) = coded.split_at(at);
        [head, tail]
            .into_iter()
            .filter(|part| !part.is_empty())
            .map(|part| Step::Chunk(part.to_vec()))
            .collect()
    })
    .encoded(coding)
}

/// Requests `/{route}/split-{at}` and returns the body the caller received, which must have ended cleanly.
async fn received_split(proxy: &common::proxy_harness::Proxy, route: &str, at: usize) -> Vec<u8> {
    Streamed::open(proxy, &format!("/{route}/split-{at}")).await.all().await.concat()
}

#[tokio::test]
async fn a_gzip_body_split_at_every_compressed_offset_scrubs_to_the_same_bytes() {
    let ca = TestCa::new("coding stream CA");
    // A static key with URL-reserved characters and a Basic credential: every scrub pattern of each, in one body.
    for make in [edge, basic] {
        let cred = make();
        let (plain, scrubbed) = body_with_every_form(&cred);
        let (route, name) = (cred.route, cred.name);
        let coded = gzip(plain.as_bytes());
        let length = coded.len();
        let upstream = MockUpstream::start(&ca, Reply::Script(split_script(coded, "gzip"))).await;
        let proxy = start(&ca, &upstream, vec![cred]).await;
        for at in 1..=length {
            let received = received_split(&proxy, route, at).await;
            assert_eq!(
                String::from_utf8(received).unwrap(),
                scrubbed,
                "{name}: gzip split at byte {at} of {length}"
            );
        }
    }
}

#[tokio::test]
async fn a_br_body_split_at_chosen_compressed_offsets_scrubs_to_the_same_bytes() {
    let ca = TestCa::new("coding stream CA");
    let cred = basic();
    let (plain, scrubbed) = body_with_every_form(&cred);
    let route = cred.route;
    let coded = br(plain.as_bytes());
    let length = coded.len();
    let upstream = MockUpstream::start(&ca, Reply::Script(split_script(coded, "br"))).await;
    let proxy = start(&ca, &upstream, vec![cred]).await;
    for at in [1, 2, 3, length / 4, length / 2, length - 2, length - 1, length] {
        let received = received_split(&proxy, route, at).await;
        assert_eq!(String::from_utf8(received).unwrap(), scrubbed, "br split at byte {at} of {length}");
    }
}

#[tokio::test]
async fn a_secret_across_two_decoder_output_pieces_is_scrubbed() {
    let ca = TestCa::new("coding stream CA");
    let cred = fx();
    let secret = cred.forms.iter().find(|form| form.len() == 32).unwrap().clone();
    let route = cred.route;
    // The decoder yields 64 KiB pieces, so a key that starts `before` bytes ahead of the first piece's end is cut by it.
    for before in [1, secret.len() / 2, secret.len() - 1] {
        let body = |middle: &str| format!("{}{middle}{}", "a".repeat(PIECE_SIZE - before), "b".repeat(PIECE_SIZE));
        let coded = gzip(body(&secret).as_bytes());
        let reply = Reply::Respond {
            status: 200,
            headers: vec![("content-encoding".into(), "gzip".into())],
            body: coded,
        };
        let upstream = MockUpstream::start(&ca, reply).await;
        let proxy = start(&ca, &upstream, vec![fx()]).await;

        let received = Streamed::open(&proxy, &format!("/{route}/pieces")).await.all().await.concat();

        assert_eq!(
            String::from_utf8(received).unwrap(),
            body(replacement()),
            "key cut {before} bytes before the piece end"
        );
    }
}

/// The caller's decoded view of a gzip SSE stream: the events, each coded and sync-flushed by the upstream as its own
/// chunk, then the trailer.
fn coded_events(events: &[String]) -> Vec<Vec<u8>> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut chunks: Vec<_> = events
        .iter()
        .map(|event| {
            encoder.write_all(event.as_bytes()).unwrap();
            encoder.flush().unwrap();
            std::mem::take(encoder.get_mut())
        })
        .collect();
    chunks.push(encoder.finish().unwrap());
    chunks
}

/// Streams `events` as gzip SSE, the upstream sending each only after the caller has received the one before, and returns
/// how long each took from the upstream's write to the moment the caller had the event in full. `request_headers` choose
/// whether the caller gets identity or recompressed gzip.
async fn stream_gzip_events(events: &[String], request_headers: &[(&str, &str)]) -> Vec<Duration> {
    let ca = TestCa::new("coding stream CA");
    let gates: Vec<_> = events.iter().map(|_| Arc::new(Notify::new())).collect();
    let steps = coded_events(events)
        .into_iter()
        .zip(gates.iter().map(Some).chain([None]))
        .flat_map(|(chunk, gate)| [Some(Step::Chunk(chunk)), gate.map(|gate| Step::Wait(Arc::clone(gate)))])
        .flatten()
        .collect();
    let script = Script::fixed("text/event-stream", steps).encoded("gzip");
    let sent = Arc::clone(&script.sent);
    let upstream = MockUpstream::start(&ca, Reply::Script(script)).await;
    let proxy = start(&ca, &upstream, vec![fx()]).await;
    let recompressed = request_headers.iter().any(|(_, value)| value.contains("identity;q=0"));
    let mut body = Streamed::open_with(&proxy, "/fx/events", request_headers).await;
    assert_eq!(
        body.headers.iter().any(|(n, v)| n == "content-encoding" && v == "gzip"),
        recompressed
    );

    let (mut raw, mut latencies) = (Vec::new(), Vec::new());
    for (i, gate) in gates.iter().enumerate() {
        let expected = events[..=i].concat();
        let at = loop {
            let (at, chunk) = body.next().await.expect("the body ended before the event arrived");
            raw.extend(chunk);
            let decoded = if recompressed { gunzip_prefix(&raw) } else { raw.clone() };
            if decoded.len() >= expected.len() {
                assert_eq!(String::from_utf8(decoded).unwrap(), expected);
                break at;
            }
        };
        latencies.push(at.saturating_duration_since(sent.lock().unwrap()[i]));
        // The upstream sends nothing more until this opens, so event `i` was relayed while the next did not exist.
        gate.notify_one();
    }
    let rest = body.all().await.concat();
    assert_eq!(
        String::from_utf8(if recompressed {
            gunzip_prefix(&[raw, rest].concat())
        } else {
            [raw, rest].concat()
        })
        .unwrap(),
        events.concat()
    );
    latencies
}

fn sse_events(count: usize) -> Vec<String> {
    (0..count).map(|i| format!("data: {{\"delta\":\"token {i}\"}}\n\n")).collect()
}

#[tokio::test]
async fn a_gzip_sse_event_reaches_the_caller_decoded_before_the_next_is_sent() {
    stream_gzip_events(&sse_events(3), &[]).await;
}

#[tokio::test]
async fn a_gzip_sse_event_reaches_the_caller_recompressed_before_the_next_is_sent() {
    stream_gzip_events(&sse_events(3), &[("Accept-Encoding", "gzip, identity;q=0")]).await;
}

/// Prints the added latency per gzip SSE event over 200 events, for identity and recompressed output. Run with `--nocapture`.
#[tokio::test]
async fn measure_gzip_sse_latency_per_event() {
    let events = sse_events(200);
    for (label, headers) in [
        ("gzip to identity", vec![]),
        ("gzip to gzip", vec![("Accept-Encoding", "gzip, identity;q=0")]),
    ] {
        let mut latencies = stream_gzip_events(&events, &headers).await;
        latencies.sort();
        let micros = |d: Duration| d.as_micros();
        eprintln!(
            "gzip SSE latency, {label}, over {} events: median {} us, p95 {} us, max {} us",
            latencies.len(),
            micros(latencies[latencies.len() / 2]),
            micros(latencies[latencies.len() * 95 / 100]),
            micros(latencies[latencies.len() - 1]),
        );
    }
}

/// A JSON reply of about `size` bytes shaped like an API listing: keys repeat, values vary. Deterministic, and it holds
/// no scrub pattern of any test credential.
fn json_listing(size: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut out = String::from("{\"data\":[");
    let mut id = 0;
    while out.len() < size {
        let (a, b) = (next(), next());
        out.push_str(&format!(
            "{{\"id\":{id},\"name\":\"item-{a:x}\",\"price\":{}.{:02},\"tags\":[\"alpha\",\"beta-{}\"],\"note\":\"{b:016x} lorem ipsum\"}},",
            a % 10_000,
            b % 100,
            b % 97
        ));
        id += 1;
    }
    out.push_str("{}]}");
    out.into_bytes()
}

/// One request for a coded reply through the fx route; the whole response as raw bytes and how long it took.
async fn timed_exchange(coding: &str, coded: Vec<u8>) -> (Vec<u8>, Duration) {
    let ca = TestCa::new("coding stream CA");
    let reply = Reply::Respond {
        status: 200,
        headers: vec![
            ("content-encoding".into(), coding.into()),
            ("content-type".into(), "application/json".into()),
        ],
        body: coded,
    };
    let upstream = MockUpstream::start(&ca, reply).await;
    let proxy = start(&ca, &upstream, vec![fx()]).await;
    let request = CallerRequest::get("/fx/listing").signed(Via::Unix);
    let began = Instant::now();
    let raw = proxy.endpoints().send_raw(Via::Unix, &request).await;
    (raw, began.elapsed())
}

/// The chunk sizes of a chunked response body, and whether it ended with the last chunk.
fn chunked_body(raw: &[u8]) -> (Vec<u8>, Vec<usize>, bool) {
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map_or(raw.len(), |at| at + 4);
    let mut rest = &raw[split..];
    let (mut body, mut sizes) = (Vec::new(), Vec::new());
    while let Some(line_end) = rest.windows(2).position(|pair| pair == b"\r\n") {
        let size = usize::from_str_radix(std::str::from_utf8(&rest[..line_end]).unwrap(), 16).unwrap();
        let after = &rest[line_end + 2..];
        if size == 0 {
            return (body, sizes, after == b"\r\n");
        }
        let Some(data) = after.get(..size) else { break };
        body.extend_from_slice(data);
        sizes.push(size);
        rest = after.get(size + 2..).unwrap_or_default();
    }
    (body, sizes, false)
}

#[tokio::test]
async fn a_realistic_gzip_json_reply_without_a_secret_decodes_to_the_same_bytes() {
    let plain = json_listing(300 * 1024);
    let codings: [(&str, Encode); 3] = [("gzip", gzip), ("deflate", deflate), ("br", br)];
    for (coding, encode) in codings {
        let (raw, _) = timed_exchange(coding, encode(&plain)).await;

        let (body, _, complete) = chunked_body(&raw);

        assert!(complete, "{coding}: the body did not end cleanly");
        assert!(body == plain, "{coding}: the decoded body differs from the upstream's");
        assert!(
            !String::from_utf8_lossy(&raw[..raw.len().min(512)])
                .to_lowercase()
                .contains("content-encoding"),
            "{coding}"
        );
    }
}

#[tokio::test]
async fn the_default_limits_accept_a_10_mib_gzip_json_reply() {
    let plain = json_listing(10 << 20);
    let coded = gzip(&plain);
    assert!(
        plain.len() as u64 / coded.len() as u64 <= 100,
        "the fixture would trip the ratio limit"
    );

    let (raw, _) = timed_exchange("gzip", coded).await;

    let (body, _, complete) = chunked_body(&raw);
    assert!(complete);
    assert!(body == plain);
}

/// Prints the time to decode a 10 MiB gzip JSON body and the largest chunk the caller received. Run with `--nocapture`
/// (in a release build for figures that mean anything).
#[tokio::test]
async fn measure_gzip_decode_throughput() {
    let plain = json_listing(10 << 20);
    let coded = gzip(&plain);
    let (compressed, decoded) = (coded.len(), plain.len());
    let mut times = Vec::new();
    let mut largest = 0;
    for _ in 0..5 {
        let (raw, elapsed) = timed_exchange("gzip", coded.clone()).await;
        let (body, sizes, complete) = chunked_body(&raw);
        assert!(complete && body == plain);
        largest = largest.max(sizes.into_iter().max().unwrap());
        times.push(elapsed);
    }
    times.sort();
    let best = times[0];
    eprintln!(
        "gzip decode: {decoded} bytes from {compressed} compressed, best of 5 {} ms ({:.0} MiB/s decoded), median {} ms; largest caller chunk {largest} bytes",
        best.as_millis(),
        decoded as f64 / (1 << 20) as f64 / best.as_secs_f64(),
        times[2].as_millis(),
    );
}

/// The compressed bytes of a bomb, 16 MiB of zeros with the key planted far past the decompression limit.
fn bomb(cred: &Cred) -> Vec<u8> {
    let key = cred.forms.iter().find(|form| form.len() == 32).unwrap();
    gzip(&[vec![0; 16 << 20], key.as_bytes().to_vec(), vec![0; 1 << 20]].concat())
}

/// Sends `bomb` as one upstream chunk, the worst case for the service, and returns the caller's raw response.
async fn bombed(cred: Cred, bomb: Vec<u8>) -> Vec<u8> {
    let ca = TestCa::new("coding stream CA");
    let upstream = MockUpstream::start(
        &ca,
        Reply::Script(Script::fixed("application/json", vec![Step::Chunk(bomb)]).encoded("gzip")),
    )
    .await;
    let route = cred.route;
    let proxy = start(&ca, &upstream, vec![cred]).await;
    let request = CallerRequest::get(&format!("/{route}/bomb")).signed(Via::Unix);
    proxy.endpoints().send_raw(Via::Unix, &request).await
}

/// A bomb in a single upstream chunk decodes to many pieces, and the service sends each on before decoding the next, so
/// the caller never sees a chunk over one decoder piece plus the scrubber's hold-back. Prints what the caller received;
/// run with `--nocapture`.
#[tokio::test]
async fn a_decompression_bomb_is_cut_off_with_no_chunk_over_one_decoder_step_plus_the_hold_back() {
    let cred = fx();
    let hold_back = cred.longest().len() - 1;
    let bomb = bomb(&cred);
    let compressed = bomb.len();

    let raw = bombed(cred, bomb).await;

    let (body, sizes, complete) = chunked_body(&raw);
    assert!(!complete, "the bomb ended as a complete response");
    let largest = sizes.iter().copied().max().unwrap_or(0);
    eprintln!(
        "bomb in one chunk ({compressed} compressed): caller received {} bytes in {} chunks, largest {largest}",
        body.len(),
        sizes.len(),
    );
    assert!(
        largest <= PIECE_SIZE + hold_back,
        "largest chunk the caller received: {largest} bytes"
    );
    // The ratio limit applies from 1 MiB decoded, and the key sits 16 MiB in.
    assert!(body.len() < 2 << 20, "the caller received {} bytes of the bomb", body.len());
    assert!(!raw.windows(32).any(|w| w == b"3f9a1c07d2b84e65a0c1f7e93b5d8a42"));
}
