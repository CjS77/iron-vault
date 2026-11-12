//! Release checks for streamed-response scrubbing on the assembled service (specification §11, §19, implementation spec §3 "Streamed
//! response compatibility"): a caller on the Unix request socket, the real request server and pipeline, and a test
//! upstream that sends scripted chunks, as HTTP/1.1 chunks or as HTTP/2 DATA frames. `design/secret-handling.md` quotes the numbers the measuring tests print.

#![cfg(target_os = "linux")]

use crate::common;

use std::sync::Arc;
use std::time::Duration;

use common::mock_upstream::{MockUpstream, Reply, Script, Step, TestCa};
use common::scrub_stream::{Cred, Http, Scripted, Streamed, basic, body_with_every_form, brave, edge, fx, replacement, start, venice};
use tokio::sync::Notify;

/// Every offset in `body` at which a run splits it into two chunks; the offset past the end is the unsplit body.
fn split_script(body: String) -> Script {
    Script::by_target("text/plain", move |target| {
        let at: usize = target.rsplit('-').next().unwrap().parse().unwrap();
        let (head, tail) = body.as_bytes().split_at(at);
        [head, tail]
            .into_iter()
            .filter(|part| !part.is_empty())
            .map(|part| Step::Chunk(part.to_vec()))
            .collect()
    })
}

/// Sends a body holding every scrub pattern of a Basic credential and of a static key with URL-reserved characters, split
/// into two upstream chunks at every byte offset over `http`, and requires the caller to receive the one-shot scrubbed body.
async fn assert_every_split_scrubs(http: Http) {
    let ca = TestCa::new("scrub stream CA");
    // One upstream and proxy per credential: the upstream's script holds that credential's body.
    for make in [basic, edge] {
        let cred = make();
        let (plain, scrubbed) = body_with_every_form(&cred);
        let (route, name) = (cred.route, cred.name);
        let upstream = Scripted::start(&ca, http, split_script(plain.clone())).await;
        let proxy = start(&ca, upstream.port(), vec![cred]).await;
        for at in 1..=plain.len() {
            let chunks = Streamed::open(&proxy, &format!("/{route}/split-{at}")).await.all().await;
            let received = String::from_utf8(chunks.concat()).unwrap();
            assert_eq!(received, scrubbed, "{name} body over {http} split at byte {at} of {}", plain.len());
        }
    }
}

#[tokio::test]
async fn a_body_split_at_every_byte_offset_scrubs_to_the_same_bytes() {
    assert_every_split_scrubs(Http::One).await;
}

/// §19 check 5: "Scrubbing handles supported representations, compression, and arbitrary stream chunk boundaries while
/// preserving ordinary streaming responses." Over HTTP/2 the body arrives as two DATA frames split at every byte offset.
#[tokio::test]
async fn an_http2_body_split_at_every_byte_offset_across_two_data_frames_scrubs_to_the_same_bytes() {
    assert_every_split_scrubs(Http::Two).await;
}

/// The steps of a server-sent-event stream: each event, then a gate the test opens once it has seen the event.
fn sse_steps(events: &[String], gates: &[Arc<Notify>]) -> Vec<Step> {
    events
        .iter()
        .zip(gates)
        .flat_map(|(event, gate)| [Step::Chunk(event.clone().into_bytes()), Step::Wait(Arc::clone(gate))])
        .collect()
}

/// Streams `events` over `http` through the `fx` route one at a time, opening the next only after the caller has
/// received the previous one, and returns what the caller received (each event read until `expected` of the same index
/// has arrived) and how long each event took from the upstream's write to the caller's read.
async fn stream_events(http: Http, events: &[String], expected: &[String]) -> (Vec<String>, Vec<Duration>) {
    let ca = TestCa::new("scrub stream CA");
    let gates: Vec<_> = events.iter().map(|_| Arc::new(Notify::new())).collect();
    let script = Script::fixed("text/event-stream", sse_steps(events, &gates));
    let sent = Arc::clone(&script.sent);
    let upstream = Scripted::start(&ca, http, script).await;
    let proxy = start(&ca, upstream.port(), vec![fx()]).await;
    let mut body = Streamed::open(&proxy, "/fx/events").await;
    let mut received = Vec::new();
    let mut latencies = Vec::new();
    for (i, gate) in gates.iter().enumerate() {
        let (at, bytes) = body.until_at(expected[i].len()).await;
        received.push(String::from_utf8(bytes).unwrap());
        latencies.push(at.saturating_duration_since(sent.lock().unwrap()[i]));
        // The upstream sends nothing more until this opens, so event `i` was relayed while the next did not exist.
        gate.notify_one();
    }
    assert!(body.next().await.is_none());
    (received, latencies)
}

#[tokio::test]
async fn an_sse_event_reaches_the_caller_before_the_next_one_is_sent() {
    let events = ["data: a\n\n".to_owned(), "data: b\n\n".to_owned()];

    let (received, _) = stream_events(Http::One, &events, &events).await;

    assert_eq!(received, events);
}

/// §19 check 5: "Scrubbing handles supported representations, compression, and arbitrary stream chunk boundaries while
/// preserving ordinary streaming responses." The upstream sends nothing more over HTTP/2 until the caller has an event.
#[tokio::test]
async fn an_http2_sse_event_reaches_the_caller_before_the_next_one_is_sent() {
    let events = ["data: a\n\n".to_owned(), "data: b\n\n".to_owned()];

    let (received, _) = stream_events(Http::Two, &events, &events).await;

    assert_eq!(received, events);
}

#[tokio::test]
async fn an_sse_event_holding_the_secret_is_scrubbed_and_released_with_its_own_event() {
    let secret = fx().forms.into_iter().find(|form| form.len() == 32).unwrap();
    let events = ["data: a\n\n".to_owned(), format!("data: {secret}\n\n"), "data: c\n\n".to_owned()];

    let scrubbed = [
        "data: a\n\n".to_owned(),
        format!("data: {}\n\n", replacement()),
        "data: c\n\n".to_owned(),
    ];

    let (received, _) = stream_events(Http::One, &events, &scrubbed).await;

    assert_eq!(received[1], format!("data: {}\n\n", replacement()));
}

/// Prints the added latency per event over 200 events from an HTTP/1.1 upstream. Run with `--nocapture`; the numbers
/// are in `secret-handling.md`.
#[tokio::test]
async fn measure_sse_latency_per_event() {
    print_sse_latency(Http::One).await;
}

/// Prints the added latency per event over 200 events from an HTTP/2 upstream. Run with `--nocapture`; the numbers are
/// in `secret-handling.md`.
#[tokio::test]
async fn measure_http2_sse_latency_per_event() {
    print_sse_latency(Http::Two).await;
}

async fn print_sse_latency(http: Http) {
    let events: Vec<_> = (0..200).map(|i| format!("data: {{\"delta\":\"token {i}\"}}\n\n")).collect();

    let (received, mut latencies) = stream_events(http, &events, &events).await;

    assert_eq!(received, events);
    latencies.sort();
    let micros = |d: Duration| d.as_micros();
    eprintln!(
        "SSE latency from {http} upstream over {} events: median {} us, p95 {} us, max {} us",
        latencies.len(),
        micros(latencies[latencies.len() / 2]),
        micros(latencies[latencies.len() * 95 / 100]),
        micros(latencies[latencies.len() - 1]),
    );
}

#[tokio::test]
async fn a_streamed_chat_completion_without_the_secret_arrives_unchanged_and_in_at_least_as_many_chunks() {
    assert_chat_completion_unchanged(Http::One).await;
}

/// §19 check 5: "Scrubbing handles supported representations, compression, and arbitrary stream chunk boundaries while
/// preserving ordinary streaming responses." Each event of the reply is its own HTTP/2 DATA frame.
#[tokio::test]
async fn an_http2_streamed_chat_completion_without_the_secret_arrives_unchanged_and_in_at_least_as_many_chunks() {
    assert_chat_completion_unchanged(Http::Two).await;
}

/// Streams a chat completion holding no secret over `http`, one upstream chunk per event, and requires the caller to
/// receive the same bytes in no fewer chunks.
async fn assert_chat_completion_unchanged(http: Http) {
    let ca = TestCa::new("scrub stream CA");
    let sent: Vec<Vec<u8>> = chat_completion();
    let script = Script::fixed("text/event-stream", sent.iter().cloned().map(Step::Chunk).collect());
    let upstream = Scripted::start(&ca, http, script).await;
    let proxy = start(&ca, upstream.port(), vec![venice()]).await;

    let received = Streamed::open(&proxy, "/venice/chat").await.all().await;

    assert_eq!(received.concat(), sent.concat());
    assert!(
        received.len() >= sent.len(),
        "{http}: {} chunks sent, {} received",
        sent.len(),
        received.len()
    );
}

/// A chat completion as an OpenAI-style API streams it: a role event, one event per token, a finish event and `[DONE]`.
fn chat_completion() -> Vec<Vec<u8>> {
    let event = |delta: &str, finish: &str| {
        format!(
            "data: {{\"id\":\"chatcmpl-9\",\"object\":\"chat.completion.chunk\",\"choices\":[{{\"index\":0,\"delta\":{delta},\"finish_reason\":{finish}}}]}}\n\n"
        )
    };
    let tokens = "The quick brown fox jumps over the lazy dog, then reads a vK3_ prefix and a Bearer realm.".split_inclusive(' ');
    [event("{\"role\":\"assistant\"}", "null")]
        .into_iter()
        .chain(tokens.map(|token| event(&format!("{{\"content\":\"{token}\"}}"), "null")))
        .chain([event("{}", "\"stop\""), "data: [DONE]\n\n".to_owned()])
        .map(String::into_bytes)
        .collect()
}

/// Pushes a typical chunk, then a chunk ending in the longest scrub pattern minus its last byte, then a byte that
/// breaks the pattern. The bytes held back are the bytes pushed minus the bytes the caller received once no more come.
async fn held_back(cred: Cred) -> (usize, usize) {
    let ca = TestCa::new("scrub stream CA");
    let typical = b"data: {\"choices\":[{\"delta\":{\"content\":\" the\"}}]}\n\n".to_vec();
    let longest = cred.longest().len();
    let worst = [b"x".repeat(32), cred.longest().as_bytes()[..longest - 1].to_vec()].concat();
    let gates = [Arc::new(Notify::new()), Arc::new(Notify::new())];
    let steps = vec![
        Step::Chunk(typical.clone()),
        Step::Wait(Arc::clone(&gates[0])),
        Step::Chunk(worst.clone()),
        Step::Wait(Arc::clone(&gates[1])),
        Step::Chunk(b"!".to_vec()),
    ];
    let upstream = MockUpstream::start(&ca, Reply::Script(Script::fixed("text/event-stream", steps))).await;
    let route = cred.route;
    let proxy = start(&ca, upstream.port(), vec![cred]).await;
    let mut body = Streamed::open(&proxy, &format!("/{route}/held")).await;

    // The caller has all of the typical chunk before the upstream sends another, so nothing of it is held.
    let received = body.until(typical.len()).await;
    assert_eq!(received, typical);
    gates[0].notify_one();
    let first = body.until(32).await;
    let rest = body.until_quiet().await;
    let held = worst.len() - (first.len() + rest.len());
    gates[1].notify_one();
    // The next byte ends the hold. What is released then may differ from what was pushed: for a padded base64 form, the
    // prefix without its padding is itself another pattern, and matches.
    let tail = body.all().await.concat();
    assert!(tail.ends_with(b"!"), "{tail:?}");
    (longest, held)
}

/// Prints the bytes held back per chunk for the FX, Brave and Venice credentials. Run with `--nocapture`.
#[tokio::test]
async fn measure_bytes_held_back_per_chunk() {
    for make in [fx, basic, brave, venice] {
        let cred = make();
        let name = cred.name;
        let (longest, held) = held_back(cred).await;
        eprintln!("{name}: longest pattern {longest} bytes, maximum held {held}, typical chunk held 0");
        assert_eq!(held, longest - 1, "{name}");
    }
}
