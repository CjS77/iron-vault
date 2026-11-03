//! Release checks for streamed-response scrubbing on the assembled service (specification §3.8, §3.15, §9 "Streamed
//! response compatibility"): a caller on the Unix request socket, the real request server and pipeline, and a test
//! upstream that sends scripted chunks. `design/secret-handling.md` quotes the numbers the measuring tests print.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use common::mock_upstream::{MockUpstream, Reply, Script, Step, TestCa};
use common::proxy_harness::{CallerRequest, Credential, Proxy, Setup, TOKEN_BYTES, Via, WAIT, token_hash};
use iron_vault::scrub::SCRUB_REPLACEMENT;
use iron_vault_kinds::CredentialMaterial;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::{Notify, mpsc};

/// How long the held-back measurement waits for more bytes before it takes what has arrived as all that will.
const QUIET: Duration = Duration::from_millis(150);

/// A credential the vault holds, the route that injects it, and every form of it the service must scrub.
struct Cred {
    route: &'static str,
    name: &'static str,
    material: CredentialMaterial,
    /// The slot, as a route's `slot` setting.
    slot: &'static str,
    forms: Vec<String>,
}

impl Cred {
    fn longest(&self) -> &str {
        self.forms.iter().max_by_key(|form| form.len()).unwrap()
    }
}

/// Shaped like the FX service's key (§3.3): 32 lowercase hex characters, sent in the `access_key` query slot.
fn fx() -> Cred {
    static_cred("fx", "fx_key", "3f9a1c07d2b84e65a0c1f7e93b5d8a42", "{ query = \"access_key\" }")
}

/// A generic Basic credential: a username and a password with characters a URL encodes.
fn basic() -> Cred {
    let (user, password) = ("fx-agent", "pa/ss+word=9f3e0a71");
    let token = STANDARD.encode(format!("{user}:{password}"));
    let forms = [token.clone(), format!("Basic {token}")]
        .into_iter()
        .chain(url_forms(&format!("{user}:{password}")))
        .chain(url_forms(password));
    Cred {
        route: "basic",
        name: "basic_cred",
        material: CredentialMaterial::Basic {
            username: user.into(),
            password: password.into(),
        },
        slot: "\"basic\"",
        forms: unique(forms),
    }
}

/// Shaped like a Brave Search key: 31 characters, `BSA` first.
fn brave() -> Cred {
    static_cred(
        "brave",
        "brave_key",
        "BSAx7Kq9ZpLm2Vt4Rw8Yc1Dn5Hf3Jb0",
        "{ header = \"X-Subscription-Token\" }",
    )
}

/// Shaped like a Venice key: 43 characters of the URL-safe alphabet.
fn venice() -> Cred {
    static_cred(
        "venice",
        "venice_key",
        "vK3_xT9-qLm2Zp7Rw4Yc1Dn8Hf5Jb0Ua6Gs-Ei_Onop",
        "{ header = \"Authorization\", format = \"Bearer {}\" }",
    )
}

/// A short static key with the three characters whose URL-encoded forms differ from it.
fn edge() -> Cred {
    static_cred("edge", "edge_key", "ed/ge+key=Ab12", "{ header = \"X-Api-Key\" }")
}

fn static_cred(route: &'static str, name: &'static str, key: &'static str, slot: &'static str) -> Cred {
    let encodings = [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD].map(|engine| engine.encode(key));
    Cred {
        route,
        name,
        material: CredentialMaterial::Static { key: key.into() },
        slot,
        forms: unique(url_forms(key).into_iter().chain(encodings)),
    }
}

/// `secret` as sent and URL-encoded in both hex cases, the forms scrubbing adds for every secret.
fn url_forms(secret: &str) -> [String; 3] {
    let encode = |lower: bool| {
        secret
            .chars()
            .map(|c| match c {
                '/' | '+' | '=' | ':' if lower => format!("%{:02x}", c as u32),
                '/' | '+' | '=' | ':' => format!("%{:02X}", c as u32),
                _ => c.to_string(),
            })
            .collect::<String>()
    };
    [secret.to_owned(), encode(false), encode(true)]
}

fn unique(forms: impl IntoIterator<Item = String>) -> Vec<String> {
    forms.into_iter().collect::<BTreeSet<_>>().into_iter().collect()
}

/// The proxy serving every credential's route to `upstream`, for one caller. The rate limit is lifted so a loop of
/// requests is never refused.
async fn start(ca: &TestCa, upstream: &MockUpstream, creds: Vec<Cred>) -> Proxy {
    let port = upstream.port();
    let hash = token_hash(TOKEN_BYTES);
    let routes = creds.iter().map(|c| format!("\"{}\"", c.route)).collect::<Vec<_>>().join(", ");
    let sections: String = creds
        .iter()
        .map(|c| {
            let (route, name, slot) = (c.route, c.name, c.slot);
            format!(
                r#"
[routes.{route}]
prefix = "/{route}"
upstream = "https://localhost:{port}/v1"
ca_file = "/etc/iron-vault/ca/test.pem"
credential = "{name}"
slot = {slot}
methods = ["GET"]
paths = ["/v1/**"]
rate_limit = {{ requests = 100000, per_seconds = 1, burst = 100000 }}
"#
            )
        })
        .collect();
    let callers_and_routes = format!("[callers.agent]\nlistener = \"local\"\ntoken_hash = \"{hash}\"\nroutes = [{routes}]\n{sections}");
    Proxy::start(Setup {
        ca,
        callers_and_routes,
        credentials: creds
            .into_iter()
            .map(|c| Credential {
                name: c.name,
                material: c.material,
                port,
            })
            .collect(),
        tcp: false,
        request_timeout_secs: 60,
    })
    .await
}

/// A response body as the caller receives it: each chunk of the chunked framing with the time it arrived.
struct Streamed {
    chunks: mpsc::UnboundedReceiver<(Instant, Vec<u8>)>,
}

impl Streamed {
    /// Sends `GET target` on a fresh Unix connection, checks the `200` head and reads the body chunk by chunk in a task,
    /// so the test can look at the body while the upstream is still sending it.
    async fn open(proxy: &Proxy, target: &str) -> Self {
        let mut stream = proxy.connect().await;
        stream
            .write_all(&CallerRequest::get(target).signed(Via::Unix).to_bytes())
            .await
            .unwrap();
        let mut reader = BufReader::new(stream);
        let status = read_line(&mut reader).await.unwrap();
        assert!(status.contains(" 200 "), "{status}");
        while !read_line(&mut reader).await.unwrap().is_empty() {}
        let (tx, chunks) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(chunk) = next_chunk(&mut reader).await {
                if tx.send((Instant::now(), chunk)).is_err() {
                    break;
                }
            }
        });
        Self { chunks }
    }

    /// The next chunk, or `None` once the body has ended.
    async fn next(&mut self) -> Option<(Instant, Vec<u8>)> {
        tokio::time::timeout(WAIT, self.chunks.recv()).await.expect("no chunk within WAIT")
    }

    /// Every chunk to the end of the body.
    async fn all(mut self) -> Vec<Vec<u8>> {
        let mut chunks = Vec::new();
        while let Some((_, chunk)) = self.next().await {
            chunks.push(chunk);
        }
        chunks
    }

    /// Reads until `at_least` bytes have arrived in all, then returns what has and when the last chunk arrived.
    async fn until_at(&mut self, at_least: usize) -> (Instant, Vec<u8>) {
        let mut body = Vec::new();
        let mut at = Instant::now();
        while body.len() < at_least {
            let (arrived, chunk) = self.next().await.expect("the body ended early");
            at = arrived;
            body.extend(chunk);
        }
        (at, body)
    }

    /// Reads until `at_least` bytes have arrived in all, then returns what has.
    async fn until(&mut self, at_least: usize) -> Vec<u8> {
        self.until_at(at_least).await.1
    }

    /// Whatever arrives until no chunk comes for [`QUIET`].
    async fn until_quiet(&mut self) -> Vec<u8> {
        let mut body = Vec::new();
        while let Ok(Some((_, chunk))) = tokio::time::timeout(QUIET, self.chunks.recv()).await {
            body.extend(chunk);
        }
        body
    }
}

async fn read_line(reader: &mut BufReader<UnixStream>) -> Option<String> {
    let mut line = String::new();
    (reader.read_line(&mut line).await.ok()? > 0).then(|| line.trim_end().to_owned())
}

/// The next chunk of a chunked body; `None` after the last chunk, or if the connection ends first.
async fn next_chunk(reader: &mut BufReader<UnixStream>) -> Option<Vec<u8>> {
    let size = usize::from_str_radix(&read_line(reader).await?, 16).ok()?;
    let mut chunk = vec![0; size];
    reader.read_exact(&mut chunk).await.ok()?;
    read_line(reader).await?;
    (size > 0).then_some(chunk)
}

fn replacement() -> &'static str {
    std::str::from_utf8(SCRUB_REPLACEMENT).unwrap()
}

/// A body holding every form of the credential between plain words, and the same body scrubbed.
fn body_with_every_form(cred: &Cred) -> (String, String) {
    let join = |forms: Vec<&str>| format!("start | {} | end\n", forms.join(" | "));
    let plain = join(cred.forms.iter().map(String::as_str).collect());
    let scrubbed = join(vec![replacement(); cred.forms.len()]);
    (plain, scrubbed)
}

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

#[tokio::test]
async fn a_body_split_at_every_byte_offset_scrubs_to_the_same_bytes() {
    let ca = TestCa::new("scrub stream CA");
    // One upstream and proxy per credential: the upstream's script holds that credential's body.
    for make in [basic, edge] {
        let cred = make();
        let (plain, scrubbed) = body_with_every_form(&cred);
        let (route, name) = (cred.route, cred.name);
        let upstream = MockUpstream::start(&ca, Reply::Script(split_script(plain.clone()))).await;
        let proxy = start(&ca, &upstream, vec![cred]).await;
        for at in 1..=plain.len() {
            let chunks = Streamed::open(&proxy, &format!("/{route}/split-{at}")).await.all().await;
            let received = String::from_utf8(chunks.concat()).unwrap();
            assert_eq!(received, scrubbed, "{name} body split at byte {at} of {}", plain.len());
        }
    }
}

/// The steps of a server-sent-event stream: each event, then a gate the test opens once it has seen the event.
fn sse_steps(events: &[String], gates: &[Arc<Notify>]) -> Vec<Step> {
    events
        .iter()
        .zip(gates)
        .flat_map(|(event, gate)| [Step::Chunk(event.clone().into_bytes()), Step::Wait(Arc::clone(gate))])
        .collect()
}

/// Streams `events` through the `fx` route one at a time, opening the next only after the caller has received the
/// previous one, and returns what the caller received (each event read until `expected` of the same index has arrived) and how long each event took from the upstream's write to the
/// caller's read.
async fn stream_events(events: &[String], expected: &[String]) -> (Vec<String>, Vec<Duration>) {
    let ca = TestCa::new("scrub stream CA");
    let gates: Vec<_> = events.iter().map(|_| Arc::new(Notify::new())).collect();
    let script = Script::fixed("text/event-stream", sse_steps(events, &gates));
    let sent = Arc::clone(&script.sent);
    let upstream = MockUpstream::start(&ca, Reply::Script(script)).await;
    let proxy = start(&ca, &upstream, vec![fx()]).await;
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

    let (received, _) = stream_events(&events, &events).await;

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

    let (received, _) = stream_events(&events, &scrubbed).await;

    assert_eq!(received[1], format!("data: {}\n\n", replacement()));
}

/// Prints the added latency per event over 200 events. Run with `--nocapture`; the numbers are in `secret-handling.md`.
#[tokio::test]
async fn measure_sse_latency_per_event() {
    let events: Vec<_> = (0..200).map(|i| format!("data: {{\"delta\":\"token {i}\"}}\n\n")).collect();

    let (received, mut latencies) = stream_events(&events, &events).await;

    assert_eq!(received, events);
    latencies.sort();
    let micros = |d: Duration| d.as_micros();
    eprintln!(
        "SSE latency over {} events: median {} us, p95 {} us, max {} us",
        latencies.len(),
        micros(latencies[latencies.len() / 2]),
        micros(latencies[latencies.len() * 95 / 100]),
        micros(latencies[latencies.len() - 1]),
    );
}

#[tokio::test]
async fn a_streamed_chat_completion_without_the_secret_arrives_unchanged_and_in_at_least_as_many_chunks() {
    let ca = TestCa::new("scrub stream CA");
    let sent: Vec<Vec<u8>> = chat_completion();
    let upstream = MockUpstream::start(
        &ca,
        Reply::Script(Script::fixed("text/event-stream", sent.iter().cloned().map(Step::Chunk).collect())),
    )
    .await;
    let proxy = start(&ca, &upstream, vec![venice()]).await;

    let received = Streamed::open(&proxy, "/venice/chat").await.all().await;

    assert_eq!(received.concat(), sent.concat());
    assert!(
        received.len() >= sent.len(),
        "{} chunks sent, {} received",
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
    let proxy = start(&ca, &upstream, vec![cred]).await;
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
