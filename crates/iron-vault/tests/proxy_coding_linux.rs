//! Compressed responses through the proxy handler end to end: a caller on a Unix request socket, the real request server
//! and pipeline, a static key in a header slot and a TLS test upstream that answers in a content coding (specification
//! §11, §15, implementation spec §2.2 Q-6).
//!
//! The upstream's bodies echo the key, so each test shows the scrubber saw the decoded bytes.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{Read, Write};

use common::mock_upstream::{MockUpstream, Reply, TestCa};
use common::proxy_harness::{CallerRequest, Credential, Proxy, Setup, TOKEN_BYTES, Via, token_hash};
use iron_vault::scrub::SCRUB_REPLACEMENT;
use iron_vault_kinds::CredentialMaterial;

const KEY: &str = "sk-coding-9f3e0a71b2c4d5e6";

/// One token caller granted the route `fx`, which sends the static key `fx_key` in `X-Api-Key` to `localhost:port`.
fn callers_and_routes(port: u16) -> String {
    let hash = token_hash(TOKEN_BYTES);
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
methods = ["GET", "HEAD"]
paths = ["/v1/**"]
rate_limit = {{ requests = 60, per_seconds = 60, burst = 10 }}
"#
    )
}

/// The proxy in front of an upstream that answers every request with `reply`.
async fn start(ca: &TestCa, reply: Reply) -> (MockUpstream, Proxy) {
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
        request_timeout_secs: 30,
        limits: "",
    })
    .await;
    (upstream, proxy)
}

/// A response as raw bytes: the status, the headers lowercased, and the body after the head, still chunked.
struct Raw {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Raw {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
    }

    fn all(&self, name: &str) -> Vec<&str> {
        self.headers.iter().filter(|(n, _)| n == name).map(|(_, v)| v.as_str()).collect()
    }

    /// The body with its chunked framing removed, or `None` if it does not end with the last chunk.
    fn dechunked(&self) -> Option<Vec<u8>> {
        let mut rest = self.body.as_slice();
        let mut out = Vec::new();
        loop {
            let line_end = rest.windows(2).position(|pair| pair == b"\r\n")?;
            let size = usize::from_str_radix(std::str::from_utf8(&rest[..line_end]).ok()?, 16).ok()?;
            let after = &rest[line_end + 2..];
            if size == 0 {
                return (after == b"\r\n").then_some(out);
            }
            out.extend_from_slice(after.get(..size)?);
            rest = after.get(size..)?.strip_prefix(b"\r\n")?;
        }
    }
}

/// The caller's `method /fx/latest` with these extra headers, and the whole response once the connection closes.
async fn send(proxy: &Proxy, method: &str, headers: &[(&str, &str)]) -> Raw {
    parse(&send_bytes(proxy, method, headers).await).unwrap()
}

/// Every byte the caller received for `method /fx/latest` with these extra headers, once the connection closed.
async fn send_bytes(proxy: &Proxy, method: &str, headers: &[(&str, &str)]) -> Vec<u8> {
    let request = headers
        .iter()
        .fold(CallerRequest::new(method, "/fx/latest"), |request, (name, value)| {
            request.header(name, value)
        })
        .signed(Via::Unix);
    proxy.endpoints().send_raw(Via::Unix, &request).await
}

/// `raw` as a response, or `None` if the connection closed before a whole head arrived.
fn parse(raw: &[u8]) -> Option<Raw> {
    let split = raw.windows(4).position(|window| window == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&raw[..split]).unwrap();
    let mut lines = head.lines();
    let status = lines.next().unwrap().split(' ').nth(1).unwrap().parse().unwrap();
    let headers = lines
        .map(|line| {
            let (name, value) = line.split_once(':').unwrap();
            (name.to_ascii_lowercase(), value.trim().to_owned())
        })
        .collect();
    Some(Raw {
        status,
        headers,
        body: raw[split + 4..].to_vec(),
    })
}

/// Asserts the caller's connection was aborted rather than given a complete response, and that `secret` never reached it.
///
/// hyper writes the head with the first body frame, so a body that fails before any frame closes the connection with
/// nothing sent; one that fails later leaves a chunked body without its last chunk.
fn assert_aborted(raw: &[u8], secret: &[u8]) {
    assert!(!contains(raw, secret), "the secret reached the caller");
    if let Some(response) = parse(raw) {
        assert_eq!(response.status, 200);
        assert!(response.dechunked().is_none(), "the body ended cleanly");
    }
}

fn reply(status: u16, headers: &[(&str, &str)], body: Vec<u8>) -> Reply {
    Reply::Respond {
        status,
        headers: headers.iter().map(|(n, v)| ((*n).to_owned(), (*v).to_owned())).collect(),
        body,
    }
}

/// A body that echoes the key twice, and what the caller should get once it is scrubbed.
fn echo() -> (Vec<u8>, Vec<u8>) {
    let echoed = format!("{{\"key\":\"{KEY}\",\"again\":\"{KEY}\"}}");
    let r = std::str::from_utf8(SCRUB_REPLACEMENT).unwrap();
    (echoed.into_bytes(), format!("{{\"key\":\"{r}\",\"again\":\"{r}\"}}").into_bytes())
}

/// Compresses a whole body in one coding.
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

fn gunzip(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(data).read_to_end(&mut out).unwrap();
    out
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

#[tokio::test]
async fn gzip_deflate_and_br_bodies_reach_the_caller_decoded_and_scrubbed() {
    let ca = TestCa::new("coding test CA");
    let (echoed, scrubbed) = echo();
    let codings: [(&str, Encode); 3] = [("gzip", gzip), ("deflate", deflate), ("br", br)];
    for (coding, encode) in codings {
        let headers = [("content-encoding", coding), ("content-type", "application/json")];
        let (upstream, proxy) = start(&ca, reply(200, &headers, encode(&echoed))).await;

        let response = send(&proxy, "GET", &[("Accept-Encoding", "zstd")]).await;

        assert_eq!(response.status, 200, "{coding}");
        assert_eq!(response.dechunked().unwrap(), scrubbed, "{coding}");
        assert_eq!(response.header("content-encoding"), None, "{coding}");
        assert_eq!(response.header("content-length"), None, "{coding}");
        assert!(!contains(&response.body, KEY.as_bytes()), "{coding}");
        // The upstream was asked for the codings the service decodes, never for the caller's.
        let sent = upstream.requests()[0].headers();
        let asked: Vec<_> = sent.iter().filter(|(name, _)| name == "accept-encoding").map(|(_, v)| v).collect();
        assert_eq!(asked, ["gzip, deflate, br"], "{coding}: {sent:?}");
    }
}

#[tokio::test]
async fn a_caller_that_refuses_identity_gets_gzip_of_the_scrubbed_body() {
    let ca = TestCa::new("coding test CA");
    let (echoed, scrubbed) = echo();
    let headers = [("content-encoding", "br"), ("vary", "Origin")];
    let (_upstream, proxy) = start(&ca, reply(200, &headers, br(&echoed))).await;

    let response = send(&proxy, "GET", &[("Accept-Encoding", "gzip, identity;q=0")]).await;

    assert_eq!(response.status, 200);
    assert_eq!(response.header("content-encoding"), Some("gzip"));
    assert_eq!(response.all("vary"), ["Origin", "Accept-Encoding"]);
    assert_eq!(response.header("content-length"), None);
    assert_eq!(gunzip(&response.dechunked().unwrap()), scrubbed);
}

#[tokio::test]
async fn an_unsupported_or_stacked_coding_is_502_with_none_of_its_body() {
    let ca = TestCa::new("coding test CA");
    for coding in ["zstd", "gzip, br"] {
        let body = b"upstream-body that must not be relayed".to_vec();
        let (_upstream, proxy) = start(&ca, reply(200, &[("content-encoding", coding)], body)).await;

        let response = send(&proxy, "GET", &[]).await;

        assert_eq!((response.status, response.body.as_slice()), (502, &b"bad gateway"[..]), "{coding}");
        assert_eq!(response.header("content-encoding"), None, "{coding}");
    }
}

#[tokio::test]
async fn a_coded_partial_content_reply_is_502() {
    let ca = TestCa::new("coding test CA");
    let headers = [("content-encoding", "gzip"), ("content-range", "bytes 0-9/100")];
    let (_upstream, proxy) = start(&ca, reply(206, &headers, gzip(b"0123456789"))).await;

    let response = send(&proxy, "GET", &[]).await;

    assert_eq!((response.status, response.body.as_slice()), (502, &b"bad gateway"[..]));
}

#[tokio::test]
async fn a_head_reply_says_what_the_get_would_send() {
    let ca = TestCa::new("coding test CA");
    let (_upstream, proxy) = start(&ca, reply(200, &[("content-encoding", "gzip")], gzip(b"hello"))).await;

    let response = send(&proxy, "HEAD", &[]).await;

    assert_eq!(response.status, 200);
    assert_eq!(response.header("content-encoding"), None);
    assert_eq!(response.header("content-length"), None);
    assert!(response.body.is_empty());
}

#[tokio::test]
async fn a_decompression_bomb_aborts_the_connection_before_a_secret_planted_past_the_limit() {
    // Zeros compress about a thousandfold, past the default ratio limit of 100 once 1 MiB has decoded; the key sits far
    // beyond that point, so no byte of it may have been decoded, let alone sent.
    let ca = TestCa::new("coding test CA");
    let plaintext = [vec![0; 16 << 20], KEY.as_bytes().to_vec(), vec![0; 1 << 20]].concat();
    let (_upstream, proxy) = start(&ca, reply(200, &[("content-encoding", "gzip")], gzip(&plaintext))).await;

    assert_aborted(&send_bytes(&proxy, "GET", &[]).await, KEY.as_bytes());
}

#[tokio::test]
async fn a_truncated_gzip_body_aborts_the_connection() {
    let ca = TestCa::new("coding test CA");
    let (echoed, _) = echo();
    let coded = gzip(&echoed);
    // The upstream frames the cut-off body with its own length, so only the decoder can tell it is incomplete.
    let cut = coded[..coded.len() - 4].to_vec();
    let (_upstream, proxy) = start(&ca, reply(200, &[("content-encoding", "gzip")], cut)).await;

    assert_aborted(&send_bytes(&proxy, "GET", &[]).await, KEY.as_bytes());
}
