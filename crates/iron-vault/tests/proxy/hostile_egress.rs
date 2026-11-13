// SPDX-License-Identifier: MPL-2.0
//! Generated hostile requests through the assembled proxy, judged by what reached the recording upstreams (specification
//! §19, second v0 release check; implementation spec §2).
//!
//! > Unauthenticated and ungranted requests, traversal, header overrides, wrong markers, and mismatched final URLs
//! > produce no credentialed egress.
//!
//! `pipeline_egress.rs` sends a fixed list of hostile requests, and the property tests in `iron-vault-policy` generate
//! them but stop at the policy's own types. Here generated targets, headers, markers, methods and caller tokens go
//! through the real request server, pipeline and upstream client, and the property is checked on the wire: each
//! upstream received nothing, or exactly one request from a caller the config grants the route, to the route's enrolled
//! origin, on one of the route's paths under every percent-decoding an upstream might apply, with no forwarding,
//! override or caller-token header, with the route's credential once and in its slot only, and no other credential
//! anywhere.
//!
//! Requests are written to the socket byte for byte, so NUL and control bytes, absolute-form and authority-form targets
//! and over-limit heads reach the server as an attacker would send them. A mismatched final URL cannot be produced
//! through the public API; release check 2 in `design/v0-acceptance.md` names the tests that show the final check
//! refusing one.

#![cfg(target_os = "linux")]

use crate::common;

use std::cell::RefCell;

use common::WAIT;
use common::mock_upstream::{MockUpstream, RecordedRequest, Reply, TestCa};
use common::proxy_harness::{CallerRequest, Credential, Endpoints, Proxy, Setup, TOKEN_BYTES, TOKEN_HEADER, Via, token_hash, token_of};
use iron_vault_kinds::CredentialMaterial;
use proptest::collection::vec;
use proptest::prelude::*;
use proptest::sample::select;
use proptest::test_runner::{Config, TestCaseError, TestRunner};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Cases per run. Each is a fresh connection and, when admitted, a TLS request upstream; this many take about seven
/// seconds in a debug build. About one case in twelve is forwarded, so every route forwards several dozen.
const CASES: u32 = 8192;

/// Each route must forward at least this many generated requests, or the property holds vacuously for it. The fewest
/// expected (Venice: POST only, and not granted on the TCP listener) is about 60.
const MIN_FORWARDED_PER_ROUTE: usize = 30;

/// Percent-decoding passes the path check follows; an accepted path settles after one.
const MAX_PASSES: usize = 4;

const BILLING_PASSWORD: &str = "billing-pw-77";
/// The token of `brave-only`, a caller granted one route.
const NARROW_TOKEN: [u8; 32] = [8; 32];
/// A token no caller holds.
const WRONG_TOKEN: [u8; 32] = [9; 32];

/// Where a route writes its credential.
#[derive(Debug)]
enum Slot {
    Query(&'static str),
    /// The header name, and the text written before the credential.
    Header(&'static str, &'static str),
    Basic,
}

/// One route of the config, which is also its credential's name, its prefix and its upstream's index.
#[derive(Debug)]
struct RouteSpec {
    name: &'static str,
    /// The upstream's base path, which no request may escape.
    base: &'static str,
    methods: &'static [&'static str],
    paths: &'static [&'static str],
    slot: Slot,
    /// The credential as the upstream sees it: the key, or for Basic the base64 of `alice:<password>`.
    wire: &'static str,
}

const ROUTE_COUNT: usize = 4;

static ROUTES: [RouteSpec; ROUTE_COUNT] = [
    RouteSpec {
        name: "fx",
        base: "/api",
        methods: &["GET"],
        paths: &["/latest", "/historical/**"],
        slot: Slot::Query("access_key"),
        wire: "fx-secret-3a7d91",
    },
    RouteSpec {
        name: "brave",
        base: "",
        methods: &["GET"],
        paths: &["/res/v1/web/search"],
        slot: Slot::Header("X-Subscription-Token", ""),
        wire: "brave-secret-51c9e2",
    },
    RouteSpec {
        name: "venice",
        base: "/api/v1",
        methods: &["POST"],
        paths: &["/chat/completions"],
        slot: Slot::Header("Authorization", "Bearer "),
        wire: "venice-secret-b20e44",
    },
    RouteSpec {
        name: "billing",
        base: "",
        methods: &["GET"],
        paths: &["/**"],
        slot: Slot::Basic,
        // base64("alice:billing-pw-77")
        wire: "YWxpY2U6YmlsbGluZy1wdy03Nw==",
    },
];

impl RouteSpec {
    fn toml(&self, port: u16) -> String {
        let slot = match self.slot {
            Slot::Query(name) => format!("{{ query = \"{name}\" }}"),
            Slot::Header(name, before) => format!("{{ header = \"{name}\", format = \"{before}{{}}\" }}"),
            Slot::Basic => "\"basic\"".to_owned(),
        };
        let quoted = |items: &[&str]| items.iter().map(|item| format!("\"{item}\"")).collect::<Vec<_>>().join(", ");
        format!(
            "[routes.{name}]\nprefix = \"/{name}\"\nupstream = \"https://localhost:{port}{base}\"\n\
             ca_file = \"/etc/iron-vault/ca/test.pem\"\ncredential = \"{name}\"\nslot = {slot}\nmethods = [{methods}]\npaths = [{paths}]\n\
             rate_limit = {{ requests = 100000, per_seconds = 1, burst = 100000 }}\n\n",
            name = self.name,
            base = self.base,
            methods = quoted(self.methods),
            paths = quoted(self.paths),
        )
    }

    fn credential(&self, port: u16) -> Credential {
        let material = match self.slot {
            Slot::Basic => CredentialMaterial::Basic {
                username: "alice".into(),
                password: BILLING_PASSWORD.into(),
            },
            _ => CredentialMaterial::Static { key: self.wire.into() },
        };
        Credential {
            name: self.name,
            material,
            port,
        }
    }
}

/// `agent` holds every route on the Unix listener, `brave-only` one route, and `cli` three routes on the TCP listener
/// with the same token as `agent`, so a valid token on the wrong listener or for the wrong route is generated too.
fn callers_and_routes(ports: &[u16]) -> String {
    let (hash, narrow) = (token_hash(TOKEN_BYTES), token_hash(NARROW_TOKEN));
    let callers = format!(
        "[callers.agent]\nlistener = \"local\"\ntoken_hash = \"{hash}\"\nroutes = [\"fx\", \"brave\", \"venice\", \"billing\"]\n\n\
         [callers.brave-only]\nlistener = \"local\"\ntoken_hash = \"{narrow}\"\nroutes = [\"brave\"]\n\n\
         [callers.cli]\nlistener = \"loopback\"\ntoken_hash = \"{hash}\"\nroutes = [\"fx\", \"brave\", \"billing\"]\n\n"
    );
    ROUTES
        .iter()
        .zip(ports)
        .fold(callers, |toml, (route, port)| toml + &route.toml(*port))
}

/// The routes the config in [`callers_and_routes`] grants the caller a case authenticates as. A token on the wrong
/// listener, a token no caller holds, or none at all is granted nothing.
fn granted(via: Via, token: Token) -> &'static [&'static str] {
    match (via, token) {
        (Via::Unix, Token::Valid) => &["fx", "brave", "venice", "billing"],
        (Via::Unix, Token::Narrow) => &["brave"],
        (Via::Tcp, Token::Valid) => &["fx", "brave", "billing"],
        _ => &[],
    }
}

// Generated requests.

#[derive(Debug, Clone, Copy)]
enum Token {
    Valid,
    Missing,
    Wrong,
    /// `brave-only`'s token, valid but granted fewer routes.
    Narrow,
    /// A valid token in the header the other listener reads.
    OtherListener,
}

#[derive(Debug, Clone)]
struct Case {
    via: Via,
    token: Token,
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl Case {
    fn request(&self) -> CallerRequest {
        let request = match self.method.as_str() {
            "POST" => CallerRequest::post(&self.target, self.body.as_bytes()),
            method => CallerRequest::new(method, &self.target),
        };
        let request = self
            .headers
            .iter()
            .fold(request, |request, (name, value)| request.header(name, value));
        match (self.token, self.via) {
            (Token::Valid, via) => request.with_token(via, TOKEN_BYTES),
            (Token::Missing, _) => request,
            (Token::Wrong, via) => request.with_token(via, WRONG_TOKEN),
            (Token::Narrow, via) => request.with_token(via, NARROW_TOKEN),
            (Token::OtherListener, Via::Unix) => request.with_token(Via::Tcp, TOKEN_BYTES),
            (Token::OtherListener, Via::Tcp) => request.with_token(Via::Unix, TOKEN_BYTES),
        }
    }
}

/// Starts of an absolute-form target, and a scheme-relative one that is origin-form but names a host.
const LEADS: &[&str] = &[
    "http://evil.example",
    "https://localhost",
    "https://localhost:443",
    "http://localhost:1",
    "//evil.example",
];
/// Whole targets in authority form or asterisk form.
const AUTHORITY_FORMS: &[&str] = &["evil.example:443", "localhost:443", "localhost", "[::1]:443", "*"];
/// Prefixes no route has, some of them a route's prefix in disguise.
const DECOYS: &[&str] = &[
    "",
    "/fxa",
    "/FX",
    "/fx.evil.example",
    "/fx@evil.example",
    "/%62illing",
    "/billing/..",
    "/brave%2f..",
];
/// Path segments: dot segments raw, encoded and double-encoded; separators; NUL and control bytes; markers; route words.
const PIECES: &[&str] = &[
    ".",
    "..",
    "...",
    "%2e",
    "%2E%2e",
    ".%2e",
    "%252e%252e",
    "%25252E%25252e",
    "\\",
    "%5c",
    "%5C",
    "%255c",
    "%2f",
    "%2F..",
    "%252f",
    "",
    "\0",
    "%00",
    "%2500",
    "\x01",
    "\x1b",
    "\x7f",
    "..;",
    "a;b",
    "%zz",
    "%",
    "%41",
    "~",
    "@evil.example",
    "evil.example:443",
    "{iv:fx}",
    "%7Biv%3Abrave%7D",
    "{iv:other}",
    "{iv:",
    "latest",
    "historical",
    "res",
    "v1",
    "web",
    "search",
    "chat",
    "completions",
];
const QUERY_PARAMS: &[&str] = &[
    "q=rust",
    "base=USD",
    "access_key=stale",
    "access_key=%7Biv%3Afx%7D",
    "access_key={iv:fx}",
    "access_key=%7Biv%3Aother%7D",
    "ACCESS_KEY=1",
    "%61ccess_key=1",
    "access%5Fkey=1",
    "access_key",
    "",
    "x=%7Biv%3Abrave%7D",
    "x={iv:venice}",
    "a=b%26access_key%3Dx",
    "url=http://evil.example/",
    "%",
    "x=%00",
];
const HEADER_NAMES: &[&str] = &[
    "Host",
    "host",
    "HOST",
    "X-Forwarded-Host",
    "X-Forwarded-For",
    "X-Forwarded-Proto",
    "Forwarded",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-HTTP-Method-Override",
    "X-Subscription-Token",
    "x-subscription-token",
    "X-SUBSCRIPTION-TOKEN",
    "Authorization",
    "authorization",
    "AUTHORIZATION",
    "Proxy-Authorization",
    "proxy-authorization",
    "X-Iron-Vault-Token",
    "x-iron-vault-token",
    "Connection",
    "X-Note",
];
const HEADER_VALUES: &[&str] = &[
    "evil.example",
    "localhost:1",
    "/admin",
    "DELETE",
    "placeholder",
    "{iv:brave}",
    "{iv:fx}",
    "{iv:venice}",
    "{iv:billing}",
    "{iv:other}",
    "{iv:",
    "{iv:brave} {iv:other}",
    "Bearer {iv:venice}",
    "Bearer {iv:fx}",
    "Bearer placeholder",
    "Basic {iv:billing}",
    "Basic cGxhY2Vob2xkZXI6cGxhY2Vob2xkZXI=",
    "for=203.0.113.9;host=evil.example",
    "https://evil.example/",
    "X-Subscription-Token",
    "a\x01b",
    "",
];
const OTHER_METHODS: &[&str] = &[
    "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT", "get", "Post", "FOO",
];
const BODIES: &[&str] = &["{}", "{\"x\":\"{iv:fx}\"}", "{iv:venice}", "{iv:other}"];

/// A request aimed mostly at one route's own prefix, methods and paths, so generated requests get past the early
/// refusals and reach every check, not just the first.
fn case() -> impl Strategy<Value = Case> {
    select(ROUTES.iter().collect::<Vec<_>>()).prop_flat_map(|route| {
        let via = prop_oneof![3 => Just(Via::Unix), 1 => Just(Via::Tcp)];
        let token = prop_oneof![
            8 => Just(Token::Valid),
            1 => Just(Token::Missing),
            1 => Just(Token::Wrong),
            1 => Just(Token::Narrow),
            1 => Just(Token::OtherListener),
        ];
        let method = prop_oneof![4 => select(route.methods), 1 => select(OTHER_METHODS)].prop_map(String::from);
        let target = prop_oneof![12 => target(route), 1 => select(AUTHORITY_FORMS).prop_map(String::from)];
        let headers =
            prop_oneof![1 => Just(Vec::new()), 1 => vec((select(HEADER_NAMES), select(HEADER_VALUES)), 1..5)].prop_map(|headers| {
                headers
                    .into_iter()
                    .map(|(name, value)| (name.to_owned(), value.to_owned()))
                    .collect()
            });
        let body = select(BODIES).prop_map(String::from);
        (via, token, method, target, headers, body).prop_map(|(via, token, method, target, headers, body)| Case {
            via,
            token,
            method,
            target,
            headers,
            body,
        })
    })
}

fn target(route: &'static RouteSpec) -> impl Strategy<Value = String> {
    let lead = prop_oneof![10 => Just(""), 1 => select(LEADS)];
    let prefix = prop_oneof![6 => Just(format!("/{}", route.name)), 1 => select(DECOYS).prop_map(String::from)];
    let segment = prop_oneof![1 => "[a-z0-9]{1,6}", 2 => select(PIECES).prop_map(String::from)];
    let rest = prop_oneof![
        4 => near_path(route),
        3 => vec(segment, 1..6).prop_map(|segments| format!("/{}", segments.join("/"))),
        1 => long_path(),
        1 => select(&["", "/"][..]).prop_map(String::from),
    ];
    let params = vec(select(QUERY_PARAMS), 1..4).prop_map(|params| format!("?{}", params.join("&")));
    let query = prop_oneof![3 => Just(String::new()), 2 => params];
    (lead, prefix, rest, query).prop_map(|(lead, prefix, rest, query)| format!("{lead}{prefix}{rest}{query}"))
}

/// One of `route`'s paths, as is or just outside it.
fn near_path(route: &'static RouteSpec) -> impl Strategy<Value = String> {
    (select(route.paths), 0..7u8).prop_map(|(pattern, mutation)| {
        let path = pattern.trim_end_matches("/**");
        match mutation {
            0 => path.to_owned(),
            1 => format!("{path}/"),
            2 => format!("{path}/2024-01-01"),
            3 => path[..path.len().saturating_sub(1)].to_owned(),
            4 => format!("{path}x"),
            5 => path.to_uppercase(),
            _ => format!("{path}/../x"),
        }
    })
}

/// Paths of a few KiB up to past the 64 KiB head limit, in one long segment or many short ones.
fn long_path() -> impl Strategy<Value = String> {
    (select(&[2_000usize, 16_000, 40_000, 70_000][..]), any::<bool>()).prop_map(|(len, segmented)| match segmented {
        true => "/seg".repeat(len / 4),
        false => format!("/historical/{}", "a".repeat(len)),
    })
}

// Sending a case.

/// Sends `case` on a fresh connection and waits for the server to close it. A server may refuse a request before
/// reading all of it, so a failed write or read ends the exchange, not the test.
async fn send(endpoints: &Endpoints, case: &Case) -> Result<(), TestCaseError> {
    let bytes = case.request().to_bytes();
    let exchange = async {
        match case.via {
            Via::Unix => talk(endpoints.connect().await, &bytes).await,
            Via::Tcp => talk(endpoints.connect_tcp().await, &bytes).await,
        }
    };
    tokio::time::timeout(WAIT, exchange)
        .await
        .map_err(|_| TestCaseError::fail("the proxy did not close the connection"))
}

async fn talk(mut stream: impl AsyncReadExt + AsyncWriteExt + Unpin, bytes: &[u8]) {
    let _ = stream.write_all(bytes).await;
    let _ = stream.read_to_end(&mut Vec::new()).await;
}

// The property.

/// Connections accepted and requests recorded by one upstream.
fn counts(upstream: &MockUpstream) -> (usize, usize) {
    (upstream.connections(), upstream.requests().len())
}

/// Checks what the upstreams received since `before`; returns the index of the route whose
/// upstream got a request.
fn check_egress(upstreams: &[MockUpstream], before: &[(usize, usize)]) -> Result<Option<usize>, TestCaseError> {
    let reached: Vec<usize> = upstreams
        .iter()
        .zip(before)
        .enumerate()
        .filter(|(_, (upstream, was))| counts(upstream) != **was)
        .map(|(index, _)| index)
        .collect();
    let [index] = reached[..] else {
        prop_assert!(reached.is_empty(), "upstreams {reached:?} were all contacted");
        return Ok(None);
    };
    let ((connections, requests), (was_connections, was_requests)) = (counts(&upstreams[index]), before[index]);
    prop_assert_eq!(
        (connections - was_connections, requests - was_requests),
        (1, 1),
        "one connection carrying one request"
    );
    let sent = upstreams[index].requests().pop().unwrap();
    check_request(&ROUTES[index], upstreams[index].port(), &sent)?;
    Ok(Some(index))
}

/// Forwarding, method-override and URL-rewrite headers, and `Proxy-Authorization`, which no upstream may receive.
/// `x-forwarded-*` is matched by prefix in [`forbidden_header`].
const FORBIDDEN_HEADERS: &[&str] = &[
    "forwarded",
    "x-original-url",
    "x-rewrite-url",
    "x-http-method-override",
    "x-method-override",
    "x-http-method",
    "proxy-authorization",
];

/// Whether `name` must not reach an upstream. The dedicated token header is reserved, so no listener forwards it.
fn forbidden_header(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    let token_header = name.eq_ignore_ascii_case(TOKEN_HEADER);
    token_header || name.starts_with("x-forwarded-") || FORBIDDEN_HEADERS.contains(&name.as_str())
}

/// The values of every header named `name`, in any case.
fn values(headers: &[(String, String)], name: &str) -> Vec<String> {
    headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
        .collect()
}

fn check_request(route: &RouteSpec, port: u16, sent: &RecordedRequest) -> Result<(), TestCaseError> {
    let headers = sent.headers();
    prop_assert_eq!(sent.server_name.as_deref(), Some("localhost"));
    prop_assert_eq!(values(&headers, "host"), [format!("localhost:{port}")]);
    let forbidden: Vec<_> = headers.iter().map(|(name, _)| name).filter(|name| forbidden_header(name)).collect();
    prop_assert!(forbidden.is_empty(), "{forbidden:?} reached {}", route.name);
    let mut line = sent.request_line().split(' ');
    let (method, target) = (line.next().unwrap_or_default(), line.next().unwrap_or_default());
    prop_assert!(route.methods.contains(&method), "{method} is not one of {}'s methods", route.name);
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    prop_assert!(path_allowed(route, path), "{path} is outside {}'s paths", route.name);
    check_slot(route, &headers, query)?;
    check_secrets(route, &format!("{}\r\n\r\n{}", sent.head, String::from_utf8_lossy(&sent.body)))
}

/// The credential is in the route's slot, once. A query parameter is matched by its percent-decoded name, so an
/// encoded `access_key` the caller sent counts as a second one.
fn check_slot(route: &RouteSpec, headers: &[(String, String)], query: &str) -> Result<(), TestCaseError> {
    match route.slot {
        Slot::Query(name) => {
            let params: Vec<_> = query
                .split('&')
                .filter(|param| decode_once(param.split('=').next().unwrap_or_default().as_bytes()) == name.as_bytes())
                .collect();
            prop_assert_eq!(params, [format!("{name}={}", route.wire)]);
        }
        Slot::Header(name, before) => prop_assert_eq!(values(headers, name), [format!("{before}{}", route.wire)]),
        Slot::Basic => prop_assert_eq!(values(headers, "authorization"), [format!("Basic {}", route.wire)]),
    }
    Ok(())
}

/// `wire`, the whole request, carries the route's credential exactly once and no other credential or caller token.
fn check_secrets(route: &RouteSpec, wire: &str) -> Result<(), TestCaseError> {
    prop_assert_eq!(
        wire.matches(route.wire).count(),
        1,
        "{}'s credential is not on the wire exactly once",
        route.name
    );
    let others = ROUTES
        .iter()
        .filter(|other| other.name != route.name)
        .map(|other| other.wire.to_owned());
    let tokens = [TOKEN_BYTES, NARROW_TOKEN, WRONG_TOKEN].map(token_of);
    let leaked = others
        .chain([BILLING_PASSWORD.to_owned()])
        .chain(tokens)
        .find(|secret| wire.contains(secret));
    prop_assert!(leaked.is_none(), "{leaked:?} reached {}", route.name);
    Ok(())
}

/// True when `path` is under the route's base and matches one of its paths, with no dot segment, separator, control
/// byte or interior empty segment, both as sent and after each further percent-decoding an upstream might apply.
fn path_allowed(route: &RouteSpec, path: &str) -> bool {
    readings(path.as_bytes()).iter().all(|reading| {
        reading
            .strip_prefix(route.base.as_bytes())
            .is_some_and(|rest| clean(rest) && route.paths.iter().any(|pattern| matches(pattern, rest)))
    })
}

/// `path` and each percent-decoding of it, until decoding changes nothing.
fn readings(path: &[u8]) -> Vec<Vec<u8>> {
    std::iter::successors(Some(path.to_vec()), |last| Some(decode_once(last)).filter(|next| next != last))
        .take(MAX_PASSES + 1)
        .collect()
}

/// One lenient decoding pass: every well-formed escape is decoded, everything else is kept.
fn decode_once(input: &[u8]) -> Vec<u8> {
    let hex = |byte: u8| char::from(byte).to_digit(16).and_then(|d| u8::try_from(d).ok());
    let mut out = Vec::with_capacity(input.len());
    let mut rest = input;
    while let Some((&first, tail)) = rest.split_first() {
        match (first, tail) {
            (b'%', [high, low, after @ ..]) if hex(*high).is_some() && hex(*low).is_some() => {
                out.extend(hex(*high).zip(hex(*low)).map(|(h, l)| h << 4 | l));
                rest = after;
            }
            _ => {
                out.push(first);
                rest = tail;
            }
        }
    }
    out
}

/// A rooted path whose segments, but for one trailing slash, are non-empty, not dot segments (counting `..;`, which some
/// servers read as `..`), and free of backslashes and control bytes.
fn clean(path: &[u8]) -> bool {
    let Some(rest) = path.strip_prefix(b"/") else {
        return false;
    };
    let rest = rest.strip_suffix(b"/").unwrap_or(rest);
    let bad_byte = |b: &u8| *b == b'\\' || *b < 0x20 || *b == 0x7f;
    rest.is_empty()
        || rest
            .split(|b| *b == b'/')
            .all(|seg| !matches!(seg, b"" | b"." | b"..") && !seg.starts_with(b"..;") && !seg.iter().any(bad_byte))
}

/// Whether a clean `path` matches `pattern`: exactly, or for `<dir>/**` at or under `<dir>`, ignoring one trailing slash.
fn matches(pattern: &str, path: &[u8]) -> bool {
    let path = path.strip_suffix(b"/").unwrap_or(path);
    match pattern.strip_suffix("/**") {
        Some(dir) => path == dir.as_bytes() || path.starts_with(format!("{dir}/").as_bytes()),
        None => path == pattern.as_bytes(),
    }
}

/// One proxy and its upstreams serve every case, so each case is judged by what the upstreams' counts gained during it.
#[test]
fn generated_hostile_requests_produce_no_credentialed_egress() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let ca = TestCa::new("hostile egress test CA");
    let (upstreams, proxy) = runtime.block_on(async {
        let mut upstreams = Vec::new();
        for _ in &ROUTES {
            upstreams.push(MockUpstream::start(&ca, Reply::ok("ok")).await);
        }
        let ports: Vec<u16> = upstreams.iter().map(MockUpstream::port).collect();
        let setup = Setup {
            ca: &ca,
            callers_and_routes: callers_and_routes(&ports),
            credentials: ROUTES.iter().zip(&ports).map(|(route, port)| route.credential(*port)).collect(),
            tcp: true,
            request_timeout_secs: 30,
            limits: "",
        };
        (upstreams, Proxy::start(setup).await)
    });
    let endpoints = proxy.endpoints();
    let forwarded = RefCell::new([0usize; ROUTE_COUNT]);
    let config = Config {
        cases: CASES,
        failure_persistence: None,
        ..Config::default()
    };

    let result = TestRunner::new(config).run(&case(), |case| {
        let before: Vec<_> = upstreams.iter().map(counts).collect();
        runtime.block_on(send(&endpoints, &case))?;
        if let Some(index) = check_egress(&upstreams, &before)? {
            let name = ROUTES[index].name;
            prop_assert!(
                granted(case.via, case.token).contains(&name),
                "{name} forwarded for {:?} {:?}",
                case.via,
                case.token
            );
            forwarded.borrow_mut()[index] += 1;
        }
        Ok(())
    });

    if let Err(failure) = result {
        panic!("{failure}");
    }
    let forwarded = forwarded.into_inner();
    assert!(
        forwarded.iter().all(|&n| n >= MIN_FORWARDED_PER_ROUTE),
        "too few forwarded requests per route to test the property: {forwarded:?}"
    );
}
