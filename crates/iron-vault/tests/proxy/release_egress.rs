// SPDX-License-Identifier: MPL-2.0
//! The first v0 release check (specification §19) through the running service: credentials added with `add`, routes
//! approved with `config approve`, and requests sent to the service's own request sockets.
//!
//! Three recording upstreams stand in for FX, Brave and Venice, each on its own loopback address with a certificate for
//! that host alone, so the three routes differ in host and not only in port. Each credential is enrolled for its own
//! upstream's origin (§6) and fills the slot its provider uses (§9). Every test reads what each upstream received
//! (implementation spec §2: "Use a mock upstream to observe exactly which requests and credentials left the service"),
//! and checks that no credential reached another route's upstream in any form response scrubbing derives from it.
//!
//! The vault and its approver come from [`Fixture`], built through the store rather than `init`.

#![cfg(target_os = "linux")]

use crate::common;

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use common::WAIT;
use common::approval_harness::{APPROVAL_PASSPHRASE, Fixture, approve, converse, send, spawn_admin};
use common::mock_upstream::{MockUpstream, RecordedRequest, Reply};
use common::proxy_harness::{CallerRequest, Response, TOKEN_BYTES, TOKEN_HEADER, Via, token_hash};
use iron_vault::admin::protocol::{AdminRequest, AdminResponse, Frame, RequestedOrigin};
use iron_vault::service_context::ServiceContext;
use iron_vault_policy::{CredentialKind, encode_query_value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// The three test secrets. Brave's holds `/` and `+`, so its percent-encoded and base64 forms differ from it.
const FX_SECRET: &str = "fx-release-3a7d91";
const BRAVE_SECRET: &str = "brave/release+51c9e2";
const VENICE_SECRET: &str = "venice-release-b20e44";

/// The local account the peer caller names; the harness maps it to the test's own uid.
const PEER_ACCOUNT: &str = "desk-user";

/// The Venice request body: a streamed chat completion.
const VENICE_BODY: &str = "{\"model\":\"m\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}],\"stream\":true}";

/// One provider's stand-in: its route, credential, secret and the host its upstream answers as.
struct Provider {
    name: &'static str,
    secret: &'static str,
    host: &'static str,
    upstream: MockUpstream,
}

impl Provider {
    /// Starts the upstream on `host`, a loopback address or `localhost`, with a certificate for `host` from the CA the
    /// service pins.
    async fn start(fixture: &Fixture, name: &'static str, secret: &'static str, host: &'static str, reply: Reply) -> Self {
        let ip = match host {
            "localhost" => Ipv4Addr::LOCALHOST,
            ip => ip.parse().unwrap(),
        };
        let upstream = MockUpstream::start_on(ip, fixture.ca().server_config(host), reply).await;
        Self {
            name,
            secret,
            host,
            upstream,
        }
    }

    /// The one request this upstream received, checked to have gone to the enrolled authority and to hold no other
    /// provider's secret.
    fn sole_request(&self, others: &[&Provider]) -> RecordedRequest {
        let [sent] = <[_; 1]>::try_from(self.upstream.requests()).unwrap_or_else(|all| panic!("{}: {all:?}", self.name));
        let authority = format!("{}:{}", self.host, self.upstream.port());
        assert_eq!(header_values(&sent, "host"), [authority.as_str()], "{}", sent.head);
        // A client sends no server name for an IP literal (RFC 6066 §3).
        let sni = self.host.parse::<Ipv4Addr>().is_err().then_some(self.host);
        assert_eq!(sent.server_name.as_deref(), sni, "{}", self.name);
        others
            .iter()
            .flat_map(|other| forms(other.secret))
            .for_each(|form| assert_eq!(count(&sent, &form), 0, "{form} reached {}: {}", self.name, sent.head));
        sent
    }

    /// Asserts the own secret is on the wire once, raw, and in no other form.
    fn assert_secret_once(&self, sent: &RecordedRequest) {
        assert_eq!(count(sent, self.secret), 1, "{}", sent.head);
        forms(self.secret)
            .iter()
            .filter(|form| *form != self.secret)
            .for_each(|form| assert_eq!(count(sent, form), 0, "{form} in {}", sent.head));
    }
}

/// The three providers, the service with the config approved, and the fixture holding its directories.
struct Release {
    fixture: Fixture,
    service: Arc<ServiceContext>,
    fx: Provider,
    brave: Provider,
    venice: Provider,
}

impl Release {
    /// Starts the three upstreams and the service, adds each credential with `add`, and approves the config.
    async fn start() -> Self {
        let fixture = Fixture::new().await;
        let gate = Arc::new(tokio::sync::Notify::new());
        // The permit is stored, so the second chunk follows the first without the test opening the gate.
        gate.notify_one();
        let streamed = Reply::TwoChunks {
            first: "data: {\"delta\":\"he\"}\n\n".to_owned(),
            second: "data: [DONE]\n\n".to_owned(),
            gate,
        };
        let fx = Provider::start(&fixture, "fx", FX_SECRET, "localhost", Reply::ok("rates")).await;
        let brave = Provider::start(&fixture, "brave", BRAVE_SECRET, "127.0.0.2", Reply::ok("results")).await;
        let venice = Provider::start(&fixture, "venice", VENICE_SECRET, "127.0.0.3", streamed).await;
        let service = fixture.ready_with_peer(PEER_ACCOUNT).await;
        for provider in [&fx, &brave, &venice] {
            add(&service, provider).await;
        }
        let release = Self {
            fixture,
            service,
            fx,
            brave,
            venice,
        };
        let approved = approve(&release.service, &release.config(), &["yes", APPROVAL_PASSPHRASE]).await;
        assert!(
            matches!(approved.response, AdminResponse::ConfigApprove(_)),
            "{:?}",
            approved.response
        );
        release
    }

    /// The token caller `agent` on the fixture's socket with all three routes, and the peer caller `desk` on a socket of
    /// its own with Brave only.
    fn config(&self) -> String {
        let ca = "/etc/iron-vault/ca/test.pem";
        let rate = "{ requests = 100000, per_seconds = 1, burst = 100000 }";
        format!(
            r#"schema_version = 1

[listeners.local]
unix_socket = "{local}"
token_header = "{TOKEN_HEADER}"

[listeners.desk]
unix_socket = "{desk}"

[callers.agent]
listener = "local"
token_hash = "{hash}"
routes = ["fx", "brave", "venice"]

[callers.desk]
listener = "desk"
auth = "peer"
user = "{PEER_ACCOUNT}"
routes = ["brave"]

[routes.fx]
prefix = "/fx"
upstream = "https://{fx}"
ca_file = "{ca}"
credential = "fx"
slot = {{ query = "access_key" }}
methods = ["GET"]
paths = ["/latest"]
rate_limit = {rate}

[routes.brave]
prefix = "/brave"
upstream = "https://{brave}"
ca_file = "{ca}"
credential = "brave"
slot = {{ header = "X-Subscription-Token" }}
methods = ["GET"]
paths = ["/res/v1/web/search"]
rate_limit = {rate}

[routes.venice]
prefix = "/venice"
upstream = "https://{venice}/api/v1"
ca_file = "{ca}"
credential = "venice"
slot = {{ header = "Authorization", format = "Bearer {{}}" }}
methods = ["POST"]
paths = ["/chat/completions"]
rate_limit = {rate}
"#,
            local = self.fixture.socket().display(),
            desk = self.desk_socket().display(),
            hash = token_hash(TOKEN_BYTES),
            fx = authority(&self.fx),
            brave = authority(&self.brave),
            venice = authority(&self.venice),
        )
    }

    fn desk_socket(&self) -> PathBuf {
        self.fixture.path("desk.sock")
    }

    fn connections(&self) -> [usize; 3] {
        [&self.fx, &self.brave, &self.venice].map(|provider| provider.upstream.connections())
    }
}

/// `add` of `provider`'s static credential, enrolled for its upstream's origin alone.
async fn add(service: &Arc<ServiceContext>, provider: &Provider) {
    let (path, stop, task) = spawn_admin(service);
    let mut stream = UnixStream::connect(path).await.unwrap();
    let request = AdminRequest::Add {
        name: provider.name.to_owned(),
        kind: CredentialKind::Static,
        origins: vec![RequestedOrigin {
            host: provider.host.to_owned(),
            port: provider.upstream.port().to_string().parse().unwrap(),
        }],
    };
    send(&mut stream, &Frame::Request(request)).await;
    let added = converse(&mut stream, &[provider.secret]).await;
    let _ = stop.send(());
    // The next command binds the admin socket again, and the server's handlers hold the service until it ends.
    let _ = task.await;
    assert!(matches!(added.response, AdminResponse::Add { .. }), "{:?}", added.response);
}

fn authority(provider: &Provider) -> String {
    format!("{}:{}", provider.host, provider.upstream.port())
}

/// Sends `request` on a fresh connection to the Unix socket `socket` and reads the whole response.
async fn exchange(socket: &Path, request: &CallerRequest) -> Response {
    let mut stream = UnixStream::connect(socket).await.unwrap();
    stream.write_all(&request.to_bytes()).await.unwrap();
    let mut raw = Vec::new();
    tokio::time::timeout(WAIT, stream.read_to_end(&mut raw)).await.unwrap().unwrap();
    Response::parse(&String::from_utf8(raw).unwrap())
}

/// `secret` in every form `iron-vault-kinds/src/scrub.rs` derives: as sent, percent-encoded with upper- and lowercase
/// escapes, and in standard and URL-safe base64 with and without padding.
fn forms(secret: &str) -> Vec<String> {
    let encoded = encode_query_value(secret);
    let base64 = [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD].map(|engine| engine.encode(secret));
    let mut forms: Vec<String> = [secret.to_owned(), lowercase_escapes(&encoded), encoded]
        .into_iter()
        .chain(base64)
        .collect();
    forms.sort();
    forms.dedup();
    forms
}

/// `encoded` with the two hex digits after each `%` in lowercase.
fn lowercase_escapes(encoded: &str) -> String {
    let mut pieces = encoded.split('%');
    let first = pieces.next().unwrap_or_default().to_owned();
    pieces.fold(first, |text, piece| {
        let split = piece.len().min(2);
        format!("{text}%{}{}", piece[..split].to_ascii_lowercase(), &piece[split..])
    })
}

/// How many times the request head and body together hold `needle`.
fn count(sent: &RecordedRequest, needle: &str) -> usize {
    format!("{}\r\n\r\n{}", sent.head, String::from_utf8_lossy(&sent.body))
        .matches(needle)
        .count()
}

fn header_values(sent: &RecordedRequest, name: &str) -> Vec<String> {
    sent.headers()
        .into_iter()
        .filter(|(n, _)| n == name)
        .map(|(_, value)| value)
        .collect()
}

/// §19: "FX, Brave, and Venice requests carry the correct credential only to the enrolled origin and selected slot."
///
/// One token caller sends a request on each route. Each upstream receives exactly one request, at its own authority,
/// with its own secret once in the route's slot and neither other secret in any form.
#[tokio::test]
async fn fx_brave_and_venice_each_carry_only_their_own_credential_to_their_enrolled_origin_and_slot() {
    let release = Release::start().await;
    let socket = release.fixture.socket();
    let venice = CallerRequest::post("/venice/chat/completions", VENICE_BODY.as_bytes())
        .header("Content-Type", "application/json")
        .header("Authorization", "Bearer placeholder");

    let fx = exchange(&socket, &CallerRequest::get("/fx/latest?base=USD").signed(Via::Unix)).await;
    let brave = exchange(&socket, &CallerRequest::get("/brave/res/v1/web/search?q=rust").signed(Via::Unix)).await;
    let streamed = exchange(&socket, &venice.signed(Via::Unix)).await;

    assert_eq!([fx.status, brave.status, streamed.status], [200; 3]);
    assert_eq!(streamed.header("transfer-encoding"), Some("chunked"));
    assert!(streamed.body.contains("data: [DONE]\n\n"), "{}", streamed.body);
    let Release { fx, brave, venice, .. } = &release;

    let sent = fx.sole_request(&[brave, venice]);
    assert_eq!(sent.request_line(), format!("GET /latest?base=USD&access_key={FX_SECRET} HTTP/1.1"));
    fx.assert_secret_once(&sent);

    let sent = brave.sole_request(&[fx, venice]);
    assert_eq!(sent.request_line(), "GET /res/v1/web/search?q=rust HTTP/1.1");
    assert_eq!(header_values(&sent, "x-subscription-token"), [BRAVE_SECRET]);
    brave.assert_secret_once(&sent);

    let sent = venice.sole_request(&[fx, brave]);
    assert_eq!(sent.request_line(), "POST /api/v1/chat/completions HTTP/1.1");
    assert_eq!(header_values(&sent, "authorization"), [format!("Bearer {VENICE_SECRET}")]);
    assert_eq!((sent.body.as_slice(), sent.body_complete), (VENICE_BODY.as_bytes(), true));
    venice.assert_secret_once(&sent);
    assert!(
        [&fx, &brave, &venice]
            .iter()
            .all(|p| p.upstream.requests().iter().all(|r| !r.head.contains(TOKEN_HEADER))),
        "the caller token header reached an upstream"
    );
}

/// §19: "FX, Brave, and Venice requests carry the correct credential only to the enrolled origin and selected slot."
///
/// A caller recognised by its Unix peer account (§7), with no token, reaches the one route it is granted and gets that
/// route's egress. Its request for a route it is not granted is refused with 403 before any upstream is contacted.
#[tokio::test]
async fn a_peer_account_caller_reaches_its_route_and_no_other() {
    let release = Release::start().await;
    let socket = release.desk_socket();

    let granted = exchange(&socket, &CallerRequest::get("/brave/res/v1/web/search?q=rust")).await;

    assert_eq!(granted.status, 200);
    let Release { fx, brave, venice, .. } = &release;
    let sent = brave.sole_request(&[fx, venice]);
    assert_eq!(header_values(&sent, "x-subscription-token"), [BRAVE_SECRET]);
    brave.assert_secret_once(&sent);
    assert_eq!(release.connections(), [0, 1, 0]);

    let refused = exchange(&socket, &CallerRequest::get("/fx/latest?base=USD")).await;

    assert_eq!(refused.status, 403);
    assert!(!format!("{:?}{}", refused.headers, refused.body).contains(FX_SECRET));
    assert_eq!(release.connections(), [0, 1, 0]);
}
