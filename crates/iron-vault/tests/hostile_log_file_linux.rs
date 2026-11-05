//! The whole log file after a hostile run holds none of the never-log values (specification §3.15; `design/audit-logging.md`,
//! "Never logged"; K-85 and K-95 do the same for the stderr log of the upstream client).
//!
//! The service logs through the rolling-file destination (`LogFile` in a verified directory) with the production
//! subscriber at global `TRACE` (`subscriber_at`), where the service itself installs `INFO` and ignores `RUST_LOG`.
//! The binary runs with `RUST_LOG=trace` too. The run sends requests that use a header
//! slot, a query slot and Basic, with a caller token, a query string and header values the caller chose, to an upstream
//! that echoes the credential, to one that fails mid-body (HTTP/2: resets the stream) and to one nobody listens on, and
//! types a credential and approval passphrases at the binary's prompts. Then every file in the log directory is read.
//!
//! The subscriber is the process-wide default, so records written on the blocking pool (the passphrase, vault and approval
//! work) reach the file too. One test runs the HTTP/1.1 session and then the HTTP/2 session, because a global default can
//! be installed once per process.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use common::WAIT;
use common::approval_harness::{APPROVAL_PASSPHRASE, Fixture, IDENTITY, WRONG_PASSPHRASE, get, serve_admin};
use common::mock_upstream::{MockUpstream, Reply, TestCa};
use common::mock_upstream_h2::{H2Reply, MockH2Upstream};
use common::proxy_harness::{CallerRequest, Credential, Proxy, Setup, TOKEN_BYTES, Via, next_free_port, token_hash, token_of};
use common::scrub_stream::url_forms;
use iron_vault::deployment::DeploymentProfile;
use iron_vault::logging::{LogDir, LogFailure, LogFile, subscriber_at};
use iron_vault::path_metadata::invoking_user;
use iron_vault_kinds::CredentialMaterial;
use tracing_subscriber::filter::LevelFilter;

const HEADER_KEY: &str = "hdr-key-Vq7e2c91";
/// Characters that percent-encoding and the query slot both change.
const QUERY_KEY: &str = "qry/key+7d1=f3&x";
const BASIC_USER: &str = "basic-user-4a9";
const BASIC_PASSWORD: &str = "p@ss/w0rd+8c2";
const CUT_KEY: &str = "cut-key-61fb08d4";
const DEAD_KEY: &str = "dead-key-c3a5e7b0";
const ADDED_KEY: &str = "ADDED-key/typed+5e0b=";
const FIXTURE_KEY: &str = "fx-secret";
/// In the body every upstream sends; a log never holds a response body.
const BODY_MARKER: &str = "UPSTREAMBODY-marker-4d2e";

/// What the caller chooses: a query string, header values, and credentials of its own that the service replaces.
const CALLER_QUERY: &str = "callerqs-3f9a1c";
const CALLER_HEADERS: [(&str, &str); 4] = [
    ("X-Caller-Note", "callerhdr-note-82d1"),
    ("User-Agent", "callerhdr-agent-5b07"),
    ("Referer", "https://caller.example/callerhdr-ref-19ce"),
    ("Cookie", "session=callerhdr-cookie-a4f8"),
];
const CALLER_AUTHORIZATION: &str = "Bearer callerhdr-auth-7e63";
const WRONG_TOKEN_BYTES: [u8; 32] = [9; 32];

/// Fixed fields of every record, and the values the constant ones hold.
const FIXED_FIELDS: [&str; 8] = [
    "timestamp",
    "level",
    "target",
    "service",
    "service_version",
    "schema_version",
    "deployment_profile",
    "message",
];

#[derive(Clone, Copy, Debug)]
enum Upstream {
    Http1,
    Http2,
}

// ---- The log -----------------------------------------------------------------------------------------------------

/// A fresh log directory under cargo's scratch space, removed on drop.
struct LogDirectory(PathBuf);

impl LogDirectory {
    fn new(name: &str) -> Self {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("hostile-log-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
        Self(dir)
    }

    /// Every file in the directory, as text, in name order.
    fn files(&self) -> Vec<(String, String)> {
        let mut names: Vec<_> = fs::read_dir(&self.0).unwrap().map(|entry| entry.unwrap().path()).collect();
        names.sort();
        names
            .iter()
            .map(|path| {
                (
                    path.display().to_string(),
                    String::from_utf8_lossy(&fs::read(path).unwrap()).into_owned(),
                )
            })
            .collect()
    }

    /// Every line of every file, parsed; a line that is not a JSON object fails the test.
    fn records(&self) -> Vec<serde_json::Value> {
        self.files()
            .iter()
            .flat_map(|(name, text)| {
                text.lines().map(move |line| {
                    let record: serde_json::Value = serde_json::from_str(line).unwrap_or_else(|e| panic!("{name}: not JSON ({e}): {line}"));
                    assert!(record.is_object(), "{name}: {line}");
                    record
                })
            })
            .collect()
    }

    /// The records written so far, leaving out a last line still being written.
    fn finished_records(&self) -> Vec<serde_json::Value> {
        self.files()
            .iter()
            .flat_map(|(_, text)| {
                text.rsplit_once('\n')
                    .map_or("", |(done, _)| done)
                    .lines()
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .map(|line| serde_json::from_str(&line).unwrap_or_else(|e| panic!("not JSON ({e}): {line}")))
            .collect()
    }

    fn text(&self) -> String {
        self.files().into_iter().map(|(_, text)| text).collect()
    }
}

impl Drop for LogDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Installs the process-wide subscriber: the production one at global `TRACE`, writing to the log file in `dir`.
fn log_to_file(dir: &LogDirectory) {
    let owner = invoking_user().unwrap();
    let file = LogFile::open(LogDir::open_leaf_only(&dir.0, owner).unwrap(), owner, LogFailure::default()).unwrap();
    let subscriber = subscriber_at(file, DeploymentProfile::Development, LevelFilter::TRACE);
    tracing::subscriber::set_global_default(subscriber).unwrap();
}

// ---- What must not appear ------------------------------------------------------------------------------------------

/// Every form of `secret` the scrubber recognises that a log could hold: plain, base64 (standard and URL-safe, with
/// and without padding) and percent-encoded.
fn forms(secret: &str) -> Vec<String> {
    let bytes = secret.as_bytes();
    vec![
        secret.to_owned(),
        STANDARD.encode(bytes),
        STANDARD_NO_PAD.encode(bytes),
        URL_SAFE.encode(bytes),
        URL_SAFE_NO_PAD.encode(bytes),
    ]
    .into_iter()
    .chain(url_forms(secret))
    .collect()
}

/// Everything the log must not hold, as `(what, text)`, with every form of each secret and the pieces of the upstream URL.
fn forbidden(ports: &[u16]) -> Vec<(String, String)> {
    let basic = format!("{BASIC_USER}:{BASIC_PASSWORD}");
    let secrets = [
        HEADER_KEY,
        QUERY_KEY,
        BASIC_USER,
        BASIC_PASSWORD,
        basic.as_str(),
        CUT_KEY,
        DEAD_KEY,
        ADDED_KEY,
        FIXTURE_KEY,
        APPROVAL_PASSPHRASE,
        WRONG_PASSPHRASE,
        IDENTITY,
        BODY_MARKER,
    ];
    // Each marker alone, since a leak need not carry the whole header value or query string.
    let caller_values =
        CALLER_HEADERS
            .iter()
            .map(|(_, value)| *value)
            .chain([CALLER_QUERY, CALLER_AUTHORIZATION, "callerhdr-", "callerqs-"]);
    let tokens = [token_of(TOKEN_BYTES), token_of(WRONG_TOKEN_BYTES)];
    // The log names the upstream host and, in an approval summary, the configured origin and route paths; it never names
    // a request's own path or query, nor the credential's query parameter.
    let url_parts = [
        "127.0.0.1",
        "access_key",
        "/v1/rates",
        "/v1/ledger",
        "/v1/stream",
        "/latest",
        "rates",
        "ledger",
        "tail-x9",
        "base=USD",
    ];
    let ports = ports.iter().map(|port| format!("localhost:{port}/"));
    secrets
        .into_iter()
        .map(str::to_owned)
        .chain(caller_values.map(str::to_owned))
        .chain(tokens)
        .flat_map(|secret| forms(&secret).into_iter().map(move |form| (secret.clone(), form)))
        .chain(url_parts.iter().map(|part| ((*part).to_owned(), (*part).to_owned())))
        .chain(ports.map(|port| (port.clone(), port)))
        .collect()
}

/// A body that shows `key` the ways an upstream echoes one: plain, base64 and percent-encoded.
fn echo_of(key: &str) -> String {
    format!(
        "{{\"key\":\"{key}\",\"b64\":\"{}\",\"url\":\"{}\",\"note\":\"{BODY_MARKER}\"}}",
        STANDARD.encode(key),
        url_forms(key)[1]
    )
}

// ---- The proxy run -----------------------------------------------------------------------------------------------

/// Ports of the five upstreams.
struct Ports {
    header: u16,
    query: u16,
    basic: u16,
    cut: u16,
    dead: u16,
}

impl Ports {
    fn all(&self) -> [u16; 5] {
        [self.header, self.query, self.basic, self.cut, self.dead]
    }
}

fn route(name: &str, upstream: &str, slot: &str, paths: &str, port: u16, credential: &str) -> String {
    format!(
        "[routes.{name}]\nprefix = \"/{name}\"\nupstream = \"https://localhost:{port}{upstream}\"\n\
         ca_file = \"/etc/iron-vault/ca/test.pem\"\n\
         credential = \"{credential}\"\nslot = {slot}\nmethods = [\"GET\"]\npaths = [\"{paths}\"]\n\
         rate_limit = {{ requests = 1000, per_seconds = 1, burst = 1000 }}\n\n"
    )
}

fn callers_and_routes(ports: &Ports) -> String {
    let hash = token_hash(TOKEN_BYTES);
    let header = "{ header = \"X-Api-Key\" }";
    [
        format!(
            "[callers.agent]\nlistener = \"local\"\ntoken_hash = \"{hash}\"\nroutes = [\"hdr\", \"qry\", \"basic\", \"cut\", \"dead\"]\n\n"
        ),
        route("hdr", "/v1", header, "/v1/**", ports.header, "hdr_key"),
        route("qry", "", "{ query = \"access_key\" }", "/latest", ports.query, "qry_key"),
        route("basic", "/v1", "\"basic\"", "/v1/**", ports.basic, "basic_cred"),
        route("cut", "/v1", header, "/v1/**", ports.cut, "cut_key"),
        route("dead", "/v1", header, "/v1/**", ports.dead, "dead_key"),
    ]
    .concat()
}

fn credentials(ports: &Ports) -> Vec<Credential> {
    let fixed = |name, key: &str, port| Credential {
        name,
        material: CredentialMaterial::Static { key: key.into() },
        port,
    };
    vec![
        fixed("hdr_key", HEADER_KEY, ports.header),
        fixed("qry_key", QUERY_KEY, ports.query),
        Credential {
            name: "basic_cred",
            material: CredentialMaterial::Basic {
                username: BASIC_USER.into(),
                password: BASIC_PASSWORD.into(),
            },
            port: ports.basic,
        },
        fixed("cut_key", CUT_KEY, ports.cut),
        fixed("dead_key", DEAD_KEY, ports.dead),
    ]
}

/// The upstreams, kept alive for the run.
#[allow(dead_code)] // Held only so the servers keep running.
enum Upstreams {
    Http1(Vec<MockUpstream>),
    Http2(Vec<MockH2Upstream>),
}

/// Starts the three echoing upstreams and the one that fails mid-body, in `protocol`; the fifth port has no listener.
async fn start_upstreams(ca: &TestCa, protocol: Upstream) -> (Upstreams, Ports) {
    let echoes = [HEADER_KEY, QUERY_KEY, BASIC_PASSWORD].map(echo_of);
    let dead = next_free_port();
    match protocol {
        Upstream::Http1 => {
            let mut servers = Vec::new();
            for body in &echoes {
                servers.push(MockUpstream::start(ca, echoing(body)).await);
            }
            servers.push(MockUpstream::start(ca, Reply::Truncated { sent: BODY_MARKER.into() }).await);
            let p = |at: usize| servers[at].port();
            let ports = Ports {
                header: p(0),
                query: p(1),
                basic: p(2),
                cut: p(3),
                dead,
            };
            (Upstreams::Http1(servers), ports)
        }
        Upstream::Http2 => {
            let mut servers = Vec::new();
            for body in &echoes {
                servers.push(MockH2Upstream::start(ca, H2Reply::ok(body)).await);
            }
            servers.push(MockH2Upstream::start(ca, H2Reply::Reset(h2::Reason::INTERNAL_ERROR)).await);
            let p = |at: usize| servers[at].port();
            let ports = Ports {
                header: p(0),
                query: p(1),
                basic: p(2),
                cut: p(3),
                dead,
            };
            (Upstreams::Http2(servers), ports)
        }
    }
}

/// A reply that echoes the credential in the body and in a header.
fn echoing(body: &str) -> Reply {
    Reply::Respond {
        status: 200,
        headers: vec![("x-echo".to_owned(), HEADER_KEY.to_owned())],
        body: body.as_bytes().to_vec(),
    }
}

/// A caller's `GET target` with the caller's own query string, header values and an `Authorization` of its own.
fn hostile_get(target: &str) -> CallerRequest {
    CALLER_HEADERS
        .iter()
        .fold(CallerRequest::get(target), |request, (name, value)| request.header(name, value))
        .header("Authorization", CALLER_AUTHORIZATION)
        .header("X-Api-Key", CALLER_AUTHORIZATION)
}

/// Sends every request of the proxy run and returns how many it sent.
async fn hostile_requests(proxy: &Proxy) -> usize {
    let endpoints = proxy.endpoints();
    let query = format!("callerqs={CALLER_QUERY}&base=USD");
    let signed = |target: &str| hostile_get(&format!("{target}?{query}")).signed(Via::Unix);
    let wrong_token = hostile_get(&format!("/hdr/v1/rates?{query}")).with_token(Via::Unix, WRONG_TOKEN_BYTES);
    let requests = [
        signed("/hdr/v1/rates"),
        signed("/qry/latest"),
        signed("/basic/v1/ledger"),
        signed("/cut/v1/tail-x9"),
        signed("/dead/v1/rates"),
        wrong_token,
        signed("/nowhere/v1/rates"),
    ];
    for request in &requests {
        endpoints.send_raw(Via::Unix, request).await;
    }
    requests.len()
}

// ---- The administrative run --------------------------------------------------------------------------------------

/// Runs the binary against `socket` with `RUST_LOG=trace`, typing `input` at its prompts, and returns its exit code.
async fn cli(socket: &Path, args: &[&str], input: &str) -> Option<i32> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_iron-vault"));
    command
        .args(args)
        .arg("--admin-socket")
        .arg(socket)
        .env("RUST_LOG", "trace")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let input = input.to_owned();
    tokio::task::spawn_blocking(move || {
        let mut child = command.spawn().unwrap();
        std::io::Write::write_all(&mut child.stdin.take().unwrap(), input.as_bytes()).unwrap();
        child.wait().unwrap().code()
    })
    .await
    .unwrap()
}

/// `add` with a typed key, a refused approval with a wrong passphrase, then an approval with the right one; returns the
/// number of requests the run sent.
async fn administrative_run() -> usize {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    let (socket, stop) = serve_admin(&service);
    let origin = format!("localhost:{}", fixture.upstream().port());
    assert_eq!(
        cli(&socket, &["add", "added_key", "--origin", &origin], &format!("{ADDED_KEY}\n")).await,
        Some(0)
    );
    let proposed = fixture.path("proposed.toml");
    fs::write(&proposed, fixture.config("fx2")).unwrap();
    let approve = |passphrase: &str| (["config", "approve"], format!("yes\n{passphrase}\n"));
    let (args, answers) = approve(WRONG_PASSPHRASE);
    assert_eq!(
        cli(&socket, &[args[0], args[1], proposed.to_str().unwrap()], &answers).await,
        Some(1)
    );
    let (args, answers) = approve(APPROVAL_PASSPHRASE);
    assert_eq!(
        cli(&socket, &[args[0], args[1], proposed.to_str().unwrap()], &answers).await,
        Some(0)
    );
    assert_eq!(get(&fixture, "fx2").await.status, 200);
    let _ = stop.send(());
    1
}

// ---- The checks --------------------------------------------------------------------------------------------------

/// How many request events are in the log, counting finished lines only.
fn request_events_written(dir: &LogDirectory) -> usize {
    dir.finished_records()
        .iter()
        .filter(|record| record["target"] == "iron-vault.request")
        .count()
}

/// Waits until `expected` request events are in the log, then until a pause shows no more come.
async fn wait_for_request_events(dir: &LogDirectory, expected: usize) {
    tokio::time::timeout(WAIT, async {
        while request_events_written(dir) < expected {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{} of {expected} request events: {}", request_events_written(dir), dir.text()));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(request_events_written(dir), expected, "{}", dir.text());
}

fn assert_fixed_fields(record: &serde_json::Value) {
    FIXED_FIELDS
        .iter()
        .for_each(|field| assert!(!record[field].is_null(), "{field} missing: {record}"));
    assert_eq!(record["service"], "iron-vault", "{record}");
    assert_eq!(record["service_version"], env!("CARGO_PKG_VERSION"), "{record}");
    assert_eq!(record["schema_version"], 1, "{record}");
    assert_eq!(record["deployment_profile"], "development", "{record}");
    assert!(record["timestamp"].as_str().is_some_and(|stamp| stamp.ends_with('Z')), "{record}");
    assert!(
        ["ERROR", "WARN", "INFO", "DEBUG", "TRACE"].contains(&record["level"].as_str().unwrap()),
        "{record}"
    );
}

fn assert_one_request_event_each(records: &[serde_json::Value], requests: usize) {
    let events: Vec<_> = records.iter().filter(|record| record["target"] == "iron-vault.request").collect();
    assert_eq!(events.len(), requests);
    let ids: BTreeSet<_> = events.iter().map(|event| event["request_id"].to_string()).collect();
    assert_eq!(ids.len(), requests, "a request id repeats: {events:?}");
    records
        .iter()
        .filter(|record| record["event"] == "response.scrubbed")
        .for_each(|scrub| assert!(ids.contains(&scrub["request_id"].to_string()), "no request event for {scrub}"));
}

/// `(route, outcome, reason)` of each request event, in order of route then reason.
fn endings(records: &[serde_json::Value]) -> Vec<(Option<String>, String, Option<String>)> {
    let text = |value: &serde_json::Value| value.as_str().map(str::to_owned);
    let mut endings: Vec<_> = records
        .iter()
        .filter(|record| record["target"] == "iron-vault.request")
        .map(|event| {
            (
                text(&event["route"]),
                text(&event["outcome"]).unwrap_or_default(),
                text(&event["reason"]),
            )
        })
        .collect();
    endings.sort();
    endings
}

/// Checks that each hostile path ran and ended the way it should: the routes answered, the failing upstreams failed with
/// their reasons, both refusals were refused, and each echo was scrubbed once.
fn assert_hostile_paths_ran(records: &[serde_json::Value], protocol: Upstream) {
    let cut = match protocol {
        Upstream::Http1 => "upstream_body",
        Upstream::Http2 => "upstream_protocol",
    };
    let ending = |route: Option<&str>, outcome: &str, reason: Option<&str>| {
        (route.map(str::to_owned), outcome.to_owned(), reason.map(str::to_owned))
    };
    let mut expected = vec![
        ending(Some("hdr"), "success", None),
        ending(Some("qry"), "success", None),
        ending(Some("basic"), "success", None),
        ending(Some("fx2"), "success", None),
        ending(Some("cut"), "failure", Some(cut)),
        ending(Some("dead"), "failure", Some("upstream_connect")),
        ending(None, "failure", Some("unauthenticated")),
        ending(None, "failure", Some("no_route")),
    ];
    expected.sort();
    assert_eq!(endings(records), expected, "{records:?}");
    ["hdr", "qry", "basic"].iter().for_each(|route| {
        let scrubs = records
            .iter()
            .filter(|r| r["event"] == "response.scrubbed" && r["route"] == *route)
            .count();
        assert_eq!(scrubs, 1, "{route}: {records:?}");
    });
    let events = |name: &str| records.iter().filter(|record| record["event"] == name).count();
    assert_eq!(events("credential.added"), 1, "{records:?}");
    assert_eq!(events("config.approval-completed"), 1, "{records:?}");
    let denied = records
        .iter()
        .filter(|record| record["message"].as_str().is_some_and(|m| m.starts_with(DENIAL)))
        .count();
    assert_eq!(denied, 1, "the wrong passphrase was not logged on the blocking pool: {records:?}");
}

/// The start of the warning a wrong approval passphrase logs, from a task on the blocking pool.
const DENIAL: &str = "the approval passphrase check failed";

/// One session against `protocol` upstreams: the proxy run and the administrative run. Returns the upstream ports and the
/// number of requests sent.
async fn hostile_session(protocol: Upstream) -> (Ports, usize) {
    let ca = TestCa::new("hostile log CA");
    let (_upstreams, ports) = start_upstreams(&ca, protocol).await;
    let proxy = Proxy::start(Setup {
        ca: &ca,
        callers_and_routes: callers_and_routes(&ports),
        credentials: credentials(&ports),
        tcp: false,
        request_timeout_secs: 30,
    })
    .await;
    let requests = hostile_requests(&proxy).await + administrative_run().await;
    (ports, requests)
}

#[tokio::test]
async fn the_whole_log_file_holds_no_forbidden_value_after_a_hostile_run_over_http1_and_http2() {
    let dir = LogDirectory::new("both");
    log_to_file(&dir);
    let (mut requests, mut seen, mut ports) = (0, 0, Vec::new());
    for protocol in [Upstream::Http1, Upstream::Http2] {
        let (session_ports, sent) = hostile_session(protocol).await;
        requests += sent;
        ports.extend(session_ports.all());
        wait_for_request_events(&dir, requests).await;
        let records = dir.records();
        assert_hostile_paths_ran(&records[seen..], protocol);
        seen = records.len();
    }

    let records = dir.records();
    records.iter().for_each(assert_fixed_fields);
    assert_one_request_event_each(&records, requests);
    assert!(
        records
            .iter()
            .any(|record| ["DEBUG", "TRACE"].contains(&record["level"].as_str().unwrap())),
        "the log holds nothing below INFO, so the verbose setting was not exercised"
    );
    let text = dir.text();
    forbidden(&ports).iter().for_each(|(what, form)| {
        assert!(!text.contains(form.as_str()), "{what} appears in the log as {form:?}:\n{text}");
    });
}
