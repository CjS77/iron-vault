//! The upstream client in an environment a user controls (specification §3.7, R-8; §3.12 for diagnostics).
//!
//! Each test name starts with the rule it proves: a §3.7 rule, or §3.8's for the redirect. A test sets hostile
//! variables (proxies, trust stores, a key log, verbose `RUST_LOG`) and asserts on what the mock servers actually
//! recorded, as §8 requires, not on how the client was built.
//!
//! `std::env::set_var` is `unsafe` in edition 2024 and the workspace forbids unsafe code, so the variables are set on a
//! child process instead: the test re-runs this test binary with `--exact` [`CHILD_TEST`] and the variables. The child
//! sends one checked request through `UpstreamClient` and prints the outcome on stdout; the parent owns the mock servers.
//! Every case runs once with a credential marker in a header slot and once with another in a query slot, and the
//! child's stdout and stderr must contain neither marker.
//!
//! Linux only: the mock upstream terminates TLS with `tokio-rustls`, which this crate depends on only on Linux.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::panic)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

use common::checked::checked;
use common::mock_upstream::{MockUpstream, RecordedRequest, Reply, TestCa, UPSTREAM_HOST};
use iron_vault::upstream::client::{TransportLimits, UpstreamClient, UpstreamResponse};
use iron_vault::upstream::transport_error::TransportError;
use iron_vault::upstream::trust::UpstreamTrust;
use iron_vault_policy::Method;

/// The credential the header-slot route injects.
const HEADER_MARKER: &str = "IVhdrMark3rSecret";

/// The credential the query-slot route injects.
const QUERY_MARKER: &str = "IVqryMark3rSecret";

/// The test this binary runs as a child; it does nothing unless [`CHILD_VAR`] is set.
const CHILD_TEST: &str = "child_sends_the_request_its_parent_describes";

/// Set on a child: the upstream origin to send to.
const CHILD_VAR: &str = "IRON_VAULT_TEST_HOSTILE_CHILD_ORIGIN";

/// Set on a child: `header` or `query`, the slot that carries the credential.
const SLOT_VAR: &str = "IRON_VAULT_TEST_HOSTILE_CHILD_SLOT";

/// Set on a child whose route pins a CA: the PEM file holding it. Unset, the route uses the built-in roots.
const PINNED_VAR: &str = "IRON_VAULT_TEST_HOSTILE_CHILD_PINNED_CA";

/// Set on a child that installs the service's logging before sending.
const LOGGING_VAR: &str = "IRON_VAULT_TEST_HOSTILE_CHILD_LOGGING";

/// Starts each line a child reports on, so the parent finds it among the test harness's own output.
const TAG: &str = "iv-child ";

/// What a logging child writes through the service's subscriber after sending, proving its stderr carries that output.
const LOGGED: &str = "hostile-env child sent its request";

/// Variables a child never inherits from the test's own environment, so only the case decides them. `NO_PROXY` would
/// exempt `localhost` from the proxy variables and let the proxy case pass without testing anything.
const AMBIENT: [&str; 12] = [
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "SSLKEYLOGFILE",
    "RUST_LOG",
];

/// The slot a case's credential marker travels in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Slot {
    Header,
    Query,
}

impl Slot {
    fn name(self) -> &'static str {
        match self {
            Self::Header => "header",
            Self::Query => "query",
        }
    }

    fn parse(name: &str) -> Self {
        match name {
            "header" => Self::Header,
            "query" => Self::Query,
            other => panic!("unknown slot {other:?}"),
        }
    }

    fn marker(self) -> &'static str {
        match self {
            Self::Header => HEADER_MARKER,
            Self::Query => QUERY_MARKER,
        }
    }

    /// The caller request target, routed to this slot's route.
    fn target(self) -> String {
        format!("/{}/rates?base=USD", self.name())
    }

    /// Whether `request` carries this slot's marker where the slot puts it.
    fn carried_by(self, request: &RecordedRequest) -> bool {
        match self {
            Self::Header => request.headers().contains(&("x-api-key".to_owned(), HEADER_MARKER.to_owned())),
            Self::Query => request.request_line() == format!("GET /v1/rates?base=USD&access_key={QUERY_MARKER} HTTP/1.1"),
        }
    }
}

// ---- Child -------------------------------------------------------------------------------------------------------

/// The child half of every case: sends the request [`CHILD_VAR`] and its siblings describe and prints the outcome.
/// Run by the test harness without those variables, it does nothing.
#[tokio::test]
async fn child_sends_the_request_its_parent_describes() {
    let Ok(origin) = std::env::var(CHILD_VAR) else {
        return;
    };
    let logging = std::env::var_os(LOGGING_VAR).is_some();
    if logging {
        iron_vault::logging::init().unwrap();
    }
    let slot = Slot::parse(&std::env::var(SLOT_VAR).unwrap());
    let request = checked(&origin, Method::Get, &slot.target(), &[], slot.marker());
    let client = UpstreamClient::new(&child_trust(), TransportLimits::default()).unwrap();
    report(client.send(request).await);
    if logging {
        tracing::info!("{LOGGED}");
    }
}

/// The route's trust: the CA in [`PINNED_VAR`]'s file if set, else the built-in roots.
fn child_trust() -> UpstreamTrust {
    std::env::var_os(PINNED_VAR).map_or(UpstreamTrust::BuiltIn, |path| {
        let path = PathBuf::from(path);
        UpstreamTrust::pinned_from_pem(&path, &fs::read(&path).unwrap()).unwrap()
    })
}

/// Prints `outcome: status <code>` and any `location`, or `outcome: error <variant>` with the error's `Display`,
/// `Debug` and alternate `Debug` forms.
fn report(outcome: Result<UpstreamResponse, TransportError>) {
    match outcome {
        Ok(response) => {
            println!("{TAG}outcome: status {}", response.status().as_u16());
            if let Some(location) = response.headers().get("location") {
                println!("{TAG}location: {}", location.to_str().unwrap());
            }
        }
        Err(error) => {
            println!("{TAG}outcome: error {error:?}");
            println!("{TAG}display: {error}");
            println!("{TAG}debug: {error:?}");
            println!("{TAG}alternate: {error:#?}");
        }
    }
}

// ---- Parent ------------------------------------------------------------------------------------------------------

/// One child run: the request it sends and the environment it sends it in.
struct Case {
    slot: Slot,
    origin: String,
    pinned: Option<PathBuf>,
    logging: bool,
    env: Vec<(String, String)>,
}

impl Case {
    fn new(slot: Slot, origin: String) -> Self {
        Self {
            slot,
            origin,
            pinned: None,
            logging: false,
            env: Vec::new(),
        }
    }

    fn pinned(self, pem: &Path) -> Self {
        Self {
            pinned: Some(pem.to_owned()),
            ..self
        }
    }

    fn logging(self) -> Self {
        Self { logging: true, ..self }
    }

    fn env(mut self, name: &str, value: &str) -> Self {
        self.env.push((name.to_owned(), value.to_owned()));
        self
    }

    fn command(&self) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", CHILD_TEST, "--nocapture", "--test-threads=1"])
            .env(CHILD_VAR, &self.origin)
            .env(SLOT_VAR, self.slot.name());
        AMBIENT.iter().for_each(|name| {
            command.env_remove(name);
        });
        self.pinned.iter().for_each(|pem| {
            command.env(PINNED_VAR, pem);
        });
        if self.logging {
            command.env(LOGGING_VAR, "1");
        }
        command.envs(self.env.iter().map(|(name, value)| (name, value)));
        command
    }

    /// Runs the child to completion off the runtime thread, so the mock servers keep serving meanwhile.
    async fn run(self) -> ChildRun {
        let mut command = self.command();
        let output = tokio::task::spawn_blocking(move || command.output().unwrap()).await.unwrap();
        ChildRun::checked(self.slot, output)
    }
}

/// A finished child's output, already checked to have exited cleanly and printed neither marker.
struct ChildRun {
    stdout: String,
    stderr: String,
}

impl ChildRun {
    fn checked(slot: Slot, output: Output) -> Self {
        let run = Self {
            stdout: String::from_utf8(output.stdout).unwrap(),
            stderr: String::from_utf8(output.stderr).unwrap(),
        };
        assert!(output.status.success(), "{slot:?} child failed: {run}");
        [HEADER_MARKER, QUERY_MARKER].iter().for_each(|marker| {
            assert!(!run.stdout.contains(marker), "{slot:?} child's stdout shows {marker}: {run}");
            assert!(!run.stderr.contains(marker), "{slot:?} child's stderr shows {marker}: {run}");
        });
        run
    }

    /// The value of the child's `name: ` line. The harness prints the test's name on the same line as the first one.
    fn line(&self, name: &str) -> Option<&str> {
        let prefix = format!("{TAG}{name}: ");
        self.stdout
            .lines()
            .find_map(|line| line.split_once(prefix.as_str()).map(|(_, value)| value))
    }

    fn assert_status(&self, status: u16) {
        assert_eq!(self.line("outcome"), Some(format!("status {status}").as_str()), "{self}");
    }

    /// Asserts the child failed with `expected`, and that no printed form of the error shows a marker or any part of
    /// the request URL (§3.12: no raw secret-bearing client diagnostics).
    fn assert_error(&self, expected: TransportError) {
        assert_eq!(self.line("outcome"), Some(format!("error {expected:?}").as_str()), "{self}");
        let forbidden = [
            HEADER_MARKER,
            QUERY_MARKER,
            UPSTREAM_HOST,
            "127.0.0.1",
            "https",
            "/v1",
            "access_key",
            "base=USD",
        ];
        ["display", "debug", "alternate"].iter().for_each(|form| {
            let text = self.line(form).unwrap_or_else(|| panic!("no {form} line: {self}"));
            forbidden
                .iter()
                .for_each(|part| assert!(!text.contains(part), "{form} {text:?} contains {part:?}"));
        });
    }
}

impl std::fmt::Display for ChildRun {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\n--- stdout ---\n{}\n--- stderr ---\n{}", self.stdout, self.stderr)
    }
}

/// A fresh directory under the system temp directory, removed on drop.
struct TempDir(PathBuf);

static NEXT: AtomicU32 = AtomicU32::new(0);

impl TempDir {
    fn new() -> Self {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("iv-hostile-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        Self(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    /// Writes `ca`'s certificate to `name` and returns its path.
    fn write_ca(&self, name: &str, ca: &TestCa) -> PathBuf {
        let path = self.path(name);
        fs::write(&path, ca.pem()).unwrap();
        path
    }

    fn entries(&self) -> Vec<PathBuf> {
        fs::read_dir(&self.0).unwrap().map(|entry| entry.unwrap().path()).collect()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The only request `upstream` recorded, which must carry `slot`'s marker.
fn assert_carried(upstream: &MockUpstream, slot: Slot) {
    let requests = upstream.requests();
    assert_eq!(requests.len(), 1, "{requests:?}");
    assert!(slot.carried_by(&requests[0]), "{slot:?} marker missing from {requests:?}");
}

/// `SSL_CERT_FILE` naming a file holding `ca`, and `SSL_CERT_DIR` naming a directory holding only that CA, both in
/// `store`.
fn trust_store_env(case: Case, store: &TempDir, ca: &TestCa) -> Case {
    let file = store.write_ca("ambient.pem", ca);
    let dir = store.path("ambient");
    fs::create_dir(&dir).unwrap();
    fs::write(dir.join("ambient.pem"), ca.pem()).unwrap();
    case.env("SSL_CERT_FILE", file.to_str().unwrap())
        .env("SSL_CERT_DIR", dir.to_str().unwrap())
}

// ---- Cases -------------------------------------------------------------------------------------------------------

async fn proxy_case(slot: Slot) {
    let ca = TestCa::new("Upstream CA");
    let upstream = MockUpstream::start(&ca, Reply::ok("")).await;
    // Any TCP listener would do; the mock counts connections before TLS, so a plaintext CONNECT is counted too.
    let proxy = MockUpstream::start(&TestCa::new("Proxy CA"), Reply::ok("")).await;
    let proxy_url = format!("http://127.0.0.1:{}", proxy.port());
    let pins = TempDir::new();
    let case = ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "HTTP_PROXY"]
        .iter()
        .fold(Case::new(slot, upstream.origin()), |case, name| case.env(name, &proxy_url))
        .pinned(&pins.write_ca("pinned.pem", &ca));

    case.run().await.assert_status(200);

    assert_eq!(proxy.connections(), 0, "the proxy listener saw a connection");
    assert_carried(&upstream, slot);
}

/// §3.7: "The outbound client must disable environment proxy discovery, including `HTTPS_PROXY` and `ALL_PROXY`."
#[tokio::test]
async fn s3_7_no_proxy_discovery_proxy_variables_never_see_a_connection() {
    proxy_case(Slot::Header).await;
    proxy_case(Slot::Query).await;
}

async fn built_in_roots_case(slot: Slot) {
    let ca = TestCa::new("Ambient CA");
    let upstream = MockUpstream::start(&ca, Reply::ok("")).await;
    let store = TempDir::new();
    let case = trust_store_env(Case::new(slot, upstream.origin()), &store, &ca);

    case.run().await.assert_error(TransportError::Tls);

    assert_eq!(upstream.requests(), []);
}

/// §3.7: "It must not inherit trust roots from `SSL_CERT_FILE`, `SSL_CERT_DIR`": the built-in roots stay the only ones.
#[tokio::test]
async fn s3_7_no_inherited_trust_ssl_cert_variables_add_no_built_in_root() {
    built_in_roots_case(Slot::Header).await;
    built_in_roots_case(Slot::Query).await;
}

async fn pinned_case(slot: Slot, pin_upstream_ca: bool) {
    let ca = TestCa::new("Upstream CA");
    let upstream = MockUpstream::start(&ca, Reply::ok("")).await;
    let store = TempDir::new();
    let pin = if pin_upstream_ca { ca.pem() } else { TestCa::new("Other CA").pem() };
    let pinned = store.path("pinned.pem");
    fs::write(&pinned, pin).unwrap();
    let case = trust_store_env(Case::new(slot, upstream.origin()), &store, &ca).pinned(&pinned);

    let run = case.run().await;

    if pin_upstream_ca {
        run.assert_status(200);
        assert_carried(&upstream, slot);
    } else {
        run.assert_error(TransportError::Tls);
        assert_eq!(upstream.requests(), []);
    }
}

/// §3.7: a route "may reference an administrator-installed pinned CA"; `SSL_CERT_FILE` and `SSL_CERT_DIR` naming the
/// upstream's CA neither add to the pinned CA nor stand in for it.
#[tokio::test]
async fn s3_7_no_inherited_trust_a_pinned_ca_alone_decides_under_ssl_cert_variables() {
    pinned_case(Slot::Header, true).await;
    pinned_case(Slot::Query, true).await;
    pinned_case(Slot::Header, false).await;
    pinned_case(Slot::Query, false).await;
}

async fn wrong_name_case(slot: Slot) {
    let ca = TestCa::new("Pinned CA");
    let upstream = MockUpstream::start_with(ca.server_config("elsewhere.invalid"), Reply::ok("")).await;
    let pins = TempDir::new();
    let case = Case::new(slot, upstream.origin()).pinned(&pins.write_ca("pinned.pem", &ca));

    case.run().await.assert_error(TransportError::Tls);

    assert_eq!(upstream.requests(), []);
}

/// §3.7: "The service must verify certificates and hostnames", also against a pinned CA.
#[tokio::test]
async fn s3_7_hostname_verified_a_pinned_cas_certificate_for_another_name_is_refused() {
    wrong_name_case(Slot::Header).await;
    wrong_name_case(Slot::Query).await;
}

async fn key_log_case(slot: Slot) {
    let ca = TestCa::new("Upstream CA");
    let upstream = MockUpstream::start(&ca, Reply::ok("")).await;
    let pins = TempDir::new();
    let key_logs = TempDir::new();
    let key_log = key_logs.path("keys.log");
    let case = Case::new(slot, upstream.origin())
        .pinned(&pins.write_ca("pinned.pem", &ca))
        .env("SSLKEYLOGFILE", key_log.to_str().unwrap());

    case.run().await.assert_status(200);

    assert_carried(&upstream, slot);
    assert!(!key_log.exists(), "the TLS session keys were logged");
    assert_eq!(key_logs.entries(), Vec::<PathBuf>::new());
}

/// §3.7: "The package must disable raw connection logging": `SSLKEYLOGFILE` cannot make it log TLS session keys.
#[tokio::test]
async fn s3_7_no_raw_connection_logging_sslkeylogfile_gets_no_key_log() {
    key_log_case(Slot::Header).await;
    key_log_case(Slot::Query).await;
}

async fn redirect_case(slot: Slot) {
    let ca = TestCa::new("Upstream CA");
    let elsewhere = MockUpstream::start(&ca, Reply::ok("followed")).await;
    let location = format!("{}/v1/elsewhere", elsewhere.origin());
    let upstream = MockUpstream::start(&ca, Reply::redirect(&location)).await;
    let pins = TempDir::new();
    let case = Case::new(slot, upstream.origin()).pinned(&pins.write_ca("pinned.pem", &ca));

    let run = case.run().await;

    run.assert_status(302);
    assert_eq!(run.line("location"), Some(location.as_str()));
    assert_carried(&upstream, slot);
    assert_eq!(elsewhere.connections(), 0, "the redirect target saw a connection");
}

/// §3.8: "The client must never follow an upstream redirect automatically", so a redirect cannot carry the credential
/// to another origin.
#[tokio::test]
async fn s3_8_no_redirect_following_a_redirect_is_returned_unfollowed() {
    redirect_case(Slot::Header).await;
    redirect_case(Slot::Query).await;
}

async fn rust_log_case(slot: Slot, rust_log: &str) {
    let ca = TestCa::new("Upstream CA");
    let upstream = MockUpstream::start(&ca, Reply::ok("")).await;
    let pins = TempDir::new();
    let case = Case::new(slot, upstream.origin())
        .pinned(&pins.write_ca("pinned.pem", &ca))
        .logging()
        .env("RUST_LOG", rust_log);

    let run = case.run().await;

    run.assert_status(200);
    assert_carried(&upstream, slot);
    assert!(run.stderr.contains(LOGGED), "the service's logging wrote nothing to stderr: {run}");
    assert_eq!(
        verbose_lines(&run.stderr),
        Vec::<&str>::new(),
        "RUST_LOG={rust_log} lifted a log level"
    );
}

/// The `DEBUG` and `TRACE` lines in a child's stderr. Over HTTP/1.1 no dependency prints a header or the request target
/// even at `TRACE`, so the markers alone could not show a lifted cap; any verbose line does.
fn verbose_lines(stderr: &str) -> Vec<&str> {
    stderr
        .lines()
        .filter(|line| matches!(line.split_whitespace().nth(1), Some("DEBUG" | "TRACE")))
        .collect()
}

/// §3.7: the package must "cap HTTP/TLS dependency log verbosity in code, regardless of `RUST_LOG`".
#[tokio::test]
async fn s3_7_capped_dependency_logs_rust_log_lifts_no_level_and_logs_no_credential() {
    rust_log_case(Slot::Header, "trace").await;
    rust_log_case(Slot::Query, "trace").await;
    rust_log_case(Slot::Header, "hyper=trace,rustls=trace,h2=trace").await;
    rust_log_case(Slot::Query, "hyper=trace,rustls=trace,h2=trace").await;
}
