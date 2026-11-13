// SPDX-License-Identifier: MPL-2.0
//! The credential commands' release checks (specification §6; §5; §19), run through the `iron-vault`
//! binary in the development profile, where malware runs as the admin principal and reaches every admin command:
//!
//! - without the approval passphrase, malware cannot take an existing name with `add`, nor `replace` or `rm` a
//!   credential, and a credential it adds serves no route until the owner approves a config that uses it (§6);
//! - a config edit cannot send a credential to an origin its record does not permit; only `replace`, with the secret
//!   typed again and the approval passphrase, changes where it may go (§6);
//! - a name removed and added again is never served by a route approved for the old record (§6);
//! - no typed secret, username, password or passphrase appears in the binary's argv, stdout or stderr, in the service
//!   log, or in `list` or `status` output (§5, §18).
//!
//! Each test runs the `config approve` harness's service context, whose route `fx` sends `fx_key` to a mock TLS
//! upstream, and serves its admin socket to the binary through `--admin-socket`. The service's profile is Development,
//! so the account running the test and the binary is the admin principal. Each test checks the manifest bytes and the
//! requests the upstreams received, and ends by scanning every run of the binary and the service log for secrets.

#![cfg(target_os = "linux")]

use crate::common;

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::approval_harness::{
    APPROVAL_PASSPHRASE, Captured, Fixture, WRONG_PASSPHRASE, captured_logs, get, identity, serve_admin, versions,
};
use common::mock_upstream::{MockUpstream, Reply};
use iron_vault::service_context::ServiceContext;
use iron_vault::service_state::{FailureReason, ServiceState};
use iron_vault_store::{RecordId, open_manifest};
use tokio::sync::oneshot;

/// The key the fixture enrols as `fx_key`.
const FX_SECRET: &str = "fx-secret";
/// Values typed at the binary's prompts; distinctive, so a search of the outputs and the log matches nothing else.
const ATTACKER_SECRET: &str = "ATTACKER-SECRET-4be1d7";
const OWNER_SECRET: &str = "OWNER-SECRET-0c93a5";
const USERNAME: &str = "BASIC-USER-71f2c0";
const PASSWORD: &str = "BASIC-PASS-e5a8d3";
const NEW_USERNAME: &str = "BASIC-USER-2-9d06b4";
const NEW_PASSWORD: &str = "BASIC-PASS-2-3a7fe1";

/// How long one run of the binary may take: an approval opens the approver's key with scrypt.
const RUN_LIMIT: Duration = Duration::from_secs(30);

/// Every value that must never be shown or logged: the fixture's key, each value typed at a prompt, and the
/// `Authorization` value each Basic pair is sent as.
fn secrets() -> Vec<String> {
    let typed = [
        FX_SECRET,
        APPROVAL_PASSPHRASE,
        WRONG_PASSPHRASE,
        ATTACKER_SECRET,
        OWNER_SECRET,
        USERNAME,
        PASSWORD,
        NEW_USERNAME,
        NEW_PASSWORD,
    ];
    let encoded =
        [(USERNAME, PASSWORD), (NEW_USERNAME, NEW_PASSWORD)].map(|(user, password)| STANDARD.encode(format!("{user}:{password}")));
    typed.into_iter().map(str::to_owned).chain(encoded).collect()
}

/// One run of the binary: its argv as `/proc/<pid>/cmdline` showed it while it ran, its exit code and its output.
#[derive(Debug, Clone)]
struct Ran {
    cmdline: Vec<u8>,
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Ran {
    fn assert_free_of(&self, secret: &str) {
        let cmdline = String::from_utf8_lossy(&self.cmdline);
        [
            ("argv", cmdline.as_ref()),
            ("stdout", self.stdout.as_str()),
            ("stderr", self.stderr.as_str()),
        ]
        .iter()
        .for_each(|(place, text)| assert!(!text.contains(secret), "{secret} reached the binary's {place}: {self:?}"));
    }

    fn assert_refused_with(&self, code: &str) {
        assert_eq!(self.code, Some(1), "{self:?}");
        assert!(self.stderr.contains(code), "expected {code}: {self:?}");
    }

    fn assert_succeeded(&self) {
        assert_eq!(self.code, Some(0), "{self:?}");
    }
}

/// Runs the binary against one admin socket and keeps every run, so a test can scan all of them for secrets.
struct Cli {
    socket: PathBuf,
    runs: Vec<Ran>,
}

impl Cli {
    /// Runs `iron-vault <args> --admin-socket <socket>` with `input` piped to its stdin, off the runtime thread, so the
    /// in-process service keeps serving while the binary waits for it.
    async fn run(&mut self, args: &[&str], input: &str) -> Ran {
        let argv = [env!("CARGO_BIN_EXE_iron-vault")]
            .into_iter()
            .chain(args.iter().copied())
            .chain(["--admin-socket", path_text(&self.socket)])
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let expected = argv.iter().flat_map(|arg| arg.bytes().chain([0])).collect::<Vec<_>>();
        let input = input.to_owned();
        let running = tokio::task::spawn_blocking(move || run_blocking(&argv, &input));
        let ran = tokio::time::timeout(RUN_LIMIT, running)
            .await
            .expect("the binary finishes")
            .unwrap();
        // A run that ended before its argv was read shows an empty one.
        assert!(ran.cmdline.is_empty() || ran.cmdline == expected, "{ran:?}");
        self.runs.push(ran.clone());
        ran
    }

    /// Runs `list` and `status`, then checks that no secret reached any run's argv or output, or the service log, which
    /// every test in this binary shares.
    async fn assert_nothing_leaked(&mut self, logs: &Captured) {
        self.run(&["list"], "").await;
        self.run(&["status"], "").await;
        let log = logs.text();
        secrets().iter().for_each(|secret| {
            assert!(!log.contains(secret.as_str()), "{secret} reached the service log");
            self.runs.iter().for_each(|ran| ran.assert_free_of(secret));
        });
    }
}

/// Spawns the binary, writes all but the last line of `input`, reads its argv from `/proc`, then writes the last line.
/// A command that reads every line is still waiting for the last one when its argv is read, holding the lines before.
fn run_blocking(argv: &[String], input: &str) -> Ran {
    let (program, args) = argv.split_first().unwrap();
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let (early, last) = input.split_at(last_line_start(input));
    let mut stdin = child.stdin.take().unwrap();
    // A command refused before it reads closes the pipe, so a failed write is not the test's failure.
    let _ = stdin.write_all(early.as_bytes());
    let cmdline = argv_of(&mut child, program);
    let _ = stdin.write_all(last.as_bytes());
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    Ran {
        cmdline,
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// `child`'s own argv as `/proc/<pid>/cmdline` shows it after it has exec'd `program`, or nothing once it has exited.
///
/// `spawn` can return while the child is still mid-exec, in one of two states that are not its argv. The kernel wakes
/// the vfork parent before it switches the child onto the new program's memory, so the child can still show this test
/// process's argv; once switched, it shows an empty one until the arguments are copied in. The kernel renames the
/// child after the switch, so once `/proc/<pid>/comm` names `program`, the cmdline read after it is the new program's:
/// empty, or its argv in full. (`/proc/<pid>/exe` would say the same, but the binary makes itself unreadable there.)
fn argv_of(child: &mut Child, program: &str) -> Vec<u8> {
    let proc = PathBuf::from(format!("/proc/{}", child.id()));
    let name = exec_name(program);
    loop {
        if let Some(cmdline) = exec_argv(&proc, &name) {
            return cmdline;
        }
        if child.try_wait().unwrap().is_some() {
            return Vec::new();
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// The name the kernel gives a process that execs `program`: its file name, cut to the 15 bytes `comm` holds.
fn exec_name(program: &str) -> Vec<u8> {
    let name = Path::new(program).file_name().unwrap().as_encoded_bytes();
    name[..name.len().min(15)].to_vec()
}

/// The process's argv once it runs a program called `name` and its arguments are in place; `None` before then or
/// after it exits.
fn exec_argv(proc: &Path, name: &[u8]) -> Option<Vec<u8>> {
    let comm = fs::read(proc.join("comm")).ok()?;
    if comm.strip_suffix(b"\n") != Some(name) {
        return None;
    }
    read_once(&proc.join("cmdline")).filter(|cmdline| !cmdline.is_empty())
}

/// More than any argv these tests pass.
const CMDLINE_LIMIT: usize = 64 * 1024;

/// `path` read in one `read` call. `fs::read` takes several, and a process that exits between them shows a cmdline cut
/// short; within one call the kernel holds the process's memory, so the read is whole or empty.
fn read_once(path: &Path) -> Option<Vec<u8>> {
    let mut buffer = vec![0; CMDLINE_LIMIT];
    let read = fs::File::open(path).ok()?.read(&mut buffer).ok()?;
    assert!(read < CMDLINE_LIMIT, "{} is longer than {CMDLINE_LIMIT} bytes", path.display());
    buffer.truncate(read);
    Some(buffer)
}

/// Where the last line of `input` starts.
fn last_line_start(input: &str) -> usize {
    input.trim_end_matches('\n').rfind('\n').map_or(0, |at| at + 1)
}

fn path_text(path: &Path) -> &str {
    path.to_str().unwrap()
}

/// The fixture's service, Ready, with its admin socket served to a [`Cli`] until the sender is used.
async fn started(fixture: &Fixture) -> (Arc<ServiceContext>, Cli, oneshot::Sender<()>) {
    let service = fixture.ready().await;
    let (socket, stop) = serve_admin(&service);
    let cli = Cli { socket, runs: Vec::new() };
    (service, cli, stop)
}

/// `upstream`'s origin as `--origin` takes it.
fn origin(upstream: &MockUpstream) -> String {
    format!("localhost:{}", upstream.port())
}

fn manifest_bytes(fixture: &Fixture) -> Vec<u8> {
    fs::read(fixture.path("state/manifest.age")).unwrap()
}

/// The record ID the manifest on disk lists for `name`, read without the state-directory lock the service holds.
fn record_id(fixture: &Fixture, name: &str) -> Option<RecordId> {
    let manifest = open_manifest(&identity(), &manifest_bytes(fixture)).unwrap();
    let mut entries = manifest.entries().iter();
    entries.find(|(_, entry)| entry.name().as_str() == name).map(|(id, _)| *id)
}

/// The value of `header` in each request `upstream` received, in arrival order.
fn received(upstream: &MockUpstream, header: &str) -> Vec<String> {
    let requests = upstream.requests();
    let values = requests.iter().map(|request| {
        request
            .headers()
            .into_iter()
            .find(|(name, _)| name == header)
            .map(|(_, value)| value)
    });
    values.map(Option::unwrap_or_default).collect()
}

/// The `X-Api-Key` each request to `upstream` carried: the slot every static route of the fixture fills.
fn api_keys(upstream: &MockUpstream) -> Vec<String> {
    received(upstream, "x-api-key")
}

fn basic(user: &str, password: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{user}:{password}")))
}

/// `yes` to the approval summary, then `passphrase`.
fn approval_answers(passphrase: &str) -> String {
    format!("yes\n{passphrase}\n")
}

#[tokio::test]
async fn malware_adding_over_an_existing_name_is_refused_with_name_taken() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let (_service, mut cli, stop) = started(&fixture).await;
    let before = manifest_bytes(&fixture);

    let ran = cli
        .run(
            &["add", "fx_key", "--origin", &origin(fixture.upstream())],
            &format!("{ATTACKER_SECRET}\n"),
        )
        .await;

    ran.assert_refused_with("error 20 (name-taken)");
    assert_eq!(manifest_bytes(&fixture), before);
    assert_eq!(get(&fixture, "fx").await.status, 200);
    assert_eq!(api_keys(fixture.upstream()), [FX_SECRET]);
    cli.assert_nothing_leaked(&logs).await;
    let _ = stop.send(());
}

#[tokio::test]
async fn malware_without_the_approval_passphrase_can_neither_replace_nor_remove_a_credential() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let (_service, mut cli, stop) = started(&fixture).await;
    let origin = origin(fixture.upstream());
    // The owner's credential that no route uses, which `rm` would remove given the passphrase.
    let spare = cli
        .run(&["add", "spare_key", "--origin", &origin], &format!("{OWNER_SECRET}\n"))
        .await;
    spare.assert_succeeded();
    let before = manifest_bytes(&fixture);

    // The same name and origin with the attacker's own key: the account swap of §6.
    let replaced = cli
        .run(
            &["replace", "fx_key", "--origin", &origin],
            &format!("{WRONG_PASSPHRASE}\n{ATTACKER_SECRET}\n"),
        )
        .await;
    let removed = cli.run(&["rm", "spare_key"], &format!("{WRONG_PASSPHRASE}\n")).await;
    // A name a route uses is refused before the passphrase is asked for (design/credential-commands.md).
    let in_use = cli.run(&["rm", "fx_key"], &format!("{WRONG_PASSPHRASE}\n")).await;

    replaced.assert_refused_with("error 9 (approval-denied)");
    assert!(replaced.stderr.starts_with("replace credential fx_key\n"), "{replaced:?}");
    removed.assert_refused_with("error 9 (approval-denied)");
    in_use.assert_refused_with("error 24 (credential-in-use)");
    assert_eq!(manifest_bytes(&fixture), before);
    assert_eq!(get(&fixture, "fx").await.status, 200);
    assert_eq!(api_keys(fixture.upstream()), [FX_SECRET]);
    cli.assert_nothing_leaked(&logs).await;
    let _ = stop.send(());
}

#[tokio::test]
async fn a_credential_malware_adds_serves_no_route_its_config_edit_names_until_the_owner_approves_it() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let (service, mut cli, stop) = started(&fixture).await;
    let active = fixture.path("etc/config.toml");

    let added = cli
        .run(
            &["add", "stolen_key", "--origin", &origin(fixture.upstream())],
            &format!("{ATTACKER_SECRET}\n"),
        )
        .await;
    added.assert_succeeded();
    assert!(record_id(&fixture, "stolen_key").is_some());
    let after_add = manifest_bytes(&fixture);
    // The route the owner's caller uses now names the attacker's account.
    fs::write(&active, fixture.config_with("fx", "stolen_key")).unwrap();

    assert_eq!(get(&fixture, "fx").await.status, 200, "the running policy never reads the edit");
    // SIGHUP, which malware running as the service's account may send.
    assert_eq!(service.reload().await, Ok(ServiceState::Unavailable(FailureReason::PolicyInvalid)));
    let refused = get(&fixture, "fx").await;
    assert_eq!((refused.status, refused.body.as_str()), (503, "policy invalid"));
    let denied = cli
        .run(&["config", "approve", path_text(&active)], &approval_answers(WRONG_PASSPHRASE))
        .await;
    denied.assert_refused_with("error 9 (approval-denied)");
    assert_eq!(get(&fixture, "fx").await.status, 503);
    assert_eq!(api_keys(fixture.upstream()), [FX_SECRET]);

    // The owner reads the summary, which names the credential, and approves.
    let approved = cli
        .run(&["config", "approve", path_text(&active)], &approval_answers(APPROVAL_PASSPHRASE))
        .await;
    approved.assert_succeeded();
    assert!(approved.stdout.starts_with("approved version 2 "), "{approved:?}");
    assert!(approved.stderr.contains("credential stolen_key"), "{approved:?}");
    assert_eq!(get(&fixture, "fx").await.status, 200);
    assert_eq!(api_keys(fixture.upstream()), [FX_SECRET, ATTACKER_SECRET]);
    assert_eq!(manifest_bytes(&fixture), after_add);
    cli.assert_nothing_leaked(&logs).await;
    let _ = stop.send(());
}

#[tokio::test]
async fn a_route_moved_to_an_origin_its_credential_does_not_permit_fails_approval_until_replace_permits_it() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let (service, mut cli, stop) = started(&fixture).await;
    let elsewhere = MockUpstream::start(fixture.ca(), Reply::ok("elsewhere")).await;
    let (here, there) = (origin(fixture.upstream()), origin(&elsewhere));
    let (moved, attacker) = (fixture.path("moved.toml"), fixture.path("attacker.toml"));
    fs::write(&moved, fixture.config("fx").replace(&here, &there)).unwrap();
    fs::write(&attacker, fixture.config("fx").replace(&here, "attacker.example")).unwrap();
    let (before, active) = (manifest_bytes(&fixture), fixture.published_pair());

    // Not even the owner, passphrase in hand, can approve either edit.
    for proposed in [&attacker, &moved] {
        let refused = cli
            .run(&["config", "approve", path_text(proposed)], &approval_answers(APPROVAL_PASSPHRASE))
            .await;
        refused.assert_refused_with("error 7 (config-invalid)");
        assert!(
            refused
                .stderr
                .contains("route fx sends credential fx_key to an origin its record does not permit"),
            "{refused:?}"
        );
    }
    assert_eq!((versions(&service).await, fixture.published_pair()), ((Some(1), 1), active));
    assert_eq!(get(&fixture, "fx").await.status, 200);
    // Malware cannot take the way round either: `replace` asks for the approval passphrase before the secret.
    let replace = ["replace", "fx_key", "--origin", here.as_str(), "--origin", there.as_str()];
    let denied = cli.run(&replace, &format!("{WRONG_PASSPHRASE}\n{ATTACKER_SECRET}\n")).await;
    denied.assert_refused_with("error 9 (approval-denied)");
    assert_eq!(manifest_bytes(&fixture), before);

    // The owner types the passphrase and the secret again for both origins, then approves the move.
    let replaced = cli.run(&replace, &format!("{APPROVAL_PASSPHRASE}\n{OWNER_SECRET}\n")).await;
    replaced.assert_succeeded();
    assert!(replaced.stderr.contains(&format!("origins: {here} -> ")), "{replaced:?}");
    let new_id = record_id(&fixture, "fx_key").unwrap();
    assert!(replaced.stdout.contains(&new_id.to_string()), "{replaced:?}");
    assert_ne!(manifest_bytes(&fixture), before);
    let approved = cli
        .run(&["config", "approve", path_text(&moved)], &approval_answers(APPROVAL_PASSPHRASE))
        .await;
    approved.assert_succeeded();

    assert_eq!(get(&fixture, "fx").await.status, 200);
    assert_eq!(api_keys(fixture.upstream()), [FX_SECRET]);
    assert_eq!(
        api_keys(&elsewhere),
        [OWNER_SECRET],
        "only the secret typed again reaches the new origin"
    );
    cli.assert_nothing_leaked(&logs).await;
    let _ = stop.send(());
}

#[tokio::test]
async fn a_name_removed_and_added_again_is_never_served_by_a_route_approved_for_the_old_record() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let (service, mut cli, stop) = started(&fixture).await;
    let origin = origin(fixture.upstream());
    // Version 1, whose route `fx` uses `fx_key`.
    let first_pair = fixture.published_pair();
    let old_id = record_id(&fixture, "fx_key").unwrap();
    let rates = fixture.path("rates.toml");
    fs::write(&rates, fixture.config_with("rates", "rates_key")).unwrap();

    // The owner retires `fx`: approves a config whose one route uses another credential, then removes `fx_key`.
    let retired = [
        cli.run(&["add", "rates_key", "--origin", &origin], &format!("{OWNER_SECRET}\n"))
            .await,
        cli.run(&["config", "approve", path_text(&rates)], &approval_answers(APPROVAL_PASSPHRASE))
            .await,
        cli.run(&["rm", "fx_key"], &format!("{APPROVAL_PASSPHRASE}\n")).await,
    ];
    retired.iter().for_each(Ran::assert_succeeded);
    assert_eq!(record_id(&fixture, "fx_key"), None);
    // Malware enrols its own account under the freed name: `add` needs no owner presence.
    let readded = cli
        .run(&["add", "fx_key", "--origin", &origin], &format!("{ATTACKER_SECRET}\n"))
        .await;
    readded.assert_succeeded();
    let new_id = record_id(&fixture, "fx_key").unwrap();
    assert_ne!(new_id, old_id);
    assert!(readded.stdout.contains(&new_id.to_string()), "{readded:?}");
    let after_add = manifest_bytes(&fixture);

    assert_eq!(get(&fixture, "fx").await.status, 404, "no active route names fx_key");
    assert_eq!(get(&fixture, "rates").await.status, 200);
    // Version 1 still names `fx_key`; putting it back and sending SIGHUP is a rollback, which the service refuses.
    fixture.put_back(&first_pair);
    assert_eq!(service.reload().await, Ok(ServiceState::Unavailable(FailureReason::PolicyInvalid)));
    let refused = get(&fixture, "fx").await;
    assert_eq!((refused.status, refused.body.as_str()), (503, "policy invalid"));

    assert_eq!(api_keys(fixture.upstream()), [OWNER_SECRET], "the attacker's key was never sent");
    assert_eq!(manifest_bytes(&fixture), after_add);
    cli.assert_nothing_leaked(&logs).await;
    let _ = stop.send(());
}

#[tokio::test]
async fn no_typed_secret_username_or_password_reaches_argv_output_the_log_list_or_status() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let (_service, mut cli, stop) = started(&fixture).await;
    let origin = origin(fixture.upstream());
    let login = fixture.path("login.toml");
    let basic_route = fixture
        .config_with("login", "api_login")
        .replace(r#"slot = { header = "X-Api-Key" }"#, r#"slot = "basic""#);
    fs::write(&login, basic_route).unwrap();
    let basic_args = ["--kind", "basic", "--origin", origin.as_str()];

    let added = cli
        .run(
            &[&["add", "api_login"][..], &basic_args[..]].concat(),
            &format!("{USERNAME}\n{PASSWORD}\n"),
        )
        .await;
    let first_id = record_id(&fixture, "api_login").unwrap();
    let approved = cli
        .run(&["config", "approve", path_text(&login)], &approval_answers(APPROVAL_PASSPHRASE))
        .await;
    let first = get(&fixture, "login").await.status;
    let replaced = cli
        .run(
            &[&["replace", "api_login"][..], &basic_args[..]].concat(),
            &format!("{APPROVAL_PASSPHRASE}\n{NEW_USERNAME}\n{NEW_PASSWORD}\n"),
        )
        .await;
    let second = get(&fixture, "login").await.status;
    let listed = cli.run(&["list"], "").await;
    let status = cli.run(&["status"], "").await;

    [&added, &approved, &replaced, &listed, &status]
        .into_iter()
        .for_each(Ran::assert_succeeded);
    // Each command that took values was still waiting for its last line when its argv was read.
    [&added, &approved, &replaced]
        .iter()
        .for_each(|ran| assert!(!ran.cmdline.is_empty(), "{ran:?}"));
    let second_id = record_id(&fixture, "api_login").unwrap();
    assert_ne!(first_id, second_id);
    assert!(replaced.stdout.contains(&second_id.to_string()), "{replaced:?}");
    assert_eq!((first, second), (200, 200));
    assert_eq!(
        received(fixture.upstream(), "authorization"),
        [basic(USERNAME, PASSWORD), basic(NEW_USERNAME, NEW_PASSWORD)]
    );
    assert_eq!(
        listed.stdout,
        format!("api_login  basic  {origin}  healthy\nfx_key  static  {origin}  healthy\n")
    );
    assert!(status.stdout.starts_with("service: ready\n"), "{status:?}");
    // The log under scan is the one the service writes to.
    assert!(logs.has_field("credential.replaced", "record_id", &second_id.to_string()));
    cli.assert_nothing_leaked(&logs).await;
    let _ = stop.send(());
}
