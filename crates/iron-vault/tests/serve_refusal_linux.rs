//! `iron-vault serve` on an unsafe installation: it refuses to start, exits non-zero and names the failing path
//! (specification §3.1, §3.15 "ownership failures produce explicit safe states").
//!
//! The development profile reads its directories from the XDG variables, so each test points them at a tree under the
//! build's scratch directory, which is not below a shared sticky directory such as `/tmp`. Only a development build has
//! that profile.

#![cfg(all(target_os = "linux", feature = "dev-mode"))]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

/// How long a refusing service gets to exit. A service that starts instead would serve forever.
const DEADLINE: Duration = Duration::from_secs(5);

trait WaitWithDeadline {
    fn wait_with_deadline(self) -> Output;
}

impl WaitWithDeadline for Child {
    /// Polls for the exit; on timeout kills the process and fails with whatever it wrote to stderr.
    fn wait_with_deadline(mut self) -> Output {
        let start = Instant::now();
        while self.try_wait().unwrap().is_none() {
            if start.elapsed() > DEADLINE {
                self.kill().unwrap();
                let output = self.wait_with_output().unwrap();
                panic!(
                    "serve did not exit within {DEADLINE:?}; stderr:\n{}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        self.wait_with_output().unwrap()
    }
}

static NEXT: AtomicU32 = AtomicU32::new(0);

/// A fresh installation tree whose XDG directories are `0700`, removed on drop.
struct Install(PathBuf);

impl Install {
    fn new() -> Self {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("iv-serve-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let install = Self(root);
        ["config", "state", "run"].iter().for_each(|name| mkdir(&install.dir(name), 0o700));
        install
    }

    fn dir(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    /// The service's own directories under the XDG bases.
    fn state_dir(&self) -> PathBuf {
        self.dir("state/iron-vault-dev")
    }

    fn config_dir(&self) -> PathBuf {
        self.dir("config/iron-vault-dev")
    }

    /// Runs `iron-vault serve` with this tree as its XDG bases.
    fn serve(&self) -> Output {
        Command::new(env!("CARGO_BIN_EXE_iron-vault"))
            .arg("serve")
            .env_clear()
            .env("HOME", &self.0)
            .env("XDG_CONFIG_HOME", self.dir("config"))
            .env("XDG_STATE_HOME", self.dir("state"))
            .env("XDG_RUNTIME_DIR", self.dir("run"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
            .wait_with_deadline()
    }
}

impl Drop for Install {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn mkdir(path: &Path, mode: u32) {
    fs::create_dir_all(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn chmod(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

/// Asserts `serve` refused to start because `path` fails with `problem`, which tells it from a refusal of an ancestor, and bound no admin socket.
///
/// `serve` opens its log directory first, then checks its own executable, so a checkout below a directory the build user's group can write is refused
/// at the binary before the tree under test is reached; the test then has nothing to say and returns.
fn assert_refused_naming(install: &Install, output: &Output, path: &Path, problem: &str) {
    if log_directory_untrusted_by_the_build_tree(output) {
        return;
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let binary_refused = format!("refusing to start: {} is not trusted", env!("CARGO_BIN_EXE_iron-vault"));
    if stderr.contains(&binary_refused) {
        assert!(
            std::env::var_os("CI").is_none(),
            "the build tree is not a trusted path in CI:\n{stderr}"
        );
        eprintln!("skipped: the build tree is not a trusted path on this host:\n{stderr}");
        return;
    }
    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    let expected = format!("refusing to start: {path} is not trusted: {path} {problem}", path = path.display());
    assert!(stderr.contains(&expected), "expected `{expected}` in:\n{stderr}");
    assert!(
        !install.dir("run/iron-vault-dev/admin.sock").exists(),
        "a refused service bound its admin socket"
    );
}

#[test]
fn a_state_directory_other_accounts_can_read_is_refused_by_path() {
    let install = Install::new();
    mkdir(&install.state_dir(), 0o755);

    assert_refused_naming(
        &install,
        &install.serve(),
        &install.state_dir(),
        "has mode 0755 but must have mode 0700",
    );
}

#[test]
fn a_config_directory_other_accounts_can_write_is_refused_by_path() {
    let install = Install::new();
    mkdir(&install.config_dir(), 0o707);

    assert_refused_naming(
        &install,
        &install.serve(),
        &install.config_dir(),
        "has mode 0707 but must have mode 0700",
    );
}

#[test]
fn a_config_file_other_accounts_can_write_is_refused_by_path() {
    let install = Install::new();
    mkdir(&install.config_dir(), 0o700);
    let config = install.config_dir().join("config.toml");
    fs::write(&config, "schema_version = 1\n").unwrap();
    chmod(&config, 0o606);

    assert_refused_naming(&install, &install.serve(), &config, "has mode 0606 but must have mode 0600");
}

/// Whether `serve` could not use its log directory because an ancestor of this checkout fails the log directory rule, as
/// a checkout below a directory the build user's group can write does. The test then has nothing to say.
fn log_directory_untrusted_by_the_build_tree(output: &Output) -> bool {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let skipped = stderr.contains("cannot use the log destination") && stderr.contains("writable by");
    if skipped {
        assert!(
            std::env::var_os("CI").is_none(),
            "the build tree is not a trusted log path in CI:\n{stderr}"
        );
        eprintln!("skipped: the build tree is not a trusted log path on this host:\n{stderr}");
    }
    skipped
}

#[test]
fn serve_creates_the_development_log_directory_and_writes_its_records_there() {
    let install = Install::new();
    mkdir(&install.state_dir(), 0o755);
    let output = install.serve();
    if log_directory_untrusted_by_the_build_tree(&output) {
        return;
    }
    let dir = install.dir("state/iron-vault-dev-log");
    let log = dir.join("iron-vault.log");
    assert_eq!(fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
    assert_eq!(fs::metadata(&log).unwrap().permissions().mode() & 0o777, 0o640);
    let text = fs::read_to_string(&log).unwrap();
    assert!(!text.is_empty(), "no record in the log file");
    text.lines().for_each(|line| {
        let record: serde_json::Value = serde_json::from_str(line).unwrap_or_else(|e| panic!("not a JSON line ({e}): {line}"));
        assert_eq!(record["deployment_profile"], "development");
    });
    assert!(output.stdout.is_empty() && !String::from_utf8_lossy(&output.stderr).contains("development mode"));
}

#[test]
fn a_log_directory_other_accounts_can_read_stops_serve_before_any_record_or_socket() {
    let install = Install::new();
    let dir = install.dir("state/iron-vault-dev-log");
    mkdir(&dir, 0o755);
    let output = install.serve();
    if log_directory_untrusted_by_the_build_tree(&output) {
        return;
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert!(stderr.contains("cannot use the log destination"), "{stderr}");
    assert!(stderr.contains("must be no more open than 0750"), "{stderr}");
    assert!(!dir.join("iron-vault.log").exists());
    assert!(!install.dir("run/iron-vault-dev/admin.sock").exists());
}
