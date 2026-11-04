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
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

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
            .output()
            .unwrap()
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

/// Asserts `serve` refused to start naming `path`, and bound no admin socket.
///
/// `serve` checks its own executable first, so a checkout below a directory the build user's group can write is refused
/// at the binary before the tree under test is reached; the test then has nothing to say and returns.
fn assert_refused_naming(install: &Install, output: &Output, path: &Path) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let binary_refused = format!("refusing to start: {} is not trusted", env!("CARGO_BIN_EXE_iron-vault"));
    if stderr.contains(&binary_refused) {
        eprintln!("skipped: the build tree is not a trusted path on this host:\n{stderr}");
        return;
    }
    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    let expected = format!("refusing to start: {} is not trusted", path.display());
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

    assert_refused_naming(&install, &install.serve(), &install.state_dir());
}

#[test]
fn a_config_directory_other_accounts_can_write_is_refused_by_path() {
    let install = Install::new();
    mkdir(&install.config_dir(), 0o777);

    assert_refused_naming(&install, &install.serve(), &install.config_dir());
}

#[test]
fn a_config_file_other_accounts_can_write_is_refused_by_path() {
    let install = Install::new();
    mkdir(&install.config_dir(), 0o700);
    let config = install.config_dir().join("config.toml");
    fs::write(&config, "schema_version = 1\n").unwrap();
    chmod(&config, 0o666);

    assert_refused_naming(&install, &install.serve(), &config);
}
