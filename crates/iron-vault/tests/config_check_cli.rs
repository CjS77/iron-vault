// SPDX-License-Identifier: MPL-2.0
//! `iron-vault config check` as the owner runs it: the real binary, no service, no vault, no admin socket.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

const REFERENCE: &str = include_str!("../../../book/src/reference/configuration-example.toml");

/// A directory of its own, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("iv-config-check-cli-{}-{name}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn write(&self, file: &str, contents: &str) -> PathBuf {
        let path = self.0.join(file);
        fs::write(&path, contents).unwrap();
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn check(file: &std::path::Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_iron-vault"))
        .args(["config", "check"])
        .arg(file)
        // No admin socket exists at this path, so a command that tried to reach the service would exit 3.
        .args(["--admin-socket", "/nonexistent/admin.sock"])
        .output()
        .expect("run iron-vault")
}

#[test]
fn a_valid_config_prints_config_ok_and_exits_zero() {
    let dir = TempDir::new("valid");
    let output = check(&dir.write("config.toml", REFERENCE));
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&output.stdout), "Config ok\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn an_invalid_config_exits_one_and_says_where() {
    let dir = TempDir::new("invalid");
    let output = check(&dir.write("config.toml", "schema_version = 1\n[callers\n"));
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.starts_with("iron-vault: the config is not valid:") && stderr.contains("line 2"),
        "{stderr}"
    );
}

#[test]
fn a_missing_file_exits_two() {
    let dir = TempDir::new("missing");
    let output = check(&dir.0.join("absent.toml"));
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot read the config file"));
}
