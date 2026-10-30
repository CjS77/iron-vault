//! Checks the binary's `--version` output and how its deployment profile starts on this machine.

#![cfg(target_os = "linux")]
#![allow(clippy::expect_used)]

use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_iron-vault"))
        .args(args)
        .output()
        .expect("spawn iron-vault")
}

#[test]
fn version_names_the_enabled_features() {
    let output = run(&["--version"]);
    assert!(output.status.success(), "exit status {:?}", output.status);
    let features = if cfg!(feature = "dev-mode") { "dev-mode" } else { "none" };
    let expected = format!("iron-vault {} (features: {features})\n", env!("CARGO_PKG_VERSION"));
    assert_eq!(String::from_utf8_lossy(&output.stdout), expected);
    assert_eq!(String::from_utf8_lossy(&output.stderr), "", "--version must not log");
}

#[cfg(not(feature = "dev-mode"))]
#[test]
fn a_protected_build_without_the_service_account_names_it() {
    let passwd = std::fs::read_to_string("/etc/passwd").expect("read /etc/passwd");
    if passwd.lines().any(|line| line.starts_with("iron-vault:")) {
        return;
    }
    let output = run(&[]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "stderr: {stderr}");
    assert!(stderr.contains("the service account `iron-vault` does not exist"), "{stderr}");
}

#[cfg(feature = "dev-mode")]
#[test]
fn a_development_build_warns_that_it_gives_no_isolation() {
    let output = Command::new(env!("CARGO_BIN_EXE_iron-vault"))
        .env("XDG_RUNTIME_DIR", "/run/user/test")
        .output()
        .expect("spawn iron-vault");
    let stderr = String::from_utf8_lossy(&output.stderr);
    if rustix::process::getuid().is_root() {
        assert!(!output.status.success(), "stderr: {stderr}");
        assert!(stderr.contains("must never be installed as the system service"), "{stderr}");
    } else {
        assert!(output.status.success(), "stderr: {stderr}");
        assert!(
            stderr.contains("development mode: no isolation from malware running as "),
            "{stderr}"
        );
    }
}
