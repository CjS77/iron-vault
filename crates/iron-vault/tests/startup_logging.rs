//! Checks that the service binary prints its startup hardening report on stderr. The process may then stop on a
//! missing install account, which `deployment_profile.rs` covers.

#![cfg(target_os = "linux")]

use std::process::Command;

#[test]
fn reports_missing_swap_protection_on_stderr() {
    // Lowering a soft limit needs no privilege, so the mlockall in harden_process fails predictably.
    let output = Command::new("sh")
        .args(["-c", "ulimit -S -l 64; exec \"$0\"", env!("CARGO_BIN_EXE_iron-vault")])
        .output()
        .expect("spawn iron-vault through sh");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let error_line = stderr
        .lines()
        .find(|line| line.contains("ERROR") && line.contains("swap protection is not in effect"))
        .unwrap_or_else(|| panic!("no swap protection ERROR line in stderr: {stderr}"));
    assert!(
        error_line.contains("LimitMEMLOCK=infinity"),
        "line does not name the fix: {error_line}"
    );
}
