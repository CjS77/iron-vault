//! Checks that `iron-vault serve --log-to-stdout` writes its startup event and missing hardening to stdout as JSON Lines, and refuses
//! stdout when it may be the systemd journal.
//!
//! Development builds only: a protected build refuses to start as any account but `iron-vault` before its log opens, which
//! `deployment_profile.rs` covers. The log destination code is the same in both profiles.

#![cfg(all(target_os = "linux", feature = "dev-mode"))]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::process::{Command, Output, Stdio};

/// Runs `iron-vault serve --log-to-stdout` after lowering the memory-lock limit, so the mlockall in `harden_process`
/// fails predictably (lowering a soft limit needs no privilege). A development build would go on to serve; a runtime
/// directory whose parent does not exist stops it first.
fn serve_to_stdout(configure: impl FnOnce(&mut Command)) -> Output {
    let mut command = Command::new("sh");
    command
        .args([
            "-c",
            "ulimit -S -l 64; exec \"$0\" serve --log-to-stdout",
            env!("CARGO_BIN_EXE_iron-vault"),
        ])
        .env("XDG_RUNTIME_DIR", "/nonexistent/iron-vault-test")
        .env_remove("JOURNAL_STREAM");
    configure(&mut command);
    command.output().expect("spawn iron-vault through sh")
}

/// The one audit event named `event` that `serve` wrote to stdout; every line must be JSON.
fn the_event(output: &Output, event: &str) -> serde_json::Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .map(|line| serde_json::from_str(line).unwrap_or_else(|e| panic!("not a JSON line ({e}): {line}")))
        .find(|record: &serde_json::Value| record["event"] == event && record["target"] == "iron-vault.audit")
        .unwrap_or_else(|| panic!("no {event} record on stdout: {stdout}"))
}

#[test]
fn the_startup_event_names_the_build_profile_and_the_destination() {
    let started = the_event(&serve_to_stdout(|_| {}), "service.started");
    assert_eq!(started["deployment_profile"], "development", "{started}");
    assert_eq!(started["level"], "INFO");
    assert_eq!(started["log_destination"], "stdout");
    assert_eq!(started["memory_protection"], "unavailable");
}

#[test]
fn reports_missing_swap_protection_as_an_error_event_naming_the_fix() {
    let incomplete = the_event(&serve_to_stdout(|_| {}), "service.hardening-incomplete");
    assert_eq!(incomplete["level"], "ERROR");
    assert_eq!(incomplete["memory_protection"], "unavailable");
    let remediation = incomplete["remediation"].as_str().unwrap();
    assert!(
        remediation.contains("LimitMEMLOCK=infinity"),
        "record does not name the fix: {incomplete}"
    );
}

#[test]
fn a_journal_stream_that_names_another_stream_does_not_stop_stdout() {
    let output = serve_to_stdout(|command| {
        command.env("JOURNAL_STREAM", "1:2");
    });
    assert!(!output.stdout.is_empty(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
}

#[test]
fn a_journal_stream_that_cannot_be_parsed_refuses_stdout_before_anything_is_written() {
    let output = serve_to_stdout(|command| {
        command.env("JOURNAL_STREAM", "not-a-stream");
    });
    assert_refused_for_the_journal(&output);
}

#[test]
fn a_journal_stream_naming_stdout_refuses_it() {
    let capture = tempfile_in_target("journal-stdout");
    let metadata = capture.metadata().unwrap();
    let output = serve_to_stdout(|command| {
        command
            .env("JOURNAL_STREAM", format!("{}:{}", metadata.dev(), metadata.ino()))
            .stdout(Stdio::from(capture.try_clone().unwrap()));
    });
    assert_refused_for_the_journal(&output);
    assert_eq!(capture.metadata().unwrap().len(), 0, "a record reached the journal's stream");
}

fn assert_refused_for_the_journal(output: &Output) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert!(stderr.contains("cannot use the log destination stdout"), "{stderr}");
    assert!(stderr.contains("journal"), "{stderr}");
    assert!(output.stdout.is_empty(), "stdout: {}", String::from_utf8_lossy(&output.stdout));
}

/// An empty file in the build's scratch directory, deleted at once: the open handle is all the test needs.
fn tempfile_in_target(name: &str) -> File {
    let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}-{}", std::process::id()));
    let file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .unwrap();
    std::fs::remove_file(&path).unwrap();
    file
}
