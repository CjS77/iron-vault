// SPDX-License-Identifier: MPL-2.0
//! Process hardening, checked in a child process because it changes process-wide limits (specification §14).
//!
//! The test runs in its own binary: it forks, and a forked child shares the parent's open lock fds until it execs, so
//! a test in the same process that dropped and retook a state-directory lock in that window would find it held.

#![cfg(target_os = "linux")]

use std::process::Command;

use rustix::process::{Resource, Rlimit, dumpable_behavior, getrlimit, setrlimit};

use iron_vault::hardening::{CoreDumps, HardeningReport, LockUnavailable, MemoryProtection, harden_process};

/// Set only in the child process, so `hardened_child` hardens the child and never the test runner.
const CHILD_ENV: &str = "IRON_VAULT_HARDENING_CHILD";
const CHILD_TEST: &str = "hardening::hardened_child";
/// The finite `RLIMIT_MEMLOCK` soft limit the child sets; lowering a soft limit needs no privilege.
const CHILD_MEMLOCK: u64 = 65_536;

/// The child half of the hardening test: a no-op unless the parent test launched it.
#[test]
fn hardened_child() {
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    let hard = getrlimit(Resource::Memlock).maximum;
    let soft = hard.map_or(CHILD_MEMLOCK, |hard| hard.min(CHILD_MEMLOCK));
    setrlimit(
        Resource::Memlock,
        Rlimit {
            current: Some(soft),
            maximum: hard,
        },
    )
    .unwrap();
    let report = harden_process();
    // The leading newline keeps the first value off the harness's "test ... " line.
    println!();
    println!("memlock={soft}");
    println!("core={:?}", getrlimit(Resource::Core).current);
    println!("dumpable={:?}", dumpable_behavior().unwrap());
    println!("report={report}");
}

fn run_child() -> String {
    let output = Command::new(std::env::current_exe().unwrap())
        .args([CHILD_TEST, "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        output.status.success(),
        "child failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    stdout
}

fn field<'a>(stdout: &'a str, key: &str) -> &'a str {
    stdout
        .lines()
        .find_map(|line| line.strip_prefix(key))
        .unwrap_or_else(|| panic!("no {key} in child output:\n{stdout}"))
}

#[test]
fn harden_process_disables_dumps_and_skips_locking_under_a_finite_limit() {
    let stdout = run_child();
    let limit_bytes: u64 = field(&stdout, "memlock=").parse().unwrap();
    assert_eq!(field(&stdout, "core="), "Some(0)");
    assert_eq!(field(&stdout, "dumpable="), "NotDumpable");
    let expected = HardeningReport {
        core_dumps: CoreDumps::Disabled,
        memory: MemoryProtection::Unavailable(LockUnavailable::LimitTooLow { limit_bytes }),
    };
    // `LimitTooLow` is only reported when `mlockall` was never called; a call would yield `Locked` or `LockFailed`.
    assert_eq!(field(&stdout, "report="), expected.to_string());
}
