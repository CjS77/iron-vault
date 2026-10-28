//! Linux hardening through `rustix`: `RLIMIT_CORE`, `PR_SET_DUMPABLE` and `mlockall`.

use rustix::mm::{MlockAllFlags, mlockall};
use rustix::process::{DumpableBehavior, Resource, Rlimit, dumpable_behavior, getrlimit, set_dumpable_behavior, setrlimit};

use super::{CoreDumps, LockPlan, LockUnavailable, MemoryProtection, memory_lock_plan};

/// Zeroes the core-size limit and clears the dumpable flag, attempting both even when one fails.
pub(super) fn disable_core_dumps() -> CoreDumps {
    let failures: Vec<String> = [zero_core_limit(), clear_dumpable()].into_iter().filter_map(Result::err).collect();
    if failures.is_empty() {
        CoreDumps::Disabled
    } else {
        CoreDumps::Failed(failures.join("; "))
    }
}

/// Sets both limits to 0, so nothing in this process can raise the soft limit again, then reads the soft limit back.
fn zero_core_limit() -> Result<(), String> {
    setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .map_err(|e| format!("setting RLIMIT_CORE failed: {e}"))?;
    match getrlimit(Resource::Core).current {
        Some(0) => Ok(()),
        other => Err(format!("RLIMIT_CORE reads back as {other:?}")),
    }
}

/// Clears the dumpable flag, which also blocks `ptrace` attach by same-user processes, then reads it back.
fn clear_dumpable() -> Result<(), String> {
    set_dumpable_behavior(DumpableBehavior::NotDumpable).map_err(|e| format!("PR_SET_DUMPABLE failed: {e}"))?;
    match dumpable_behavior() {
        Ok(DumpableBehavior::NotDumpable) => Ok(()),
        Ok(other) => Err(format!("PR_GET_DUMPABLE reads back as {other:?}")),
        Err(e) => Err(format!("PR_GET_DUMPABLE failed: {e}")),
    }
}

/// Locks current and future mappings when the `RLIMIT_MEMLOCK` soft limit allows it; see [`memory_lock_plan`].
pub(super) fn lock_memory() -> MemoryProtection {
    match memory_lock_plan(getrlimit(Resource::Memlock).current) {
        LockPlan::Skip(reason) => MemoryProtection::Unavailable(reason),
        LockPlan::LockAll => mlockall(MlockAllFlags::CURRENT | MlockAllFlags::FUTURE).map_or_else(
            |e| MemoryProtection::Unavailable(LockUnavailable::LockFailed { error: e.to_string() }),
            |()| MemoryProtection::Locked,
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use rustix::process::{Resource, Rlimit, dumpable_behavior, getrlimit, setrlimit};

    use crate::hardening::{CoreDumps, HardeningReport, LockUnavailable, MemoryProtection, harden_process};

    /// Set only in the child process, so `hardened_child` hardens the child and never the test runner.
    const CHILD_ENV: &str = "IRON_VAULT_HARDENING_CHILD";
    const CHILD_TEST: &str = "hardening::linux::tests::hardened_child";
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
}
