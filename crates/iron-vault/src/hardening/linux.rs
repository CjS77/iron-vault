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
