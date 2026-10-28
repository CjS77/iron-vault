//! Process hardening: turn off core dumps and keep memory out of swap before the service holds any secret.
//!
//! A core dump or a swapped-out page would leave the vault identity and credential values on disk in plain text
//! (specification §3.11, R-20). This module only measures and reports what took effect; whether an incomplete
//! report stops the service is a deployment-profile decision.

// Off Linux only the unsupported report is built; the locking outcomes wait for the platform adapters.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::fmt;

#[cfg(target_os = "linux")]
mod linux;

/// What process hardening achieved, reported at startup and later in `status`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardeningReport {
    /// Whether core dumps are off for this process.
    pub core_dumps: CoreDumps,
    /// The memory protection status.
    pub memory: MemoryProtection,
}

/// Whether the process can still write a core dump.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreDumps {
    /// `RLIMIT_CORE` is 0 and the process is not dumpable, both read back after setting them.
    Disabled,
    /// At least one step failed or did not read back; the text names each failure.
    Failed(String),
}

/// Whether the service's memory is kept out of swap. Only `Locked` means swap protection is in effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoryProtection {
    /// `mlockall` returned success for current and future mappings.
    Locked,
    /// Memory was not locked.
    Unavailable(LockUnavailable),
    /// This platform has no memory-locking adapter yet. Linux builds never construct it.
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    Unsupported,
}

/// Why memory was not locked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockUnavailable {
    /// The `RLIMIT_MEMLOCK` soft limit is finite, so locking was not attempted.
    LimitTooLow {
        /// The soft limit in bytes.
        limit_bytes: u64,
    },
    /// `mlockall` returned an error.
    LockFailed {
        /// The system error text.
        error: String,
    },
}

/// Whether to call `mlockall`, decided from the `RLIMIT_MEMLOCK` soft limit alone.
#[derive(Debug, Clone, PartialEq, Eq)]
enum LockPlan {
    /// Lock current and future mappings.
    LockAll,
    /// Do not lock, for the given reason.
    Skip(LockUnavailable),
}

/// Decides whether locking is safe under the `RLIMIT_MEMLOCK` soft limit, where `None` means unlimited.
///
/// Locking uses `MCL_FUTURE`, so once locked, every later allocation must also fit under the limit; under a finite
/// limit the service would fail allocations, and abort, as soon as it grew past it. Locking only when the limit is
/// unlimited avoids that. The Linux package grants `LimitMEMLOCK=infinity`.
fn memory_lock_plan(memlock_soft_limit: Option<u64>) -> LockPlan {
    memlock_soft_limit.map_or(LockPlan::LockAll, |limit_bytes| LockPlan::Skip(LockUnavailable::LimitTooLow { limit_bytes }))
}

/// Disables core dumps and locks memory where it is safe to, then reports what took effect.
///
/// Call it first in `main`, before any secret exists, so nothing secret is ever dumpable or swappable.
#[cfg(target_os = "linux")]
pub fn harden_process() -> HardeningReport {
    HardeningReport { core_dumps: linux::disable_core_dumps(), memory: linux::lock_memory() }
}

/// Reports that this platform has no hardening adapter yet, rather than claiming protection it lacks.
#[cfg(not(target_os = "linux"))]
pub fn harden_process() -> HardeningReport {
    HardeningReport { core_dumps: CoreDumps::Failed("unsupported platform".to_owned()), memory: MemoryProtection::Unsupported }
}

/// Logs the report: each missing protection at ERROR with its fix, and full success at INFO.
pub fn log_report(report: &HardeningReport) {
    if let CoreDumps::Failed(reason) = &report.core_dumps {
        tracing::error!("core dumps are not disabled ({reason}); a crash could write secrets to disk");
    }
    match &report.memory {
        MemoryProtection::Locked if report.core_dumps == CoreDumps::Disabled => tracing::info!("process hardened: {report}"),
        MemoryProtection::Locked => {}
        MemoryProtection::Unavailable(_) => tracing::error!(
            "{}; swap protection is not in effect. Run the service with LimitMEMLOCK=infinity, or use encrypted swap as \
             the install guide describes",
            report.memory
        ),
        MemoryProtection::Unsupported => {
            tracing::error!("{}; swap protection is not in effect. Use encrypted swap as the install guide describes", report.memory)
        }
    }
}

impl fmt::Display for HardeningReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}; {}", self.core_dumps, self.memory)
    }
}

impl fmt::Display for CoreDumps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => f.write_str("core dumps: disabled"),
            Self::Failed(reason) => write!(f, "core dumps: NOT disabled ({reason})"),
        }
    }
}

// Only `Locked` may use the word "locked": the other wordings are what an operator greps status for.
impl fmt::Display for MemoryProtection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Locked => f.write_str("memory: locked against swap"),
            Self::Unavailable(LockUnavailable::LimitTooLow { limit_bytes }) => write!(
                f,
                "memory: swap protection unavailable (RLIMIT_MEMLOCK soft limit is {limit_bytes} bytes, not unlimited)"
            ),
            Self::Unavailable(LockUnavailable::LockFailed { error }) => {
                write!(f, "memory: swap protection unavailable (mlockall failed: {error})")
            }
            Self::Unsupported => f.write_str("memory: swap protection unsupported on this platform"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unprotected() -> [MemoryProtection; 3] {
        [
            MemoryProtection::Unavailable(LockUnavailable::LimitTooLow { limit_bytes: 65_536 }),
            MemoryProtection::Unavailable(LockUnavailable::LockFailed { error: "Cannot allocate memory".to_owned() }),
            MemoryProtection::Unsupported,
        ]
    }

    #[test]
    fn unlimited_memlock_plans_a_lock() {
        assert_eq!(memory_lock_plan(None), LockPlan::LockAll);
    }

    #[test]
    fn finite_memlock_skips_locking_and_names_the_limit() {
        [0, 65_536, u64::MAX - 1].into_iter().for_each(|limit_bytes| {
            assert_eq!(memory_lock_plan(Some(limit_bytes)), LockPlan::Skip(LockUnavailable::LimitTooLow { limit_bytes }));
        });
    }

    #[test]
    fn only_locked_memory_displays_as_locked() {
        assert_eq!(MemoryProtection::Locked.to_string(), "memory: locked against swap");
        unprotected().iter().for_each(|memory| assert!(!memory.to_string().to_lowercase().contains("locked"), "{memory}"));
    }

    #[test]
    fn report_display_is_fixed_text() {
        let report = HardeningReport {
            core_dumps: CoreDumps::Disabled,
            memory: MemoryProtection::Unavailable(LockUnavailable::LimitTooLow { limit_bytes: 8_388_608 }),
        };
        assert_eq!(
            report.to_string(),
            "core dumps: disabled; memory: swap protection unavailable (RLIMIT_MEMLOCK soft limit is 8388608 bytes, not unlimited)"
        );
        let failed =
            HardeningReport { core_dumps: CoreDumps::Failed("unsupported platform".to_owned()), memory: MemoryProtection::Unsupported };
        assert_eq!(
            failed.to_string(),
            "core dumps: NOT disabled (unsupported platform); memory: swap protection unsupported on this platform"
        );
    }
}
