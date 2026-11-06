use std::sync::Arc;

use tokio::sync::Mutex;

use super::unlock::memory_guard;
use super::{Inner, SettleGuard, UnlockRefusal};
use crate::deployment::DeploymentProfile;
use crate::hardening::{LockUnavailable, MemoryProtection};
use crate::migration_authorization::{AttemptLimiter, PendingMigration};
use crate::service_state::{FailureReason, ServiceState, UnavailableReason};
use crate::serving_snapshot::{Admission, SnapshotHolder};
use crate::socket_activation::PassedSockets;

fn inner_in(state: ServiceState) -> Arc<Mutex<Inner>> {
    Arc::new(Mutex::new(Inner {
        state,
        identity: None,
        open: None,
        serving: None,
        passed: PassedSockets::default(),
        checks: 0,
        migration: PendingMigration::new(tokio::time::Instant::now()),
        attempts: AttemptLimiter::new(),
    }))
}

/// Drops a settle guard held on `inner`, as a crashed settle task does, and returns the state and the holder's admission
/// it left.
fn drop_guard(inner: &Arc<Mutex<Inner>>, holder: &Arc<SnapshotHolder>) -> (ServiceState, Admission) {
    let guard = SettleGuard::new(Arc::clone(inner).try_lock_owned().unwrap(), Arc::clone(holder));
    drop(guard);
    (inner.try_lock().unwrap().state, holder.load())
}

#[test]
fn dropping_the_settle_guard_in_checking_fails_closed() {
    let inner = inner_in(ServiceState::Checking);
    let holder = Arc::new(SnapshotHolder::refusing(UnavailableReason::Checking));
    let (state, admission) = drop_guard(&inner, &holder);
    assert_eq!(state, ServiceState::Unavailable(FailureReason::RecoveryNeeded));
    let refused = UnavailableReason::from_failure(FailureReason::RecoveryNeeded);
    assert!(matches!(admission, Admission::Refuse(reason) if reason == refused));
}

#[test]
fn dropping_the_settle_guard_after_settling_keeps_the_state() {
    let inner = inner_in(ServiceState::Unavailable(FailureReason::PolicyInvalid));
    let refused = UnavailableReason::from_failure(FailureReason::PolicyInvalid);
    let holder = Arc::new(SnapshotHolder::refusing(refused));
    let (state, admission) = drop_guard(&inner, &holder);
    assert_eq!(state, ServiceState::Unavailable(FailureReason::PolicyInvalid));
    assert!(matches!(admission, Admission::Refuse(reason) if reason == refused));
}

/// Every memory protection status but `Locked`, each with the reason its refusal message names.
fn unprotected() -> [(MemoryProtection, &'static str); 3] {
    [
        (
            MemoryProtection::Unavailable(LockUnavailable::LimitTooLow { limit_bytes: 65_536 }),
            "RLIMIT_MEMLOCK soft limit is 65536 bytes, not unlimited",
        ),
        (
            MemoryProtection::Unavailable(LockUnavailable::LockFailed {
                error: "Cannot allocate memory".to_owned(),
            }),
            "mlockall failed: Cannot allocate memory",
        ),
        (MemoryProtection::Unsupported, "this platform has no memory-locking adapter"),
    ]
}

#[test]
fn a_protected_install_refuses_unlock_unless_memory_is_locked() {
    unprotected().into_iter().for_each(|(memory, reason)| {
        let refusal = memory_guard(DeploymentProfile::Protected, &memory).unwrap_err();
        let expected = format!("memory is not locked against swap ({reason}), so a protected install does not open the vault");
        assert_eq!(refusal.to_string(), expected);
        assert!(matches!(refusal, UnlockRefusal::MemoryUnprotected(held) if held == memory));
    });
    assert!(memory_guard(DeploymentProfile::Protected, &MemoryProtection::Locked).is_ok());
}

#[test]
fn development_mode_never_refuses_unlock_for_memory() {
    unprotected()
        .into_iter()
        .map(|(memory, _)| memory)
        .chain([MemoryProtection::Locked])
        .for_each(|memory| assert!(memory_guard(DeploymentProfile::Development, &memory).is_ok(), "{memory}"));
}
