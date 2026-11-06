use std::sync::Arc;

use tokio::sync::Mutex;

use super::{Inner, SettleGuard};
use crate::migration_authorization::PendingMigration;
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
