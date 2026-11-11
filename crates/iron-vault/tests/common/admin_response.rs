//! Comparing admin responses, which have no `PartialEq` because `caller-token`'s result holds a secret.

use iron_vault::admin::protocol::AdminResponse;

/// Asserts that `actual` is `expected`: the same variant with the same fields. Only the variants these tests expect are
/// compared; any other is a mismatch.
pub fn assert_response(actual: &AdminResponse, expected: &AdminResponse) {
    let same = match (actual, expected) {
        (AdminResponse::Success, AdminResponse::Success) => true,
        (AdminResponse::Ping { profile: a }, AdminResponse::Ping { profile: b }) => a == b,
        (AdminResponse::Unlock { owner_lock_removed: a }, AdminResponse::Unlock { owner_lock_removed: b }) => a == b,
        (AdminResponse::Lock { cleared: a, .. }, AdminResponse::Lock { cleared: b, .. }) => a == b,
        (AdminResponse::Error { code: a, message: m }, AdminResponse::Error { code: b, message: n }) => a == b && m == n,
        _ => false,
    };
    assert!(same, "expected {expected:?}, got {actual:?}");
}
