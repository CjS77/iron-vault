//! The approver order (design/approval-signers.md, "Approver order"): which pinned approver the approver prompt asks
//! first, and which each switch moves to.
//!
//! Pure, so the order is testable without a service. Nothing is stored: the order is recomputed from the approval state
//! and the active approval's signer at each prompt, so an owner has no preference to set.

use iron_vault_store::{ApproverId, PinnedApprover};

/// `approvers` in approver order: the signer of the active approval first, when it is still pinned, then every other
/// approver by enrolment time, earliest first, with ties broken by approver ID. With no active approval (the service is
/// Unavailable) that is enrolment order alone.
pub(super) fn approver_order(approvers: &[PinnedApprover], active: Option<ApproverId>) -> Vec<PinnedApprover> {
    let mut ordered = approvers.to_vec();
    ordered.sort_by_key(|approver| (Some(approver.id()) != active, approver.enrolled_at(), approver.id()));
    ordered
}

#[cfg(test)]
mod tests {
    use iron_vault_store::{ApproverLabel, ApproverPublicKey, SignatureAlgorithm, SignerKind, UtcSecond};

    use super::*;

    fn approver(id: ApproverId, enrolled_at: u64, seed: u8) -> PinnedApprover {
        let key = ApproverPublicKey::new(SignatureAlgorithm::Ed25519, signing_key_bytes(seed)).unwrap();
        let label = ApproverLabel::new(&format!("approver {seed}")).unwrap();
        PinnedApprover::new(
            id,
            SignerKind::Software,
            key,
            label,
            UtcSecond::from_unix_seconds(enrolled_at).unwrap(),
        )
        .unwrap()
    }

    fn signing_key_bytes(seed: u8) -> Vec<u8> {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes()
            .to_vec()
    }

    fn ids(ordered: &[PinnedApprover]) -> Vec<ApproverId> {
        ordered.iter().map(PinnedApprover::id).collect()
    }

    fn three() -> (Vec<PinnedApprover>, [ApproverId; 3]) {
        let mut generated = [ApproverId::generate(), ApproverId::generate(), ApproverId::generate()];
        generated.sort();
        let [low, mid, high] = generated;
        // Enrolled earliest to latest: high, low, mid, so enrolment order differs from ID order.
        (
            vec![approver(low, 20, 1), approver(mid, 30, 2), approver(high, 10, 3)],
            [low, mid, high],
        )
    }

    #[test]
    fn enrolment_order_without_an_active_approval() {
        let (approvers, [low, mid, high]) = three();
        assert_eq!(ids(&approver_order(&approvers, None)), [high, low, mid]);
    }

    #[test]
    fn the_active_signer_is_first_and_the_rest_keep_enrolment_order() {
        let (approvers, [low, mid, high]) = three();
        assert_eq!(ids(&approver_order(&approvers, Some(mid))), [mid, high, low]);
    }

    #[test]
    fn an_active_signer_that_is_no_longer_pinned_changes_nothing() {
        let (approvers, [low, mid, high]) = three();
        assert_eq!(ids(&approver_order(&approvers, Some(ApproverId::generate()))), [high, low, mid]);
    }

    #[test]
    fn equal_enrolment_times_are_ordered_by_approver_id() {
        let mut generated = [ApproverId::generate(), ApproverId::generate()];
        generated.sort();
        let [low, high] = generated;
        let approvers = vec![approver(high, 5, 1), approver(low, 5, 2)];
        assert_eq!(ids(&approver_order(&approvers, None)), [low, high]);
    }
}
