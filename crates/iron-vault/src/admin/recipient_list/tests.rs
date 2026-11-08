use super::*;
use crate::service_state::ServiceState;

fn answer(refusal: RecipientRefusal) -> (ErrorCode, String) {
    match refused("recipient list", refusal) {
        AdminResponse::Error { code, message } => (code, message),
        other => panic!("expected an error, got {other:?}"),
    }
}

#[test]
fn each_refusal_has_the_documented_code() {
    let cases = [
        (RecipientRefusal::Busy, ErrorCode::Busy),
        (RecipientRefusal::WrongState(ServiceState::Locked), ErrorCode::WrongState),
        (
            RecipientRefusal::Damaged(InventoryDamage::Mac),
            ErrorCode::RecipientInventoryDamaged,
        ),
        (RecipientRefusal::Write("x".to_owned()), ErrorCode::VaultWriteFailed),
        (RecipientRefusal::Interrupted, ErrorCode::VaultWriteFailed),
    ];
    cases.into_iter().for_each(|(refusal, code)| assert_eq!(answer(refusal).0, code));
}

#[test]
fn the_damage_is_named_and_only_a_missing_inventory_mentions_older_vaults() {
    let (_, missing) = answer(RecipientRefusal::Damaged(InventoryDamage::Missing));
    let (_, mac) = answer(RecipientRefusal::Damaged(InventoryDamage::Mac));
    assert!(
        missing.contains("(missing)") && missing.contains("initialized before recipient commands"),
        "{missing}"
    );
    assert!(mac.contains("(mac)") && !mac.contains("before"), "{mac}");
}
