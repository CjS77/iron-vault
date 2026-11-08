use iron_vault_store::{EnvelopeError, RecipientChangeError};

use super::*;
use crate::service_state::ServiceState;

const KEY: &str = "age1v4q6gqhc84l6yrmyeqcske956a65frdww5rc4jnrdfhkpsdglqksx4muhw";

fn answer(response: AdminResponse) -> (ErrorCode, String) {
    match response {
        AdminResponse::Error { code, message } => (code, message),
        other => panic!("expected an error, got {other:?}"),
    }
}

#[test]
fn a_bad_key_or_label_names_the_rule_and_not_the_argument() {
    let (key, label) = parse_arguments(KEY, "bob's new laptop").unwrap();
    assert_eq!((key.to_string().as_str(), label.as_str()), (KEY, "bob's new laptop"));
    ["", "age1", "AGE-SECRET-KEY-1QQQ", "not a key"].into_iter().for_each(|bad| {
        let message = parse_arguments(bad, "x").unwrap_err();
        assert_eq!(message, "the recipient is not an age1... X25519 recipient key");
    });
    ["", " padded", "tab\there", &"x".repeat(65)].into_iter().for_each(|bad| {
        let message = parse_arguments(KEY, bad).unwrap_err();
        assert!(message.starts_with("invalid label: "), "{message}");
    });
}

#[test]
fn each_rule_refusal_has_the_documented_code() {
    use RecipientChangeRefusal::*;
    [
        (AlreadyEnrolled, ErrorCode::RecipientEnrolled),
        (TooMany, ErrorCode::RecipientSetInvalid),
        (NoRecovery, ErrorCode::RecipientSetInvalid),
        (NoOperational, ErrorCode::RecipientSetInvalid),
    ]
    .into_iter()
    .for_each(|(rule, code)| {
        let (got, message) = answer(plan_refused(PlanRefusal::Rule(rule)));
        assert_eq!(got, code);
        assert!(message.ends_with("nothing was changed"), "{message}");
    });
}

#[test]
fn a_step_3_refusal_outside_ready_or_with_a_damaged_inventory_uses_the_shared_codes() {
    let wrong = PlanRefusal::Inventory(crate::service_context::RecipientRefusal::WrongState(ServiceState::Locked));
    let (code, message) = answer(plan_refused(wrong));
    assert_eq!(code, ErrorCode::WrongState);
    assert!(message.contains("`recipient add`"), "{message}");
    let damaged = PlanRefusal::Inventory(crate::service_context::RecipientRefusal::Damaged(
        iron_vault_store::InventoryDamage::Mac,
    ));
    assert_eq!(answer(plan_refused(damaged)).0, ErrorCode::RecipientInventoryDamaged);
}

#[test]
fn a_failed_rewrap_says_whether_it_may_have_committed() {
    let (code, message) = answer(add_refused(
        AddRefusal::Failed(RecipientChangeError::Wrap(EnvelopeError::Encryption)),
        UNKNOWN_KEY,
    ));
    assert_eq!(code, ErrorCode::VaultWriteFailed);
    assert!(message.ends_with("nothing was changed"), "{message}");
    let (code, message) = answer(add_refused(AddRefusal::Interrupted, UNKNOWN_KEY));
    assert_eq!(code, ErrorCode::VaultWriteFailed);
    assert!(
        message.contains("may have committed") && message.contains("recipient list"),
        "{message}"
    );
    assert_eq!(
        answer(add_refused(AddRefusal::WrongState(ServiceState::Locked), UNKNOWN_KEY)).0,
        ErrorCode::WrongState
    );
}

#[test]
fn a_service_that_is_not_ready_is_wrong_state_even_when_locked() {
    let (code, message) = answer(not_begun(MigrationRefusal::WrongState(ServiceState::Locked)));
    assert_eq!(code, ErrorCode::WrongState);
    assert!(message.contains("`recipient add`") && message.contains("Locked"), "{message}");
    assert_eq!(answer(not_begun(MigrationRefusal::Unavailable)).0, ErrorCode::MigrationUnavailable);
}

const NEW_KEY: &str = "age1csc5wgcsw68jdz8uxh9sramjkys02nk8qf740lpywzvlzm9pjf7qxffk4e";

fn rotated(refusal: AddRefusal) -> String {
    answer(revealed_key_advice(&NEW_KEY.parse().unwrap(), refusal)).1
}

#[test]
fn an_uncertain_rotation_names_the_new_key_once() {
    let message = rotated(AddRefusal::Interrupted);
    assert!(message.ends_with(&unconfirmed_rotated_key(&NEW_KEY)), "{message}");
    assert_eq!(message.matches("recipient list").count(), 1, "{message}");
    assert!(!message.contains(DEAD_RECOVERY_KEY));
}

#[test]
fn a_rotation_that_enrolled_nothing_calls_the_key_dead() {
    let refusals = [
        AddRefusal::Failed(RecipientChangeError::Wrap(EnvelopeError::Encryption)),
        AddRefusal::Unauthorized(MigrationRefusal::Unavailable),
        AddRefusal::WrongState(ServiceState::Locked),
    ];
    refusals.into_iter().for_each(|refusal| {
        let message = rotated(refusal);
        assert!(message.ends_with(DEAD_RECOVERY_KEY), "{message}");
    });
}

#[test]
fn advice_is_added_to_errors_only() {
    let kept = with_advice(AdminResponse::Success, "x");
    assert!(matches!(kept, AdminResponse::Success));
    assert_eq!(answer(with_advice(error(ErrorCode::Declined, "no".to_owned()), "x")).1, "no; x");
}
