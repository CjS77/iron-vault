use super::*;
use crate::{RecipientIdentity, RecipientLabel, UtcSecond, VaultId};

fn entry(role: RecipientRole) -> RecipientEntry {
    let key = RecipientIdentity::generate().recipient_key();
    RecipientEntry::new(key, role, RecipientLabel::new(role.name()).unwrap(), UtcSecond::EPOCH)
}

fn inventory(roles: &[RecipientRole]) -> RecipientInventory {
    RecipientInventory::new(VaultId::new_random(), [7; 32], roles.iter().map(|&role| entry(role))).unwrap()
}

/// The vault `init` leaves: one `operational` and one `recovery` recipient.
fn initial() -> RecipientInventory {
    inventory(&[RecipientRole::Operational, RecipientRole::Recovery])
}

fn key_of(inventory: &RecipientInventory, role: RecipientRole) -> RecipientKey {
    inventory.entries().find(|entry| entry.role() == role).unwrap().key().clone()
}

/// Applies `change` to `current`, which must refuse it with `refusal` and leave `current` as it was.
fn assert_refused(current: &RecipientInventory, change: RecipientChange, refusal: RecipientChangeRefusal) {
    let before = current.clone();
    assert_eq!(change.apply(current), Err(refusal));
    assert_eq!(*current, before);
}

#[test]
fn an_add_enrolls_the_entry_and_keeps_the_rest() {
    let current = initial();
    let added = entry(RecipientRole::Added);
    let next = RecipientChange::Add(added.clone()).apply(&current).unwrap();
    assert_eq!(next.get(added.key()), Some(&added));
    assert_eq!(next.entries().len(), 3);
    assert!(current.entries().all(|entry| next.get(entry.key()) == Some(entry)));
    assert_eq!(
        (next.vault_id(), next.envelope_digest()),
        (current.vault_id(), current.envelope_digest())
    );
}

#[test]
fn a_remove_drops_only_that_entry() {
    let current = inventory(&[RecipientRole::Operational, RecipientRole::Recovery, RecipientRole::Added]);
    let added = key_of(&current, RecipientRole::Added);
    let next = RecipientChange::Remove(added.clone()).apply(&current).unwrap();
    assert_eq!(next.get(&added), None);
    assert_eq!(next.entries().len(), 2);
}

#[test]
fn a_second_recovery_recipient_can_replace_the_first() {
    let current = inventory(&[RecipientRole::Operational, RecipientRole::Recovery, RecipientRole::Recovery]);
    let one = key_of(&current, RecipientRole::Recovery);
    assert!(RecipientChange::Remove(one).apply(&current).is_ok());
}

#[test]
fn adding_an_enrolled_key_is_refused() {
    let current = initial();
    let again = current.entries().next().unwrap().clone();
    assert_refused(&current, RecipientChange::Add(again), RecipientChangeRefusal::AlreadyEnrolled);
}

#[test]
fn removing_a_key_that_is_not_enrolled_is_refused() {
    let stranger = RecipientIdentity::generate().recipient_key();
    assert_refused(&initial(), RecipientChange::Remove(stranger), RecipientChangeRefusal::NotEnrolled);
}

#[test]
fn removing_the_operational_recipient_is_refused() {
    let current = inventory(&[RecipientRole::Operational, RecipientRole::Recovery, RecipientRole::Added]);
    let operational = key_of(&current, RecipientRole::Operational);
    assert_refused(
        &current,
        RecipientChange::Remove(operational),
        RecipientChangeRefusal::NoOperational,
    );
    let initial = initial();
    let operational = key_of(&initial, RecipientRole::Operational);
    assert_refused(
        &initial,
        RecipientChange::Remove(operational),
        RecipientChangeRefusal::NoOperational,
    );
}

#[test]
fn removing_the_last_recovery_recipient_is_refused() {
    let current = inventory(&[RecipientRole::Operational, RecipientRole::Recovery, RecipientRole::Added]);
    let recovery = key_of(&current, RecipientRole::Recovery);
    assert_refused(&current, RecipientChange::Remove(recovery), RecipientChangeRefusal::NoRecovery);
}

/// Parts 1 and 3 hold two distinct entries between them, so no change reaches part 4's floor in v0; the part is checked
/// on its own.
#[test]
fn fewer_than_two_recipients_breaks_the_count_rule() {
    assert_eq!(count_rule(0), Err(RecipientChangeRefusal::TooFew));
    assert_eq!(count_rule(1), Err(RecipientChangeRefusal::TooFew));
    assert_eq!(count_rule(2), Ok(()));
    assert_eq!(count_rule(MAX_RECIPIENTS), Ok(()));
}

#[test]
fn adding_past_the_maximum_is_refused() {
    let roles: Vec<RecipientRole> = [RecipientRole::Operational, RecipientRole::Recovery]
        .into_iter()
        .chain(std::iter::repeat_n(RecipientRole::Added, MAX_RECIPIENTS - 2))
        .collect();
    let full = inventory(&roles);
    assert_refused(
        &full,
        RecipientChange::Add(entry(RecipientRole::Added)),
        RecipientChangeRefusal::TooMany,
    );
}

#[test]
fn describing_changes_only_the_envelope_digest() {
    let current = initial();
    let described = current.clone().describing([9; 32]);
    assert_eq!(described.envelope_digest(), &[9; 32]);
    assert!(described.entries().eq(current.entries()));
}
