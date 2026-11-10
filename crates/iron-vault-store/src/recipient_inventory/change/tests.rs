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
    let recovery = key_of(&current, RecipientRole::Recovery);
    let again = current.get(&recovery).unwrap().clone();
    assert_refused(&current, RecipientChange::Add(again), RecipientChangeRefusal::AlreadyEnrolled);
}

#[test]
fn removing_a_key_that_is_not_enrolled_is_refused() {
    let stranger = RecipientIdentity::generate().recipient_key();
    assert_refused(&initial(), RecipientChange::Remove(stranger), RecipientChangeRefusal::NotEnrolled);
}

/// A second `operational` entry could stand in for the first, so a later removal of the real one would pass part 1 and
/// leave out the key `operational.age` opens.
#[test]
fn adding_an_operational_recipient_is_refused() {
    let current = inventory(&[RecipientRole::Operational, RecipientRole::Recovery, RecipientRole::Added]);
    let change = RecipientChange::Add(entry(RecipientRole::Operational));
    assert_refused(&current, change, RecipientChangeRefusal::AddsOperational);
}

#[test]
fn removing_an_operational_recipient_is_refused() {
    let current = inventory(&[RecipientRole::Operational, RecipientRole::Operational, RecipientRole::Recovery]);
    let operational = key_of(&current, RecipientRole::Operational);
    assert_refused(
        &current,
        RecipientChange::Remove(operational),
        RecipientChangeRefusal::RemovesOperational,
    );
}

#[test]
fn a_change_that_leaves_no_operational_recipient_is_refused() {
    let current = inventory(&[RecipientRole::Recovery, RecipientRole::Added]);
    let change = RecipientChange::Add(entry(RecipientRole::Added));
    assert_refused(&current, change, RecipientChangeRefusal::NoOperational);
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

/// A Compose vault after re-enrolment: the old and the new host unlock identity are both `host-unlock` recipients.
fn two_host_unlocks() -> (RecipientInventory, RecipientKey, RecipientKey) {
    let current = inventory(&[
        RecipientRole::Operational,
        RecipientRole::Recovery,
        RecipientRole::HostUnlock,
        RecipientRole::HostUnlock,
    ]);
    let keys: Vec<RecipientKey> = current
        .entries()
        .filter(|entry| entry.role() == RecipientRole::HostUnlock)
        .map(|entry| entry.key().clone())
        .collect();
    (current, keys[0].clone(), keys[1].clone())
}

#[test]
fn a_host_unlock_recipient_the_handoff_does_not_hold_can_be_removed() {
    let (current, old, new) = two_host_unlocks();
    let next = RecipientChange::Remove(old.clone()).apply_configured(&current, Some(&new)).unwrap();
    assert_eq!(next.get(&old), None);
}

#[test]
fn the_host_unlock_recipient_the_handoff_holds_is_kept() {
    let (current, old, _) = two_host_unlocks();
    let before = current.clone();
    assert_eq!(
        RecipientChange::Remove(old.clone()).apply_configured(&current, Some(&old)),
        Err(RecipientChangeRefusal::RemovesConfiguredHostUnlock)
    );
    assert_eq!(current, before);
}

#[test]
fn with_no_configured_adapter_the_last_host_unlock_recipient_can_be_removed() {
    let current = inventory(&[RecipientRole::Operational, RecipientRole::Recovery, RecipientRole::HostUnlock]);
    let host = key_of(&current, RecipientRole::HostUnlock);
    assert!(RecipientChange::Remove(host).apply_configured(&current, None).is_ok());
}

#[test]
fn an_added_recipient_with_the_handoff_key_is_not_the_adapters_recipient() {
    let current = inventory(&[RecipientRole::Operational, RecipientRole::Recovery, RecipientRole::Added]);
    let added = key_of(&current, RecipientRole::Added);
    assert!(
        RecipientChange::Remove(added.clone())
            .apply_configured(&current, Some(&added))
            .is_ok()
    );
}
