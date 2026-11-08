use super::*;
use crate::recipient_inventory::seal_with_role_code;
use crate::test_vault::{TestVault, entry};
use crate::{RecipientEntry, RecipientIdentity, RecipientRole, seal_recipient_inventory};

fn current() -> StateFileName {
    StateFileName::recipient_inventory()
}

fn staged() -> StateFileName {
    StateFileName::staged_recipient_inventory()
}

/// An inventory sealed by this vault's identity, with the vault ID, digest and entries `vary` gives it.
fn sealed(vault: &TestVault, vary: impl FnOnce(&TestVault) -> (VaultId, [u8; 32], Vec<RecipientEntry>)) -> Vec<u8> {
    let (vault_id, digest, entries) = vary(vault);
    let inventory = RecipientInventory::new(vault_id, digest, entries).unwrap();
    seal_recipient_inventory(&vault.vault, &inventory).unwrap()
}

fn setup_entries(vault: &TestVault) -> Vec<RecipientEntry> {
    vault.inventory.entries().cloned().collect()
}

/// An inventory of this vault that describes another envelope.
fn other_envelope(vault: &TestVault) -> Vec<u8> {
    sealed(vault, |vault| (vault.vault_id, [7; 32], setup_entries(vault)))
}

/// A label for the test directory, what to damage, and the damage the check must name.
type DamageCase = (&'static str, fn(&TestVault), InventoryDamage);

fn damaged(damage: InventoryDamage) -> Result<CheckedInventory, InventoryCheckError> {
    Err(InventoryCheckError::Damaged(damage))
}

#[test]
fn an_inventory_that_matches_the_envelope_is_checked_as_it_is() {
    let vault = TestVault::new("check-clean");
    let before = vault.files();
    assert_eq!(
        vault.check().unwrap(),
        CheckedInventory {
            inventory: vault.inventory.clone(),
            recovered: None
        }
    );
    assert_eq!(vault.files(), before);
}

#[test]
fn each_kind_of_damage_is_named_and_nothing_is_written() {
    let cases: [DamageCase; 9] = [
        ("check-missing", |vault| vault.remove(&current()), InventoryDamage::Missing),
        (
            "check-mac",
            |vault| {
                let mut bytes = vault.file(&current()).unwrap();
                *bytes.last_mut().unwrap() ^= 1;
                vault.put(&current(), &bytes);
            },
            InventoryDamage::Mac,
        ),
        (
            "check-malformed",
            |vault| vault.put(&current(), b"not an inventory"),
            InventoryDamage::Malformed,
        ),
        (
            "check-envelope",
            |vault| vault.put(&current(), &other_envelope(vault)),
            InventoryDamage::EnvelopeMismatch,
        ),
        (
            "check-count",
            |vault| {
                let extra = entry(&RecipientIdentity::generate(), RecipientRole::Added);
                let bytes = sealed(vault, |vault| {
                    let entries = setup_entries(vault).into_iter().chain([extra]).collect();
                    (vault.vault_id, *vault.inventory.envelope_digest(), entries)
                });
                vault.put(&current(), &bytes);
            },
            InventoryDamage::CountMismatch,
        ),
        (
            "check-other-vault",
            |vault| {
                let bytes = sealed(vault, |vault| {
                    (VaultId::new_random(), *vault.inventory.envelope_digest(), setup_entries(vault))
                });
                vault.put(&current(), &bytes);
            },
            InventoryDamage::OtherVault,
        ),
        (
            "check-unreadable",
            |vault| vault.put(&current(), &vec![0; MAX_RECIPIENT_INVENTORY_LEN + 1]),
            InventoryDamage::Unreadable,
        ),
        (
            "check-unknown-role",
            |vault| vault.put(&current(), &seal_with_role_code(&vault.vault, &vault.inventory, 4)),
            InventoryDamage::UnknownRole,
        ),
        (
            "check-envelope-unreadable",
            |vault| vault.put(&StateFileName::identity_envelope(), b"not an envelope"),
            InventoryDamage::EnvelopeUnreadable,
        ),
    ];
    cases.into_iter().for_each(|(label, damage, expected)| {
        let vault = TestVault::new(label);
        damage(&vault);
        let before = vault.files();
        assert_eq!(vault.check(), damaged(expected), "{label}");
        assert_eq!(vault.files(), before, "{label}");
    });
}

#[test]
fn a_staged_inventory_for_another_envelope_is_discarded() {
    let vault = TestVault::new("check-discard");
    vault.put(&staged(), &other_envelope(&vault));
    assert_eq!(vault.check().unwrap().recovered, Some(ChangeRecovery::Discarded));
    assert_eq!(vault.file(&staged()), None);
    assert_eq!(vault.check().unwrap().recovered, None);
}

#[test]
fn a_staged_inventory_left_after_its_change_finished_is_removed_as_completed() {
    let vault = TestVault::new("check-leftover");
    vault.put(&staged(), &vault.file(&current()).unwrap());
    assert_eq!(
        vault.check().unwrap(),
        CheckedInventory {
            inventory: vault.inventory.clone(),
            recovered: Some(ChangeRecovery::Completed)
        }
    );
    assert_eq!(vault.file(&staged()), None);
}

#[test]
fn a_staged_inventory_that_alone_matches_the_envelope_finishes_the_change() {
    let vault = TestVault::new("check-complete");
    let matching = vault.file(&current()).unwrap();
    vault.put(&staged(), &matching);
    vault.put(&current(), &other_envelope(&vault));
    assert_eq!(
        vault.check().unwrap(),
        CheckedInventory {
            inventory: vault.inventory.clone(),
            recovered: Some(ChangeRecovery::Completed)
        }
    );
    assert_eq!(vault.file(&current()), Some(matching));
    assert_eq!(vault.file(&staged()), None);
}

#[test]
fn damage_beside_a_staged_inventory_that_does_not_match_either_leaves_both_in_place() {
    let vault = TestVault::new("check-both-damaged");
    vault.remove(&current());
    vault.put(&staged(), &other_envelope(&vault));
    let before = vault.files();
    assert_eq!(vault.check(), damaged(InventoryDamage::Missing));
    assert_eq!(vault.files(), before);
}

#[test]
fn a_failed_settle_is_a_write_error() {
    let vault = TestVault::new("check-settle-fault");
    vault.put(&staged(), &other_envelope(&vault));
    vault.fs.fail_first(crate::fault_fs::FsOp::RemoveFile, std::io::ErrorKind::Other);
    assert!(matches!(vault.check(), Err(InventoryCheckError::Write(_))));
    assert_eq!(vault.check().unwrap().recovered, Some(ChangeRecovery::Discarded));
}

#[test]
fn damage_labels_are_the_audit_log_names() {
    let labels = [
        InventoryDamage::EnvelopeUnreadable,
        InventoryDamage::Missing,
        InventoryDamage::Unreadable,
        InventoryDamage::Mac,
        InventoryDamage::Malformed,
        InventoryDamage::UnknownRole,
        InventoryDamage::OtherVault,
        InventoryDamage::EnvelopeMismatch,
        InventoryDamage::CountMismatch,
    ]
    .map(InventoryDamage::label);
    assert_eq!(
        labels,
        [
            "envelope_unreadable",
            "missing",
            "unreadable",
            "mac",
            "malformed",
            "unknown_role",
            "other_vault",
            "envelope_mismatch",
            "count_mismatch"
        ]
    );
    assert_eq!(
        [ChangeRecovery::Completed, ChangeRecovery::Discarded].map(ChangeRecovery::label),
        ["completed", "discarded"]
    );
}
