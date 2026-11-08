use std::io;

use secrecy::ExposeSecret;

use super::*;
use crate::secret_types_tests::assert_hides;
use crate::test_vault::{TestVault, entry};
use crate::{ChangeRecovery, EnvelopeError, RecipientIdentity, RecipientRole, RecipientSet, unwrap_identity};

fn add(identity: &RecipientIdentity) -> RecipientChange {
    RecipientChange::Add(entry(identity, RecipientRole::Added))
}

fn rewrap(vault: &TestVault, current: &RecipientInventory, change: &RecipientChange) -> Result<RewrappedIdentity, RecipientChangeError> {
    rewrap_identity(&vault.lock, &vault.fs, &vault.vault, current, change, None)
}

/// `recipient add --recovery`: enrolls `recovery` and proves the new envelope with `prover`.
fn add_recovery(
    vault: &TestVault,
    recovery: &RecipientIdentity,
    prover: &RecipientIdentity,
) -> Result<RewrappedIdentity, RecipientChangeError> {
    let change = RecipientChange::Add(entry(recovery, RecipientRole::Recovery));
    rewrap_identity(&vault.lock, &vault.fs, &vault.vault, &vault.inventory, &change, Some(prover))
}

/// A vault with a third, `added` recipient enrolled through a rewrap, and that recipient's identity.
fn with_added(label: &str) -> (TestVault, RecipientIdentity, RecipientInventory) {
    let vault = TestVault::new(label);
    let added = RecipientIdentity::generate();
    let inventory = rewrap(&vault, &vault.inventory, &add(&added)).unwrap().inventory;
    (vault, added, inventory)
}

#[test]
fn an_added_recipient_opens_the_vault_and_so_do_the_others() {
    let vault = TestVault::new("rewrap-add");
    let added = RecipientIdentity::generate();
    let rewrapped = rewrap(&vault, &vault.inventory, &add(&added)).unwrap();
    assert_eq!(rewrapped.unfinished, None);
    assert!(vault.opens_with(&added));
    assert!(vault.opens_with(&vault.operational) && vault.opens_with(&vault.recovery));
    let expected = RecipientSet::new([&vault.operational, &vault.recovery, &added].map(RecipientIdentity::recipient_key)).unwrap();
    assert_eq!(rewrapped.inventory.recipient_set(), expected);
    assert_eq!(
        vault.check().unwrap(),
        crate::CheckedInventory {
            inventory: rewrapped.inventory,
            recovered: None
        }
    );
    assert_eq!(vault.file(&StateFileName::staged_recipient_inventory()), None);
}

#[test]
fn a_removed_recipient_no_longer_opens_the_new_envelope() {
    let (vault, added, inventory) = with_added("rewrap-remove");
    let removed = rewrap(&vault, &inventory, &RecipientChange::Remove(added.recipient_key())).unwrap();
    assert_eq!(removed.inventory.recipient_set(), vault.inventory.recipient_set());
    assert!(!vault.opens_with(&added));
    assert!(vault.opens_with(&vault.operational) && vault.opens_with(&vault.recovery));
}

/// R-24: removal reaches only envelopes written from now on. A copy of `identity.age` taken before still opens with the
/// removed key; this is the documented limit, not a defect.
#[test]
fn a_copy_of_the_old_envelope_still_opens_with_a_removed_key() {
    let (vault, added, inventory) = with_added("rewrap-old-copy");
    let old_copy = vault.file(&StateFileName::identity_envelope()).unwrap();
    rewrap(&vault, &inventory, &RecipientChange::Remove(added.recipient_key())).unwrap();
    let new = vault.file(&StateFileName::identity_envelope()).unwrap();
    assert_eq!(unwrap_identity(&new, &added).unwrap_err(), EnvelopeError::NotARecipient);
    assert_eq!(unwrap_identity(&old_copy, &added).unwrap().public_key(), vault.vault.public_key());
}

#[test]
fn only_the_envelope_and_the_inventory_change() {
    let vault = TestVault::new("rewrap-untouched");
    let before = vault.files();
    rewrap(&vault, &vault.inventory, &add(&RecipientIdentity::generate())).unwrap();
    let after = vault.files();
    assert_eq!(before.keys().collect::<Vec<_>>(), after.keys().collect::<Vec<_>>());
    let changed: Vec<&str> = before
        .iter()
        .filter(|(name, bytes)| after[*name] != **bytes)
        .map(|(name, _)| name.as_str())
        .collect();
    assert_eq!(changed, ["identity.age", "recipients.age"]);
    assert!(before.keys().any(|name| name.starts_with("record-")) && before.contains_key("manifest.age"));
}

#[test]
fn a_refused_change_writes_nothing() {
    let vault = TestVault::new("rewrap-refused");
    let (before, calls) = (vault.files(), vault.calls());
    let change = RecipientChange::Remove(vault.recovery.recipient_key());
    assert_eq!(
        rewrap(&vault, &vault.inventory, &change),
        Err(RecipientChangeError::Refused(RecipientChangeRefusal::NoRecovery))
    );
    assert_eq!(vault.calls(), calls);
    assert_eq!(vault.files(), before);
}

#[test]
fn a_new_recovery_recipient_proves_the_envelope_it_is_added_to() {
    let vault = TestVault::new("rewrap-proved");
    let recovery = RecipientIdentity::generate();
    let rewrapped = add_recovery(&vault, &recovery, &recovery).unwrap();
    assert_eq!(rewrapped.unfinished, None);
    assert!(vault.opens_with(&recovery));
    assert_eq!(
        rewrapped.inventory.get(&recovery.recipient_key()).map(|entry| entry.role()),
        Some(RecipientRole::Recovery)
    );
}

#[test]
fn a_proof_with_an_identity_outside_the_new_set_writes_nothing() {
    let vault = TestVault::new("rewrap-unproved");
    let (before, calls) = (vault.files(), vault.calls());
    let outcome = add_recovery(&vault, &RecipientIdentity::generate(), &RecipientIdentity::generate());
    assert_eq!(
        outcome,
        Err(RecipientChangeError::Proof(EnvelopeProofError::Unwrap(
            EnvelopeError::NotARecipient
        )))
    );
    assert_eq!(vault.calls(), calls);
    assert_eq!(vault.files(), before);
}

#[test]
fn the_steps_run_in_the_designed_order() {
    let vault = TestVault::new("rewrap-order");
    let from = vault.calls();
    rewrap(&vault, &vault.inventory, &add(&RecipientIdentity::generate())).unwrap();
    let renamed: Vec<String> = vault.fs.trace()[from..]
        .iter()
        .filter_map(|call| match call {
            crate::fault_fs::FsCall::Rename { to, .. } => Some(to.file_name().unwrap().to_string_lossy().into_owned()),
            crate::fault_fs::FsCall::RemoveFile(path) => Some(format!("rm {}", path.file_name().unwrap().to_string_lossy())),
            _ => None,
        })
        .collect();
    assert_eq!(
        renamed,
        [
            "recipients.age.staged",
            "identity.age",
            "recipients.age",
            "rm recipients.age.staged"
        ]
    );
}

/// The number of filesystem calls a clean rewrap makes.
fn rewrap_calls() -> usize {
    let vault = TestVault::new("rewrap-count");
    let from = vault.calls();
    rewrap(&vault, &vault.inventory, &add(&RecipientIdentity::generate())).unwrap();
    vault.calls() - from
}

/// The number of filesystem calls a clean rewrap makes up to its commit point: through the read back of `identity.age`.
fn commit_calls() -> usize {
    let vault = TestVault::new("rewrap-commit-point");
    let from = vault.calls();
    rewrap(&vault, &vault.inventory, &add(&RecipientIdentity::generate())).unwrap();
    let is_read_back = |call: &crate::fault_fs::FsCall| matches!(call, crate::fault_fs::FsCall::ReadBounded(path) if path.ends_with(StateFileName::identity_envelope().as_str()));
    vault.fs.trace()[from..].iter().position(is_read_back).unwrap() + 1
}

/// After power loss, whatever the rewrap reported: the old recipients still open the vault, and the inventory check
/// settles on the inventory of the envelope on disk, the old set or the new one as the rewrap's outcome allows.
fn assert_recoverable(vault: &TestVault, added: &RecipientIdentity, outcome: &Result<RewrappedIdentity, RecipientChangeError>) {
    vault.fs.crash();
    assert!(vault.opens_with(&vault.operational) && vault.opens_with(&vault.recovery));
    let checked = vault.check().unwrap();
    let is_new = checked.inventory.recipient_set().contains(&added.recipient_key());
    assert_eq!(is_new, vault.opens_with(added));
    match outcome {
        Ok(_) => assert!(is_new),
        Err(RecipientChangeError::Write(error)) => match error.committed() {
            ChangeCommitted::No => assert!(!is_new, "{error}"),
            ChangeCommitted::Yes => assert!(is_new, "{error}"),
            ChangeCommitted::Unknown => (),
        },
        Err(other) => panic!("{other}"),
    }
    assert_eq!(vault.check().unwrap().recovered, None);
    assert_eq!(vault.file(&StateFileName::staged_recipient_inventory()), None);
}

#[test]
fn a_fault_at_any_call_leaves_a_vault_that_opens_and_checks() {
    (0..rewrap_calls()).for_each(|k| {
        let vault = TestVault::new("rewrap-fault");
        let added = RecipientIdentity::generate();
        vault.fs.fail_call(vault.calls() + k, io::ErrorKind::Other);
        let outcome = rewrap(&vault, &vault.inventory, &add(&added));
        assert!(
            outcome.as_ref().is_err() || outcome.as_ref().is_ok_and(|done| done.unfinished.is_some()),
            "call {k}"
        );
        assert_recoverable(&vault, &added, &outcome);
    });
}

#[test]
fn power_loss_at_any_call_leaves_a_vault_that_opens_and_checks() {
    (0..=rewrap_calls()).for_each(|k| {
        let vault = TestVault::new("rewrap-power");
        let added = RecipientIdentity::generate();
        vault.fs.cut_power_after(vault.calls() + k);
        let outcome = rewrap(&vault, &vault.inventory, &add(&added));
        assert_recoverable(&vault, &added, &outcome);
    });
}

/// Power lost after the envelope's commit and before the inventory's replace: the next check finishes the change from
/// the staged inventory. Without the staged file the same disk is damage, never accepted.
#[test]
fn a_crash_between_the_two_replaces_is_finished_from_the_staged_inventory_and_nothing_else() {
    let finish = |label| {
        let vault = TestVault::new(label);
        let added = RecipientIdentity::generate();
        vault.fs.cut_power_after(vault.calls() + commit_calls());
        let outcome = rewrap(&vault, &vault.inventory, &add(&added)).unwrap();
        assert_eq!(outcome.unfinished.map(|error| error.step()), Some(RecipientChangeStep::Inventory));
        vault.fs.crash();
        (vault, added)
    };
    let (vault, added) = finish("rewrap-between");
    assert_eq!(vault.check().unwrap().recovered, Some(ChangeRecovery::Completed));
    assert!(vault.opens_with(&added));
    let (vault, _) = finish("rewrap-between-unstaged");
    vault.remove(&StateFileName::staged_recipient_inventory());
    assert_eq!(
        vault.check(),
        Err(crate::InventoryCheckError::Damaged(crate::InventoryDamage::EnvelopeMismatch))
    );
}

#[test]
fn nothing_the_rewrap_returns_shows_a_secret_key() {
    let vault = TestVault::new("rewrap-secrets");
    let added = RecipientIdentity::generate();
    vault.fs.fail_first(crate::fault_fs::FsOp::Rename, io::ErrorKind::Other);
    let failed = rewrap(&vault, &vault.inventory, &add(&added));
    let done = rewrap(&vault, &vault.inventory, &add(&added));
    let secrets = [
        vault.vault.secret_text(),
        vault.operational.secret_text(),
        vault.recovery.secret_text(),
        added.secret_text(),
    ];
    secrets.iter().for_each(|secret| {
        let secret = secret.expose_secret();
        assert_hides(&failed, secret);
        assert_hides(&done, secret);
        assert!(!failed.as_ref().unwrap_err().to_string().contains(secret));
    });
}
