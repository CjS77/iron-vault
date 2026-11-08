//! The recipient change rule: which inventory a change to the recipient set leads to, or why it is refused (spec §3.11,
//! `design/recipients.md`).
//!
//! The rule is pure, so `recipient add` and `recipient remove` can apply it before any prompt and the rewrap applies it
//! again before it writes. It is checked on the inventory the change would write, never on the change itself.

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;

use thiserror::Error;

use super::{RecipientEntry, RecipientInventory, RecipientRole};
use crate::{MAX_RECIPIENTS, RecipientKey};

/// One change to the recipient set of the identity envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecipientChange {
    /// Enroll a recipient that is not enrolled yet.
    Add(RecipientEntry),
    /// Remove the enrolled recipient with this key.
    Remove(RecipientKey),
}

/// Why a recipient change is refused. Nothing has been written when it is; each variant names the rule it breaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RecipientChangeRefusal {
    /// The key to add is already enrolled.
    #[error("the recipient is already enrolled")]
    AlreadyEnrolled,
    /// The key to remove is not enrolled.
    #[error("no enrolled recipient has this key")]
    NotEnrolled,
    /// The entry to add has the `operational` role. Only `init` enrolls it, with the key `operational.age` opens; a
    /// second one could take the first one's place.
    #[error("only init enrolls an operational recipient")]
    AddsOperational,
    /// The key to remove is the `operational` recipient's, which passphrase unlock and migration authorization go through.
    /// It is never removed, and no other recipient takes its place.
    #[error("the operational recipient is never removed: passphrase unlock goes through it")]
    RemovesOperational,
    /// The change would leave no `operational` recipient: the inventory it starts from has none.
    #[error("the vault would be left with no operational recipient")]
    NoOperational,
    /// The change would leave no `recovery` recipient, the owner's offline way in.
    #[error("the vault would be left with no recovery recipient")]
    NoRecovery,
    /// The change would leave fewer than two recipients.
    #[error("the vault would be left with fewer than 2 recipients")]
    TooFew,
    /// The change would make more than [`MAX_RECIPIENTS`] recipients.
    #[error("the vault takes at most {MAX_RECIPIENTS} recipients")]
    TooMany,
}

impl RecipientChange {
    /// The inventory after this change, if the independence rule allows it.
    ///
    /// The result still carries `current`'s envelope digest: the envelope it describes does not exist until the rewrap
    /// wraps the vault identity for it, which then gives it that envelope's digest.
    pub fn apply(&self, current: &RecipientInventory) -> Result<RecipientInventory, RecipientChangeRefusal> {
        let entries = self.next_entries(&current.entries)?;
        independence_rule(&entries)?;
        Ok(RecipientInventory {
            vault_id: current.vault_id,
            envelope_digest: current.envelope_digest,
            entries,
        })
    }

    fn next_entries(
        &self,
        entries: &BTreeMap<RecipientKey, RecipientEntry>,
    ) -> Result<BTreeMap<RecipientKey, RecipientEntry>, RecipientChangeRefusal> {
        let mut next = entries.clone();
        match self {
            Self::Add(entry) if entry.role == RecipientRole::Operational => Err(RecipientChangeRefusal::AddsOperational),
            Self::Add(entry) => match next.insert(entry.key.clone(), entry.clone()) {
                None => Ok(next),
                Some(_) => Err(RecipientChangeRefusal::AlreadyEnrolled),
            },
            Self::Remove(key) => match next.remove(key) {
                Some(removed) if removed.role == RecipientRole::Operational => Err(RecipientChangeRefusal::RemovesOperational),
                Some(_) => Ok(next),
                None => Err(RecipientChangeRefusal::NotEnrolled),
            },
        }
    }
}

/// The independence rule, part by part in the order `design/recipients.md` numbers them; the first part that fails is
/// the refusal. Part 2, the recipient of each configured unlock method, adds nothing while passphrase unlock is the only
/// method. Parts 1 and 3 already imply part 4's floor in v0; it stays so the rule still means two ways in once later
/// roles join.
fn independence_rule(entries: &BTreeMap<RecipientKey, RecipientEntry>) -> Result<(), RecipientChangeRefusal> {
    let has = |role| entries.values().any(|entry| entry.role == role);
    match entries.len() {
        _ if !has(RecipientRole::Operational) => Err(RecipientChangeRefusal::NoOperational),
        _ if !has(RecipientRole::Recovery) => Err(RecipientChangeRefusal::NoRecovery),
        count => count_rule(count),
    }
}

/// Part 4: from 2 to [`MAX_RECIPIENTS`] recipients.
fn count_rule(count: usize) -> Result<(), RecipientChangeRefusal> {
    match count {
        0..2 => Err(RecipientChangeRefusal::TooFew),
        count if count > MAX_RECIPIENTS => Err(RecipientChangeRefusal::TooMany),
        _ => Ok(()),
    }
}
