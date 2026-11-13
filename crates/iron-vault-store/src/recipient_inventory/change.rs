// SPDX-License-Identifier: MPL-2.0
//! The recipient change rule: which inventory a change to the recipient set leads to, or why it is refused
//! ([spec §14](../../../../design/iron-vault-specification.md#14-recipients-startup-and-memory),
//! [the recipient change](../../../../design/recipients.md#the-recipient-change)).
//!
//! The rule is pure, so `recipient add` and `recipient remove` can apply it before any prompt, and the rewrap applies it
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

/// Says why a recipient change is refused. Nothing has been written when it is, and each variant names the rule it
/// breaks.
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
    /// The key to remove is the `operational` recipient's, which passphrase unlock and migration authorization go
    /// through. It is never removed, and no other recipient takes its place.
    #[error("the operational recipient is never removed: passphrase unlock goes through it")]
    RemovesOperational,
    /// The change would leave no `operational` recipient: the inventory it starts from has none.
    #[error("the vault would be left with no operational recipient")]
    NoOperational,
    /// The key to remove is the `host-unlock` recipient of the configured host unlock adapter: the identity the unlock
    /// handoff holds now. Removing it would make the next restart wait for passphrase `unlock`.
    #[error("the recipient is the host unlock identity the unlock handoff holds; retire host unlock on the host first")]
    RemovesConfiguredHostUnlock,
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
    /// Returns the inventory after this change, if the independence rule allows it.
    ///
    /// The result still carries `current`'s envelope digest, because the envelope it describes does not exist until the
    /// rewrap wraps the vault identity for it. The rewrap then gives it that envelope's digest.
    pub fn apply(&self, current: &RecipientInventory) -> Result<RecipientInventory, RecipientChangeRefusal> {
        self.apply_configured(current, None)
    }

    /// Does what [`Self::apply`] does, given `host_unlock`, the recipient key of the configured host unlock adapter, if
    /// there is one.
    ///
    /// Part 1 of the independence rule keeps that recipient while `current` enrols it with the `host-unlock` role. A key
    /// enrolled with another role is not the adapter's recipient, so it is not kept.
    pub fn apply_configured(
        &self,
        current: &RecipientInventory,
        host_unlock: Option<&RecipientKey>,
    ) -> Result<RecipientInventory, RecipientChangeRefusal> {
        let entries = self.next_entries(&current.entries)?;
        let configured = host_unlock.filter(|key| current.get(key).is_some_and(|entry| entry.role == RecipientRole::HostUnlock));
        configured_unlock_rule(&entries, configured)?;
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

impl RecipientInventory {
    /// Checks that this inventory, as it is, meets parts 2 to 4 of the independence rule, and returns the refusal of the
    /// first part it breaks.
    ///
    /// Part 1 needs the configured host unlock identity, which only a change that removes it can break.
    /// `forget-machine` asks this of the inventory a past removal wrote, to find one restored from an old copy or edited
    /// around the service.
    pub fn independence(&self) -> Result<(), RecipientChangeRefusal> {
        independence_rule(&self.entries)
    }
}

/// Checks the [independence rule](../../../../design/recipients.md#independence-rule) part by part, in the order the
/// design numbers them. The first part that fails is the refusal.
///
/// - Part 1, the configured unlock method's recipient, is checked by `configured_unlock_rule`, because only the caller
///   knows which host unlock identity is configured. Its floor of one unlock-class recipient follows from part 2 in v0.
/// - Part 2 keeps `operational`, because the vault passphrase is the only source-owner method in v0.
/// - Part 3 keeps a `recovery` recipient.
/// - Part 4 is the count. Parts 2 and 3 already imply its floor in v0; it stays so the rule still means two ways in
///   once later roles join.
fn independence_rule(entries: &BTreeMap<RecipientKey, RecipientEntry>) -> Result<(), RecipientChangeRefusal> {
    let has = |role| entries.values().any(|entry| entry.role == role);
    match entries.len() {
        _ if !has(RecipientRole::Operational) => Err(RecipientChangeRefusal::NoOperational),
        _ if !has(RecipientRole::Recovery) => Err(RecipientChangeRefusal::NoRecovery),
        count => count_rule(count),
    }
}

/// Checks part 1 for the host unlock adapter: the set still holds the `host-unlock` recipient it is configured for.
fn configured_unlock_rule(
    entries: &BTreeMap<RecipientKey, RecipientEntry>,
    host_unlock: Option<&RecipientKey>,
) -> Result<(), RecipientChangeRefusal> {
    match host_unlock {
        Some(key) if !entries.contains_key(key) => Err(RecipientChangeRefusal::RemovesConfiguredHostUnlock),
        _ => Ok(()),
    }
}

/// Checks part 4: from 2 to [`MAX_RECIPIENTS`] recipients.
fn count_rule(count: usize) -> Result<(), RecipientChangeRefusal> {
    match count {
        0..2 => Err(RecipientChangeRefusal::TooFew),
        count if count > MAX_RECIPIENTS => Err(RecipientChangeRefusal::TooMany),
        _ => Ok(()),
    }
}
