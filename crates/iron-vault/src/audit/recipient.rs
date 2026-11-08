//! The recipient inventory events: `recipient.inventory-damaged` and `recipient.change-recovered`
//! (`design/recipients.md`, "Audit events").
//!
//! Each holds a fixed label only: never a recipient key, a label or a file's bytes.

use iron_vault_store::{ChangeRecovery, InventoryDamage};

use super::{AUDIT_TARGET, AuditEvent, EventName};

/// `recipient.inventory-damaged`: the inventory check found the recipient inventory missing or damaged, and wrote nothing.
#[derive(Debug, Clone, Copy)]
pub struct InventoryDamaged(pub InventoryDamage);

impl AuditEvent for InventoryDamaged {
    const NAME: EventName = EventName("recipient.inventory-damaged");

    fn emit(&self) {
        tracing::warn!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            inventory_damage = self.0.label(),
            "recipient inventory is damaged",
        );
    }
}

/// `recipient.change-recovered`: the inventory check finished a committed recipient change or removed a staged inventory.
#[derive(Debug, Clone, Copy)]
pub struct ChangeRecovered(pub ChangeRecovery);

impl AuditEvent for ChangeRecovered {
    const NAME: EventName = EventName("recipient.change-recovered");

    fn emit(&self) {
        tracing::warn!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            recovery = self.0.label(),
            "staged recipient change settled",
        );
    }
}
