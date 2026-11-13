// SPDX-License-Identifier: MPL-2.0
//! Runs the service's part of `forget-machine`
//! ([forget machine: What it checks](../../../../design/forget-machine.md#what-it-checks)), which checks that a
//! retired machine's recipient key no longer opens the vault.
//!
//! It reads the recipient inventory and the recovery check record and writes nothing of its own. It runs no process:
//! the TPM belongs to the host, and the administrator runs every step the command prints.

use iron_vault_store::{RecipientEntry, RecipientKey, StoreFs};

use super::ServiceContext;
use super::recipients::RecipientRefusal;
use crate::admin::protocol::RecoveryStatus;

/// What `forget-machine` found for a key.
#[derive(Debug)]
pub enum ForgetCheck {
    /// The key is still a recipient: it is not forgotten, and this is its entry.
    Enrolled(RecipientEntry),
    /// The key is not a recipient.
    Forgotten {
        /// The sentence naming the part of the independence rule the current inventory fails; `None` when the rule
        /// holds.
        independence: Option<String>,
        /// The recovery check record; a due reminder means the owner has not lately proved the recovery key.
        recovery: RecoveryStatus,
    },
}

impl<F: StoreFs + Send + Sync + 'static> ServiceContext<F> {
    /// Checks whether `key` is still a recipient, and if not, gathers the facts the decommission guidance depends on.
    ///
    /// Like `recipient list` it needs Ready and answers [`RecipientRefusal::Busy`] at once while another operation
    /// holds the service-wide lock, and its inventory check may settle a staged recipient change.
    pub async fn check_forgotten(&self, key: &RecipientKey) -> Result<ForgetCheck, RecipientRefusal> {
        let inventory = self.recipient_inventory().await?;
        if let Some(entry) = inventory.get(key) {
            return Ok(ForgetCheck::Enrolled(entry.clone()));
        }
        Ok(ForgetCheck::Forgotten {
            independence: inventory.independence().err().map(|rule| rule.to_string()),
            recovery: self.recovery_status().await,
        })
    }
}
