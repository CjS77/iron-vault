//! The migration authorization events: `migration.challenge-issued`, `migration.authorized` and
//! `migration.authorization-refused` (`design/migration-authorization.md`, "Audit events").
//!
//! Each holds the operation, the method's label, fixed refusal labels and a count of seconds: never the owner's input, a
//! challenge's nonce or a binding digest. The destination recipient is a public key.

use super::{AUDIT_TARGET, AuditEvent, EventName};
use crate::migration_authorization::{MigrationOperation, MigrationRefusal};

/// The destination recipient's `age1...` text for `add_recipient`; left out for `export`, which names none.
fn destination(operation: &MigrationOperation) -> Option<String> {
    operation.destination().map(ToString::to_string)
}

/// `migration.challenge-issued`: a migration challenge went into the pending slot (step 5).
#[derive(Debug, Clone, Copy)]
pub struct ChallengeIssued<'a> {
    /// What the challenge is for.
    pub operation: &'a MigrationOperation,
    /// The label of the source-owner method the owner will be asked to prove it with.
    pub method: &'static str,
}

impl AuditEvent for ChallengeIssued<'_> {
    const NAME: EventName = EventName("migration.challenge-issued");

    fn emit(&self) {
        tracing::info!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            operation = self.operation.label(),
            method = self.method,
            destination_recipient = destination(self.operation).as_deref(),
            "migration challenge issued",
        );
    }
}

/// `migration.authorized`: a source-owner method proved the challenge (step 7). It records the proof, not the migration.
#[derive(Debug, Clone, Copy)]
pub struct Authorized<'a> {
    /// What was authorized.
    pub operation: &'a MigrationOperation,
    /// The label of the method that proved the challenge.
    pub method: &'static str,
}

impl AuditEvent for Authorized<'_> {
    const NAME: EventName = EventName("migration.authorized");

    fn emit(&self) {
        tracing::info!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            operation = self.operation.label(),
            method = self.method,
            destination_recipient = destination(self.operation).as_deref(),
            "migration authorized",
        );
    }
}

/// Why a challenge's exchange ended without an authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The service refused the challenge, at the attempt limit, the method or the consuming operation.
    Refused(MigrationRefusal),
    /// The prompt got no owner input: the CLI closed, the connection failed or the prompt deadline passed.
    Cancelled,
}

impl Refusal {
    /// The `refusal` field's label.
    fn label(self) -> &'static str {
        match self {
            Self::Refused(refusal) => refusal.label(),
            Self::Cancelled => "cancelled",
        }
    }

    /// The whole seconds left in the attempt limit's cooldown, when that is the refusal.
    fn retry_after(self) -> Option<u64> {
        match self {
            Self::Refused(MigrationRefusal::AttemptsCoolingDown(cooling)) => Some(cooling.retry_after),
            _ => None,
        }
    }
}

/// `migration.authorization-refused`: the challenge was refused or its prompt cancelled (steps 6 and 7), or the
/// authorization was refused when consumed (step 9).
#[derive(Debug, Clone, Copy)]
pub struct AuthorizationRefused<'a> {
    /// What was to be authorized.
    pub operation: &'a MigrationOperation,
    /// The label of the source-owner method the challenge was for.
    pub method: &'static str,
    /// Why it was refused.
    pub refusal: Refusal,
}

impl AuditEvent for AuthorizationRefused<'_> {
    const NAME: EventName = EventName("migration.authorization-refused");

    fn emit(&self) {
        tracing::warn!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            operation = self.operation.label(),
            method = self.method,
            refusal = self.refusal.label(),
            destination_recipient = destination(self.operation).as_deref(),
            retry_after = self.refusal.retry_after(),
            "migration authorization refused",
        );
    }
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use iron_vault_store::RecipientKey;

    use super::*;
    use crate::audit::tests::record_of;
    use crate::migration_authorization::{AttemptsCoolingDown, OwnerRefusal};

    const RECIPIENT: &str = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";

    fn add() -> MigrationOperation {
        MigrationOperation::AddRecipient(RECIPIENT.parse::<RecipientKey>().unwrap())
    }

    #[test]
    fn an_export_names_no_destination_and_an_add_names_its_recipient() {
        let export = record_of(
            ChallengeIssued {
                operation: &MigrationOperation::Export,
                method: "vault_passphrase",
            },
            "INFO",
            &["operation", "method"],
        );
        assert_eq!(export["operation"], "export");
        let operation = add();
        let added = record_of(
            Authorized {
                operation: &operation,
                method: "vault_passphrase",
            },
            "INFO",
            &["operation", "method", "destination_recipient"],
        );
        assert_eq!(
            (added["operation"].as_str(), added["destination_recipient"].as_str()),
            (Some("add_recipient"), Some(RECIPIENT))
        );
    }

    #[test]
    fn a_refusal_is_a_label_and_only_the_cooldown_has_a_retry_after() {
        let operation = MigrationOperation::Export;
        let refused = |refusal| AuthorizationRefused {
            operation: &operation,
            method: "vault_passphrase",
            refusal,
        };
        let fields = ["operation", "method", "refusal"];
        [
            (
                Refusal::Refused(MigrationRefusal::Denied(OwnerRefusal::WrongSecret)),
                "wrong_passphrase",
            ),
            (
                Refusal::Refused(MigrationRefusal::Denied(OwnerRefusal::NotThisVault)),
                "not_this_vault",
            ),
            (Refusal::Refused(MigrationRefusal::Expired), "expired"),
            (Refusal::Refused(MigrationRefusal::Unavailable), "unavailable"),
            (Refusal::Cancelled, "cancelled"),
        ]
        .into_iter()
        .for_each(|(refusal, label)| assert_eq!(record_of(refused(refusal), "WARN", &fields)["refusal"], label));
        let cooling = Refusal::Refused(MigrationRefusal::AttemptsCoolingDown(AttemptsCoolingDown { retry_after: 30 }));
        let record = record_of(refused(cooling), "WARN", &["operation", "method", "refusal", "retry_after"]);
        assert_eq!(
            (record["refusal"].as_str(), record["retry_after"].as_u64()),
            (Some("rate_limited"), Some(30))
        );
    }
}
