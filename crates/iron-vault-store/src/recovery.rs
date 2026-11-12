//! The offline recovery key: a second, independent way to unwrap the identity envelope when the machine or the
//! passphrase is lost ([spec §3](../../../design/iron-vault-specification.md#3-terms-and-definitions),
//! [§14](../../../design/iron-vault-specification.md#14-recipients-startup-and-memory),
//! [§16](../../../design/iron-vault-specification.md#16-administration-recovery-and-migration)).
//!
//! The service generates the key at initialization, hands its secret text to the owner to keep offline, and enrolls only
//! its recipient key in `identity.age`. Nothing in the store writes or keeps the secret, so the recovery path needs
//! something only the owner holds.

use std::fmt;

use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;

use crate::recipient::{RecipientIdentity, RecipientKey};

/// Generates offline recovery keys.
pub enum RecoveryKey {}

impl RecoveryKey {
    /// Returns a fresh recovery key: its secret text, to present to the owner once, and the recipient key to enroll in
    /// the identity envelope's recipient set.
    ///
    /// The identity is dropped, and its key bytes cleared, before this returns, so the secret text is the only copy.
    pub fn generate() -> (RecoveryKeySecret, RecipientKey) {
        let (secret, identity) = Self::generate_with_identity();
        (secret, identity.recipient_key())
    }

    /// Returns a fresh recovery key's secret text and its recipient identity. The identity is kept so initialization
    /// and `recipient add --recovery` can prove the identity envelope opens for it without parsing the text back.
    pub fn generate_with_identity() -> (RecoveryKeySecret, RecipientIdentity) {
        let identity = RecipientIdentity::generate();
        (RecoveryKeySecret(identity.secret_text()), identity)
    }
}

/// The secret text of an offline recovery key, `AGE-SECRET-KEY-1…`, for the owner to keep outside the service.
///
/// It has no `Clone` or `Display`, its `Debug` shows nothing of it, and its text is cleared when it is dropped. The store
/// never writes it to disk.
pub struct RecoveryKeySecret(SecretString);

impl RecoveryKeySecret {
    /// Parses the recipient identity in what the owner typed or pasted back, ignoring surrounding whitespace.
    ///
    /// The text is parsed in place in the caller's cleared buffer, and a rejected input is not carried in the error.
    pub fn parse(text: SecretString) -> Result<RecipientIdentity, RecoveryError> {
        RecipientIdentity::from_secret_text(text.expose_secret().trim().as_bytes()).ok_or(RecoveryError::NotARecoveryKey)
    }
}

impl ExposeSecret<str> for RecoveryKeySecret {
    /// Borrows the secret text, for presenting to the owner once.
    fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl fmt::Debug for RecoveryKeySecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryKeySecret([REDACTED])")
    }
}

/// Says why a recovery key the owner entered could not be used. No variant carries the entered text.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RecoveryError {
    /// The text is not an `age` X25519 secret key, for instance because of a typo its checksum caught.
    #[error("not a valid recovery key")]
    NotARecoveryKey,
}

#[cfg(test)]
mod tests;
