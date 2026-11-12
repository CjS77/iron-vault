//! The two passphrases the owner chooses at initialization, checked together against the
//! [passphrase rules](../../../../design/vault-initialization.md#passphrase-rules).

use std::fmt;

use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::{ApprovalPassphrase, Passphrase};

/// The fewest Unicode scalar values a passphrase chosen at initialization may have.
pub const MIN_PASSPHRASE_CHARS: usize = 12;

/// The vault passphrase and the approval passphrase, each long enough and the two different.
///
/// The rules apply when a passphrase is chosen, never when one is typed to unlock or approve, so a vault created before
/// them still opens. It has no `Clone` or `Display`, and its `Debug` shows nothing of either passphrase.
///
/// ```
/// use iron_vault_store::{ApprovalPassphrase, InitPassphrases, InitPassphrasesError, Passphrase, WhichPassphrase};
/// use secrecy::SecretString;
///
/// let vault = |text: &str| Passphrase::new(SecretString::from(text)).unwrap();
/// let approval = |text: &str| ApprovalPassphrase::new(SecretString::from(text)).unwrap();
///
/// assert!(InitPassphrases::new(vault("correct horse battery"), approval("staple of approval")).is_ok());
/// assert!(matches!(
///     InitPassphrases::new(vault("short"), approval("staple of approval")),
///     Err(InitPassphrasesError::TooShort { which: WhichPassphrase::Vault }),
/// ));
/// assert!(matches!(
///     InitPassphrases::new(vault("correct horse battery"), approval("correct horse battery")),
///     Err(InitPassphrasesError::Same),
/// ));
/// ```
pub struct InitPassphrases {
    vault: Passphrase,
    approval: ApprovalPassphrase,
}

/// Names the passphrase that broke a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WhichPassphrase {
    /// The vault-unlock passphrase.
    Vault,
    /// The approval passphrase.
    Approval,
    /// The export passphrase.
    Export,
}

impl fmt::Display for WhichPassphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Vault => "the vault passphrase",
            Self::Approval => "the approval passphrase",
            Self::Export => "the export passphrase",
        })
    }
}

/// Names the passphrase rule the owner's choice broke. No variant carries the input or its length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum InitPassphrasesError {
    /// The passphrase has fewer than [`MIN_PASSPHRASE_CHARS`] Unicode scalar values.
    #[error("{which} is shorter than 12 characters")]
    TooShort {
        /// The passphrase that is too short.
        which: WhichPassphrase,
    },
    /// The two passphrases are the same, so unlocking the vault would imply authority to approve a config.
    #[error("the vault and approval passphrases must differ")]
    Same,
}

impl InitPassphrases {
    /// Checks both rules, length first, then compares the two passphrases' bytes in constant time.
    pub fn new(vault: Passphrase, approval: ApprovalPassphrase) -> Result<Self, InitPassphrasesError> {
        Self::ensure_long_enough(vault.text(), WhichPassphrase::Vault)?;
        Self::ensure_long_enough(approval.text(), WhichPassphrase::Approval)?;
        match bool::from(vault.text().as_bytes().ct_eq(approval.text().as_bytes())) {
            true => Err(InitPassphrasesError::Same),
            false => Ok(Self { vault, approval }),
        }
    }

    /// Checks the length rule on one passphrase alone, so the owner hears of a short vault passphrase before choosing
    /// the approval passphrase. [`InitPassphrases::new`] checks it again.
    pub fn ensure_long_enough(text: &str, which: WhichPassphrase) -> Result<(), InitPassphrasesError> {
        match text.chars().nth(MIN_PASSPHRASE_CHARS - 1) {
            Some(_) => Ok(()),
            None => Err(InitPassphrasesError::TooShort { which }),
        }
    }

    /// Returns the two passphrases, for the steps that seal and open with them.
    pub(crate) fn into_parts(self) -> (Passphrase, ApprovalPassphrase) {
        (self.vault, self.approval)
    }
}

impl fmt::Debug for InitPassphrases {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InitPassphrases([REDACTED])")
    }
}
