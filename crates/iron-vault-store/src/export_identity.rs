//! The sealed entries of a migration bundle that hold keys: the exported identity envelope and the bundled approver keys
//! ([spec §16](../../../design/iron-vault-specification.md#16-administration-recovery-and-migration) step 2;
//! [exported identity envelope](../../../design/storage-formats.md#exported-identity-envelope),
//! [migration bundle v1](../../../design/storage-formats.md#migration-bundle-v1)).
//!
//! Both are built from the store's existing sealing code. Nothing here writes to disk: the bundle codec streams the
//! bytes these functions return. The two layers:
//!
//! ```text
//! exported identity envelope   age, one scrypt stanza at PASSPHRASE_WORK_FACTOR ──▶ the vault identity's secret text
//!          (export passphrase)
//! bundled approver key         age, one X25519 stanza for the vault public key  ──▶ approver-<approver ID>.age bytes
//!          (vault identity)                                                           (still sealed to its approval
//!                                                                                      passphrase)
//! ```

use std::fmt;

use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;

use crate::{
    EnvelopeError, MAX_PASSPHRASE_ENVELOPE_LEN, OpenError, PASSPHRASE_WORK_FACTOR, PassphraseError, SealError, open,
    passphrase::{check_header, open_scrypt_file, seal_scrypt_file},
    seal,
    stanza::parse_header,
    vault_identity::{VaultIdentity, VaultPublicKey},
};

/// The length of the exported identity envelope's plaintext: the `AGE-SECRET-KEY-1…` text of an X25519 identity.
const SECRET_TEXT_LEN: usize = 74;

/// The owner's passphrase for the exported identity envelope, and nothing else.
///
/// It is a different type from [`crate::Passphrase`] and [`crate::ApprovalPassphrase`], so one can never be passed for
/// another: the export passphrase protects the transfer only and never authorizes a migration. It has no `Display` or
/// `Clone`, its `Debug` shows nothing of it, and its text is cleared when it is dropped. The 12-character rule is
/// applied when it is chosen, through [`crate::InitPassphrases::ensure_long_enough`].
pub struct ExportPassphrase(SecretString);

impl ExportPassphrase {
    /// Wraps `text` as an export passphrase, refusing an empty one.
    pub fn new(text: SecretString) -> Result<Self, PassphraseError> {
        match text.expose_secret().is_empty() {
            true => Err(PassphraseError::Empty),
            false => Ok(Self(text)),
        }
    }

    /// Returns a copy of the passphrase for `age`, which takes its passphrase by value. The copy is cleared on drop too.
    fn for_age(&self) -> SecretString {
        SecretString::from(self.0.expose_secret())
    }
}

impl fmt::Debug for ExportPassphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExportPassphrase([REDACTED])")
    }
}

/// Seals the vault identity's secret text to `passphrase` as the exported identity envelope, at exactly
/// [`PASSPHRASE_WORK_FACTOR`]. The result is in memory only.
pub fn seal_exported_identity(identity: &VaultIdentity, passphrase: &ExportPassphrase) -> Result<Vec<u8>, EnvelopeError> {
    seal_scrypt_file(
        identity.secret_text().expose_secret().as_bytes(),
        passphrase.for_age(),
        PASSPHRASE_WORK_FACTOR,
    )
}

/// Opens the exported identity envelope to the vault identity it holds.
///
/// Every check that needs no passphrase runs first, in this order: the size bound, that the header holds exactly one
/// scrypt stanza, and that its work factor is exactly [`PASSPHRASE_WORK_FACTOR`]. The bundle comes from outside the
/// machine, so its sender must not choose how much memory and time scrypt spends. A passphrase that does not open the
/// file gives [`EnvelopeError::WrongPassphrase`].
///
/// As with [`crate::unwrap_identity`], the identity is trusted only once the bundle's manifest MAC verifies.
pub fn open_exported_identity(bytes: &[u8], passphrase: &ExportPassphrase) -> Result<VaultIdentity, EnvelopeError> {
    check_exact_work_factor(bytes)?;
    let secret = open_scrypt_file(bytes, passphrase.for_age(), SECRET_TEXT_LEN)?;
    VaultIdentity::from_secret_text(&secret).ok_or(EnvelopeError::Malformed)
}

/// Runs the envelope checks that need no passphrase, ending in the exact work factor.
fn check_exact_work_factor(bytes: &[u8]) -> Result<(), EnvelopeError> {
    if bytes.len() > MAX_PASSPHRASE_ENVELOPE_LEN {
        return Err(EnvelopeError::TooLarge);
    }
    check_header(bytes)?;
    match parse_header(bytes).map(|header| header.scrypt_work_factors) {
        Some(factors) if factors.as_slice() == [Some(PASSPHRASE_WORK_FACTOR)] => Ok(()),
        _ => Err(EnvelopeError::WrongWorkFactor),
    }
}

/// Says why a bundled approver key could not be sealed or opened. No variant carries key material or input bytes.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BundledApproverKeyError {
    /// The approver key envelope could not be encrypted to the vault public key.
    #[error(transparent)]
    Seal(#[from] SealError),
    /// The outer file is not an `age` file the vault identity opens, has a stanza other than X25519, or holds more than
    /// [`MAX_PASSPHRASE_ENVELOPE_LEN`] of plaintext.
    #[error(transparent)]
    Open(#[from] OpenError),
    /// The plaintext is not an approver key envelope.
    #[error("the bundled approver key does not hold an approver key envelope: {0}")]
    Form(EnvelopeError),
}

/// Encrypts an approver key `envelope`, unopened, to the vault public key as a plain binary `age` file with one X25519
/// stanza, so the bundled key sits under the export passphrase.
pub fn seal_bundled_approver_key(envelope: &[u8], vault: &VaultPublicKey) -> Result<Vec<u8>, BundledApproverKeyError> {
    Ok(seal(vault, envelope)?)
}

/// Opens a bundled approver key with the vault identity and returns the approver key envelope inside, byte for byte.
///
/// A stanza other than X25519 and `age`'s grease stanza is refused before decrypting, at most
/// [`MAX_PASSPHRASE_ENVELOPE_LEN`] of plaintext is read, and the plaintext must pass [`check_approver_key_form`].
pub fn open_bundled_approver_key(bytes: &[u8], identity: &VaultIdentity) -> Result<Vec<u8>, BundledApproverKeyError> {
    let plaintext = open(identity, bytes, MAX_PASSPHRASE_ENVELOPE_LEN)?;
    check_approver_key_form(&plaintext).map_err(BundledApproverKeyError::Form)?;
    Ok(plaintext.to_vec())
}

/// Checks that `bytes` has the form of an approver key envelope: at most [`MAX_PASSPHRASE_ENVELOPE_LEN`], exactly one
/// scrypt stanza, and a work factor no higher than [`crate::MAX_PASSPHRASE_WORK_FACTOR`].
///
/// It reads the header only: it never runs scrypt and never needs an approval passphrase.
pub fn check_approver_key_form(bytes: &[u8]) -> Result<(), EnvelopeError> {
    if bytes.len() > MAX_PASSPHRASE_ENVELOPE_LEN {
        return Err(EnvelopeError::TooLarge);
    }
    check_header(bytes)
}

#[cfg(test)]
mod tests;
