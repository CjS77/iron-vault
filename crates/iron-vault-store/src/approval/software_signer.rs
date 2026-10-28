//! The software signer: an Ed25519 approval key kept in `approver.age` under the approval passphrase (spec §3.9).
//!
//! The private key is decrypted only inside the service, for one approval, and dropped with the signer; nothing here
//! keeps a global or cached signer. The file is written and read by the same scrypt envelope code as the passphrase
//! envelope, so it has the same single-stanza rule and work-factor bounds. The layout is in
//! `design/storage-formats.md`.

#[cfg(test)]
mod tests;

use std::fmt;

use ed25519_dalek::{SECRET_KEY_LENGTH, Signer, SigningKey};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use super::{ApprovalEnvelope, ApprovalPayload, ApprovalSigner, PinnedApprover, SignError, SignatureAlgorithm};
use crate::{
    EnvelopeError, MAX_PASSPHRASE_ENVELOPE_LEN, PASSPHRASE_WORK_FACTOR, PassphraseError, StateDirLock, StateFileName, StoreFs,
    durable::{ReadError, WriteError, durable_replace, read_state_file},
    passphrase::{open_scrypt_file, seal_scrypt_file},
};

/// The owner's secret for the approver key envelope, and nothing else.
///
/// It is a different type from the vault-unlock [`crate::Passphrase`] so one can never be passed for the other:
/// unlocking the vault must never imply authority to approve a config. It has no `Display` or `Clone`, its `Debug`
/// shows nothing of it, and its text is cleared when it is dropped.
pub struct ApprovalPassphrase(SecretString);

impl ApprovalPassphrase {
    /// Wraps `text` as an approval passphrase, refusing an empty one.
    pub fn new(text: SecretString) -> Result<Self, PassphraseError> {
        match text.expose_secret().is_empty() {
            true => Err(PassphraseError::Empty),
            false => Ok(Self(text)),
        }
    }

    /// A copy of the passphrase for `age`, which takes its passphrase by value; the copy is also cleared on drop.
    fn for_age(&self) -> SecretString {
        SecretString::from(self.0.expose_secret())
    }
}

impl fmt::Debug for ApprovalPassphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApprovalPassphrase([REDACTED])")
    }
}

/// A software signer's Ed25519 private key, between generation and sealing into `approver.age`.
///
/// The key is cleared when it is dropped; it has no `Clone` and its `Debug` shows nothing of it.
pub struct SoftwareSignerKey(SigningKey);

impl SoftwareSignerKey {
    /// The approver this key verifies as.
    fn pinned(&self) -> Result<PinnedApprover, SignError> {
        PinnedApprover::ed25519(self.0.verifying_key()).map_err(SignError::Unpinnable)
    }
}

impl fmt::Debug for SoftwareSignerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SoftwareSignerKey([REDACTED])")
    }
}

/// An open software signer: the private key and the pinned approver it was checked against.
///
/// Open one with [`open_signer_key`] for a single approval and drop it once that approval is signed. Its key is cleared
/// on drop, and it has no `Clone`, so the decrypted key lives no longer than the approval that needed it.
pub struct SoftwareSigner {
    key: SigningKey,
    pinned: PinnedApprover,
}

impl SoftwareSigner {
    /// A fresh software signer key from the operating system's random source, and the approver to pin for it.
    ///
    /// The key is sealed with [`seal_signer_key`] and then dropped; the approver goes into the approval state.
    pub fn generate() -> Result<(SoftwareSignerKey, PinnedApprover), SignError> {
        let mut seed = Zeroizing::new([0u8; SECRET_KEY_LENGTH]);
        getrandom::fill(seed.as_mut_slice()).map_err(|_| SignError::Randomness)?;
        let key = SoftwareSignerKey(SigningKey::from_bytes(&seed));
        let pinned = key.pinned()?;
        Ok((key, pinned))
    }

    /// The signer for `key`, refusing it unless its public key is `pinned`'s.
    fn new(key: SoftwareSignerKey, pinned: &PinnedApprover) -> Result<Self, SignError> {
        match key.pinned()? == *pinned {
            true => Ok(Self { key: key.0, pinned: pinned.clone() }),
            false => Err(SignError::KeyMismatch),
        }
    }
}

impl ApprovalSigner for SoftwareSigner {
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Ed25519
    }

    fn pinned(&self) -> PinnedApprover {
        self.pinned.clone()
    }

    fn sign(&self, payload: &ApprovalPayload) -> Result<ApprovalEnvelope, SignError> {
        let signature = self.key.sign(&payload.encode()).to_bytes().to_vec();
        ApprovalEnvelope::new(SignatureAlgorithm::Ed25519, *payload, signature).map_err(SignError::Signature)
    }
}

impl fmt::Debug for SoftwareSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SoftwareSigner").field("algorithm", &SignatureAlgorithm::Ed25519).finish_non_exhaustive()
    }
}

/// Encrypts `key` to `passphrase` alone, at [`PASSPHRASE_WORK_FACTOR`]: the `approver.age` bytes.
///
/// The output has exactly one scrypt stanza and no other, as the passphrase envelope does.
pub fn seal_signer_key(key: &SoftwareSignerKey, passphrase: &ApprovalPassphrase) -> Result<Vec<u8>, SignError> {
    seal_signer_key_at(key, passphrase, PASSPHRASE_WORK_FACTOR)
}

/// Decrypts `approver.age` with `passphrase` and opens a signer for `pinned`.
///
/// The header checks of the passphrase envelope run before any scrypt work. A wrong passphrase is
/// [`SignError::WrongPassphrase`] and nothing more; a key that is not `pinned`'s is [`SignError::KeyMismatch`], so a
/// swapped `approver.age` signs nothing.
pub fn open_signer_key(envelope: &[u8], passphrase: &ApprovalPassphrase, pinned: &PinnedApprover) -> Result<SoftwareSigner, SignError> {
    SoftwareSigner::new(open_key(envelope, passphrase)?, pinned)
}

/// Durably replaces `approver.age` with `envelope`.
pub fn write_signer_key(lock: &StateDirLock, fs: &impl StoreFs, envelope: &[u8]) -> Result<(), WriteError> {
    durable_replace(lock, fs, &StateFileName::approver_key(), envelope)
}

/// Reads `approver.age`, refusing a file longer than [`MAX_PASSPHRASE_ENVELOPE_LEN`].
pub fn read_signer_key(lock: &StateDirLock, fs: &impl StoreFs) -> Result<Vec<u8>, ReadError> {
    read_state_file(lock, fs, &StateFileName::approver_key(), MAX_PASSPHRASE_ENVELOPE_LEN as u64)
}

/// [`seal_signer_key`] at work factor `log_n`, which must be in `1..64`.
fn seal_signer_key_at(key: &SoftwareSignerKey, passphrase: &ApprovalPassphrase, log_n: u8) -> Result<Vec<u8>, SignError> {
    Ok(seal_scrypt_file(key.0.as_bytes(), passphrase.for_age(), log_n)?)
}

/// The private key in `envelope`, which must be exactly [`SECRET_KEY_LENGTH`] bytes, so `operational.age` or any
/// other plaintext never opens as a signing key.
fn open_key(envelope: &[u8], passphrase: &ApprovalPassphrase) -> Result<SoftwareSignerKey, SignError> {
    let plaintext = open_scrypt_file(envelope, passphrase.for_age(), SECRET_KEY_LENGTH)?;
    let seed: &[u8; SECRET_KEY_LENGTH] =
        plaintext.as_slice().try_into().map_err(|_| SignError::Envelope(EnvelopeError::Malformed))?;
    Ok(SoftwareSignerKey(SigningKey::from_bytes(seed)))
}
