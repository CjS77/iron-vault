//! The recovery check: proves that a recovery key opens the vault on disk, changing nothing (specification §16,
//! `design/recovery.md`, "What the check proves").
//!
//! `age` does not authenticate the sender, so unwrapping `identity.age` proves nothing by itself: anyone who knows the
//! recovery key's recipient can wrap an identity of their own for it. Only the manifest's MAC, keyed from the vault
//! identity, shows the unwrapped identity is this vault's.

use std::io;

use thiserror::Error;

use crate::{
    EnvelopeError, ErrorKindLabel, MAX_MANIFEST_LEN, ManifestError, ReadError, StateDirLock, StateFileName, StoreFs, VaultId,
    open_manifest, read_identity_envelope, read_state_file, recipient::RecipientIdentity, unwrap_identity,
};

/// A recovery key that was proved to open the vault on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryCheck {
    vault_id: VaultId,
}

impl RecoveryCheck {
    /// The ID of the vault whose manifest verified, as that manifest records it.
    pub fn vault_id(&self) -> VaultId {
        self.vault_id
    }
}

/// Why a file of the vault is unusable, in words that name no key material and no file content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum MalformedReason {
    /// The file is longer than the store's bound for it.
    #[error("too large")]
    TooLarge,
    /// The file is truncated, not of the expected format, or fails to decode.
    #[error("malformed")]
    Malformed,
    /// The identity envelope holds a stanza that is not X25519.
    #[error("holds an unexpected stanza")]
    UnexpectedStanza,
    /// The manifest has a version this build cannot read.
    #[error("has an unknown version")]
    UnknownVersion,
}

/// A recovery check ended without confirming the key. No variant carries the key's text or any key material.
///
/// [`NotARecipient`](Self::NotARecipient) and [`IdentityNotGenuine`](Self::IdentityNotGenuine) say the key cannot be shown
/// to open the vault; the other two mean the check could not be run, which says nothing against the key.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RecoveryCheckError {
    /// The key has no stanza in `identity.age`, or its stanza is damaged, which `age` cannot tell apart.
    #[error("the recovery key is not a recipient of the identity envelope")]
    NotARecipient,
    /// The key unwrapped an identity whose manifest MAC does not verify: a forged or foreign envelope, or a damaged
    /// manifest, which the MAC cannot tell apart.
    #[error("the identity the recovery key unwraps is not this vault's")]
    IdentityNotGenuine,
    /// `identity.age` or `manifest.age` could not be read.
    #[error("cannot read {file}: {kind}")]
    Unreadable {
        /// The file that could not be read.
        file: StateFileName,
        /// The underlying error kind.
        kind: io::ErrorKind,
    },
    /// `identity.age` or `manifest.age` is a symlink, directory or other entry that is not a regular file, so it was not read.
    #[error("{file} is not a regular file")]
    NotARegularFile {
        /// The entry that is not a regular file.
        file: StateFileName,
    },
    /// `identity.age` or `manifest.age` was read but cannot be used.
    #[error("{file} cannot be used: {reason}")]
    EnvelopeMalformed {
        /// The file that cannot be used.
        file: StateFileName,
        /// What is wrong with it.
        reason: MalformedReason,
    },
}

/// Proves that `recipient`, the identity parsed from the recovery key the owner typed, opens the vault on disk.
///
/// Reads `identity.age`, unwraps it, then opens `manifest.age` with what it unwrapped, so the manifest's MAC is checked
/// before anything is decrypted. Nothing is written: the caller holds the state directory lock so both files come from
/// one vault state. The unwrapped vault identity is dropped, and so cleared, before this returns; only the vault ID leaves.
///
/// The recipient need not be the recovery key: any enrolled recipient's identity passes. The envelope's size bound and
/// stanza kinds are checked by [`unwrap_identity`] before any key work.
pub fn check_recovery_key(
    lock: &StateDirLock,
    fs: &impl StoreFs,
    recipient: &RecipientIdentity,
) -> Result<RecoveryCheck, RecoveryCheckError> {
    let identity_file = StateFileName::identity_envelope();
    let envelope = read_identity_envelope(lock, fs).map_err(|e| unreadable(identity_file.clone(), e))?;
    let identity = unwrap_identity(&envelope, recipient).map_err(|e| match e {
        EnvelopeError::NotARecipient => RecoveryCheckError::NotARecipient,
        other => malformed(identity_file, envelope_reason(&other)),
    })?;
    let manifest_file = StateFileName::manifest();
    // MAX_MANIFEST_LEN is 1 MiB, so it always fits in a u64.
    let bytes = read_state_file(lock, fs, &manifest_file, MAX_MANIFEST_LEN as u64).map_err(|e| unreadable(manifest_file.clone(), e))?;
    let manifest = open_manifest(&identity, &bytes).map_err(|e| match e {
        ManifestError::Damaged => RecoveryCheckError::IdentityNotGenuine,
        other => malformed(manifest_file, manifest_reason(&other)),
    })?;
    Ok(RecoveryCheck {
        vault_id: manifest.vault_id(),
    })
}

impl RecoveryCheckError {
    /// Whether the key was judged and found not to open the vault, as opposed to the check not being run.
    pub fn is_key_rejected(&self) -> bool {
        matches!(self, Self::NotARecipient | Self::IdentityNotGenuine)
    }

    /// The file the check could not use, for the errors that name one.
    pub fn file(&self) -> Option<&StateFileName> {
        match self {
            Self::Unreadable { file, .. } | Self::NotARegularFile { file } | Self::EnvelopeMalformed { file, .. } => Some(file),
            Self::NotARecipient | Self::IdentityNotGenuine => None,
        }
    }

    /// The error as a label that holds no file name or error text, for a log record.
    pub fn error_kind_label(&self) -> ErrorKindLabel {
        match self {
            Self::Unreadable { kind, .. } => ErrorKindLabel::from(*kind),
            Self::NotARegularFile { .. } => ErrorKindLabel::fixed("not_a_regular_file"),
            Self::EnvelopeMalformed { reason, .. } => ErrorKindLabel::fixed(match reason {
                MalformedReason::TooLarge => "too_large",
                MalformedReason::Malformed => "malformed",
                MalformedReason::UnexpectedStanza => "unexpected_stanza",
                MalformedReason::UnknownVersion => "unknown_version",
            }),
            Self::NotARecipient => ErrorKindLabel::fixed("not_a_recipient"),
            Self::IdentityNotGenuine => ErrorKindLabel::fixed("identity_unverified"),
        }
    }
}

fn malformed(file: StateFileName, reason: MalformedReason) -> RecoveryCheckError {
    RecoveryCheckError::EnvelopeMalformed { file, reason }
}

/// A failed read: an oversized file is unusable, anything else is unreadable.
fn unreadable(file: StateFileName, error: ReadError) -> RecoveryCheckError {
    match error {
        ReadError::TooLarge { .. } => malformed(file, MalformedReason::TooLarge),
        ReadError::NotARegularFile { .. } => RecoveryCheckError::NotARegularFile { file },
        ReadError::Io { kind, .. } => RecoveryCheckError::Unreadable { file, kind },
    }
}

fn envelope_reason(error: &EnvelopeError) -> MalformedReason {
    match error {
        EnvelopeError::TooLarge => MalformedReason::TooLarge,
        EnvelopeError::UnexpectedStanza(_) => MalformedReason::UnexpectedStanza,
        _ => MalformedReason::Malformed,
    }
}

fn manifest_reason(error: &ManifestError) -> MalformedReason {
    match error {
        ManifestError::TooLarge { .. } => MalformedReason::TooLarge,
        ManifestError::UnknownVersion(_) => MalformedReason::UnknownVersion,
        _ => MalformedReason::Malformed,
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use secrecy::{ExposeSecret, SecretString};

    use super::*;
    use crate::{
        OperationalIdentity, OsFs, Passphrase, RecipientSet, RecoveryKey, Vault, VaultIdentity,
        fault_fs::{FaultFs, FsCall, FsOp},
        passphrase::seal_at,
        test_dir::TestDir,
        wrap_identity, write_identity_envelope,
    };

    /// A vault in a state directory with its two enrolled recipients: the recovery key and the operational identity.
    struct Fixture {
        dir: TestDir,
        lock: StateDirLock,
        vault_id: VaultId,
        recovery_text: String,
        recovery: RecipientIdentity,
        operational: RecipientIdentity,
    }

    fn fixture(name: &str) -> Fixture {
        let dir = TestDir::new(name);
        let lock = StateDirLock::acquire(dir.path()).unwrap();
        let vault_identity = VaultIdentity::generate();
        let (operational, operational_key) = OperationalIdentity::generate();
        let (secret, recovery_key) = RecoveryKey::generate();
        let recipients = RecipientSet::new([operational_key, recovery_key]).unwrap();
        write_identity_envelope(&lock, &OsFs, &wrap_identity(&vault_identity, &recipients).unwrap()).unwrap();
        let vault = Vault::create(&lock, &OsFs, vault_identity).unwrap();
        let recovery_text = secret.expose_secret().to_owned();
        Fixture {
            vault_id: vault.manifest().vault_id(),
            recovery: crate::RecoveryKeySecret::parse(SecretString::from(recovery_text.as_str())).unwrap(),
            recovery_text,
            operational,
            lock,
            dir,
        }
    }

    impl Fixture {
        fn path(&self, file: &StateFileName) -> std::path::PathBuf {
            self.dir.path().join(file.as_str())
        }

        /// The state directory's vault files, copied into a fault filesystem that records every call.
        fn fault_fs(&self) -> FaultFs {
            [StateFileName::identity_envelope(), StateFileName::manifest()]
                .iter()
                .filter_map(|file| std::fs::read(self.path(file)).ok().map(|bytes| (self.path(file), bytes)))
                .fold(FaultFs::new(), |fs, (path, bytes)| fs.with_durable_file(&path, &bytes))
        }

        fn check(&self, recipient: &RecipientIdentity) -> Result<RecoveryCheck, RecoveryCheckError> {
            check_recovery_key(&self.lock, &OsFs, recipient)
        }

        /// The outcome of the check run against a fault filesystem, which must have seen reads and nothing else.
        fn check_without_writes(&self, recipient: &RecipientIdentity) -> Result<RecoveryCheck, RecoveryCheckError> {
            let fs = self.fault_fs();
            let outcome = check_recovery_key(&self.lock, &fs, recipient);
            assert_eq!(outcome, self.check(recipient));
            assert!(fs.trace().iter().all(|call| call.op() == FsOp::ReadBounded), "{:?}", fs.trace());
            outcome
        }
    }

    #[test]
    fn the_recovery_key_opens_the_vault_and_names_it() {
        let f = fixture("rc-recovery");
        assert_eq!(f.check_without_writes(&f.recovery).unwrap().vault_id(), f.vault_id);
    }

    #[test]
    fn the_operational_identity_opens_it_too() {
        let f = fixture("rc-operational");
        assert_eq!(f.check_without_writes(&f.operational).unwrap().vault_id(), f.vault_id);
    }

    #[test]
    fn another_vaults_recovery_key_is_not_a_recipient() {
        let f = fixture("rc-foreign");
        let other = fixture("rc-foreign-other");
        assert_eq!(f.check_without_writes(&other.recovery), Err(RecoveryCheckError::NotARecipient));
    }

    #[test]
    fn an_envelope_wrapped_for_the_recovery_recipient_around_a_foreign_identity_is_not_genuine() {
        let f = fixture("rc-forged");
        let attacker = VaultIdentity::generate();
        let recipients = RecipientSet::new([f.recovery.recipient_key(), RecipientIdentity::generate().recipient_key()]).unwrap();
        write_identity_envelope(&f.lock, &OsFs, &wrap_identity(&attacker, &recipients).unwrap()).unwrap();
        assert_eq!(f.check_without_writes(&f.recovery), Err(RecoveryCheckError::IdentityNotGenuine));
    }

    #[test]
    fn a_damaged_manifest_is_not_genuine_either() {
        let f = fixture("rc-damaged");
        let path = f.path(&StateFileName::manifest());
        let mut bytes = std::fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        std::fs::write(&path, bytes).unwrap();
        assert_eq!(f.check_without_writes(&f.recovery), Err(RecoveryCheckError::IdentityNotGenuine));
    }

    #[test]
    fn a_passphrase_envelope_in_place_of_identity_age_is_refused_before_scrypt() {
        let f = fixture("rc-scrypt");
        let passphrase = Passphrase::new(SecretString::from("correct horse battery staple")).unwrap();
        let envelope = seal_at(&f.operational, &passphrase, 2).unwrap();
        let line_end = 22 + envelope[22..].iter().position(|&b| b == b'\n').unwrap();
        // Raise the stanza's work factor so that any scrypt run on it would take far longer than the bound below.
        let slow = [&envelope[..line_end - 1], b"30", &envelope[line_end..]].concat();
        write_identity_envelope(&f.lock, &OsFs, &slow).unwrap();
        let started = Instant::now();
        let outcome = f.check_without_writes(&f.recovery);
        assert_eq!(
            outcome,
            Err(RecoveryCheckError::EnvelopeMalformed {
                file: StateFileName::identity_envelope(),
                reason: MalformedReason::UnexpectedStanza
            })
        );
        assert!(started.elapsed() < Duration::from_millis(500), "took {:?}", started.elapsed());
    }

    #[test]
    fn a_missing_file_is_unreadable_with_its_kind() {
        [StateFileName::identity_envelope(), StateFileName::manifest()]
            .into_iter()
            .for_each(|file| {
                let f = fixture("rc-missing");
                std::fs::remove_file(f.path(&file)).unwrap();
                let expected = RecoveryCheckError::Unreadable {
                    file,
                    kind: io::ErrorKind::NotFound,
                };
                assert_eq!(f.check_without_writes(&f.recovery), Err(expected));
            });
    }

    #[test]
    fn a_failed_read_is_unreadable_and_writes_nothing() {
        let f = fixture("rc-io");
        let fs = f.fault_fs();
        fs.fail_first(FsOp::ReadBounded, io::ErrorKind::PermissionDenied);
        let expected = RecoveryCheckError::Unreadable {
            file: StateFileName::identity_envelope(),
            kind: io::ErrorKind::PermissionDenied,
        };
        assert_eq!(check_recovery_key(&f.lock, &fs, &f.recovery), Err(expected));
        assert!(
            fs.trace().iter().all(|call| matches!(call, FsCall::ReadBounded(_))),
            "{:?}",
            fs.trace()
        );
    }

    #[test]
    fn an_entry_that_is_not_a_regular_file_is_named_as_such() {
        let f = fixture("rc-not-regular");
        let path = f.path(&StateFileName::manifest());
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        let expected = RecoveryCheckError::NotARegularFile {
            file: StateFileName::manifest(),
        };
        assert_eq!(f.check(&f.recovery), Err(expected.clone()));
        assert_eq!(expected.error_kind_label().as_str(), "not_a_regular_file");
        assert!(!expected.is_key_rejected());
    }

    #[test]
    fn unusable_files_are_malformed_not_unreadable() {
        let f = fixture("rc-malformed");
        let manifest = f.path(&StateFileName::manifest());
        let good = std::fs::read(&manifest).unwrap();
        std::fs::write(&manifest, &good[..10]).unwrap();
        assert!(matches!(
            f.check_without_writes(&f.recovery),
            Err(RecoveryCheckError::EnvelopeMalformed {
                reason: MalformedReason::Malformed,
                ..
            })
        ));
        std::fs::write(&manifest, &good).unwrap();
        write_identity_envelope(&f.lock, &OsFs, &vec![0; crate::MAX_IDENTITY_ENVELOPE_LEN + 1]).unwrap();
        let expected = RecoveryCheckError::EnvelopeMalformed {
            file: StateFileName::identity_envelope(),
            reason: MalformedReason::TooLarge,
        };
        assert_eq!(f.check_without_writes(&f.recovery), Err(expected));
    }

    #[test]
    fn no_error_shows_the_key() {
        let f = fixture("rc-redacted");
        let secret_part = &f.recovery_text[16..];
        let other = fixture("rc-redacted-other");
        let errors = [f.check(&other.recovery).unwrap_err(), RecoveryCheckError::IdentityNotGenuine];
        errors.iter().for_each(|e| {
            let shown = format!("{e} {e:?}");
            assert!(!shown.contains(secret_part) && !shown.contains("AGE-SECRET"), "{shown}");
        });
        assert!(!format!("{:?}", f.check(&f.recovery)).contains(secret_part));
    }
}
