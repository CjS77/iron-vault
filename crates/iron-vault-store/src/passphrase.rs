//! Passphrase unlock: the operational identity and the passphrase envelope that holds it (specification §3.11, §3.12,
//! §3.15).
//!
//! `age` refuses an scrypt stanza beside any other recipient, so a passphrase cannot be a recipient of the identity
//! envelope. The service instead generates an operational identity, enrolls its recipient key in `identity.age` like
//! any other, and keeps its secret text in `operational.age`, encrypted to the passphrase alone. Unlocking goes
//! passphrase, then operational identity, then vault identity.
//!
//! Attempt limits and lockout are not enforced here: they belong to the lock and unlock epic (EP-23) and to migration
//! authorization (EP-29), which call into this module.

use std::{fmt, iter};

use age::{DecryptError, Decryptor, Encryptor, scrypt};
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    EnvelopeError, StateDirLock, StateFileName, StoreFs,
    durable::{ReadError, WriteError, durable_replace, read_state_file},
    envelope::{read_identity_envelope, unwrap_identity},
    recipient::{RecipientIdentity, RecipientKey},
    sealed::read_bounded,
    stanza::{StanzaKind, parse_header},
    vault_identity::VaultIdentity,
};

/// The scrypt work factor, as `log2(N)`, that new passphrase envelopes are sealed with.
///
/// N = 2^18 with `age`'s r = 8 needs 256 MiB of memory and takes roughly half a second to one second on a current
/// desktop CPU, once per unlock. `age`'s own default measures the machine to aim for about one second; a fixed value
/// keeps the envelope's cost the same on every host it is copied to.
pub const PASSPHRASE_WORK_FACTOR: u8 = 18;

/// The highest scrypt work factor, as `log2(N)`, the store will run when opening a passphrase envelope.
///
/// N = 2^20 needs 1 GiB and about four times the unlock time of [`PASSPHRASE_WORK_FACTOR`]. It leaves room to raise the
/// sealing factor later without stranding existing envelopes, while a planted file still cannot force an unbounded
/// scrypt run: a higher factor is refused from the header, before any scrypt work.
pub const MAX_PASSPHRASE_WORK_FACTOR: u8 = 20;

/// The largest passphrase envelope, and the largest approver key envelope, the store reads.
///
/// The passphrase envelope is about 256 bytes: the 22-byte version line, a 36-byte scrypt stanza line and its 44-byte
/// body, the 48-byte MAC line, and a 106-byte payload (16-byte nonce, 74-byte secret text, 16-byte tag). The approver
/// key envelope has a 64-byte payload instead, 214 bytes in all. 1 KiB bounds what a planted file can make an open read.
pub const MAX_PASSPHRASE_ENVELOPE_LEN: usize = 1024;

/// The length of the envelope's plaintext: the `AGE-SECRET-KEY-1…` text of an X25519 identity.
const SECRET_TEXT_LEN: usize = 74;

// `age` panics on a work factor outside 1..64; checking the constants here keeps that path unreachable.
const _: () = assert!(0 < PASSPHRASE_WORK_FACTOR && PASSPHRASE_WORK_FACTOR <= MAX_PASSPHRASE_WORK_FACTOR);
const _: () = assert!(MAX_PASSPHRASE_WORK_FACTOR < 64);

/// The owner's passphrase for the passphrase envelope.
///
/// It has no `Display` or `Clone`, its `Debug` shows nothing of it, and its text is cleared when it is dropped. A
/// minimum length or strength is not enforced here; vault initialization sets that rule.
pub struct Passphrase(SecretString);

/// A passphrase that cannot be used.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PassphraseError {
    /// The passphrase is empty.
    #[error("the passphrase is empty")]
    Empty,
}

impl Passphrase {
    /// Wraps `text` as a passphrase, refusing an empty one.
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

impl fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Passphrase([REDACTED])")
    }
}

/// The generator of operational identities: the X25519 recipients through which a passphrase reaches the vault.
pub enum OperationalIdentity {}

impl OperationalIdentity {
    /// A fresh operational identity and its recipient key.
    ///
    /// The key is enrolled in the identity envelope's recipient set; the identity is sealed into the passphrase
    /// envelope and then dropped.
    pub fn generate() -> (RecipientIdentity, RecipientKey) {
        let identity = RecipientIdentity::generate();
        let key = identity.recipient_key();
        (identity, key)
    }
}

/// Encrypts the operational identity's secret text to `passphrase` alone, at [`PASSPHRASE_WORK_FACTOR`].
///
/// The output is a binary `age` file with exactly one scrypt stanza and no other: `age` adds its grease stanza only to
/// files without one.
pub fn seal_passphrase_envelope(identity: &RecipientIdentity, passphrase: &Passphrase) -> Result<Vec<u8>, EnvelopeError> {
    seal_at(identity, passphrase, PASSPHRASE_WORK_FACTOR)
}

/// Decrypts the passphrase envelope to the operational identity.
///
/// Every check that needs no passphrase runs first: the size bound, then that the header holds exactly one scrypt
/// stanza, then that its work factor is at most [`MAX_PASSPHRASE_WORK_FACTOR`]. Only then does scrypt run. A wrong
/// passphrase is [`EnvelopeError::WrongPassphrase`] and nothing more.
pub fn open_passphrase_envelope(envelope: &[u8], passphrase: &Passphrase) -> Result<RecipientIdentity, EnvelopeError> {
    let secret = open_scrypt_file(envelope, passphrase.for_age(), SECRET_TEXT_LEN)?;
    RecipientIdentity::from_secret_text(&secret).ok_or(EnvelopeError::Malformed)
}

/// Opens `envelope` with `old` and seals the same operational identity to `new`.
///
/// Changing the passphrase rewrites only `operational.age`: the operational identity, and so `identity.age`, stay as
/// they are.
pub fn reseal_passphrase_envelope(envelope: &[u8], old: &Passphrase, new: &Passphrase) -> Result<Vec<u8>, EnvelopeError> {
    reseal_at(envelope, old, new, PASSPHRASE_WORK_FACTOR)
}

/// Durably replaces `operational.age` with `envelope`.
pub fn write_passphrase_envelope(lock: &StateDirLock, fs: &impl StoreFs, envelope: &[u8]) -> Result<(), WriteError> {
    durable_replace(lock, fs, &StateFileName::passphrase_envelope(), envelope)
}

/// Reads `operational.age`, refusing a file longer than [`MAX_PASSPHRASE_ENVELOPE_LEN`].
pub fn read_passphrase_envelope(lock: &StateDirLock, fs: &impl StoreFs) -> Result<Vec<u8>, ReadError> {
    read_state_file(lock, fs, &StateFileName::passphrase_envelope(), MAX_PASSPHRASE_ENVELOPE_LEN as u64)
}

/// Unlocking the vault with the passphrase failed. No variant carries key material or passphrase text.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum UnlockError {
    /// The passphrase does not open `operational.age`.
    #[error("wrong passphrase")]
    WrongPassphrase,
    /// `operational.age` or `identity.age` could not be read.
    #[error(transparent)]
    Read(#[from] ReadError),
    /// `operational.age` is damaged, oversized or not a passphrase envelope.
    #[error("the passphrase envelope cannot be opened: {0}")]
    PassphraseEnvelope(EnvelopeError),
    /// `identity.age` is damaged, or the operational identity is not one of its recipients.
    #[error("the identity envelope cannot be opened with the operational identity: {0}")]
    IdentityEnvelope(EnvelopeError),
}

/// Reads both envelopes and unlocks the vault identity: the passphrase opens the operational identity, which unwraps
/// the vault identity.
///
/// As with [`unwrap_identity`], the returned identity is trusted only once the vault manifest's MAC verifies.
pub fn unlock_with_passphrase(lock: &StateDirLock, fs: &impl StoreFs, passphrase: &Passphrase) -> Result<VaultIdentity, UnlockError> {
    let operational = open_passphrase_envelope(&read_passphrase_envelope(lock, fs)?, passphrase).map_err(|error| match error {
        EnvelopeError::WrongPassphrase => UnlockError::WrongPassphrase,
        other => UnlockError::PassphraseEnvelope(other),
    })?;
    unwrap_identity(&read_identity_envelope(lock, fs)?, &operational).map_err(UnlockError::IdentityEnvelope)
}

/// [`reseal_passphrase_envelope`] sealing at work factor `log_n`, which must be in `1..64`.
fn reseal_at(envelope: &[u8], old: &Passphrase, new: &Passphrase, log_n: u8) -> Result<Vec<u8>, EnvelopeError> {
    seal_at(&open_passphrase_envelope(envelope, old)?, new, log_n)
}

/// [`seal_passphrase_envelope`] at work factor `log_n`, which must be in `1..64`.
pub(crate) fn seal_at(identity: &RecipientIdentity, passphrase: &Passphrase, log_n: u8) -> Result<Vec<u8>, EnvelopeError> {
    seal_scrypt_file(identity.secret_text().expose_secret().as_bytes(), passphrase.for_age(), log_n)
}

/// Encrypts `secret` as an `age` file with one scrypt stanza for `passphrase` at work factor `log_n`, which must be in
/// `1..64`; the shared sealing path of every passphrase-protected state file.
pub(crate) fn seal_scrypt_file(secret: &[u8], passphrase: SecretString, log_n: u8) -> Result<Vec<u8>, EnvelopeError> {
    let mut recipient = scrypt::Recipient::new(passphrase);
    recipient.set_work_factor(log_n);
    let encryptor = Encryptor::with_recipients(iter::once(&recipient as &dyn age::Recipient)).map_err(|_| EnvelopeError::Encryption)?;
    let mut writer = encryptor.wrap_output(Vec::with_capacity(MAX_PASSPHRASE_ENVELOPE_LEN)).map_err(|_| EnvelopeError::Encryption)?;
    std::io::Write::write_all(&mut writer, secret).map_err(|_| EnvelopeError::Encryption)?;
    writer.finish().map_err(|_| EnvelopeError::Encryption)
}

/// Decrypts an `age` file with exactly one scrypt stanza, returning at most `max_plaintext` bytes in a buffer cleared
/// on drop; the shared opening path of every passphrase-protected state file.
///
/// Every check that needs no passphrase runs first: the size bound, then that the header holds exactly one scrypt
/// stanza, then that its work factor is at most [`MAX_PASSPHRASE_WORK_FACTOR`]. Only then does scrypt run.
pub(crate) fn open_scrypt_file(
    envelope: &[u8],
    passphrase: SecretString,
    max_plaintext: usize,
) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
    if envelope.len() > MAX_PASSPHRASE_ENVELOPE_LEN {
        return Err(EnvelopeError::TooLarge);
    }
    check_header(envelope)?;
    let mut identity = scrypt::Identity::new(passphrase);
    // Belt and braces: `age` enforces the same bound if the header check above were ever loosened.
    identity.set_max_work_factor(MAX_PASSPHRASE_WORK_FACTOR);
    let decryptor = Decryptor::new_buffered(envelope).map_err(map_decrypt_error)?;
    let reader = decryptor.decrypt(iter::once(&identity as &dyn age::Identity)).map_err(map_decrypt_error)?;
    read_bounded(reader, max_plaintext, envelope.len()).map_err(|_| EnvelopeError::Malformed)
}

/// Refuses, from the header alone, anything but one scrypt stanza at an accepted work factor.
fn check_header(envelope: &[u8]) -> Result<(), EnvelopeError> {
    let header = parse_header(envelope).filter(|header| header.complete).ok_or(EnvelopeError::Malformed)?;
    if let Some(other) = header.kinds.iter().find(|kind| **kind != StanzaKind::Scrypt) {
        return Err(EnvelopeError::UnexpectedStanza(other.clone()));
    }
    match header.scrypt_work_factors.as_slice() {
        [Some(log_n)] if *log_n <= MAX_PASSPHRASE_WORK_FACTOR => Ok(()),
        [Some(_)] => Err(EnvelopeError::WorkFactorTooHigh),
        _ => Err(EnvelopeError::Malformed),
    }
}

/// Maps `age`'s decryption errors onto [`EnvelopeError`] without keeping their text.
fn map_decrypt_error(error: DecryptError) -> EnvelopeError {
    match error {
        // The scrypt stanza's key did not open its file key: a wrong passphrase, or a damaged stanza.
        DecryptError::DecryptionFailed => EnvelopeError::WrongPassphrase,
        DecryptError::ExcessiveWork { .. } => EnvelopeError::WorkFactorTooHigh,
        _ => EnvelopeError::Malformed,
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use proptest::prelude::*;

    use super::*;
    use crate::{
        OsFs, RecipientSet,
        envelope::{stanza_kinds, wrap_identity, write_identity_envelope},
        sealed::seal_to,
        test_dir::TestDir,
    };

    /// The work factor tests seal with, so CI does not spend 256 MiB and a second per envelope.
    const TEST_WORK_FACTOR: u8 = 2;

    fn passphrase(text: &str) -> Passphrase {
        Passphrase::new(SecretString::from(text)).unwrap()
    }

    /// A passphrase envelope sealed at the test work factor, with the identity inside it.
    fn sealed(text: &str) -> (RecipientIdentity, Vec<u8>) {
        let (identity, _) = OperationalIdentity::generate();
        let envelope = seal_at(&identity, &passphrase(text), TEST_WORK_FACTOR).unwrap();
        (identity, envelope)
    }

    /// `envelope` with its scrypt stanza's work factor argument replaced by `log_n`.
    fn with_work_factor(envelope: &[u8], log_n: &str) -> Vec<u8> {
        let line_end = 22 + envelope[22..].iter().position(|&b| b == b'\n').unwrap();
        let suffix = format!(" {TEST_WORK_FACTOR}");
        assert!(envelope[22..line_end].starts_with(b"-> scrypt ") && envelope[..line_end].ends_with(suffix.as_bytes()));
        [&envelope[..line_end - suffix.len()], b" ", log_n.as_bytes(), &envelope[line_end..]].concat()
    }

    /// A vault identity wrapped for a fresh operational identity and a second key, with the passphrase envelope, both
    /// written to a new state directory.
    fn vault_on_disk(dir: &TestDir, text: &str) -> (StateDirLock, VaultIdentity) {
        let lock = StateDirLock::acquire(dir.path()).unwrap();
        let vault = VaultIdentity::generate();
        let (operational, operational_key) = OperationalIdentity::generate();
        let set = RecipientSet::new([operational_key, RecipientIdentity::generate().recipient_key()]).unwrap();
        write_identity_envelope(&lock, &OsFs, &wrap_identity(&vault, &set).unwrap()).unwrap();
        write_passphrase_envelope(&lock, &OsFs, &seal_at(&operational, &passphrase(text), TEST_WORK_FACTOR).unwrap()).unwrap();
        (lock, vault)
    }

    #[test]
    fn production_work_factors_are_pinned() {
        assert_eq!(PASSPHRASE_WORK_FACTOR, 18);
        assert_eq!(MAX_PASSPHRASE_WORK_FACTOR, 20);
    }

    #[test]
    fn an_empty_passphrase_is_refused() {
        assert_eq!(Passphrase::new(SecretString::from("")).unwrap_err(), PassphraseError::Empty);
        assert!(Passphrase::new(SecretString::from(" ")).is_ok());
    }

    #[test]
    fn passphrase_debug_shows_nothing_of_it() {
        let debug = format!("{:?} {:#?}", passphrase("correct horse"), passphrase("correct horse"));
        assert!(!debug.contains("correct") && !debug.contains("horse"), "{debug}");
    }

    #[test]
    fn the_operational_key_matches_its_identity() {
        let (identity, key) = OperationalIdentity::generate();
        assert_eq!(identity.recipient_key(), key);
        assert_ne!(OperationalIdentity::generate().1, key);
    }

    #[test]
    fn the_passphrase_opens_the_operational_identity() {
        let (identity, envelope) = sealed("correct horse");
        let opened = open_passphrase_envelope(&envelope, &passphrase("correct horse")).unwrap();
        assert_eq!(opened.recipient_key(), identity.recipient_key());
    }

    #[test]
    fn a_wrong_passphrase_is_wrong_passphrase() {
        let (_, envelope) = sealed("correct horse");
        ["correct horsE", "correct horse ", "x"].iter().for_each(|wrong| {
            assert_eq!(open_passphrase_envelope(&envelope, &passphrase(wrong)).unwrap_err(), EnvelopeError::WrongPassphrase);
        });
    }

    #[test]
    fn the_envelope_holds_exactly_one_scrypt_stanza_and_fits_its_bound() {
        let (_, envelope) = sealed("correct horse");
        assert_eq!(stanza_kinds(&envelope).unwrap(), [StanzaKind::Scrypt]);
        assert!(envelope.len() < MAX_PASSPHRASE_ENVELOPE_LEN / 2, "{} bytes", envelope.len());
        assert!(envelope.starts_with(b"age-encryption.org/v1\n-> scrypt "));
    }

    #[test]
    fn a_work_factor_above_the_maximum_is_refused_before_any_scrypt_work() {
        let (_, envelope) = sealed("correct horse");
        let planted = with_work_factor(&envelope, "40");
        let started = Instant::now();
        let refused = open_passphrase_envelope(&planted, &passphrase("correct horse"));
        let elapsed = started.elapsed();
        assert_eq!(refused.unwrap_err(), EnvelopeError::WorkFactorTooHigh);
        assert!(elapsed < Duration::from_millis(100), "took {elapsed:?}");
        let over = (MAX_PASSPHRASE_WORK_FACTOR + 1).to_string();
        let refused = open_passphrase_envelope(&with_work_factor(&envelope, &over), &passphrase("x"));
        assert_eq!(refused.unwrap_err(), EnvelopeError::WorkFactorTooHigh);
    }

    #[test]
    fn an_unreadable_work_factor_is_malformed() {
        let (_, envelope) = sealed("correct horse");
        ["02", "100", "x"].iter().for_each(|log_n| {
            let planted = with_work_factor(&envelope, log_n);
            assert_eq!(open_passphrase_envelope(&planted, &passphrase("correct horse")).unwrap_err(), EnvelopeError::Malformed, "{log_n}");
        });
    }

    #[test]
    fn an_x25519_file_is_refused_as_an_unexpected_stanza() {
        let keys = [RecipientIdentity::generate().recipient_key()];
        let file = seal_to(keys.iter().map(RecipientKey::as_age), b"not a passphrase file").unwrap();
        assert_eq!(open_passphrase_envelope(&file, &passphrase("x")).unwrap_err(), EnvelopeError::UnexpectedStanza(StanzaKind::X25519));
    }

    #[test]
    fn a_second_stanza_is_refused() {
        let (_, envelope) = sealed("correct horse");
        let mac = envelope.windows(5).position(|w| w == b"\n--- ").unwrap() + 1;
        let planted = [&envelope[..mac], b"-> scrypt AAAAAAAAAAAAAAAAAAAAAA 2\nAAAA\n", &envelope[mac..]].concat();
        assert_eq!(open_passphrase_envelope(&planted, &passphrase("correct horse")).unwrap_err(), EnvelopeError::Malformed);
        let planted = [&envelope[..mac], b"-> piv-p256 AAAA\nAAAA\n", &envelope[mac..]].concat();
        let other = StanzaKind::Other("piv-p256".to_owned());
        assert_eq!(open_passphrase_envelope(&planted, &passphrase("correct horse")).unwrap_err(), EnvelopeError::UnexpectedStanza(other));
    }

    #[test]
    fn an_oversized_envelope_is_refused_unread() {
        let (_, envelope) = sealed("correct horse");
        let padded = [envelope.as_slice(), &vec![0; MAX_PASSPHRASE_ENVELOPE_LEN + 1 - envelope.len()]].concat();
        assert_eq!(open_passphrase_envelope(&padded, &passphrase("correct horse")).unwrap_err(), EnvelopeError::TooLarge);
    }

    #[test]
    fn non_age_input_is_malformed() {
        [&b""[..], b"hello\n", b"age-encryption.org/v1\n", b"age-encryption.org/v1\n--- AAAA\n"].iter().for_each(|input| {
            assert_eq!(open_passphrase_envelope(input, &passphrase("x")).unwrap_err(), EnvelopeError::Malformed, "{input:?}");
        });
    }

    #[test]
    fn every_truncation_is_an_error() {
        let (_, envelope) = sealed("correct horse");
        let pass = passphrase("correct horse");
        (0..envelope.len()).for_each(|len| assert!(open_passphrase_envelope(&envelope[..len], &pass).is_err(), "truncated to {len}"));
    }

    #[test]
    fn unlock_composes_both_envelopes() {
        let dir = TestDir::new("passphrase-unlock");
        let (lock, vault) = vault_on_disk(&dir, "correct horse");
        assert!(dir.path().join("operational.age").is_file());
        let unlocked = unlock_with_passphrase(&lock, &OsFs, &passphrase("correct horse")).unwrap();
        assert_eq!(unlocked.public_key(), vault.public_key());
        assert!(!stanza_kinds(&read_identity_envelope(&lock, &OsFs).unwrap()).unwrap().contains(&StanzaKind::Scrypt));
    }

    #[test]
    fn unlock_with_a_wrong_passphrase_is_wrong_passphrase() {
        let dir = TestDir::new("passphrase-wrong");
        let (lock, _) = vault_on_disk(&dir, "correct horse");
        assert_eq!(unlock_with_passphrase(&lock, &OsFs, &passphrase("battery staple")).unwrap_err(), UnlockError::WrongPassphrase);
    }

    #[test]
    fn unlock_with_an_unenrolled_operational_identity_is_an_identity_envelope_error() {
        let dir = TestDir::new("passphrase-unenrolled");
        let (lock, _) = vault_on_disk(&dir, "correct horse");
        let (_, stranger) = sealed("correct horse");
        write_passphrase_envelope(&lock, &OsFs, &stranger).unwrap();
        let error = unlock_with_passphrase(&lock, &OsFs, &passphrase("correct horse")).unwrap_err();
        assert_eq!(error, UnlockError::IdentityEnvelope(EnvelopeError::NotARecipient));
    }

    #[test]
    fn unlock_without_a_passphrase_envelope_is_a_read_error() {
        let dir = TestDir::new("passphrase-missing");
        let lock = StateDirLock::acquire(dir.path()).unwrap();
        assert!(matches!(unlock_with_passphrase(&lock, &OsFs, &passphrase("x")), Err(UnlockError::Read(ReadError::Io { .. }))));
    }

    #[test]
    fn changing_the_passphrase_leaves_the_identity_envelope_untouched() {
        let dir = TestDir::new("passphrase-change");
        let (lock, vault) = vault_on_disk(&dir, "correct horse");
        let identity_before = read_identity_envelope(&lock, &OsFs).unwrap();
        let (old, new) = (passphrase("correct horse"), passphrase("battery staple"));
        let resealed = reseal_at(&read_passphrase_envelope(&lock, &OsFs).unwrap(), &old, &new, TEST_WORK_FACTOR).unwrap();
        write_passphrase_envelope(&lock, &OsFs, &resealed).unwrap();
        assert_eq!(read_identity_envelope(&lock, &OsFs).unwrap(), identity_before);
        assert_eq!(unlock_with_passphrase(&lock, &OsFs, &new).unwrap().public_key(), vault.public_key());
        assert_eq!(unlock_with_passphrase(&lock, &OsFs, &old).unwrap_err(), UnlockError::WrongPassphrase);
    }

    #[test]
    fn an_oversized_passphrase_file_is_not_read() {
        let dir = TestDir::new("passphrase-big");
        let lock = StateDirLock::acquire(dir.path()).unwrap();
        write_passphrase_envelope(&lock, &OsFs, &vec![0; MAX_PASSPHRASE_ENVELOPE_LEN + 1]).unwrap();
        assert!(matches!(read_passphrase_envelope(&lock, &OsFs), Err(ReadError::TooLarge { .. })));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        #[test]
        fn every_bit_flip_fails_to_open(offset in any::<prop::sample::Index>(), bit in 0u8..8) {
            let (_, mut envelope) = sealed("correct horse");
            let at = offset.index(envelope.len());
            envelope[at] ^= 1 << bit;
            // The header MAC authenticates the stanza and the payload is AEAD protected, so a flip anywhere must fail.
            prop_assert!(open_passphrase_envelope(&envelope, &passphrase("correct horse")).is_err(), "flip at {at} bit {bit} opened");
        }
    }
}
