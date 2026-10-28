//! The identity envelope: the vault identity wrapped for every enrolled recipient in `identity.age` (specification
//! §3.10, §3.11).
//!
//! The envelope is a plain binary `age` file whose plaintext is the vault identity's secret text. It holds only X25519
//! stanzas, because `age` forbids a passphrase stanza beside any other recipient; passphrase unlock and the recovery key
//! each reach the vault through an X25519 recipient listed here. Unwrapping it is the one secret-key operation at
//! startup, so every check that needs no key runs first.

use secrecy::ExposeSecret;
use thiserror::Error;

use crate::{
    StateDirLock, StateFileName, StoreFs,
    durable::{ReadError, WriteError, durable_replace, read_state_file},
    recipient::{RecipientIdentity, RecipientSet},
    sealed::{OpenError, open_as, seal_to},
    stanza::{StanzaKind, parse_header},
    vault_identity::VaultIdentity,
};

/// The largest identity envelope the store reads.
///
/// An X25519 stanza is 98 bytes (`-> X25519 `, a 43-character share, a 43-character body and two newlines), `age`'s
/// grease stanza at most about 220, the version and MAC lines 70, and the payload 106 (a 16-byte nonce, the 74-byte
/// secret text and a 16-byte tag). A [`RecipientSet`] of [`crate::MAX_RECIPIENTS`] (64) keys therefore makes an
/// envelope of under 6,700 bytes; 16 KiB leaves room for later stanza kinds without letting a planted file make
/// startup read an unbounded amount.
pub const MAX_IDENTITY_ENVELOPE_LEN: usize = 16 * 1024;

/// The length of the envelope's plaintext: the `AGE-SECRET-KEY-1…` text of an X25519 identity.
const SECRET_TEXT_LEN: usize = 74;

/// Wrapping or unwrapping the identity envelope failed. No variant carries key material or `age` error text.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EnvelopeError {
    /// `age` refused to encrypt to the recipient keys.
    #[error("could not wrap the vault identity for its recipients")]
    Encryption,
    /// The envelope is longer than [`MAX_IDENTITY_ENVELOPE_LEN`]; nothing in it was parsed.
    #[error("the identity envelope exceeds the {MAX_IDENTITY_ENVELOPE_LEN}-byte limit")]
    TooLarge,
    /// The envelope is not a well-formed, authentic `age` file holding a vault identity.
    #[error("the identity envelope is malformed or has been altered")]
    Malformed,
    /// The header holds a stanza other than X25519, such as a passphrase (scrypt) or plugin stanza.
    #[error("the identity envelope has a {0} stanza; it may hold only X25519 recipients")]
    UnexpectedStanza(StanzaKind),
    /// No stanza unwraps with the recipient identity: its key is not listed, or its stanza is damaged, which `age`
    /// cannot tell apart from a stanza for another key.
    #[error("the identity envelope is not wrapped for this recipient")]
    NotARecipient,
}

/// Encrypts the vault identity's secret text as an `age` file with one X25519 stanza per key in `recipients`.
///
/// A [`RecipientSet`] holds only X25519 keys, so no passphrase stanza can be mixed in (specification §3.11). The secret
/// text lives only in a buffer that is cleared on drop.
pub fn wrap_identity(identity: &VaultIdentity, recipients: &RecipientSet) -> Result<Vec<u8>, EnvelopeError> {
    let secret = identity.secret_text();
    seal_to(recipients.iter().map(|key| key.as_age()), secret.expose_secret().as_bytes()).map_err(|_| EnvelopeError::Encryption)
}

/// Decrypts the identity envelope with one recipient's identity.
///
/// The size bound and the header's stanza kinds are checked before any key work, so a planted passphrase file is
/// refused without running scrypt, and only the X25519 recipient identity is ever offered to `age`.
///
/// `age` does not authenticate the sender: anyone who knows a recipient key can write an envelope that unwraps
/// cleanly. The identity returned here is therefore trusted only once the vault manifest's MAC, keyed from this
/// identity, verifies; a forged envelope can only yield an identity that fails that check.
pub fn unwrap_identity(envelope: &[u8], recipient: &RecipientIdentity) -> Result<VaultIdentity, EnvelopeError> {
    if envelope.len() > MAX_IDENTITY_ENVELOPE_LEN {
        return Err(EnvelopeError::TooLarge);
    }
    // The header is read here and again by `age` inside `open_as`. This read is the one that refuses an scrypt or
    // plugin stanza before any key work; `age`'s parse is the one that authenticates the header. Neither replaces the other.
    check_x25519_only(&stanza_kinds(envelope)?)?;
    let secret = open_as(recipient.as_age(), envelope, SECRET_TEXT_LEN).map_err(map_open_error)?;
    VaultIdentity::from_secret_text(&secret).ok_or(EnvelopeError::Malformed)
}

/// The kinds of the stanzas in an `age` file's header, in header order, read without decrypting anything.
///
/// The list includes the grease stanza `age` adds to every file without a passphrase, so an envelope wrapped for `n`
/// recipients lists `n` [`StanzaKind::X25519`] and one [`StanzaKind::Grease`].
///
/// A file that is not `age` v1, or whose header is cut off before its MAC line, is [`EnvelopeError::Malformed`].
pub fn stanza_kinds(file: &[u8]) -> Result<Vec<StanzaKind>, EnvelopeError> {
    parse_header(file).filter(|header| header.complete).map(|header| header.kinds).ok_or(EnvelopeError::Malformed)
}

/// Durably replaces `identity.age` with `envelope`.
pub fn write_identity_envelope(lock: &StateDirLock, fs: &impl StoreFs, envelope: &[u8]) -> Result<(), WriteError> {
    durable_replace(lock, fs, &StateFileName::identity_envelope(), envelope)
}

/// Reads `identity.age`, refusing a file longer than [`MAX_IDENTITY_ENVELOPE_LEN`].
pub fn read_identity_envelope(lock: &StateDirLock, fs: &impl StoreFs) -> Result<Vec<u8>, ReadError> {
    read_state_file(lock, fs, &StateFileName::identity_envelope(), MAX_IDENTITY_ENVELOPE_LEN as u64)
}

/// Refuses the first stanza that is neither X25519 nor `age`'s inert grease stanza.
fn check_x25519_only(kinds: &[StanzaKind]) -> Result<(), EnvelopeError> {
    kinds.iter().find(|kind| !kind.is_x25519_or_grease()).map_or(Ok(()), |kind| Err(EnvelopeError::UnexpectedStanza(kind.clone())))
}

/// Maps a sealed-file failure onto the envelope's errors. Plaintext longer than a secret text is not an identity.
fn map_open_error(error: OpenError) -> EnvelopeError {
    match error {
        OpenError::NotForThisIdentity => EnvelopeError::NotARecipient,
        OpenError::Malformed | OpenError::TooLarge { .. } => EnvelopeError::Malformed,
        OpenError::UnexpectedStanza => EnvelopeError::UnexpectedStanza(StanzaKind::Scrypt),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        iter,
        time::{Duration, Instant},
    };

    use proptest::prelude::*;
    use secrecy::SecretString;

    use super::*;
    use crate::{MAX_RECIPIENTS, OsFs, recipient::RecipientKey, test_dir::TestDir};

    /// A vault identity wrapped for `n` fresh recipients, with their identities.
    fn wrapped(n: usize) -> (VaultIdentity, Vec<RecipientIdentity>, Vec<u8>) {
        let vault = VaultIdentity::generate();
        let recipients: Vec<RecipientIdentity> = (0..n).map(|_| RecipientIdentity::generate()).collect();
        let set = RecipientSet::new(recipients.iter().map(RecipientIdentity::recipient_key)).unwrap();
        let envelope = wrap_identity(&vault, &set).unwrap();
        (vault, recipients, envelope)
    }

    /// An `age` passphrase file whose header asks for scrypt work factor `log_n`.
    ///
    /// The file is written with a tiny work factor and its header's work-factor argument is then raised, because
    /// writing it at the high factor would itself take seconds and a gigabyte. Any reader that started scrypt on it
    /// would spend that long before discovering the header MAC no longer matches.
    fn scrypt_file(log_n: u8) -> Vec<u8> {
        let mut recipient = age::scrypt::Recipient::new(SecretString::from("planted passphrase"));
        recipient.set_work_factor(2);
        let encryptor = age::Encryptor::with_recipients(iter::once(&recipient as &dyn age::Recipient)).unwrap();
        let mut writer = encryptor.wrap_output(Vec::new()).unwrap();
        std::io::Write::write_all(&mut writer, b"planted").unwrap();
        let file = writer.finish().unwrap();
        let line_end = 22 + file[22..].iter().position(|&b| b == b'\n').unwrap();
        assert!(file[22..line_end].starts_with(b"-> scrypt ") && file[..line_end].ends_with(b" 2"));
        [&file[..line_end - 1], log_n.to_string().as_bytes(), &file[line_end..]].concat()
    }

    /// `envelope` with an extra stanza line inserted just before its MAC line.
    fn with_stanza(envelope: &[u8], stanza: &[u8]) -> Vec<u8> {
        let mac = envelope.windows(5).position(|w| w == b"\n--- ").unwrap() + 1;
        [&envelope[..mac], stanza, &envelope[mac..]].concat()
    }

    #[test]
    fn every_recipient_unwraps_the_same_identity() {
        let (vault, recipients, envelope) = wrapped(2);
        recipients.iter().for_each(|recipient| {
            assert_eq!(unwrap_identity(&envelope, recipient).unwrap().public_key(), vault.public_key());
        });
    }

    #[test]
    fn an_unlisted_recipient_is_not_a_recipient() {
        let (_, _, envelope) = wrapped(2);
        assert_eq!(unwrap_identity(&envelope, &RecipientIdentity::generate()).unwrap_err(), EnvelopeError::NotARecipient);
    }

    #[test]
    fn stanza_kinds_lists_one_x25519_per_recipient_and_one_grease() {
        [2, 3, 7].into_iter().for_each(|n| {
            let (_, _, envelope) = wrapped(n);
            let kinds = stanza_kinds(&envelope).unwrap();
            assert_eq!(kinds.iter().filter(|kind| **kind == StanzaKind::X25519).count(), n);
            // age 0.12 adds exactly one grease stanza to every file without a passphrase stanza.
            assert_eq!(kinds.iter().filter(|kind| **kind == StanzaKind::Grease).count(), 1);
            assert_eq!(kinds.len(), n + 1, "{kinds:?}");
        });
    }

    #[test]
    fn a_full_recipient_set_fits_the_size_bound_and_unwraps() {
        let (vault, recipients, envelope) = wrapped(MAX_RECIPIENTS);
        assert!(envelope.len() < MAX_IDENTITY_ENVELOPE_LEN / 2, "{} bytes", envelope.len());
        let last = recipients.last().unwrap();
        assert_eq!(unwrap_identity(&envelope, last).unwrap().public_key(), vault.public_key());
    }

    #[test]
    fn plaintext_is_the_secret_text() {
        let (vault, recipients, envelope) = wrapped(2);
        let secret = open_as(recipients[0].as_age(), &envelope, 1024).unwrap();
        assert_eq!(secret.as_slice(), vault.secret_text().expose_secret().as_bytes());
        assert_eq!(secret.len(), SECRET_TEXT_LEN);
    }

    #[test]
    fn scrypt_file_is_refused_before_any_scrypt_work() {
        let file = scrypt_file(30);
        assert_eq!(stanza_kinds(&file).unwrap(), [StanzaKind::Scrypt]);
        let recipient = RecipientIdentity::generate();
        let started = Instant::now();
        let refused = unwrap_identity(&file, &recipient);
        let elapsed = started.elapsed();
        assert_eq!(refused.unwrap_err(), EnvelopeError::UnexpectedStanza(StanzaKind::Scrypt));
        assert!(elapsed < Duration::from_millis(100), "took {elapsed:?}");
    }

    #[test]
    fn a_scrypt_stanza_beside_x25519_is_refused() {
        let (_, recipients, envelope) = wrapped(2);
        let planted = with_stanza(&envelope, b"-> scrypt AAAAAAAAAAAAAAAAAAAAAA 30\nAAAA\n");
        assert_eq!(unwrap_identity(&planted, &recipients[0]).unwrap_err(), EnvelopeError::UnexpectedStanza(StanzaKind::Scrypt));
    }

    #[test]
    fn a_plugin_stanza_is_refused_by_name() {
        let (_, recipients, envelope) = wrapped(2);
        let planted = with_stanza(&envelope, b"-> piv-p256 AAAA\nAAAA\n");
        let other = StanzaKind::Other("piv-p256".to_owned());
        assert_eq!(unwrap_identity(&planted, &recipients[0]).unwrap_err(), EnvelopeError::UnexpectedStanza(other));
    }

    #[test]
    fn an_oversized_envelope_is_refused_unread() {
        let (_, recipients, envelope) = wrapped(2);
        let padded = [envelope.as_slice(), &vec![0; MAX_IDENTITY_ENVELOPE_LEN + 1 - envelope.len()]].concat();
        assert_eq!(unwrap_identity(&padded, &recipients[0]).unwrap_err(), EnvelopeError::TooLarge);
    }

    #[test]
    fn an_envelope_of_something_other_than_an_identity_is_malformed() {
        let recipients = [RecipientIdentity::generate(), RecipientIdentity::generate()];
        let keys = recipients.iter().map(RecipientIdentity::recipient_key).collect::<Vec<RecipientKey>>();
        [&b""[..], b"AGE-SECRET-KEY-1", &[b'A'; SECRET_TEXT_LEN], &[b'A'; SECRET_TEXT_LEN + 1]].iter().for_each(|plaintext| {
            let envelope = seal_to(keys.iter().map(RecipientKey::as_age), plaintext).unwrap();
            assert_eq!(unwrap_identity(&envelope, &recipients[0]).unwrap_err(), EnvelopeError::Malformed);
        });
    }

    #[test]
    fn non_age_input_is_malformed() {
        let recipient = RecipientIdentity::generate();
        [&b""[..], b"hello\n", b"age-encryption.org/v1\n", b"-----BEGIN AGE ENCRYPTED FILE-----\n"].iter().for_each(|input| {
            assert_eq!(stanza_kinds(input), Err(EnvelopeError::Malformed), "{input:?}");
            assert_eq!(unwrap_identity(input, &recipient).unwrap_err(), EnvelopeError::Malformed, "{input:?}");
        });
    }

    #[test]
    fn every_truncation_is_an_error() {
        let (_, recipients, envelope) = wrapped(2);
        (0..envelope.len()).for_each(|len| assert!(unwrap_identity(&envelope[..len], &recipients[0]).is_err(), "truncated to {len}"));
    }

    #[test]
    fn identity_envelope_round_trips_through_the_state_directory() {
        let dir = TestDir::new("envelope-rw");
        let lock = StateDirLock::acquire(dir.path()).unwrap();
        let (vault, recipients, envelope) = wrapped(2);
        write_identity_envelope(&lock, &OsFs, &envelope).unwrap();
        assert!(dir.path().join("identity.age").is_file());
        let read = read_identity_envelope(&lock, &OsFs).unwrap();
        assert_eq!(unwrap_identity(&read, &recipients[1]).unwrap().public_key(), vault.public_key());
    }

    #[test]
    fn an_oversized_identity_file_is_not_read() {
        let dir = TestDir::new("envelope-big");
        let lock = StateDirLock::acquire(dir.path()).unwrap();
        write_identity_envelope(&lock, &OsFs, &vec![0; MAX_IDENTITY_ENVELOPE_LEN + 1]).unwrap();
        assert!(matches!(read_identity_envelope(&lock, &OsFs), Err(ReadError::TooLarge { .. })));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn every_bit_flip_fails_to_unwrap(offset in any::<prop::sample::Index>(), bit in 0u8..8) {
            let (_, recipients, mut envelope) = wrapped(2);
            let at = offset.index(envelope.len());
            envelope[at] ^= 1 << bit;
            // The header MAC authenticates every stanza, age refuses non-canonical base64, and the payload is AEAD
            // protected, so a flip anywhere, even in another recipient's stanza, must fail.
            prop_assert!(unwrap_identity(&envelope, &recipients[0]).is_err(), "flip at {at} bit {bit} unwrapped");
        }
    }
}
