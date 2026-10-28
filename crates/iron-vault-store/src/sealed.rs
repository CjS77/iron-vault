//! Sealed files: binary `age` ciphertext encrypted to the vault public key (specification §3.10).
//!
//! [`seal`] and [`open`] are the only way the store encrypts and decrypts with an X25519 key, so `age` types and error
//! text stay inside this crate; the passphrase envelope's scrypt use lives in `passphrase`. Plaintext comes back in a
//! buffer that is cleared on drop (specification §3.11).

use std::{
    io::{self, Read, Write},
    iter,
};

use age::{DecryptError, Decryptor, Encryptor, x25519};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    stanza::parse_header,
    vault_identity::{VaultIdentity, VaultPublicKey},
};

/// Sealing failed. The cause is not carried: it could only come from `age`, whose text is not passed through.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SealError {
    /// `age` refused to encrypt to the key or to write the output.
    #[error("could not encrypt to the vault public key")]
    Encryption,
}

/// Opening a sealed file failed. No variant carries plaintext, key material or `age` error text.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OpenError {
    /// No stanza in the header unwraps with this vault identity.
    #[error("the file is not sealed to this vault identity")]
    NotForThisIdentity,
    /// The file is not a well-formed, authentic `age` file: truncated, altered, or not `age` at all.
    #[error("the sealed file is malformed or has been altered")]
    Malformed,
    /// The plaintext is longer than the caller's limit; reading stopped at the first byte past it.
    #[error("the sealed plaintext exceeds the {limit}-byte limit")]
    TooLarge {
        /// The `max_plaintext` that was exceeded.
        limit: usize,
    },
    /// The header holds a stanza other than X25519, such as a passphrase (scrypt) or plugin stanza.
    #[error("the sealed file has a stanza the vault identity does not accept")]
    UnexpectedStanza,
}

/// Encrypts `plaintext` to `key` as binary (unarmored) `age` output.
pub fn seal(key: &VaultPublicKey, plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
    seal_to(iter::once(key.as_age()), plaintext)
}

/// Encrypts `plaintext` as binary `age` output with one X25519 stanza per key in `keys`.
///
/// Taking only X25519 recipients means no caller can put a passphrase stanza beside them (specification §3.11).
pub(crate) fn seal_to<'a>(keys: impl Iterator<Item = &'a x25519::Recipient>, plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
    let encryptor = Encryptor::with_recipients(keys.map(|key| key as &dyn age::Recipient)).map_err(|_| SealError::Encryption)?;
    let mut writer = encryptor
        .wrap_output(Vec::with_capacity(plaintext.len()))
        .map_err(|_| SealError::Encryption)?;
    writer.write_all(plaintext).map_err(|_| SealError::Encryption)?;
    writer.finish().map_err(|_| SealError::Encryption)
}

/// Decrypts a sealed file with the vault identity, refusing plaintext longer than `max_plaintext` bytes.
///
/// The header is checked before any key work: a file with any stanza other than X25519 is refused with
/// [`OpenError::UnexpectedStanza`], so a planted passphrase file cannot start an scrypt run on the record path. Only
/// the X25519 identity is ever offered to `age`, so even a header this check missed could not run scrypt or a plugin.
pub fn open(identity: &VaultIdentity, ciphertext: &[u8], max_plaintext: usize) -> Result<Zeroizing<Vec<u8>>, OpenError> {
    open_as(identity.as_age(), ciphertext, max_plaintext)
}

/// [`open`] with any X25519 identity, under the same header check and plaintext bound.
pub(crate) fn open_as(identity: &x25519::Identity, ciphertext: &[u8], max_plaintext: usize) -> Result<Zeroizing<Vec<u8>>, OpenError> {
    check_stanzas(ciphertext)?;
    let decryptor = Decryptor::new_buffered(ciphertext).map_err(map_decrypt_error)?;
    if decryptor.is_scrypt() {
        return Err(OpenError::UnexpectedStanza);
    }
    let reader = decryptor
        .decrypt(iter::once(identity as &dyn age::Identity))
        .map_err(map_decrypt_error)?;
    read_bounded(reader, max_plaintext, ciphertext.len())
}

/// Refuses a header with any stanza other than X25519 or `age`'s grease stanza.
///
/// A file that is not `age` v1 at all passes here and is refused by `age` as malformed.
fn check_stanzas(ciphertext: &[u8]) -> Result<(), OpenError> {
    parse_header(ciphertext)
        .is_none_or(|header| header.kinds.iter().all(|kind| kind.is_x25519_or_grease()))
        .then_some(())
        .ok_or(OpenError::UnexpectedStanza)
}

/// Maps `age`'s decryption errors onto [`OpenError`] without keeping their text.
fn map_decrypt_error(error: DecryptError) -> OpenError {
    match error {
        DecryptError::NoMatchingKeys => OpenError::NotForThisIdentity,
        // Work-factor errors come only from scrypt stanzas, which `check_stanzas` refuses first.
        DecryptError::ExcessiveWork { .. } => OpenError::UnexpectedStanza,
        _ => OpenError::Malformed,
    }
}

/// Reads at most `max + 1` bytes into a buffer that is cleared on drop, and refuses the plaintext if it got them all.
///
/// The buffer is sized up front from the ciphertext length, which always exceeds the plaintext length, so it never
/// reallocates and leaves no uncleared copy behind.
pub(crate) fn read_bounded(reader: impl Read, max: usize, ciphertext_len: usize) -> Result<Zeroizing<Vec<u8>>, OpenError> {
    let limit = max.saturating_add(1);
    let mut plaintext = Zeroizing::new(Vec::with_capacity(limit.min(ciphertext_len)));
    reader
        .take(u64::try_from(limit).unwrap_or(u64::MAX))
        .read_to_end(&mut plaintext)
        .map_err(|_: io::Error| OpenError::Malformed)?;
    if plaintext.len() > max {
        return Err(OpenError::TooLarge { limit: max });
    }
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use secrecy::SecretString;

    use super::*;

    const LIMIT: usize = 1 << 20;

    fn sealed(plaintext: &[u8]) -> (VaultIdentity, Vec<u8>) {
        let identity = VaultIdentity::generate();
        let ciphertext = seal(&identity.public_key(), plaintext).unwrap();
        (identity, ciphertext)
    }

    /// The offset of the first payload byte: just past the header's `---` MAC line.
    fn payload_start(ciphertext: &[u8]) -> usize {
        let mac = ciphertext.windows(5).position(|w| w == b"\n--- ").unwrap() + 1;
        mac + ciphertext[mac..].iter().position(|&b| b == b'\n').unwrap() + 1
    }

    /// A passphrase file made with a tiny work factor so the test stays fast.
    fn scrypt_file() -> Vec<u8> {
        let mut recipient = age::scrypt::Recipient::new(SecretString::from("planted passphrase"));
        recipient.set_work_factor(2);
        let encryptor = Encryptor::with_recipients(iter::once(&recipient as &dyn age::Recipient)).unwrap();
        let mut writer = encryptor.wrap_output(Vec::new()).unwrap();
        writer.write_all(b"planted").unwrap();
        writer.finish().unwrap()
    }

    /// `ciphertext` with an extra stanza line inserted just before its MAC line.
    fn with_stanza(ciphertext: &[u8], stanza: &[u8]) -> Vec<u8> {
        let mac = ciphertext.windows(5).position(|w| w == b"\n--- ").unwrap() + 1;
        [&ciphertext[..mac], stanza, &ciphertext[mac..]].concat()
    }

    #[test]
    fn seal_then_open_round_trips() {
        [&b""[..], b"x", b"sk-live-0123456789", &[7u8; 200_000]]
            .iter()
            .for_each(|plaintext| {
                let (identity, ciphertext) = sealed(plaintext);
                assert_eq!(open(&identity, &ciphertext, LIMIT).unwrap().as_slice(), *plaintext);
            });
    }

    #[test]
    fn sealed_output_is_binary_not_armored() {
        let (_, ciphertext) = sealed(b"secret");
        assert!(ciphertext.starts_with(b"age-encryption.org/v1\n"));
        assert!(!ciphertext.windows(5).any(|w| w == b"BEGIN"));
    }

    #[test]
    fn another_identity_is_refused() {
        let (_, ciphertext) = sealed(b"secret");
        assert_eq!(
            open(&VaultIdentity::generate(), &ciphertext, LIMIT),
            Err(OpenError::NotForThisIdentity)
        );
    }

    #[test]
    fn plaintext_at_the_limit_opens_and_one_byte_over_is_too_large() {
        let (identity, ciphertext) = sealed(&[1u8; 100]);
        assert_eq!(open(&identity, &ciphertext, 100).unwrap().len(), 100);
        assert_eq!(open(&identity, &ciphertext, 99), Err(OpenError::TooLarge { limit: 99 }));
        assert_eq!(open(&identity, &ciphertext, 0), Err(OpenError::TooLarge { limit: 0 }));
    }

    #[test]
    fn too_large_is_reported_before_a_later_corrupt_chunk() {
        // age chunks are 64 KiB; corrupt the last chunk and set the limit inside the first.
        let (identity, mut ciphertext) = sealed(&[3u8; 200_000]);
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 1;
        assert_eq!(open(&identity, &ciphertext, 1000), Err(OpenError::TooLarge { limit: 1000 }));
    }

    #[test]
    fn scrypt_file_is_an_unexpected_stanza() {
        assert_eq!(
            open(&VaultIdentity::generate(), &scrypt_file(), LIMIT),
            Err(OpenError::UnexpectedStanza)
        );
    }

    #[test]
    fn plugin_stanza_is_an_unexpected_stanza() {
        let (identity, ciphertext) = sealed(b"secret");
        let planted = with_stanza(&ciphertext, b"-> piv-p256 AAAA\nAAAA\n");
        assert_eq!(open(&identity, &planted, LIMIT), Err(OpenError::UnexpectedStanza));
    }

    #[test]
    fn extra_x25519_stanza_is_malformed_not_unexpected() {
        // An added stanza of an accepted type fails the header MAC instead.
        let (identity, ciphertext) = sealed(b"secret");
        let planted = with_stanza(&ciphertext, b"-> X25519 AAAA\nAAAA\n");
        assert_eq!(open(&identity, &planted, LIMIT), Err(OpenError::Malformed));
    }

    #[test]
    fn non_age_input_is_malformed() {
        let identity = VaultIdentity::generate();
        [
            &b""[..],
            b"\n",
            b"hello",
            b"age-encryption.org/v1\n",
            b"-----BEGIN AGE ENCRYPTED FILE-----\n",
        ]
        .iter()
        .for_each(|input| assert_eq!(open(&identity, input, LIMIT), Err(OpenError::Malformed), "{input:?}"));
    }

    #[test]
    fn every_truncation_is_malformed() {
        let (identity, ciphertext) = sealed(b"a short credential record");
        (0..ciphertext.len()).for_each(|len| {
            assert_eq!(
                open(&identity, &ciphertext[..len], LIMIT),
                Err(OpenError::Malformed),
                "truncated to {len}"
            );
        });
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn payload_bit_flip_is_malformed(offset in any::<prop::sample::Index>(), bit in 0u8..8) {
            let (identity, mut ciphertext) = sealed(b"a short credential record");
            let start = payload_start(&ciphertext);
            let at = start + offset.index(ciphertext.len() - start);
            ciphertext[at] ^= 1 << bit;
            prop_assert_eq!(open(&identity, &ciphertext, LIMIT), Err(OpenError::Malformed));
        }

        #[test]
        fn header_bit_flip_never_opens(offset in any::<prop::sample::Index>(), bit in 0u8..8) {
            // A flip inside the X25519 stanza is indistinguishable from a file sealed to someone else, so the
            // header only promises a refusal, never plaintext.
            let (identity, mut ciphertext) = sealed(b"a short credential record");
            let at = offset.index(payload_start(&ciphertext));
            ciphertext[at] ^= 1 << bit;
            prop_assert!(open(&identity, &ciphertext, LIMIT).is_err());
        }
    }
}
