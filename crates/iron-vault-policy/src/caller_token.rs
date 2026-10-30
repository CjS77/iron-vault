//! The caller token itself: its text format, generation from a cryptographic source, and parsing (spec §3.4).

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_core::CryptoRngCore;
use secrecy::zeroize::Zeroizing;
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;

/// The text that starts every caller token, so secret scanners and the owner can recognize one.
pub const CALLER_TOKEN_PREFIX: &str = "ivt_";

/// Random bytes in a caller token: 256 bits, beyond any online or offline guessing.
pub const CALLER_TOKEN_BYTES: usize = 32;

/// Base64url characters, unpadded, that encode [`CALLER_TOKEN_BYTES`] bytes.
const ENCODED_LEN: usize = CALLER_TOKEN_BYTES.div_ceil(3) * 4 - 1;

/// Length in bytes of a whole caller token's text.
pub const CALLER_TOKEN_LEN: usize = CALLER_TOKEN_PREFIX.len() + ENCODED_LEN;

/// A caller token: `ivt_` followed by 43 base64url characters without padding, which encode 32 random bytes.
///
/// The service generates a token with [`CallerToken::from_random`], shows it to the owner once through
/// [`CallerToken::expose_once`], and stores only its [`TokenHash`](crate::TokenHash). A caller presents it on each
/// request, where [`CallerToken::parse`] reads it back.
///
/// The token is secret-bearing: its text lives in a [`SecretString`], it has no `Clone`, `Display` or serde, and its
/// `Debug` shows nothing of it.
pub struct CallerToken(SecretString);

/// Why a presented caller token was rejected.
///
/// No variant carries the presented bytes: a near-miss token is still a secret, or another credential sent by mistake.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CallerTokenError {
    /// The value does not start with `ivt_`.
    #[error("caller token must start with \"{CALLER_TOKEN_PREFIX}\"")]
    MissingPrefix,
    /// The value has the wrong number of bytes.
    #[error("caller token is {len} bytes long; it must be {CALLER_TOKEN_LEN}")]
    WrongLength {
        /// Length of the presented value in bytes.
        len: usize,
    },
    /// A byte after the prefix is not in the base64url alphabet `A-Z a-z 0-9 - _`; padding is not allowed.
    #[error("caller token has a byte outside the base64url alphabet at byte {position}")]
    BadCharacter {
        /// Byte offset of the offending byte within the whole token.
        position: usize,
    },
    /// The last character sets bits beyond the 256 the token encodes, so it is not the canonical encoding of any
    /// 32 bytes. 43 base64url characters carry 258 bits; the last must be one of `AEIMQUYcgkosw048`.
    #[error("caller token's last character is not a canonical base64url ending")]
    NonCanonicalEnding,
}

impl CallerToken {
    /// Draws [`CALLER_TOKEN_BYTES`] bytes from `rng` and encodes them as a new token.
    ///
    /// The `CryptoRngCore` bound makes the type system demand a cryptographic source. The bytes are drawn with
    /// `try_fill_bytes` because `fill_bytes` panics when an operating-system source fails, and a failed draw must be
    /// an error, never a crash or a weaker token.
    pub fn from_random<R: CryptoRngCore + ?Sized>(rng: &mut R) -> Result<Self, rand_core::Error> {
        let mut bytes = Zeroizing::new([0u8; CALLER_TOKEN_BYTES]);
        rng.try_fill_bytes(bytes.as_mut_slice())?;
        Ok(Self::encode(&bytes))
    }

    /// Encodes the given bytes as a token.
    ///
    /// This promises no randomness: the caller is responsible for the bytes being fresh and unpredictable. New tokens
    /// come from [`CallerToken::from_random`].
    pub fn from_bytes(bytes: [u8; CALLER_TOKEN_BYTES]) -> Self {
        Self::encode(&Zeroizing::new(bytes))
    }

    /// Encodes bytes the caller already holds in a wiped buffer, so neither constructor copies them out of it.
    fn encode(bytes: &[u8; CALLER_TOKEN_BYTES]) -> Self {
        // Sized exactly, so neither encoding nor the conversion to a boxed `str` reallocates and strands a copy.
        let mut text = String::with_capacity(CALLER_TOKEN_LEN);
        text.push_str(CALLER_TOKEN_PREFIX);
        URL_SAFE_NO_PAD.encode_string(bytes.as_slice(), &mut text);
        Self(SecretString::from(text))
    }

    /// Reads a presented token, checking its prefix, its length, that every following byte is base64url, and that the
    /// last character is one of `AEIMQUYcgkosw048`.
    ///
    /// The last check keeps the text canonical: 43 base64url characters carry 258 bits, so the last character's low
    /// two bits must be zero for the text to be the one encoding of its 32 bytes.
    pub fn parse(presented: &[u8]) -> Result<Self, CallerTokenError> {
        let encoded = presented
            .strip_prefix(CALLER_TOKEN_PREFIX.as_bytes())
            .ok_or(CallerTokenError::MissingPrefix)?;
        if presented.len() != CALLER_TOKEN_LEN {
            return Err(CallerTokenError::WrongLength { len: presented.len() });
        }
        if let Some(offset) = encoded.iter().position(|b| !is_base64url(*b)) {
            return Err(CallerTokenError::BadCharacter {
                position: CALLER_TOKEN_PREFIX.len() + offset,
            });
        }
        if !encoded.last().is_some_and(|b| is_canonical_ending(*b)) {
            return Err(CallerTokenError::NonCanonicalEnding);
        }
        // Every byte is ASCII by now, so this conversion cannot fail. The error is still mapped rather than unwrapped
        // because library code never panics. It borrows instead of copying.
        let text = std::str::from_utf8(presented).map_err(|e| CallerTokenError::BadCharacter { position: e.valid_up_to() })?;
        Ok(Self(SecretString::from(text)))
    }

    /// Hands the token's text over for its single display at enrollment, consuming the token.
    pub fn expose_once(self) -> SecretString {
        self.0
    }

    /// The token's full text, prefix included: the input to its hash.
    pub(crate) fn text(&self) -> &str {
        self.0.expose_secret()
    }
}

/// Whether `b` is in the URL-safe base64 alphabet (RFC 4648 §5).
fn is_base64url(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

/// Whether `b` is a base64url character whose alphabet index is divisible by 4, so its low two bits are zero.
fn is_canonical_ending(b: u8) -> bool {
    b"AEIMQUYcgkosw048".contains(&b)
}

impl fmt::Debug for CallerToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CallerToken").finish_non_exhaustive()
    }
}

#[cfg(test)]
pub(crate) mod tests;
