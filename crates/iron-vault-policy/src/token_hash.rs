//! The stored form of a caller token (spec §3.3, §3.4).

use std::fmt;
use std::str::FromStr;

use blake2::{Blake2b256, Digest};
use serde::Deserialize;
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::CallerToken;

/// The text that starts every stored token hash and names its algorithm.
pub const TOKEN_HASH_PREFIX: &str = "blake2b:";

/// Digest length in bytes: BLAKE2b with a 256-bit output.
///
/// [`TokenHash::of`] hashes a caller token with BLAKE2b-256 into exactly this many bytes, written as
/// `2 * TOKEN_DIGEST_LEN` lowercase hex digits. 256 bits leaves no practical preimage or collision attack against a
/// high-entropy token while keeping the configuration line short.
pub const TOKEN_DIGEST_LEN: usize = 32;

/// A BLAKE2b-256 digest of a caller token, written `blake2b:` followed by 64 lowercase hex digits.
///
/// Only the digest is ever held; the plaintext token never enters configuration. One spelling per digest (lowercase
/// only) means two configurations that grant the same token compare equal as text and as values.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct TokenHash([u8; TOKEN_DIGEST_LEN]);

/// Why a token hash was rejected.
///
/// No variant carries the rejected text: an operator who pastes a plaintext token where its hash belongs must not
/// have the token copied into an error message or log.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TokenHashError {
    /// The value does not start with `blake2b:`.
    #[error("token hash must start with \"{TOKEN_HASH_PREFIX}\"")]
    MissingPrefix,
    /// The digest after the prefix has the wrong number of characters.
    #[error("token hash digest is {len} characters long; it must be {} lowercase hex digits", 2 * TOKEN_DIGEST_LEN)]
    WrongLength {
        /// Length of the digest text in bytes.
        len: usize,
    },
    /// The digest contains a character other than `0-9` or `a-f`.
    #[error("token hash digest has a character other than 0-9 or a-f at byte {position}")]
    NotLowercaseHex {
        /// Byte offset of the offending character within the digest text.
        position: usize,
    },
}

impl TokenHash {
    /// The unkeyed BLAKE2b-256 digest of the token's full text, prefix included.
    ///
    /// No key or salt is needed: a caller token carries 256 random bits, so its digest cannot be reversed by guessing.
    pub fn of(token: &CallerToken) -> Self {
        Self(Blake2b256::digest(token.text().as_bytes()).into())
    }

    /// Whether `token` hashes to this digest, compared in constant time so that response timing does not reveal how
    /// many leading bytes of a guess's digest were right (spec §3.4).
    pub fn matches(&self, token: &CallerToken) -> bool {
        self.0.as_slice().ct_eq(Self::of(token).0.as_slice()).into()
    }

    /// The raw digest bytes.
    pub fn digest(&self) -> &[u8; TOKEN_DIGEST_LEN] {
        &self.0
    }
}

/// The value of one lowercase hex digit, or `None` for anything else, including uppercase.
fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// Decodes exactly [`TOKEN_DIGEST_LEN`] bytes of lowercase hex.
fn decode_digest(hex: &str) -> Result<[u8; TOKEN_DIGEST_LEN], TokenHashError> {
    if hex.len() != 2 * TOKEN_DIGEST_LEN {
        return Err(TokenHashError::WrongLength { len: hex.len() });
    }
    let nibbles = hex
        .bytes()
        .enumerate()
        .map(|(position, b)| hex_value(b).ok_or(TokenHashError::NotLowercaseHex { position }))
        .collect::<Result<Vec<u8>, _>>()?;
    let mut digest = [0u8; TOKEN_DIGEST_LEN];
    digest
        .iter_mut()
        .zip(nibbles.as_chunks::<2>().0)
        .for_each(|(byte, [high, low])| *byte = (high << 4) | low);
    Ok(digest)
}

impl TryFrom<&str> for TokenHash {
    type Error = TokenHashError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let hex = s.strip_prefix(TOKEN_HASH_PREFIX).ok_or(TokenHashError::MissingPrefix)?;
        decode_digest(hex).map(Self)
    }
}

impl TryFrom<String> for TokenHash {
    type Error = TokenHashError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::try_from(s.as_str())
    }
}

impl FromStr for TokenHash {
    type Err = TokenHashError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

impl fmt::Display for TokenHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(TOKEN_HASH_PREFIX)?;
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caller_token::tests::{KAT_BYTES, KAT_TOKEN};

    /// BLAKE2b-256 of `KAT_TOKEN`'s text, computed independently with `printf '%s' "$KAT_TOKEN" | b2sum -l 256` and
    /// confirmed with Python's `hashlib.blake2b(token, digest_size=32)`.
    const KAT_HASH: &str = "blake2b:1ab69d873c36df86f5479ae9070aedf3c0ee702e851610d232b9421921615ed0";

    const DIGEST: &str = "0123456789abcdef00112233445566778899aabbccddeeff0f1e2d3c4b5a6978";

    fn hash() -> String {
        format!("blake2b:{DIGEST}")
    }

    #[test]
    fn valid_hash_round_trips() {
        let h: TokenHash = hash().parse().unwrap();
        assert_eq!(h.digest()[..4], [0x01, 0x23, 0x45, 0x67]);
        assert_eq!(h.digest()[31], 0x78);
        assert_eq!(h.to_string(), hash());
    }

    #[test]
    fn wrong_prefix_is_rejected() {
        [
            DIGEST.to_owned(),
            format!("sha256:{DIGEST}"),
            format!("BLAKE2B:{DIGEST}"),
            format!("blake2b {DIGEST}"),
        ]
        .iter()
        .for_each(|s| assert_eq!(s.parse::<TokenHash>(), Err(TokenHashError::MissingPrefix), "{s}"));
    }

    #[test]
    fn uppercase_is_rejected() {
        let upper = format!("blake2b:{}", DIGEST.to_ascii_uppercase());
        assert_eq!(upper.parse::<TokenHash>(), Err(TokenHashError::NotLowercaseHex { position: 10 }));
    }

    #[test]
    fn non_hex_is_rejected() {
        let bad = format!("blake2b:{}g", &DIGEST[1..]);
        assert_eq!(bad.parse::<TokenHash>(), Err(TokenHashError::NotLowercaseHex { position: 63 }));
        assert!(format!("blake2b:{}é", &DIGEST[2..]).parse::<TokenHash>().is_err());
    }

    #[test]
    fn wrong_length_is_rejected() {
        [
            "blake2b:",
            "blake2b:...",
            &format!("blake2b:{}", &DIGEST[1..]),
            &format!("blake2b:{DIGEST}00"),
        ]
        .iter()
        .for_each(|s| assert!(matches!(s.parse::<TokenHash>(), Err(TokenHashError::WrongLength { .. })), "{s}"));
        let doubled = format!("blake2b:{DIGEST}{DIGEST}");
        assert_eq!(doubled.parse::<TokenHash>(), Err(TokenHashError::WrongLength { len: 128 }));
    }

    #[test]
    fn errors_never_echo_the_value() {
        let secret = "ivt_secret_plaintext_token";
        [secret.to_owned(), format!("blake2b:{secret}")].iter().for_each(|s| {
            let message = s.parse::<TokenHash>().unwrap_err().to_string();
            assert!(!message.contains("secret"), "{message}");
        });
    }

    #[test]
    fn known_token_gives_the_known_hash() {
        let token = CallerToken::from_bytes(KAT_BYTES);
        assert_eq!(TokenHash::of(&token).to_string(), KAT_HASH);
        assert_eq!(
            TokenHash::of(&CallerToken::parse(KAT_TOKEN.as_bytes()).unwrap()).to_string(),
            KAT_HASH
        );
    }

    #[test]
    fn display_parses_back() {
        let hash = TokenHash::of(&CallerToken::from_bytes(KAT_BYTES));
        assert_eq!(hash.to_string().parse::<TokenHash>().unwrap(), hash);
    }

    #[test]
    fn a_token_matches_its_own_hash() {
        let token = CallerToken::from_bytes(KAT_BYTES);
        assert!(TokenHash::of(&token).matches(&token));
        assert!(KAT_HASH.parse::<TokenHash>().unwrap().matches(&token));
    }

    #[test]
    fn a_hash_differing_in_any_one_byte_does_not_match() {
        let token = CallerToken::from_bytes(KAT_BYTES);
        let own = TokenHash::of(&token);
        (0..TOKEN_DIGEST_LEN).for_each(|position| {
            let mut digest = *own.digest();
            digest[position] ^= 0x01;
            assert!(!TokenHash(digest).matches(&token), "byte {position}");
        });
    }

    #[test]
    fn a_different_token_does_not_match() {
        let other = CallerToken::from_bytes([0xff; TOKEN_DIGEST_LEN]);
        assert!(!KAT_HASH.parse::<TokenHash>().unwrap().matches(&other));
    }
}
