//! The vault identity and its public key (specification §3.10).
//!
//! The vault identity is the one `age` X25519 private key that opens every sealed file in the vault. It stays in
//! service memory while the vault is unlocked; this module never writes it anywhere. Wrapping it for recipients is a
//! separate concern.

use std::{cmp::Ordering, fmt, hash, str::FromStr};

use age::x25519;
use thiserror::Error;

/// The vault's generated `age` X25519 private key.
///
/// It has no `Display`, `Clone` or serialization so the key cannot leave service memory by accident, and its `Debug`
/// output shows only the public key. The key bytes are cleared when the value is dropped.
pub struct VaultIdentity {
    secret: x25519::Identity,
}

impl VaultIdentity {
    /// Generates a fresh vault identity from the operating system's random source.
    pub fn generate() -> Self {
        Self { secret: x25519::Identity::generate() }
    }

    /// The public half of this identity, which anything can be sealed to.
    pub fn public_key(&self) -> VaultPublicKey {
        VaultPublicKey::from_recipient(self.secret.to_public())
    }

    /// The `age` identity, for decryption inside this crate only.
    pub(crate) fn as_age(&self) -> &x25519::Identity {
        &self.secret
    }
}

impl fmt::Debug for VaultIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultIdentity").field("public_key", &self.public_key()).finish_non_exhaustive()
    }
}

/// The public half of the vault identity, written as an `age1…` string.
///
/// Safe to log. Two keys are equal when their canonical lowercase encodings are equal, and they order by that
/// encoding so that any list of keys written to disk sorts deterministically.
#[derive(Clone)]
pub struct VaultPublicKey {
    encoded: String,
    recipient: x25519::Recipient,
}

impl VaultPublicKey {
    fn from_recipient(recipient: x25519::Recipient) -> Self {
        Self { encoded: recipient.to_string(), recipient }
    }

    /// The `age` recipient, for encryption inside this crate only.
    pub(crate) fn as_age(&self) -> &x25519::Recipient {
        &self.recipient
    }
}

/// A string that is not an `age1…` X25519 public key.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("not an age X25519 public key")]
pub struct ParseVaultPublicKeyError;

impl FromStr for VaultPublicKey {
    type Err = ParseVaultPublicKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<x25519::Recipient>().map(Self::from_recipient).map_err(|_| ParseVaultPublicKeyError)
    }
}

impl fmt::Display for VaultPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.encoded)
    }
}

impl fmt::Debug for VaultPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("VaultPublicKey").field(&self.encoded).finish()
    }
}

impl PartialEq for VaultPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.encoded == other.encoded
    }
}

impl Eq for VaultPublicKey {}

impl PartialOrd for VaultPublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for VaultPublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.encoded.cmp(&other.encoded)
    }
}

impl hash::Hash for VaultPublicKey {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.encoded.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

    #[test]
    fn public_key_round_trips_through_its_string() {
        let key = VaultIdentity::generate().public_key();
        let text = key.to_string();
        assert!(text.starts_with("age1"));
        assert_eq!(text.parse::<VaultPublicKey>(), Ok(key));
    }

    #[test]
    fn uppercase_encoding_parses_to_the_same_key() {
        let key = VaultIdentity::generate().public_key();
        assert_eq!(key.to_string().to_uppercase().parse::<VaultPublicKey>(), Ok(key));
    }

    #[test]
    fn rejects_strings_that_are_not_public_keys() {
        let secret = VaultIdentity::generate().secret.to_string();
        ["", "age1", "not a key", secret.expose_secret()]
            .iter()
            .for_each(|s| assert_eq!(s.parse::<VaultPublicKey>(), Err(ParseVaultPublicKeyError), "{s:?} parsed"));
    }

    #[test]
    fn keys_order_by_their_encoding() {
        let mut keys: Vec<VaultPublicKey> = (0..8).map(|_| VaultIdentity::generate().public_key()).collect();
        keys.sort();
        assert!(keys.windows(2).all(|w| w[0].to_string() < w[1].to_string()));
    }

    #[test]
    fn debug_shows_no_part_of_the_secret_key() {
        let identity = VaultIdentity::generate();
        let debug = format!("{identity:?} {identity:#?}");
        let secret = identity.secret.to_string();
        let secret = secret.expose_secret();
        let data = secret.trim_start_matches("AGE-SECRET-KEY-1");
        assert!(!debug.to_uppercase().contains("AGE-SECRET-KEY"));
        // Any eight-character run of the key's data part would be a partial leak.
        let chars: Vec<char> = data.chars().collect();
        assert!(chars.windows(8).map(String::from_iter).all(|part| !debug.to_uppercase().contains(&part)));
        assert!(debug.contains(&identity.public_key().to_string()));
    }
}
