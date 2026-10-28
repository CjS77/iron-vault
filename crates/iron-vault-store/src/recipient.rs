//! Recipients of the identity envelope: their public keys, the private keys that unwrap it, and the set it is wrapped
//! for (specification §3.10, §3.11).

use std::{cmp::Ordering, collections::BTreeSet, fmt, hash, str::FromStr};

use age::x25519;
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;

/// The most recipient keys an identity envelope is wrapped for.
///
/// Enough for every planned recipient (TPM, passphrase, recovery, hardware keys) many times over, and small enough
/// that a full envelope stays well inside [`crate::MAX_IDENTITY_ENVELOPE_LEN`].
pub const MAX_RECIPIENTS: usize = 64;

/// An X25519 public key, written as an `age1…` string, listed as a recipient of the identity envelope.
///
/// Safe to log. Keys compare and order by their canonical lowercase encoding, so a [`RecipientSet`] iterates in a
/// deterministic order.
#[derive(Clone)]
pub struct RecipientKey {
    encoded: String,
    recipient: x25519::Recipient,
}

impl RecipientKey {
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
#[error("not an age X25519 recipient key")]
pub struct ParseRecipientKeyError;

impl FromStr for RecipientKey {
    type Err = ParseRecipientKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<x25519::Recipient>().map(Self::from_recipient).map_err(|_| ParseRecipientKeyError)
    }
}

impl fmt::Display for RecipientKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.encoded)
    }
}

impl fmt::Debug for RecipientKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RecipientKey").field(&self.encoded).finish()
    }
}

impl PartialEq for RecipientKey {
    fn eq(&self, other: &Self) -> bool {
        self.encoded == other.encoded
    }
}

impl Eq for RecipientKey {}

impl PartialOrd for RecipientKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RecipientKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.encoded.cmp(&other.encoded)
    }
}

impl hash::Hash for RecipientKey {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.encoded.hash(state);
    }
}

/// The X25519 private key matching a [`RecipientKey`], used only to unwrap the identity envelope.
///
/// It has no `Display`, `Clone` or serialization, its `Debug` shows only the recipient key, and the key bytes are cleared
/// when it is dropped.
pub struct RecipientIdentity {
    secret: x25519::Identity,
}

impl RecipientIdentity {
    /// Parses an `AGE-SECRET-KEY-1…` string. The text stays in the caller's [`SecretString`]; nothing here copies it.
    pub fn parse(text: &SecretString) -> Result<Self, ParseRecipientIdentityError> {
        text.expose_secret().parse().map(|secret| Self { secret }).map_err(|_| ParseRecipientIdentityError)
    }

    /// The public key this identity unwraps for.
    pub fn recipient_key(&self) -> RecipientKey {
        RecipientKey::from_recipient(self.secret.to_public())
    }

    /// The `age` identity, for decryption inside this crate only.
    pub(crate) fn as_age(&self) -> &x25519::Identity {
        &self.secret
    }

    /// A fresh identity from the operating system's random source.
    pub(crate) fn generate() -> Self {
        Self { secret: x25519::Identity::generate() }
    }

    /// The identity's `age` secret-key text, `AGE-SECRET-KEY-1…`, in a buffer cleared on drop; the passphrase
    /// envelope's plaintext.
    pub(crate) fn secret_text(&self) -> SecretString {
        self.secret.to_string()
    }

    /// The identity whose `age` secret-key text is `text`, or `None` when `text` is not one.
    ///
    /// `text` is borrowed from the caller's cleared buffer and parsed in place, so no uncleared copy of it is made here.
    pub(crate) fn from_secret_text(text: &[u8]) -> Option<Self> {
        let secret = std::str::from_utf8(text).ok()?.parse().ok()?;
        Some(Self { secret })
    }
}

impl fmt::Debug for RecipientIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecipientIdentity").field("recipient_key", &self.recipient_key()).finish_non_exhaustive()
    }
}

/// A string that is not an `age` X25519 secret key. The rejected text is not carried.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("not an age X25519 secret key")]
pub struct ParseRecipientIdentityError;

/// The recipient keys an identity envelope is wrapped for: at least two and at most [`MAX_RECIPIENTS`].
///
/// Two is the floor because every vault needs a second way in (specification §3.11); whether the two are independent
/// is for the caller that enrolls them to decide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientSet(BTreeSet<RecipientKey>);

/// Why a set of recipient keys cannot wrap an identity envelope.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RecipientSetError {
    /// Fewer than two distinct keys; repeated keys count once.
    #[error("an identity envelope needs at least two distinct recipient keys, got {count}")]
    TooFew {
        /// The number of distinct keys given.
        count: usize,
    },
    /// More than [`MAX_RECIPIENTS`] distinct keys.
    #[error("an identity envelope takes at most {MAX_RECIPIENTS} recipient keys, got {count}")]
    TooMany {
        /// The number of distinct keys given.
        count: usize,
    },
}

impl RecipientSet {
    /// The distinct keys of `keys`, if there are between two and [`MAX_RECIPIENTS`] of them.
    pub fn new(keys: impl IntoIterator<Item = RecipientKey>) -> Result<Self, RecipientSetError> {
        let keys: BTreeSet<RecipientKey> = keys.into_iter().collect();
        match keys.len() {
            count @ 0..2 => Err(RecipientSetError::TooFew { count }),
            count if count > MAX_RECIPIENTS => Err(RecipientSetError::TooMany { count }),
            _ => Ok(Self(keys)),
        }
    }

    /// The keys in their canonical order.
    pub fn iter(&self) -> impl Iterator<Item = &RecipientKey> {
        self.0.iter()
    }

    /// The number of keys, always at least two.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Always `false`: a recipient set has at least two keys.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Whether `key` is in the set.
    pub fn contains(&self, key: &RecipientKey) -> bool {
        self.0.contains(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(n: usize) -> Vec<RecipientKey> {
        (0..n).map(|_| RecipientIdentity::generate().recipient_key()).collect()
    }

    #[test]
    fn recipient_key_round_trips_through_its_string() {
        let key = RecipientIdentity::generate().recipient_key();
        assert!(key.to_string().starts_with("age1"));
        assert_eq!(key.to_string().parse::<RecipientKey>(), Ok(key.clone()));
        assert_eq!(key.to_string().to_uppercase().parse::<RecipientKey>(), Ok(key));
    }

    #[test]
    fn recipient_key_rejects_non_keys() {
        let secret = x25519::Identity::generate().to_string();
        ["", "age1", "not a key", secret.expose_secret()]
            .iter()
            .for_each(|s| assert_eq!(s.parse::<RecipientKey>(), Err(ParseRecipientKeyError), "{s:?} parsed"));
    }

    #[test]
    fn recipient_identity_parses_its_secret_text() {
        let secret = x25519::Identity::generate();
        let identity = RecipientIdentity::parse(&secret.to_string()).unwrap();
        assert_eq!(identity.recipient_key().to_string(), secret.to_public().to_string());
        ["", "age1qqqq", "AGE-SECRET-KEY-1"]
            .iter()
            .for_each(|s| assert_eq!(RecipientIdentity::parse(&SecretString::from(*s)).unwrap_err(), ParseRecipientIdentityError));
    }

    #[test]
    fn recipient_identity_debug_shows_no_secret() {
        let secret = x25519::Identity::generate().to_string();
        let identity = RecipientIdentity::parse(&secret).unwrap();
        let debug = format!("{identity:?} {identity:#?}").to_uppercase();
        let data: Vec<char> = secret.expose_secret().trim_start_matches("AGE-SECRET-KEY-1").chars().collect();
        assert!(!debug.contains("AGE-SECRET-KEY"));
        assert!(data.windows(8).map(String::from_iter).all(|part| !debug.contains(&part)));
        assert!(debug.contains(&identity.recipient_key().to_string().to_uppercase()));
    }

    #[test]
    fn a_set_needs_two_distinct_keys() {
        let [a, b] = <[RecipientKey; 2]>::try_from(keys(2)).unwrap();
        assert_eq!(RecipientSet::new([]), Err(RecipientSetError::TooFew { count: 0 }));
        assert_eq!(RecipientSet::new([a.clone()]), Err(RecipientSetError::TooFew { count: 1 }));
        assert_eq!(RecipientSet::new([a.clone(), a.clone()]), Err(RecipientSetError::TooFew { count: 1 }));
        let set = RecipientSet::new([b.clone(), a.clone(), b.clone()]).unwrap();
        assert_eq!(set.len(), 2);
        assert!(set.contains(&a) && set.contains(&b));
    }

    #[test]
    fn a_set_holds_at_most_the_maximum() {
        assert_eq!(RecipientSet::new(keys(MAX_RECIPIENTS)).map(|set| set.len()), Ok(MAX_RECIPIENTS));
        assert_eq!(RecipientSet::new(keys(MAX_RECIPIENTS + 1)), Err(RecipientSetError::TooMany { count: MAX_RECIPIENTS + 1 }));
    }

    #[test]
    fn a_set_iterates_in_key_order() {
        let set = RecipientSet::new(keys(8)).unwrap();
        let listed: Vec<String> = set.iter().map(RecipientKey::to_string).collect();
        assert!(listed.windows(2).all(|w| w[0] < w[1]));
    }
}
