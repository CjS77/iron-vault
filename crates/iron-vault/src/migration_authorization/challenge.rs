//! The migration challenge and its binding digest (design/migration-authorization.md, "Migration challenge").

use std::fmt;

use blake2::{Blake2b256, Digest, digest::CustomizedInit};
use iron_vault_store::VaultId;
use subtle::ConstantTimeEq;
use tokio::time::{Duration, Instant};

use super::MigrationOperation;

/// How long a challenge stays valid after it is issued. It covers the vault passphrase prompt, the scrypt check and,
/// for `export`, the export passphrase prompts that follow before the export starts.
pub const CHALLENGE_LIFETIME: Duration = Duration::from_secs(120);

/// The BLAKE2b personalization of the binding digest, which separates it from every other BLAKE2b use in the service.
/// Its `v1` versions the canonical encoding: a change to the layout takes a new persona.
const BINDING_PERSONA: &[u8] = b"iv-migration-v1";

/// The BLAKE2b-256 digest of a migration challenge's canonical encoding (glossary: *Binding digest*).
///
/// The service takes a challenge out of its pending slot only by this digest, so a proof for one pending migration
/// matches no other.
#[derive(Clone, Copy, Debug)]
pub struct BindingDigest([u8; 32]);

impl BindingDigest {
    /// The digest's 32 bytes, which a signing source-owner method signs.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl PartialEq for BindingDigest {
    /// Constant time, as the approval digests compare, so no comparison leaks how much of a digest matched.
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for BindingDigest {}

/// The short-lived, single-use value the service issues just before it asks for a source-owner proof (glossary:
/// *Migration challenge*).
///
/// It has no `Clone`, so a challenge taken out of the pending slot exists exactly once. Its `Debug` shows only the
/// operation and the expiry.
pub struct MigrationChallenge {
    vault_id: VaultId,
    operation: MigrationOperation,
    nonce: [u8; 32],
    /// The service's clock origin, which the encoding measures both times from.
    origin: Instant,
    issued_at: Instant,
    expires_at: Instant,
}

impl MigrationChallenge {
    /// A challenge issued at `now`, expiring [`CHALLENGE_LIFETIME`] later.
    pub(super) fn new(vault_id: VaultId, operation: MigrationOperation, nonce: [u8; 32], origin: Instant, now: Instant) -> Self {
        Self {
            vault_id,
            operation,
            nonce,
            origin,
            issued_at: now,
            expires_at: now + CHALLENGE_LIFETIME,
        }
    }

    /// The binding digest: BLAKE2b-256, personalized with `iv-migration-v1`, of the canonical encoding.
    pub fn binding_digest(&self) -> BindingDigest {
        BindingDigest(
            Blake2b256::new_customized(BINDING_PERSONA)
                .chain_update(self.canonical_encoding())
                .finalize()
                .into(),
        )
    }

    /// The vault the challenge binds to.
    pub fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    /// The operation the challenge binds to, with its destination recipient when there is one.
    pub fn operation(&self) -> &MigrationOperation {
        &self.operation
    }

    /// The first instant at which the challenge is expired.
    pub fn expires_at(&self) -> Instant {
        self.expires_at
    }

    /// Whether the challenge is expired at `now`. It is expired from `expires_at` on, so the lifetime is never exceeded.
    pub fn is_expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }

    /// The encoding the digest covers, in the conventions of record payload v1: the vault ID's 16 bytes, the operation
    /// tag, the destination as a `u64` big-endian length and its `age1…` text (zero length for export), the nonce,
    /// then the issue time and the expiry as `u64` big-endian milliseconds from the clock origin.
    pub(super) fn canonical_encoding(&self) -> Vec<u8> {
        let destination = self.operation.destination().map(ToString::to_string).unwrap_or_default();
        let length = u64::try_from(destination.len()).unwrap_or(u64::MAX);
        [
            self.vault_id.as_bytes().as_slice(),
            &[self.operation.tag()],
            &length.to_be_bytes(),
            destination.as_bytes(),
            &self.nonce,
            &self.millis_since_origin(self.issued_at).to_be_bytes(),
            &self.millis_since_origin(self.expires_at).to_be_bytes(),
        ]
        .concat()
    }

    /// Whole milliseconds from the clock origin to `instant`; zero before it, and saturating far past it.
    fn millis_since_origin(&self, instant: Instant) -> u64 {
        u64::try_from(instant.saturating_duration_since(self.origin).as_millis()).unwrap_or(u64::MAX)
    }
}

impl fmt::Debug for MigrationChallenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MigrationChallenge")
            .field("operation", &self.operation)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}
