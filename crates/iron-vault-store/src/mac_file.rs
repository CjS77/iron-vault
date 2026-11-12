//! The MAC'd file frame shared by the vault manifest, the approval state and the recipient inventory
//! ([spec §13](../../../design/iron-vault-specification.md#13-vault-structure-and-durable-writes),
//! [storage formats](../../../design/storage-formats.md#macd-file-frame)).
//!
//! `age` does not authenticate the sender, so anyone holding the vault public key could plant a control file sealed to
//! it. The frame adds a MAC keyed from the private vault identity over a clear header and the ciphertext, and checks it
//! before anything is decrypted. Every MAC'd file uses this one implementation, so a fix reaches all of them.
//!
//! ```text
//! 0       4         5                21                          end − 32     end
//! ┌───────┬─────────┬────────────────┬───────────────────────────┬────────────┐
//! │ magic │ version │ vault ID       │ payload, sealed to the    │ MAC        │
//! │ (4)   │ 01      │ (16, in clear) │ vault public key by age   │ (32)       │
//! └───────┴─────────┴────────────────┴───────────────────────────┴────────────┘
//! └────────── MAC input, after the file type's domain tag ───────┘
//!
//! open: size limit ──▶ magic and version ──▶ MAC (constant time) ──▶ vault ID ──▶ decrypt
//! ```

use blake2::Blake2bMac;
use blake2::digest::{KeyInit, Mac, consts::U32};
use zeroize::Zeroizing;

use crate::sealed::{self, OpenError, SealError};
use crate::vault_id::{VaultId, VaultIdError};
use crate::vault_identity::VaultIdentity;

/// The length of the clear header: magic (4), version (1) and vault ID (16), all covered by the MAC.
pub(crate) const HEADER_LEN: usize = 4 + 1 + 16;
/// The length of the trailing MAC.
pub(crate) const MAC_LEN: usize = 32;

/// Describes one MAC'd file type: what tells it from the others, and the errors of type `E` its frame failures are
/// reported as.
///
/// Each type has its own persona and domain tag, so a MAC from one never verifies another. No error carries key
/// material or MAC bytes.
pub(crate) struct MacFileKind<E> {
    /// The first bytes of the file, so a file of another type is never read as this one.
    pub magic: [u8; 4],
    /// The version this code writes and the only one it reads. It fixes the MAC construction.
    pub version: u8,
    /// The BLAKE2b personalization of the MAC key, which keeps it independent of other keys from the vault identity.
    pub persona: &'static [u8],
    /// Prefixed to the MAC input so a MAC under this key can never be mistaken for one over other data.
    pub domain_tag: &'static [u8],
    /// The largest file accepted, checked before any other work. It also bounds the decrypted payload.
    pub max_len: usize,
    /// The error for a file larger than `max_len`. Nothing else was read.
    pub too_large: E,
    /// The error for a file that ends inside the header or the MAC.
    pub truncated: E,
    /// The error for a file that does not start with `magic`.
    pub bad_magic: E,
    /// Builds the error for a file with a version other than `version`.
    pub unknown_version: fn(u8) -> E,
    /// The error for a MAC that does not match: the file was altered, or written by someone without this vault's
    /// identity.
    pub damaged: E,
    /// Builds the error for an authenticated header whose vault ID is not a random version 4 UUID.
    pub invalid_vault_id: fn(VaultIdError) -> E,
}

impl<E: Clone + From<OpenError>> MacFileKind<E> {
    /// Builds the file's bytes: the header, `payload` sealed to the vault public key, then the MAC.
    pub(crate) fn seal(&self, identity: &VaultIdentity, vault_id: VaultId, payload: &[u8]) -> Result<Vec<u8>, SealError> {
        let signed = [
            &self.magic[..],
            &[self.version],
            vault_id.as_bytes(),
            &sealed::seal(&identity.public_key(), payload)?,
        ]
        .concat();
        let tag = self.mac(&identity.derive_key(self.persona), &signed).finalize().into_bytes();
        Ok([&signed[..], &tag].concat())
    }

    /// Checks the size, header and MAC, in that order, then returns the header's vault ID and the decrypted payload.
    ///
    /// The caller decodes the payload and checks that it names the same vault.
    pub(crate) fn open(&self, identity: &VaultIdentity, file: &[u8]) -> Result<(VaultId, Zeroizing<Vec<u8>>), E> {
        if file.len() > self.max_len {
            return Err(self.too_large.clone());
        }
        let (signed, tag) = file
            .len()
            .checked_sub(MAC_LEN)
            .and_then(|at| file.split_at_checked(at))
            .ok_or_else(|| self.truncated.clone())?;
        let (header, ciphertext) = signed.split_first_chunk::<HEADER_LEN>().ok_or_else(|| self.truncated.clone())?;
        let vault_id = self.read_header(header)?;
        self.mac(&identity.derive_key(self.persona), signed)
            .verify_slice(tag)
            .map_err(|_| self.damaged.clone())?;
        Ok((
            VaultId::from_bytes(vault_id).map_err(self.invalid_vault_id)?,
            sealed::open(identity, ciphertext, self.max_len)?,
        ))
    }

    /// Returns the header's vault ID, read without the MAC check and so unverified.
    ///
    /// It can name which vault a file claims to belong to while the vault is locked, and must never be trusted for
    /// anything else.
    pub(crate) fn unverified_vault_id(&self, file: &[u8]) -> Result<VaultId, E> {
        let header = file.first_chunk::<HEADER_LEN>().ok_or_else(|| self.truncated.clone())?;
        VaultId::from_bytes(self.read_header(header)?).map_err(self.invalid_vault_id)
    }

    /// Checks the header's magic and version, then returns its vault ID bytes.
    ///
    /// The version is read before the MAC is checked because it decides how the MAC is computed. The ID is not
    /// trusted until the MAC passes.
    fn read_header(&self, header: &[u8; HEADER_LEN]) -> Result<[u8; 16], E> {
        let [m0, m1, m2, m3, version, id @ ..] = *header;
        if [m0, m1, m2, m3] != self.magic {
            return Err(self.bad_magic.clone());
        }
        if version != self.version {
            return Err((self.unknown_version)(version));
        }
        Ok(id)
    }

    /// Returns the keyed BLAKE2b-256 MAC over the domain tag and `signed`, the file's header and ciphertext. Its
    /// `verify_slice` compares in constant time.
    pub(crate) fn mac(&self, key: &[u8; 64], signed: &[u8]) -> Blake2bMac<U32> {
        <Blake2bMac<U32> as KeyInit>::new(key.into())
            .chain_update(self.domain_tag)
            .chain_update(signed)
    }
}
