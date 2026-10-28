//! The MAC'd file frame shared by the vault manifest and the approval state (spec §3.10, `design/storage-formats.md`).
//!
//! `age` does not authenticate the sender, so a control file sealed to the vault public key could be planted by anyone
//! holding that key. The frame adds a MAC keyed from the private vault identity over a clear header and the ciphertext,
//! and checks it before anything is decrypted. Both files use this one implementation so a fix reaches both.

use blake2::Blake2bMac;
use blake2::digest::{KeyInit, Mac, consts::U32};
use zeroize::Zeroizing;

use crate::sealed::{self, OpenError, SealError};
use crate::vault_id::{VaultId, VaultIdError};
use crate::vault_identity::VaultIdentity;

/// Magic, version and vault ID, in clear and covered by the MAC.
pub(crate) const HEADER_LEN: usize = 4 + 1 + 16;
/// The length of the trailing MAC.
pub(crate) const MAC_LEN: usize = 32;

/// What tells one MAC'd file type from another, and the errors of type `E` its frame failures are reported as. Each
/// type has its own persona and domain tag, so a MAC from one never verifies another. No error carries key material
/// or MAC bytes.
pub(crate) struct MacFileKind<E> {
    /// The first bytes of the file, so a file of another type is never read as this one.
    pub magic: [u8; 4],
    /// The version this code writes and the only one it reads; it fixes the MAC construction.
    pub version: u8,
    /// The BLAKE2b personalization of the MAC key, which keeps it independent of other keys from the vault identity.
    pub persona: &'static [u8],
    /// Prefixed to the MAC input so a MAC under this key can never be mistaken for one over other data.
    pub domain_tag: &'static [u8],
    /// The largest file accepted, checked before any other work; it also bounds the decrypted payload.
    pub max_len: usize,
    /// The file is larger than `max_len`; nothing else was read.
    pub too_large: E,
    /// The file ends inside the header or the MAC.
    pub truncated: E,
    /// The file does not start with `magic`.
    pub bad_magic: E,
    /// The file has a version other than `version`.
    pub unknown_version: fn(u8) -> E,
    /// The MAC does not match: the file was altered, or written by someone without this vault's identity.
    pub damaged: E,
    /// The authenticated header's vault ID is not a random version 4 UUID.
    pub invalid_vault_id: fn(VaultIdError) -> E,
}

impl<E: Clone + From<OpenError>> MacFileKind<E> {
    /// The file's bytes: header, `payload` sealed to the vault public key, then the MAC.
    pub(crate) fn seal(&self, identity: &VaultIdentity, vault_id: VaultId, payload: &[u8]) -> Result<Vec<u8>, SealError> {
        let signed = [&self.magic[..], &[self.version], vault_id.as_bytes(), &sealed::seal(&identity.public_key(), payload)?].concat();
        let tag = self.mac(&identity.derive_key(self.persona), &signed).finalize().into_bytes();
        Ok([&signed[..], &tag].concat())
    }

    /// The header's vault ID and the decrypted payload, after the size, header and MAC are checked in that order. The
    /// caller decodes the payload and checks that it names the same vault.
    pub(crate) fn open(&self, identity: &VaultIdentity, file: &[u8]) -> Result<(VaultId, Zeroizing<Vec<u8>>), E> {
        if file.len() > self.max_len {
            return Err(self.too_large.clone());
        }
        let (signed, tag) = file.len().checked_sub(MAC_LEN).and_then(|at| file.split_at_checked(at)).ok_or_else(|| self.truncated.clone())?;
        let (header, ciphertext) = signed.split_first_chunk::<HEADER_LEN>().ok_or_else(|| self.truncated.clone())?;
        let vault_id = self.read_header(header)?;
        self.mac(&identity.derive_key(self.persona), signed).verify_slice(tag).map_err(|_| self.damaged.clone())?;
        Ok((VaultId::from_bytes(vault_id).map_err(self.invalid_vault_id)?, sealed::open(identity, ciphertext, self.max_len)?))
    }

    /// The header's vault ID bytes, after its magic and version. The version is read before the MAC is checked because
    /// it decides how the MAC is computed; the ID is not trusted until the MAC passes.
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

    /// The keyed BLAKE2b-256 MAC over the domain tag and `signed`, the file's header and ciphertext. `verify_slice`
    /// compares in constant time.
    pub(crate) fn mac(&self, key: &[u8; 64], signed: &[u8]) -> Blake2bMac<U32> {
        <Blake2bMac<U32> as KeyInit>::new(key.into()).chain_update(self.domain_tag).chain_update(signed)
    }
}
