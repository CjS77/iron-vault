// SPDX-License-Identifier: MPL-2.0
//! The [presence payload v1](../../../../design/storage-formats.md#presence-payload-v1) and the
//! [migration proof payload v1](../../../../design/storage-formats.md#migration-proof-payload-v1): the two messages
//! besides the approval payload that a TPM approver signs
//! ([TPM approval signer, "What the helper signs"](../../../../design/tpm-approval-signer.md#what-the-helper-signs)).
//!
//! A TPM approver proves owner presence for `replace`, `rm` and the migration commands by signing one of these once the
//! owner types its PIN. Each payload starts with its own magic, so a signature over one never reads as a signature over
//! another, over an approval payload, or over bytes of any other structure. Both have a fixed length and one encoding:
//!
//! ```text
//! presence:        "IVPP" 01 | vault ID (16) | approver ID (16) | nonce (32)     69 bytes
//! migration proof: "IVMA" 01 | binding digest (32)                               37 bytes
//! ```

#[cfg(test)]
mod tests;

use super::encoding::{header, read_header};
use super::{ApprovalDecodeError, ApproverId};
use crate::vault_id::VaultId;
use crate::wire::Reader;

/// The first bytes of every presence payload.
const PRESENCE_MAGIC: [u8; 4] = *b"IVPP";
/// The presence payload format version this code writes and the only one it reads.
const PRESENCE_VERSION: u8 = 1;
/// The first bytes of every migration proof payload.
const MIGRATION_PROOF_MAGIC: [u8; 4] = *b"IVMA";
/// The migration proof payload format version this code writes and the only one it reads.
const MIGRATION_PROOF_VERSION: u8 = 1;

/// What a TPM approver signs to prove owner presence: this vault, the approver asked, and a nonce the service chose for
/// this one prompt. The service verifies the signature against the pinned key and drops the nonce, so a signature over
/// an earlier nonce, another vault or another approver proves nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresencePayload {
    vault_id: VaultId,
    approver_id: ApproverId,
    nonce: [u8; 32],
}

impl PresencePayload {
    /// Builds the payload that asks approver `approver_id` of vault `vault_id` to sign over `nonce`. The caller draws
    /// `nonce` fresh from the operating system's random source for each prompt.
    pub fn new(vault_id: VaultId, approver_id: ApproverId, nonce: [u8; 32]) -> Self {
        Self {
            vault_id,
            approver_id,
            nonce,
        }
    }

    /// The vault the owner is proving presence for.
    pub fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    /// The approver asked.
    pub fn approver_id(&self) -> ApproverId {
        self.approver_id
    }

    /// The nonce chosen for this prompt.
    pub fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }

    /// Encodes the 69 bytes a signer signs: magic, format version, vault ID, approver ID, nonce.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = header(PRESENCE_MAGIC, PRESENCE_VERSION);
        out.extend_from_slice(self.vault_id.as_bytes());
        out.extend_from_slice(self.approver_id.as_bytes());
        out.extend_from_slice(&self.nonce);
        out
    }

    /// Decodes a presence payload, accepting `bytes` only in its one encoding.
    pub fn decode(bytes: &[u8]) -> Result<Self, ApprovalDecodeError> {
        let mut reader = Reader::new(bytes);
        read_header(&mut reader, PRESENCE_MAGIC, PRESENCE_VERSION)?;
        let vault_id = VaultId::from_bytes(reader.array()?)?;
        let approver_id = ApproverId::from_bytes(reader.array()?).map_err(|_| ApprovalDecodeError::InvalidApproverId)?;
        let nonce = reader.array()?;
        reader.finish()?;
        Ok(Self::new(vault_id, approver_id, nonce))
    }
}

/// What a TPM approver signs to prove a migration challenge: the challenge's 32-byte binding digest, wrapped so the
/// signature can never be read as one over 32 bytes of any other structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrationProofPayload {
    binding_digest: [u8; 32],
}

impl MigrationProofPayload {
    /// Builds the payload that proves the challenge whose binding digest is `binding_digest`.
    pub fn new(binding_digest: [u8; 32]) -> Self {
        Self { binding_digest }
    }

    /// The challenge's binding digest.
    pub fn binding_digest(&self) -> &[u8; 32] {
        &self.binding_digest
    }

    /// Encodes the 37 bytes a signer signs: magic, format version, binding digest.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = header(MIGRATION_PROOF_MAGIC, MIGRATION_PROOF_VERSION);
        out.extend_from_slice(&self.binding_digest);
        out
    }

    /// Decodes a migration proof payload, accepting `bytes` only in its one encoding.
    pub fn decode(bytes: &[u8]) -> Result<Self, ApprovalDecodeError> {
        let mut reader = Reader::new(bytes);
        read_header(&mut reader, MIGRATION_PROOF_MAGIC, MIGRATION_PROOF_VERSION)?;
        let binding_digest = reader.array()?;
        reader.finish()?;
        Ok(Self::new(binding_digest))
    }
}
