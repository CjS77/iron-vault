// SPDX-License-Identifier: MPL-2.0
//! Encodes and decodes the TPM key blob `IVTK` v1, which the store keeps as `approver-<approver ID>.tpm`
//! ([TPM approval signer: the TPM key blob](../../../design/tpm-approval-signer.md#the-tpm-key-blob)).
//!
//! The blob holds what the helper needs to load a TPM approval key again: the parent's name and the key's public and
//! private areas. The service writes it after enrollment and sends its parts in each sign request.
//!
//! ```text
//! "IVTK" | version 01 | approver ID (16 bytes) | primary name | public area | private area
//!                                                 └──────── each a u64 length, then the bytes ────────┘
//! ```

use crate::request::{put_key, read_key};
use crate::wire::Reader;
use crate::{APPROVER_ID_LEN, ProtocolError, TpmKeyParts};

const MAGIC: [u8; 4] = *b"IVTK";
const VERSION: u8 = 1;

/// The longest key blob written or read, checked before anything is read.
pub const MAX_TPM_KEY_BLOB_LEN: usize = 4096;

/// Holds a TPM approval key's parts as the service keeps them, bound to its approver ID.
///
/// The service checks only the framing and the approver ID; the TPM structures are the helper's to parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmKeyBlob {
    approver_id: [u8; APPROVER_ID_LEN],
    key: TpmKeyParts,
}

impl TpmKeyBlob {
    /// Binds `key` to approver `approver_id`.
    pub fn new(approver_id: [u8; APPROVER_ID_LEN], key: TpmKeyParts) -> Self {
        Self { approver_id, key }
    }

    /// Returns the approver the key belongs to.
    pub fn approver_id(&self) -> &[u8; APPROVER_ID_LEN] {
        &self.approver_id
    }

    /// Returns the key's parts, for a sign request.
    pub fn key(&self) -> &TpmKeyParts {
        &self.key
    }

    /// Encodes the blob, refusing a result over [`MAX_TPM_KEY_BLOB_LEN`].
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut out = MAGIC.to_vec();
        out.push(VERSION);
        out.extend_from_slice(&self.approver_id);
        put_key(&mut out, &self.key);
        check_len(out.len())?;
        Ok(out)
    }

    /// Decodes a blob, accepting only its one encoding and only for approver `expected`, the ID in the blob's file name.
    ///
    /// The ID check stops a blob copied under another approver's file name from being used for that approver.
    pub fn decode(bytes: &[u8], expected: &[u8; APPROVER_ID_LEN]) -> Result<Self, ProtocolError> {
        check_len(bytes.len())?;
        let mut reader = Reader::with_header(bytes, MAGIC, VERSION)?;
        let approver_id = reader.array()?;
        let key = read_key(&mut reader)?;
        reader.finish()?;
        match approver_id == *expected {
            true => Ok(Self::new(approver_id, key)),
            false => Err(ProtocolError::ApproverMismatch),
        }
    }
}

fn check_len(len: usize) -> Result<(), ProtocolError> {
    match len <= MAX_TPM_KEY_BLOB_LEN {
        true => Ok(()),
        false => Err(ProtocolError::TooLarge {
            len,
            limit: MAX_TPM_KEY_BLOB_LEN,
        }),
    }
}
