//! The TPM key blob `IVTK` v1, kept as `approver-<approver ID>.tpm` (`design/tpm-approval-signer.md` "The TPM key
//! blob").

use crate::request::{put_key, read_key};
use crate::wire::Reader;
use crate::{APPROVER_ID_LEN, ProtocolError, TpmKeyParts};

const MAGIC: [u8; 4] = *b"IVTK";
const VERSION: u8 = 1;

/// The longest key blob written or read, checked before anything is read.
pub const MAX_TPM_KEY_BLOB_LEN: usize = 4096;

/// A TPM approval key's parts as the service keeps them, bound to its approver ID.
///
/// The service checks only the framing and the approver ID; the TPM structures are the helper's to parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmKeyBlob {
    approver_id: [u8; APPROVER_ID_LEN],
    key: TpmKeyParts,
}

impl TpmKeyBlob {
    /// The blob for approver `approver_id`'s key.
    pub fn new(approver_id: [u8; APPROVER_ID_LEN], key: TpmKeyParts) -> Self {
        Self { approver_id, key }
    }

    /// The approver the key belongs to.
    pub fn approver_id(&self) -> &[u8; APPROVER_ID_LEN] {
        &self.approver_id
    }

    /// The key's parts, for a sign request.
    pub fn key(&self) -> &TpmKeyParts {
        &self.key
    }

    /// The blob's bytes, refused when they are over [`MAX_TPM_KEY_BLOB_LEN`].
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut out = MAGIC.to_vec();
        out.push(VERSION);
        out.extend_from_slice(&self.approver_id);
        put_key(&mut out, &self.key);
        check_len(out.len())?;
        Ok(out)
    }

    /// The blob `bytes` hold, accepted only in its one encoding and only for approver `expected`, the ID in the
    /// blob's file name.
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
