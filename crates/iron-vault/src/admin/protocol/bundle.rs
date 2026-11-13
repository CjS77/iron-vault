// SPDX-License-Identifier: MPL-2.0
//! The bundle data frame and the results of `export` and `import` ([migration bundle: Transfer][transfer] and
//! [Admin exchanges][exchanges]). Neither command's request carries the bundle: it travels as bundle data frames beside
//! the exchange, so the service never reads or writes a path the owner names.
//!
//! ```text
//! export:  CLI --> request                                     service
//!          CLI <-> authorization and export passphrase prompts service
//!          CLI <-- bundle data, bundle data, ...               service
//!          CLI <-- bundle data, empty: the end                 service
//!          CLI <-- success: vault ID, record count, byte count service   the CLI checks the byte count
//!
//! import:  CLI --> request                                     service
//!          CLI --> bundle data, bundle data, ...               service
//!          CLI --> bundle data, empty: the end                 service
//!          CLI <-> export passphrase, new vault passphrase,    service
//!                  recovery key reveal and confirmation
//!          CLI <-- success: the import result                  service
//! ```
//!
//! [transfer]: ../../../../../design/migration-bundle.md#transfer
//! [exchanges]: ../../../../../design/migration-bundle.md#admin-exchanges

use std::fmt;

use iron_vault_store::{RecipientRole, VaultId};

use super::fields::{self, Field, exact, read_u64};
use super::{AdminResponse, FrameError, MAX_BODY_LEN};

const TAG_COMMAND: u16 = super::body::TAG_COMMAND;
const TAG_VAULT_ID: u16 = 2;
const TAG_RECORDS: u16 = 3;
/// `export`: the bundle's byte count.
const TAG_BYTES: u16 = 4;
/// `import`: the committed approval version.
const TAG_COMMITTED: u16 = 4;
const TAG_HIGHEST_RESERVED: u16 = 5;
const TAG_DIGEST: u16 = 6;
const TAG_RECIPIENTS: u16 = 7;

/// The body of one bundle data frame (kind 9): up to [`MAX_BODY_LEN`] raw bytes of a migration bundle, never parsed as
/// fields. The empty chunk ends the bundle. A bundle is ciphertext and public metadata, so a chunk is not a secret
/// type; its `Debug` shows the length only, so a trace never prints 64 KiB.
#[derive(Clone, PartialEq, Eq)]
pub struct BundleChunk(Vec<u8>);

impl BundleChunk {
    /// Wraps `bytes`. Returns `None` if there are more than [`MAX_BODY_LEN`] of them.
    pub fn new(bytes: Vec<u8>) -> Option<Self> {
        (bytes.len() <= MAX_BODY_LEN).then_some(Self(bytes))
    }

    /// Returns the empty chunk, which ends a bundle.
    pub const fn end() -> Self {
        Self(Vec::new())
    }

    /// Returns `true` if and only if this is the empty chunk that ends the bundle.
    pub fn is_end(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the bundle bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the bundle bytes, by value.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Debug for BundleChunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BundleChunk({} bytes)", self.0.len())
    }
}

/// Encodes `export`'s success body: the command it answers, the vault ID as its 16 raw bytes, the record count, then the
/// bundle's byte count.
pub(super) fn encode_export_result(command: u16, vault_id: VaultId, records: u64, bytes: u64) -> Vec<u8> {
    let mut out = Vec::new();
    fields::put(&mut out, TAG_COMMAND, &command.to_be_bytes());
    fields::put(&mut out, TAG_VAULT_ID, vault_id.as_bytes());
    fields::put(&mut out, TAG_RECORDS, &records.to_be_bytes());
    fields::put(&mut out, TAG_BYTES, &bytes.to_be_bytes());
    out
}

pub(super) fn decode_export_result(fields: &[Field<'_>]) -> Result<AdminResponse, FrameError> {
    let [_, vault_id, records, bytes] = exact(fields, [TAG_COMMAND, TAG_VAULT_ID, TAG_RECORDS, TAG_BYTES])?;
    Ok(AdminResponse::Export {
        vault_id: read_vault_id(vault_id)?,
        records: read_u64(TAG_RECORDS, records)?,
        bytes: read_u64(TAG_BYTES, bytes)?,
    })
}

/// What a completed `import` reports: the vault now on disk, Locked, with its committed approval and the recipients
/// enrolled for this machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportResult {
    /// The imported vault's ID.
    pub vault_id: VaultId,
    /// How many credential records the bundle carried.
    pub records: u64,
    /// The committed approval version.
    pub version: u64,
    /// The highest reserved approval version, so the owner can compare it with the source's `status`.
    pub highest_reserved: u64,
    /// The BLAKE2b-256 digest of the committed config.
    pub digest: [u8; 32],
    /// The roles of the recipients the identity envelope was wrapped for: kinds, never keys.
    pub recipients: Vec<RecipientRole>,
}

/// Encodes `import`'s success body: the command it answers, the vault ID as its 16 raw bytes, the record count, the committed
/// approval version, the highest reserved version, the committed config's digest, then the code of each recipient role
/// enrolled, one byte each, as `init` sends them.
pub(super) fn encode_import_result(command: u16, result: &ImportResult) -> Vec<u8> {
    let mut out = Vec::new();
    fields::put(&mut out, TAG_COMMAND, &command.to_be_bytes());
    fields::put(&mut out, TAG_VAULT_ID, result.vault_id.as_bytes());
    fields::put(&mut out, TAG_RECORDS, &result.records.to_be_bytes());
    fields::put(&mut out, TAG_COMMITTED, &result.version.to_be_bytes());
    fields::put(&mut out, TAG_HIGHEST_RESERVED, &result.highest_reserved.to_be_bytes());
    fields::put(&mut out, TAG_DIGEST, &result.digest);
    fields::put(
        &mut out,
        TAG_RECIPIENTS,
        &result.recipients.iter().map(|role| role.code()).collect::<Vec<_>>(),
    );
    out
}

pub(super) fn decode_import_result(fields: &[Field<'_>]) -> Result<AdminResponse, FrameError> {
    let [_, vault_id, records, version, highest_reserved, digest, recipients] = exact(
        fields,
        [
            TAG_COMMAND,
            TAG_VAULT_ID,
            TAG_RECORDS,
            TAG_COMMITTED,
            TAG_HIGHEST_RESERVED,
            TAG_DIGEST,
            TAG_RECIPIENTS,
        ],
    )?;
    Ok(AdminResponse::Import(ImportResult {
        vault_id: read_vault_id(vault_id)?,
        records: read_u64(TAG_RECORDS, records)?,
        version: read_u64(TAG_COMMITTED, version)?,
        highest_reserved: read_u64(TAG_HIGHEST_RESERVED, highest_reserved)?,
        digest: <[u8; 32]>::try_from(digest).map_err(|_| FrameError::InvalidValue(TAG_DIGEST))?,
        recipients: recipients
            .iter()
            .map(|code| RecipientRole::from_code(*code).ok_or(FrameError::InvalidValue(TAG_RECIPIENTS)))
            .collect::<Result<_, _>>()?,
    }))
}

fn read_vault_id(bytes: &[u8]) -> Result<VaultId, FrameError> {
    <[u8; 16]>::try_from(bytes)
        .ok()
        .and_then(|bytes| VaultId::from_bytes(bytes).ok())
        .ok_or(FrameError::InvalidValue(TAG_VAULT_ID))
}
