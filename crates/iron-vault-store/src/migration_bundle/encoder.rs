// SPDX-License-Identifier: MPL-2.0
//! The streaming migration bundle encoder for `export`: one gzip member around a ustar archive of the bundle's entries
//! ([migration bundle v1, "Entry header"](../../../../design/storage-formats.md#entry-header)).

use std::io::{self, Write};

use flate2::Compression;
use flate2::GzBuilder;
use flate2::write::GzEncoder;
use thiserror::Error;

use super::ustar::{BLOCK_LEN, END_OF_ARCHIVE, entry_header, padding_len};
use super::{BundleHeader, EntryName};

/// The fixed compression level. Most of a bundle is `age` ciphertext, which does not compress, so a higher level would
/// spend time under the service-wide lock for nothing. It is fixed in code so the same entries always give the same
/// bytes.
const COMPRESSION: Compression = Compression::fast();

const PADDING: [u8; BLOCK_LEN] = [0; BLOCK_LEN];

/// Writes a migration bundle to `W` one entry at a time, so export never holds the whole bundle.
///
/// [`BundleEncoder::new`] writes the bundle header; [`BundleEncoder::write_entry`] then takes every other entry in
/// bundle order, and [`BundleEncoder::finish`] ends the archive once every entry the header counts is in. The gzip
/// member has no file name, comment or extra field and modification time 0, so the output depends only on the entries.
///
/// Dropping an encoder that was not finished still writes a gzip trailer to `W`, after the part of the archive written
/// so far, so the output of an encoder that failed or was dropped must be discarded, never kept as a bundle.
pub struct BundleEncoder<W: Write> {
    gzip: GzEncoder<W>,
    header: BundleHeader,
    last: EntryName,
    approvers: usize,
    records: usize,
}

/// An entry the bundle format does not allow where it was given, or a failed write.
///
/// A refused entry writes nothing, but after an [`EncodeError::Io`] the output is incomplete and must be discarded.
#[derive(Debug, Error)]
pub enum EncodeError {
    /// The entry does not come next in bundle order: a fixed entry out of place or repeated, an approver or record
    /// not above the one before, or a record before all the approvers.
    #[error("bundle entry {0} is out of order")]
    OutOfOrder(EntryName),
    /// The entry is an approver or record beyond the header's count.
    #[error("bundle entry {0} is beyond the bundle header's count")]
    Extra(EntryName),
    /// The bundle ended before every entry the header counts was written.
    #[error("bundle is missing entries")]
    Incomplete,
    /// The entry holds more bytes than its size limit.
    #[error("bundle entry {entry} holds {len} bytes, over its limit of {limit}")]
    TooLarge {
        /// The entry.
        entry: EntryName,
        /// Its length in bytes.
        len: usize,
        /// Its size limit in bytes.
        limit: u64,
    },
    /// Writing to the output failed.
    #[error("writing the bundle failed: {0}")]
    Io(#[from] io::Error),
}

impl<W: Write> BundleEncoder<W> {
    /// Starts a bundle on `writer` and writes its header entry.
    pub fn new(writer: W, header: BundleHeader) -> Result<Self, EncodeError> {
        let gzip = GzBuilder::new().mtime(0).write(writer, COMPRESSION);
        let mut encoder = Self {
            gzip,
            header,
            last: EntryName::BundleHeader,
            approvers: 0,
            records: 0,
        };
        encoder.write_archive_entry(EntryName::BundleHeader, &header.encode())?;
        Ok(encoder)
    }

    /// Writes the next entry, refusing one out of bundle order, beyond the header's counts or over its size limit.
    pub fn write_entry(&mut self, name: EntryName, bytes: &[u8]) -> Result<(), EncodeError> {
        self.check_order(name)?;
        self.check_count(name)?;
        self.write_archive_entry(name, bytes)?;
        self.last = name;
        match name {
            EntryName::Approver(_) => self.approvers += 1,
            EntryName::Record(_) => self.records += 1,
            _ => {}
        }
        Ok(())
    }

    /// Ends the archive and the gzip member and returns the writer, refusing a bundle that lacks an entry the header
    /// counts.
    pub fn finish(mut self) -> Result<W, EncodeError> {
        if (self.approvers, self.records) != (self.header.approver_count(), self.header.record_count()) {
            return Err(EncodeError::Incomplete);
        }
        self.gzip.write_all(&END_OF_ARCHIVE)?;
        Ok(self.gzip.finish()?)
    }

    fn check_order(&self, name: EntryName) -> Result<(), EncodeError> {
        let follows = match (self.last, name) {
            (EntryName::BundleHeader, EntryName::ExportedIdentity)
            | (EntryName::ExportedIdentity, EntryName::Manifest)
            | (EntryName::Manifest, EntryName::ApprovalState)
            | (EntryName::ApprovalState, EntryName::Config)
            | (EntryName::Config, EntryName::Approver(_)) => true,
            (EntryName::Approver(_), EntryName::Record(_)) => self.approvers == self.header.approver_count(),
            (EntryName::Approver(_), EntryName::Approver(_)) | (EntryName::Record(_), EntryName::Record(_)) => self.last < name,
            _ => false,
        };
        follows.then_some(()).ok_or(EncodeError::OutOfOrder(name))
    }

    fn check_count(&self, name: EntryName) -> Result<(), EncodeError> {
        let full = match name {
            EntryName::Approver(_) => self.approvers == self.header.approver_count(),
            EntryName::Record(_) => self.records == self.header.record_count(),
            _ => false,
        };
        (!full).then_some(()).ok_or(EncodeError::Extra(name))
    }

    fn write_archive_entry(&mut self, name: EntryName, bytes: &[u8]) -> Result<(), EncodeError> {
        let limit = name.size_limit();
        let too_large = || EncodeError::TooLarge {
            entry: name,
            len: bytes.len(),
            limit,
        };
        let size = u32::try_from(bytes.len()).map_err(|_| too_large())?;
        if u64::from(size) > limit {
            return Err(too_large());
        }
        self.gzip.write_all(&entry_header(&name, size))?;
        self.gzip.write_all(bytes)?;
        self.gzip.write_all(&PADDING[..padding_len(bytes.len())])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
