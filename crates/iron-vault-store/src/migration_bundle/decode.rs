//! The strict streaming migration bundle decoder for `import`: it accepts only the one encoding
//! [`super::BundleEncoder`] writes.
//!
//! The bundle is hostile input that crossed machines, so the decoder checks every rule of
//! [migration bundle v1, "One encoding per bundle"](../../../../design/storage-formats.md#one-encoding-per-bundle) as
//! soon as the bytes it needs are in, and never holds the compressed bundle whole. The gzip layer hands the archive
//! layer only the bytes it has inflated, and the archive layer asks the order check to admit each entry before reading
//! its bytes:
//!
//! ```text
//! pushed bytes ─→ gzip.rs: header, inflate, trailer ─→ archive.rs: entry headers, padding, end blocks
//!                                                                      │ each entry name
//!                                                                      ▼
//!                                                       order.rs: bundle order, header counts
//! ```

mod archive;
mod gzip;
mod order;

use std::collections::BTreeMap;

use thiserror::Error;

use self::archive::ArchiveReader;
use self::gzip::GzipReader;
use super::{BundleHeader, BundleHeaderError, EntryName, MAX_BUNDLE_LEN};

/// Decodes a migration bundle pushed in pieces, such as the bodies of bundle data frames as they arrive.
///
/// Each entry is available from [`BundleDecoder::entry`] as soon as its last byte is decoded, so a reader that needs
/// only `config.toml` can stop pushing once it is in. After a refusal every further call refuses with the same error,
/// so no later bytes are read under a state the refusal left behind.
pub struct BundleDecoder {
    gzip: GzipReader,
    archive: ArchiveReader,
    failed: Option<BundleError>,
}

/// The entries of a migration bundle whose form the decoder accepted.
///
/// Only the form is checked: no `age` entry has been opened and no MAC or digest checked, so nothing here is trusted
/// until import has verified it with the vault identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedBundle {
    header: BundleHeader,
    entries: BTreeMap<EntryName, Vec<u8>>,
}

/// A rule of
/// [migration bundle v1, "One encoding per bundle"](../../../../design/storage-formats.md#one-encoding-per-bundle) that
/// the bytes break.
///
/// Import names the rule in its `bundle-invalid` message and the `migration.import-refused` event, so each variant has
/// a fixed short name, [`BundleError::rule`], and none carries a byte of the bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum BundleError {
    /// The compressed bytes or the archive they inflate to exceed [`MAX_BUNDLE_LEN`].
    #[error("the bundle exceeds the size limit")]
    TooLarge,
    /// The gzip header's magic is not `1f 8b` or its compression method is not deflate.
    #[error("the bundle is not a gzip deflate member")]
    GzipHeader,
    /// The gzip header sets a flag.
    #[error("the bundle's gzip header sets a flag")]
    GzipFlags,
    /// The deflate stream is malformed.
    #[error("the bundle's deflate stream is malformed")]
    Deflate,
    /// The gzip trailer's CRC-32 does not match the archive.
    #[error("the bundle's gzip CRC-32 does not match")]
    GzipCrc,
    /// The gzip trailer's ISIZE does not match the archive's length.
    #[error("the bundle's gzip length does not match")]
    GzipSize,
    /// Bytes follow the gzip member, such as a second member.
    #[error("bytes follow the bundle's gzip member")]
    GzipTrailing,
    /// The bundle ended before its gzip member or its archive did.
    #[error("the bundle is truncated")]
    Truncated,
    /// An entry name is not one the bundle format lists.
    #[error("the bundle holds an unknown entry name")]
    EntryName,
    /// An entry header differs from the one the encoder writes for its name and size.
    #[error("a bundle entry header is not in the one allowed form")]
    EntryHeader,
    /// An entry is out of bundle order, repeated or missing.
    #[error("the bundle's entries are out of order")]
    EntryOrder,
    /// The approver or record entries do not number what the bundle header counts.
    #[error("the bundle's entries do not match the bundle header's counts")]
    EntryCount,
    /// An entry's size field is over its size limit.
    #[error("a bundle entry is over its size limit")]
    EntrySize,
    /// The padding after an entry holds a byte other than zero.
    #[error("a bundle entry's padding is not zero bytes")]
    Padding,
    /// The second end-of-archive block holds a byte other than zero.
    #[error("the bundle's end of archive is not zero bytes")]
    EndOfArchive,
    /// Bytes follow the end of the archive.
    #[error("bytes follow the bundle's end of archive")]
    ArchiveTrailing,
    /// The `bundle-header` entry is not exactly its length.
    #[error("the bundle header has the wrong length")]
    HeaderLength,
    /// The bundle header's magic is not `IVBH`.
    #[error("the bundle header has the wrong magic")]
    HeaderMagic,
    /// The bundle format version is not one this code reads.
    #[error("the bundle format version is unknown")]
    HeaderVersion,
    /// The bundle header's vault ID is not a version 4 UUID.
    #[error("the bundle header's vault ID is invalid")]
    HeaderVaultId,
    /// The bundle header's approver or record count is out of range.
    #[error("the bundle header's counts are out of range")]
    HeaderCount,
}

impl BundleError {
    /// Returns the rule's fixed short name, for the `bundle-invalid` message and the audit event's `detail`.
    pub fn rule(&self) -> &'static str {
        match self {
            Self::TooLarge => "too_large",
            Self::GzipHeader => "gzip_header",
            Self::GzipFlags => "gzip_flags",
            Self::Deflate => "deflate",
            Self::GzipCrc => "gzip_crc",
            Self::GzipSize => "gzip_size",
            Self::GzipTrailing => "gzip_trailing",
            Self::Truncated => "truncated",
            Self::EntryName => "entry_name",
            Self::EntryHeader => "entry_header",
            Self::EntryOrder => "entry_order",
            Self::EntryCount => "entry_count",
            Self::EntrySize => "entry_size",
            Self::Padding => "padding",
            Self::EndOfArchive => "end_of_archive",
            Self::ArchiveTrailing => "archive_trailing",
            Self::HeaderLength => "header_length",
            Self::HeaderMagic => "header_magic",
            Self::HeaderVersion => "header_version",
            Self::HeaderVaultId => "header_vault_id",
            Self::HeaderCount => "header_count",
        }
    }
}

impl From<BundleHeaderError> for BundleError {
    fn from(error: BundleHeaderError) -> Self {
        match error {
            BundleHeaderError::WrongLength => Self::HeaderLength,
            BundleHeaderError::WrongMagic => Self::HeaderMagic,
            BundleHeaderError::UnknownVersion(_) => Self::HeaderVersion,
            BundleHeaderError::InvalidVaultId => Self::HeaderVaultId,
            BundleHeaderError::ApproverCount | BundleHeaderError::RecordCount => Self::HeaderCount,
        }
    }
}

impl BundleDecoder {
    /// Creates a decoder for one bundle of at most [`MAX_BUNDLE_LEN`] bytes, compressed and decompressed.
    pub fn new() -> Self {
        Self::with_max_len(MAX_BUNDLE_LEN)
    }

    /// Creates a decoder with a lower length bound, so tests can pass it without allocating a full bundle.
    pub(crate) fn with_max_len(max_len: u64) -> Self {
        Self {
            gzip: GzipReader::new(max_len),
            archive: ArchiveReader::default(),
            failed: None,
        }
    }

    /// Decodes the next bytes of the bundle, refusing them at the first rule they break.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), BundleError> {
        self.refuse_after_failure()?;
        let result = self.gzip.push(bytes, &mut self.archive);
        self.failed = result.err();
        result
    }

    /// Returns the entry `name` once it is decoded in full; `None` before then, and always for the bundle header.
    pub fn entry(&self, name: &EntryName) -> Option<&[u8]> {
        self.archive.entry(name)
    }

    /// Returns the decoded bundle, refusing one whose gzip member or archive has not ended.
    pub fn finish(self) -> Result<DecodedBundle, BundleError> {
        self.refuse_after_failure()?;
        self.gzip.finish()?;
        let (header, entries) = self.archive.into_parts().ok_or(BundleError::Truncated)?;
        Ok(DecodedBundle { header, entries })
    }

    fn refuse_after_failure(&self) -> Result<(), BundleError> {
        self.failed.map_or(Ok(()), Err)
    }
}

impl Default for BundleDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl DecodedBundle {
    /// The bundle header, checked for form only.
    pub fn header(&self) -> BundleHeader {
        self.header
    }

    /// Returns the bytes of the entry `name`, or `None` if the bundle does not hold it; the bundle header is not an
    /// entry here.
    pub fn entry(&self, name: &EntryName) -> Option<&[u8]> {
        self.entries.get(name).map(Vec::as_slice)
    }

    /// Returns every entry after the bundle header, in bundle order.
    pub fn entries(&self) -> impl Iterator<Item = (EntryName, &[u8])> {
        self.entries.iter().map(|(name, bytes)| (*name, bytes.as_slice()))
    }

    /// Moves out the header and the entries after it, so `import` keeps one copy of a bundle of up to
    /// [`MAX_BUNDLE_LEN`] bytes.
    pub(crate) fn into_parts(self) -> (BundleHeader, BTreeMap<EntryName, Vec<u8>>) {
        (self.header, self.entries)
    }
}

#[cfg(test)]
mod tests;
