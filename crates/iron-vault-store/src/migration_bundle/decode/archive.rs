// SPDX-License-Identifier: MPL-2.0
//! The ustar reader: entry headers, entry bytes, padding and the end of the archive, fed in pieces of any size.

use std::collections::BTreeMap;

use super::BundleError;
use super::order::EntryOrder;
use crate::migration_bundle::ustar::{BLOCK_LEN, padding_len, parse_entry_header};
use crate::migration_bundle::{BundleHeader, EntryName};

/// Where the next archive byte belongs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// Filling a 512-byte header block.
    Header,
    /// Filling the entry `name` of `size` bytes.
    Body { name: EntryName, size: usize },
    /// This many padding bytes are still due.
    Padding(usize),
    /// This many bytes of the second end block are still due.
    EndBlock(usize),
    /// The archive has ended; any further byte is refused.
    Ended,
}

/// The archive's state and the entries decoded so far.
pub(super) struct ArchiveReader {
    stage: Stage,
    block: [u8; BLOCK_LEN],
    filled: usize,
    body: Vec<u8>,
    order: EntryOrder,
    entries: BTreeMap<EntryName, Vec<u8>>,
}

impl Default for ArchiveReader {
    fn default() -> Self {
        Self {
            stage: Stage::Header,
            block: [0; BLOCK_LEN],
            filled: 0,
            body: Vec::new(),
            order: EntryOrder::default(),
            entries: BTreeMap::new(),
        }
    }
}

impl ArchiveReader {
    /// Reads the next archive bytes, refusing them at the first rule they break.
    pub(super) fn feed(&mut self, mut bytes: &[u8]) -> Result<(), BundleError> {
        while !bytes.is_empty() {
            bytes = match self.stage {
                Stage::Header => self.fill_block(bytes)?,
                Stage::Body { name, size } => self.fill_body(name, size, bytes)?,
                Stage::Padding(due) => self.skip_zeros(bytes, due, BundleError::Padding, (Stage::Padding, Stage::Header))?,
                Stage::EndBlock(due) => self.skip_zeros(bytes, due, BundleError::EndOfArchive, (Stage::EndBlock, Stage::Ended))?,
                Stage::Ended => return Err(BundleError::ArchiveTrailing),
            };
        }
        Ok(())
    }

    /// Refuses an archive that has not reached its end, once no more of it can arrive.
    pub(super) fn check_ended(&self) -> Result<(), BundleError> {
        (self.stage == Stage::Ended).then_some(()).ok_or(BundleError::Truncated)
    }

    pub(super) fn entry(&self, name: &EntryName) -> Option<&[u8]> {
        self.entries.get(name).map(Vec::as_slice)
    }

    /// Returns the bundle header and entries of an archive that has ended, or `None` before its end.
    pub(super) fn into_parts(self) -> Option<(BundleHeader, BTreeMap<EntryName, Vec<u8>>)> {
        let header = self.order.header().filter(|_| self.stage == Stage::Ended)?;
        Some((header, self.entries))
    }

    fn fill_block<'a>(&mut self, bytes: &'a [u8]) -> Result<&'a [u8], BundleError> {
        let (head, rest) = bytes.split_at(bytes.len().min(BLOCK_LEN - self.filled));
        self.block[self.filled..self.filled + head.len()].copy_from_slice(head);
        self.filled += head.len();
        if self.filled == BLOCK_LEN {
            self.filled = 0;
            self.stage = self.read_header()?;
        }
        Ok(rest)
    }

    /// Returns the stage after a whole header block: the end of the archive at the first zero block, else the entry it
    /// opens, whose order and size limit are checked before any of its bytes are read.
    fn read_header(&mut self) -> Result<Stage, BundleError> {
        if self.block.iter().all(|&byte| byte == 0) {
            self.order.check_complete()?;
            return Ok(Stage::EndBlock(BLOCK_LEN));
        }
        let (name, size) = parse_entry_header(&self.block)?;
        self.order.admit(name)?;
        if u64::from(size) > name.size_limit() {
            return Err(BundleError::EntrySize);
        }
        // The size is within the entry's limit, at most 1 MiB, so this allocation is bounded whatever the input says.
        let size = usize::try_from(size).map_err(|_| BundleError::EntrySize)?;
        self.body = Vec::with_capacity(size);
        match size {
            0 => self.complete(name, 0),
            _ => Ok(Stage::Body { name, size }),
        }
    }

    fn fill_body<'a>(&mut self, name: EntryName, size: usize, bytes: &'a [u8]) -> Result<&'a [u8], BundleError> {
        let (head, rest) = bytes.split_at(bytes.len().min(size - self.body.len()));
        self.body.extend_from_slice(head);
        if self.body.len() == size {
            self.stage = self.complete(name, size)?;
        }
        Ok(rest)
    }

    /// Stores a whole entry, checking the bundle header's fields as soon as its bytes are in.
    fn complete(&mut self, name: EntryName, size: usize) -> Result<Stage, BundleError> {
        let bytes = std::mem::take(&mut self.body);
        match name {
            EntryName::BundleHeader => self.order.set_header(BundleHeader::decode(&bytes)?),
            _ => {
                self.entries.insert(name, bytes);
            }
        }
        Ok(match padding_len(size) {
            0 => Stage::Header,
            due => Stage::Padding(due),
        })
    }

    /// Reads up to `due` bytes that must be zero, moving to `still` with the bytes left due, or to `then` once none are.
    fn skip_zeros<'a>(
        &mut self,
        bytes: &'a [u8],
        due: usize,
        error: BundleError,
        (still, then): (fn(usize) -> Stage, Stage),
    ) -> Result<&'a [u8], BundleError> {
        let (head, rest) = bytes.split_at(bytes.len().min(due));
        if head.iter().any(|&byte| byte != 0) {
            return Err(error);
        }
        self.stage = match due - head.len() {
            0 => then,
            left => still(left),
        };
        Ok(rest)
    }
}
