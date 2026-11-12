//! The gzip framing, parsed by hand: one member with a flagless header, raw deflate and a checked trailer.
//!
//! A general gzip reader accepts file names, comments, extra fields and further members; the bundle allows none
//! ([migration bundle v1, "One encoding per bundle"](../../../../../design/storage-formats.md#one-encoding-per-bundle)).
//! Parsing the ten header bytes here keeps the inflater fed incrementally with nothing buffered whole.

use flate2::{Crc, Decompress, FlushDecompress, Status};

use super::BundleError;
use super::archive::ArchiveReader;

const HEADER_LEN: usize = 10;
const TRAILER_LEN: usize = 8;
const MAGIC: [u8; 2] = [0x1f, 0x8b];
const METHOD_DEFLATE: u8 = 8;

/// The inflate buffer: each piece of archive is handed on before the next is inflated, so this bounds the decoder's
/// own working memory at any compression ratio.
const OUT_LEN: usize = 32 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    Header,
    Body,
    Trailer,
    Done,
}

/// The gzip member's state, counting the compressed bytes and the inflated archive against one bound.
pub(super) struct GzipReader {
    stage: Stage,
    fixed: [u8; HEADER_LEN],
    filled: usize,
    inflate: Decompress,
    crc: Crc,
    out: Vec<u8>,
    compressed: u64,
    max_len: u64,
}

impl GzipReader {
    pub(super) fn new(max_len: u64) -> Self {
        Self {
            stage: Stage::Header,
            fixed: [0; HEADER_LEN],
            filled: 0,
            inflate: Decompress::new(false),
            crc: Crc::new(),
            out: vec![0; OUT_LEN],
            compressed: 0,
            max_len,
        }
    }

    /// Reads the next compressed bytes, handing each inflated piece to `archive` as it comes out.
    pub(super) fn push(&mut self, bytes: &[u8], archive: &mut ArchiveReader) -> Result<(), BundleError> {
        self.compressed = self.compressed.saturating_add(bytes.len() as u64);
        if self.compressed > self.max_len {
            return Err(BundleError::TooLarge);
        }
        let mut rest = bytes;
        while !rest.is_empty() {
            rest = match self.stage {
                Stage::Header => self.read_header(rest)?,
                Stage::Body => self.inflate(rest, archive)?,
                Stage::Trailer => self.read_trailer(rest)?,
                Stage::Done => return Err(BundleError::GzipTrailing),
            };
        }
        Ok(())
    }

    /// Refuses a member whose trailer has not been read.
    pub(super) fn finish(&self) -> Result<(), BundleError> {
        (self.stage == Stage::Done).then_some(()).ok_or(BundleError::Truncated)
    }

    /// Copies bytes toward the `len`-byte header or trailer, returning what is left and whether it is now whole.
    fn fill<'a>(&mut self, bytes: &'a [u8], len: usize) -> (&'a [u8], bool) {
        let (head, rest) = bytes.split_at(bytes.len().min(len - self.filled));
        self.fixed[self.filled..self.filled + head.len()].copy_from_slice(head);
        self.filled += head.len();
        (rest, self.filled == len)
    }

    fn read_header<'a>(&mut self, bytes: &'a [u8]) -> Result<&'a [u8], BundleError> {
        let (rest, whole) = self.fill(bytes, HEADER_LEN);
        if whole {
            check_header(&self.fixed)?;
            self.filled = 0;
            self.stage = Stage::Body;
        }
        Ok(rest)
    }

    fn read_trailer<'a>(&mut self, bytes: &'a [u8]) -> Result<&'a [u8], BundleError> {
        let (rest, whole) = self.fill(bytes, TRAILER_LEN);
        if whole {
            let [c0, c1, c2, c3, s0, s1, s2, s3, ..] = self.fixed;
            if u32::from_le_bytes([c0, c1, c2, c3]) != self.crc.sum() {
                return Err(BundleError::GzipCrc);
            }
            // ISIZE is the archive's length modulo 2^32, as RFC 1952 defines it.
            if u32::from_le_bytes([s0, s1, s2, s3]) != self.crc.amount() {
                return Err(BundleError::GzipSize);
            }
            self.stage = Stage::Done;
        }
        Ok(rest)
    }

    /// Inflates until `input` is used up with no output pending, or the deflate stream ends; returns what follows it.
    fn inflate<'a>(&mut self, mut input: &'a [u8], archive: &mut ArchiveReader) -> Result<&'a [u8], BundleError> {
        loop {
            let room = self.room();
            let (consumed, produced, status) = self.inflate_once(input, room)?;
            input = input.get(consumed..).ok_or(BundleError::Deflate)?;
            let output = self.out.get(..produced).ok_or(BundleError::Deflate)?;
            self.crc.update(output);
            archive.feed(output)?;
            if status == Status::StreamEnd {
                archive.check_ended()?;
                self.stage = Stage::Trailer;
                return Ok(input);
            }
            if produced == 0 && consumed == 0 {
                // No progress with input left would drop bytes unread; refuse rather than skip them.
                return input.is_empty().then_some(input).ok_or(BundleError::Deflate);
            }
            if input.is_empty() && produced < room {
                return Ok(input);
            }
        }
    }

    /// Makes one inflate call into the first `room` bytes of the buffer, refusing an archive past the bound.
    fn inflate_once(&mut self, input: &[u8], room: usize) -> Result<(usize, usize, Status), BundleError> {
        let (in_before, out_before) = (self.inflate.total_in(), self.inflate.total_out());
        let out = self.out.get_mut(..room).ok_or(BundleError::Deflate)?;
        let status = self
            .inflate
            .decompress(input, out, FlushDecompress::None)
            .map_err(|_| BundleError::Deflate)?;
        if self.inflate.total_out() > self.max_len {
            return Err(BundleError::TooLarge);
        }
        let consumed = usize::try_from(self.inflate.total_in() - in_before).map_err(|_| BundleError::Deflate)?;
        let produced = usize::try_from(self.inflate.total_out() - out_before).map_err(|_| BundleError::Deflate)?;
        Ok((consumed, produced, status))
    }

    /// Returns how many archive bytes have been inflated, for the bound tests.
    #[cfg(test)]
    pub(super) fn archive_len(&self) -> u64 {
        self.inflate.total_out()
    }

    /// Returns the output room for one call: at most one byte past the bound, so an archive that passes it is refused at
    /// once.
    fn room(&self) -> usize {
        let left = self.max_len.saturating_sub(self.inflate.total_out()).saturating_add(1);
        usize::try_from(left).map_or(OUT_LEN, |left| left.min(OUT_LEN))
    }
}

/// Checks the gzip header: the magic and method must be gzip's deflate, and no flag may be set. The modification time,
/// XFL and OS bytes do not change the archive, so they are not checked.
fn check_header(header: &[u8; HEADER_LEN]) -> Result<(), BundleError> {
    let [m0, m1, method, flags, ..] = *header;
    if [m0, m1] != MAGIC || method != METHOD_DEFLATE {
        return Err(BundleError::GzipHeader);
    }
    (flags == 0).then_some(()).ok_or(BundleError::GzipFlags)
}
