//! The cursor every store payload decoder reads with (spec §3.10, `design/storage-formats.md`).
//!
//! The record, manifest, approval and approval state encodings share one layout vocabulary: fixed-width fields,
//! big-endian integers and `u64` length prefixes. They read it through this one reader, so a bounds check fixed here is
//! fixed for every file a planted copy could reach. Each decoder maps [`WireError`] into its own error once, with a
//! `From` impl, so its public variants stay its own.

/// Why the bytes could not be read as the layout asked for. Each decoder reports these as its own variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WireError {
    /// The bytes end inside a fixed-width field.
    Truncated,
    /// A length prefix or count is larger than the bytes left.
    LengthPastEnd,
    /// Bytes follow the last field.
    TrailingBytes,
}

/// The unread rest of an encoding. Every read borrows from the input, so nothing is copied until the caller asks.
pub(crate) struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    /// A reader positioned at the start of `bytes`.
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Reader(bytes)
    }

    /// The next `n` bytes.
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let (head, rest) = self.0.split_at_checked(n).ok_or(WireError::Truncated)?;
        self.0 = rest;
        Ok(head)
    }

    /// The next `N` bytes as an array, for IDs, digests and integers.
    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        let (head, rest) = self.0.split_first_chunk::<N>().ok_or(WireError::Truncated)?;
        self.0 = rest;
        Ok(*head)
    }

    /// The next byte.
    pub(crate) fn u8(&mut self) -> Result<u8, WireError> {
        self.array().map(|[byte]| byte)
    }

    /// The next two bytes as a big-endian `u16`.
    pub(crate) fn u16(&mut self) -> Result<u16, WireError> {
        self.array().map(u16::from_be_bytes)
    }

    /// The next eight bytes as a big-endian `u64`.
    pub(crate) fn u64(&mut self) -> Result<u64, WireError> {
        self.array().map(u64::from_be_bytes)
    }

    /// A `u64` length prefix or count. Either is refused when it exceeds the bytes left, since a field's bytes follow
    /// its prefix and every counted item takes at least one byte, so a huge value fails here rather than driving a
    /// long loop or a large slice.
    pub(crate) fn len(&mut self) -> Result<usize, WireError> {
        let len = self.u64()?;
        usize::try_from(len)
            .ok()
            .filter(|len| *len <= self.0.len())
            .ok_or(WireError::LengthPastEnd)
    }

    /// A length-prefixed field. A length past the bytes left fails before anything is read.
    pub(crate) fn field(&mut self) -> Result<&'a [u8], WireError> {
        let len = self.len()?;
        self.take(len)
    }

    /// Succeeds only when every byte has been read, so an encoding has no second spelling with extra bytes on the end.
    pub(crate) fn finish(&self) -> Result<(), WireError> {
        match self.0.is_empty() {
            true => Ok(()),
            false => Err(WireError::TrailingBytes),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_width_reads_are_big_endian_and_refuse_short_input() {
        let mut reader = Reader::new(&[1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3]);
        assert_eq!(reader.u8(), Ok(1));
        assert_eq!(reader.u16(), Ok(2));
        assert_eq!(reader.u64(), Ok(3));
        assert_eq!(reader.u8(), Err(WireError::Truncated));
        assert_eq!(Reader::new(&[0; 7]).u64(), Err(WireError::Truncated));
        assert_eq!(Reader::new(&[0; 3]).take(4), Err(WireError::Truncated));
    }

    #[test]
    fn a_length_past_the_bytes_left_is_refused_before_any_slice() {
        let field = [&2u64.to_be_bytes()[..], b"ab"].concat();
        assert_eq!(Reader::new(&field).field(), Ok(&b"ab"[..]));
        assert_eq!(Reader::new(&field[..9]).field(), Err(WireError::LengthPastEnd));
        assert_eq!(Reader::new(&u64::MAX.to_be_bytes()).len(), Err(WireError::LengthPastEnd));
        assert_eq!(Reader::new(&field[..7]).len(), Err(WireError::Truncated));
    }

    #[test]
    fn finish_refuses_trailing_bytes() {
        let mut reader = Reader::new(&[7, 8]);
        assert_eq!(reader.u8(), Ok(7));
        assert_eq!(reader.finish(), Err(WireError::TrailingBytes));
        assert_eq!(reader.u8(), Ok(8));
        assert_eq!(reader.finish(), Ok(()));
    }
}
