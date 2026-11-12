//! Reads and writes the byte conventions every message and blob in this crate shares: big-endian integers, `u64`
//! length-prefixed fields, and no trailing bytes (`design/storage-formats.md` "Conventions").
//!
//! The conventions give each value exactly one encoding, so a decoder can refuse anything else.

use crate::ProtocolError;

/// A cursor over the unread rest of an encoding.
pub(crate) struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    /// Checks that `bytes` start with `magic` and `version`, then returns a reader positioned after them.
    pub(crate) fn with_header(bytes: &'a [u8], magic: [u8; 4], version: u8) -> Result<Self, ProtocolError> {
        let mut reader = Reader(bytes);
        if reader.array::<4>()? != magic {
            return Err(ProtocolError::WrongMagic);
        }
        match reader.u8()? {
            found if found == version => Ok(reader),
            found => Err(ProtocolError::UnsupportedVersion(found)),
        }
    }

    /// Reads the next `N` bytes as an array.
    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], ProtocolError> {
        let (head, rest) = self.0.split_first_chunk::<N>().ok_or(ProtocolError::Truncated)?;
        self.0 = rest;
        Ok(*head)
    }

    /// Reads the next byte.
    pub(crate) fn u8(&mut self) -> Result<u8, ProtocolError> {
        self.array().map(|[byte]| byte)
    }

    /// Reads a length-prefixed field. A length past the bytes left fails before anything is copied.
    pub(crate) fn field(&mut self) -> Result<Vec<u8>, ProtocolError> {
        let len = u64::from_be_bytes(self.array()?);
        let len = usize::try_from(len)
            .ok()
            .filter(|len| *len <= self.0.len())
            .ok_or(ProtocolError::LengthPastEnd)?;
        let (head, rest) = self.0.split_at(len);
        self.0 = rest;
        Ok(head.to_vec())
    }

    /// Succeeds only when every byte has been read, so an encoding has one spelling.
    pub(crate) fn finish(self) -> Result<(), ProtocolError> {
        match self.0.is_empty() {
            true => Ok(()),
            false => Err(ProtocolError::TrailingBytes),
        }
    }
}

/// Appends `bytes` as a field: its `u64` length, then the bytes.
pub(crate) fn put_field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}
