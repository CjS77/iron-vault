// SPDX-License-Identifier: MPL-2.0
//! Frames each helper message: a `u32` big-endian length, at most [`MAX_FRAME_LEN`], then the body.
//!
//! The length comes first so a reader can refuse an oversized message before it allocates or reads the body.

use std::io::Read;

use zeroize::Zeroizing;

use crate::ProtocolError;

/// The longest frame body either side sends or reads. A sign request, the largest message, needs about 1 KiB.
pub const MAX_FRAME_LEN: usize = 8192;

/// Reads one frame's body from `reader`, refusing a length over [`MAX_FRAME_LEN`] before reading any of it.
///
/// The body is zeroized on drop because a request carries an authorization value.
pub fn read_frame(reader: &mut impl Read) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    let mut prefix = [0; 4];
    reader.read_exact(&mut prefix)?;
    let len = checked_len(u32::from_be_bytes(prefix) as usize)?;
    let mut body = Zeroizing::new(vec![0; len]);
    reader.read_exact(&mut body)?;
    Ok(body)
}

/// Prepends the length prefix to `body`, refusing a body over [`MAX_FRAME_LEN`].
pub(crate) fn framed(body: &[u8]) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    let len = checked_len(body.len())?;
    let mut out = Zeroizing::new(Vec::with_capacity(4 + len));
    out.extend_from_slice(&(len as u32).to_be_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

fn checked_len(len: usize) -> Result<usize, ProtocolError> {
    match len <= MAX_FRAME_LEN {
        true => Ok(len),
        false => Err(ProtocolError::TooLarge { len, limit: MAX_FRAME_LEN }),
    }
}
