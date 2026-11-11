//! The one ustar entry header form the migration bundle uses: every field fixed except the name, size and checksum.

use super::EntryName;

/// The ustar block size: each header is one block, and each entry's bytes are padded with zero bytes to a whole block.
pub(crate) const BLOCK_LEN: usize = 512;

/// The two zero blocks that end the archive.
pub(crate) const END_OF_ARCHIVE: [u8; 2 * BLOCK_LEN] = [0; 2 * BLOCK_LEN];

const NAME_LEN: usize = 100;
const MODE: (usize, &[u8]) = (100, b"0000600\0");
const UID: (usize, &[u8]) = (108, b"0000000\0");
const GID: (usize, &[u8]) = (116, b"0000000\0");
const SIZE_AT: usize = 124;
const MTIME: (usize, &[u8]) = (136, b"00000000000\0");
const CHECKSUM_AT: usize = 148;
const TYPE_REGULAR_FILE: (usize, &[u8]) = (156, b"0");
const MAGIC: (usize, &[u8]) = (257, b"ustar\0");
const VERSION: (usize, &[u8]) = (263, b"00");

/// The ustar header the bundle encoder writes for the entry `name` holding `size` bytes, checksum included.
///
/// The decoder requires each header it reads to equal this one for the name and size it parsed, so this function is
/// the format's only definition of an entry header. A `u32` size always fits the 11 octal digits of the size field.
pub(crate) fn entry_header(name: &EntryName, size: u32) -> [u8; BLOCK_LEN] {
    ustar_header(name.to_string().as_bytes(), size)
}

/// Every entry name is at most [`NAME_LEN`] bytes (the longest, an approver's, is 49), so no name is ever cut here.
fn ustar_header(name: &[u8], size: u32) -> [u8; BLOCK_LEN] {
    let mut header = [0; BLOCK_LEN];
    header[..NAME_LEN].iter_mut().zip(name).for_each(|(slot, byte)| *slot = *byte);
    [MODE, UID, GID, MTIME, TYPE_REGULAR_FILE, MAGIC, VERSION]
        .into_iter()
        .for_each(|(at, value)| put(&mut header, at, value));
    // The size field's terminating zero byte is already in place.
    put(&mut header, SIZE_AT, &octal::<11>(size));
    put(&mut header, CHECKSUM_AT, b"        ");
    let checksum = header.iter().map(|&byte| u32::from(byte)).sum();
    put(&mut header, CHECKSUM_AT, &[octal::<6>(checksum).as_slice(), b"\0 "].concat());
    header
}

fn put(header: &mut [u8; BLOCK_LEN], at: usize, value: &[u8]) {
    header[at..].iter_mut().zip(value).for_each(|(slot, byte)| *slot = *byte);
}

/// `value` in `N` zero-padded octal digits. Callers pass values that fit: a `u32` size in 11 digits, and a checksum of
/// at most 512 × 255 = 0o377000 in 6.
fn octal<const N: usize>(value: u32) -> [u8; N] {
    std::array::from_fn(|i| b'0' + ((u64::from(value) >> (3 * (N - 1 - i))) & 7) as u8)
}

/// How many zero bytes follow an entry of `size` bytes to fill its last block.
pub(crate) fn padding_len(size: usize) -> usize {
    (BLOCK_LEN - size % BLOCK_LEN) % BLOCK_LEN
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(header: &[u8; BLOCK_LEN], at: usize, len: usize) -> &[u8] {
        &header[at..at + len]
    }

    #[test]
    fn fixed_fields_match_the_entry_header_table() {
        let header = entry_header(&EntryName::Config, 19);
        assert_eq!(field(&header, 0, 12), b"config.toml\0");
        assert!(field(&header, 11, 89).iter().all(|&byte| byte == 0));
        assert_eq!(field(&header, 100, 8), b"0000600\0");
        assert_eq!(field(&header, 108, 8), b"0000000\0");
        assert_eq!(field(&header, 116, 8), b"0000000\0");
        assert_eq!(field(&header, 124, 12), b"00000000023\0");
        assert_eq!(field(&header, 136, 12), b"00000000000\0");
        assert_eq!(field(&header, 148, 8), b"010072\0 ");
        assert_eq!(field(&header, 156, 1), b"0");
        assert!(field(&header, 157, 100).iter().all(|&byte| byte == 0));
        assert_eq!(field(&header, 257, 8), b"ustar\x0000");
        assert!(field(&header, 265, 247).iter().all(|&byte| byte == 0));
    }

    #[test]
    fn largest_size_fills_the_size_field() {
        let header = entry_header(&EntryName::Manifest, u32::MAX);
        assert_eq!(field(&header, 124, 12), b"37777777777\0");
    }

    #[test]
    fn hundred_byte_name_fills_the_name_field() {
        let name = [b'n'; NAME_LEN];
        let header = ustar_header(&name, 0);
        assert_eq!(field(&header, 0, NAME_LEN), name);
        assert_eq!(field(&header, 100, 8), b"0000600\0");
    }

    #[test]
    fn padding_fills_the_last_block() {
        [(0, 0), (1, 511), (37, 475), (512, 0), (546, 478)]
            .into_iter()
            .for_each(|(size, padding)| assert_eq!(padding_len(size), padding, "{size}"));
    }
}
