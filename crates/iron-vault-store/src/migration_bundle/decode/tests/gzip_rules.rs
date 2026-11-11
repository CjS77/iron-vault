//! One test per gzip framing rule of "One encoding per bundle".

use super::*;

fn altered(at: usize, byte: u8) -> Vec<u8> {
    let mut bundle = example_bundle();
    bundle[at] = byte;
    bundle
}

#[test]
fn each_gzip_flag_is_refused() {
    // FTEXT, FHCRC, FEXTRA, FNAME, FCOMMENT and the three reserved bits.
    (0..8).for_each(|bit| assert_eq!(decode(&altered(3, 1 << bit)), Err(BundleError::GzipFlags), "bit {bit}"));
}

#[test]
fn wrong_magic_or_method_is_refused() {
    [(0, 0x1e), (1, 0x8c), (2, 0), (2, 7)]
        .into_iter()
        .for_each(|(at, byte)| assert_eq!(decode(&altered(at, byte)), Err(BundleError::GzipHeader), "{at}"));
}

#[test]
fn modification_time_xfl_and_os_are_not_checked() {
    let mut bundle = example_bundle();
    bundle[4..10].copy_from_slice(&[0x12, 0x34, 0x56, 0x78, 2, 3]);
    assert_eq!(decode(&bundle), decode(&example_bundle()));
}

#[test]
fn malformed_deflate_is_refused() {
    // Block type 3 is reserved.
    assert_eq!(decode(&altered(10, 0xff)), Err(BundleError::Deflate));
}

#[test]
fn bad_crc_is_refused() {
    let at = example_bundle().len() - 8;
    assert_eq!(decode(&altered(at, example_bundle()[at] ^ 1)), Err(BundleError::GzipCrc));
}

#[test]
fn bad_isize_is_refused() {
    let at = example_bundle().len() - 4;
    assert_eq!(decode(&altered(at, example_bundle()[at] ^ 1)), Err(BundleError::GzipSize));
}

#[test]
fn bytes_after_the_member_are_refused() {
    let trailing = [example_bundle(), vec![0]].concat();
    assert_eq!(decode(&trailing), Err(BundleError::GzipTrailing));
    let second_member = [example_bundle(), gzip(b"x")].concat();
    assert_eq!(decode(&second_member), Err(BundleError::GzipTrailing));
    let twice = [example_bundle(), example_bundle()].concat();
    assert_eq!(decode_in(&twice, 7), Err(BundleError::GzipTrailing));
}

#[test]
fn every_truncation_is_refused() {
    let bundle = example_bundle();
    (0..bundle.len()).for_each(|len| assert_eq!(decode_in(&bundle[..len], 64), Err(BundleError::Truncated), "{len}"));
}
