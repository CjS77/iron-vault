//! One test per ustar, order and bundle header rule of
//! [migration bundle v1, "One encoding per bundle"](../../../../../../design/storage-formats.md#one-encoding-per-bundle).

use super::*;

const MANIFEST_AT: usize = 2_048;

fn example_archive() -> Vec<u8> {
    gunzip(&example_bundle())
}

/// Returns the refusal of the example archive with the header block at `at` changed by `change`, checksum recomputed.
fn block_refusal(at: usize, change: impl FnOnce(&mut [u8])) -> BundleError {
    let mut archive = example_archive();
    let block = &mut archive[at..at + BLOCK_LEN];
    change(block);
    rechecksum(block);
    archive_refusal(&archive)
}

fn named(name: &[u8]) -> impl FnOnce(&mut [u8]) {
    move |block: &mut [u8]| {
        block[..100].fill(0);
        block[..name.len()].copy_from_slice(name);
    }
}

fn typed(kind: u8) -> impl FnOnce(&mut [u8]) {
    move |block: &mut [u8]| block[156] = kind
}

#[test]
fn names_outside_the_list_are_refused() {
    [
        b"/manifest.age".as_slice(),
        b"../manifest.age",
        b"./manifest.age",
        b"state/manifest.age",
        b"operational.age",
        b"PaxHeaders.0/manifest.age",
        b"././@LongLink",
        b"MANIFEST.AGE",
    ]
    .into_iter()
    .for_each(|name| assert_eq!(block_refusal(MANIFEST_AT, named(name)), BundleError::EntryName, "{name:?}"));
}

#[test]
fn other_entry_types_are_refused() {
    // Hard link, symlink, character and block device, directory, FIFO, contiguous file, pax, pax global, GNU long
    // name and long link, and the old-style regular file.
    [b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'x', b'g', b'L', b'K', 0]
        .into_iter()
        .for_each(|kind| assert_eq!(block_refusal(MANIFEST_AT, typed(kind)), BundleError::EntryHeader, "{kind}"));
}

#[test]
fn links_and_devices_with_their_fields_are_refused() {
    let symlink = |block: &mut [u8]| {
        block[156] = b'2';
        block[157..169].copy_from_slice(b"/etc/passwd\0");
    };
    assert_eq!(block_refusal(MANIFEST_AT, symlink), BundleError::EntryHeader);
    let device = |block: &mut [u8]| {
        block[156] = b'3';
        block[329..337].copy_from_slice(b"0000001\0");
    };
    assert_eq!(block_refusal(MANIFEST_AT, device), BundleError::EntryHeader);
}

#[test]
fn each_wrong_fixed_field_is_refused() {
    let fields: [(&str, usize, &[u8]); 14] = [
        ("mode", 100, b"0000644\0"),
        ("uid", 108, b"0001750\0"),
        ("gid", 116, b"0001750\0"),
        ("mtime", 136, b"14567721650\0"),
        ("link name", 157, b"x"),
        ("magic", 257, b"ustar "),
        ("gnu magic", 257, b"ustar  \0"),
        ("version", 263, b"01"),
        ("user name", 265, b"root"),
        ("group name", 297, b"root"),
        ("device major", 329, b"0000000\0"),
        ("device minor", 337, b"0000000\0"),
        ("prefix", 345, b"state"),
        ("padding", 511, b"\x01"),
    ];
    fields.into_iter().for_each(|(field, at, value)| {
        let change = |block: &mut [u8]| block[at..at + value.len()].copy_from_slice(value);
        assert_eq!(block_refusal(MANIFEST_AT, change), BundleError::EntryHeader, "{field}");
    });
}

#[test]
fn other_spellings_of_the_size_and_name_are_refused() {
    let spellings: [(&str, usize, &[u8]); 4] = [
        ("size without its zero byte", 135, b" "),
        ("size with a space", 124, b" 0000000722\0"),
        ("size with a non-octal digit", 124, b"00000000822\0"),
        ("NUL inside the name", 13, b"x"),
    ];
    spellings.into_iter().for_each(|(spelling, at, value)| {
        let change = |block: &mut [u8]| block[at..at + value.len()].copy_from_slice(value);
        assert_eq!(block_refusal(MANIFEST_AT, change), BundleError::EntryHeader, "{spelling}");
    });
}

#[test]
fn bad_checksum_is_refused() {
    let mut archive = example_archive();
    archive[MANIFEST_AT + 150] ^= 1;
    assert_eq!(archive_refusal(&archive), BundleError::EntryHeader);
    // The same sum in another spelling: seven digits, as some writers use, instead of six, a zero byte and a space.
    let mut archive = example_archive();
    let checksum = archive[MANIFEST_AT + 148..MANIFEST_AT + 154].to_vec();
    archive[MANIFEST_AT + 148..MANIFEST_AT + 156].copy_from_slice(&[b"0", checksum.as_slice(), b"\0"].concat());
    assert_eq!(archive_refusal(&archive), BundleError::EntryHeader);
}

#[test]
fn oversized_entries_are_refused_from_the_header() {
    let oversized = [
        (EntryName::BundleHeader, 38),
        (EntryName::Config, 61_441),
        (record(RECORD), 65_537),
        (EntryName::Manifest, u32::MAX),
    ];
    oversized.into_iter().for_each(|(name, size)| {
        let entries = with_header(header(1, 1), example_entries());
        let at = entries.iter().position(|(entry, _)| *entry == name).unwrap();
        // The header alone is enough: the entry's bytes never arrive.
        let mut archive = raw_archive(&entries[..at]);
        archive.truncate(archive.len() - END_OF_ARCHIVE.len());
        archive.extend_from_slice(&entry_header(&name, size));
        let mut decoder = BundleDecoder::new();
        assert_eq!(decoder.push(&gzip(&archive)), Err(BundleError::EntrySize), "{name}");
    });
}

fn order_refusal(header: BundleHeader, entries: Vec<(EntryName, Vec<u8>)>) -> BundleError {
    archive_refusal(&raw_archive(&with_header(header, entries)))
}

fn with(entries: Vec<(EntryName, Vec<u8>)>, at: usize, entry: (EntryName, Vec<u8>)) -> Vec<(EntryName, Vec<u8>)> {
    let mut entries = entries;
    entries.insert(at, entry);
    entries
}

#[test]
fn raw_archive_of_the_example_entries_is_accepted() {
    assert_eq!(raw_archive(&with_header(header(1, 1), example_entries())), example_archive());
}

#[test]
fn entries_out_of_order_are_refused() {
    let mut swapped = example_entries();
    swapped.swap(1, 2);
    assert_eq!(order_refusal(header(1, 1), swapped), BundleError::EntryOrder);
    let without_config = [&example_entries()[..3], &example_entries()[4..]].concat();
    assert_eq!(order_refusal(header(1, 1), without_config), BundleError::EntryOrder);
    let header_last = [example_entries(), vec![(EntryName::BundleHeader, header(1, 1).encode().to_vec())]].concat();
    assert_eq!(archive_refusal(&raw_archive(&header_last)), BundleError::EntryOrder);
    let descending = with(example_entries(), 5, (record(SECOND_ID), vec![0; 10]));
    assert_eq!(order_refusal(header(1, 2), descending), BundleError::EntryOrder);
    let approver_after_record = with(example_entries(), 6, (approver(SECOND_ID), vec![0; 10]));
    assert_eq!(order_refusal(header(1, 1), approver_after_record), BundleError::EntryOrder);
}

#[test]
fn duplicates_are_refused() {
    let manifest_twice = with(example_entries(), 2, (EntryName::Manifest, vec![0; 10]));
    assert_eq!(order_refusal(header(1, 1), manifest_twice), BundleError::EntryOrder);
    let approver_twice = with(example_entries(), 5, (approver(APPROVER), vec![0; 10]));
    assert_eq!(order_refusal(header(2, 1), approver_twice), BundleError::EntryOrder);
    let record_twice = with(example_entries(), 6, (record(RECORD), vec![0; 10]));
    assert_eq!(order_refusal(header(1, 2), record_twice), BundleError::EntryOrder);
    let header_twice = with(example_entries(), 0, (EntryName::BundleHeader, header(1, 1).encode().to_vec()));
    assert_eq!(order_refusal(header(1, 1), header_twice), BundleError::EntryOrder);
}

#[test]
fn counts_that_differ_from_the_header_are_refused() {
    [(2, 1), (1, 2), (1, 0)].into_iter().for_each(|(approvers, records)| {
        assert_eq!(
            order_refusal(header(approvers, records), example_entries()),
            BundleError::EntryCount,
            "{approvers} {records}"
        );
    });
    let extra_approver = with(example_entries(), 5, (approver(SECOND_ID), vec![0; 10]));
    assert_eq!(order_refusal(header(1, 1), extra_approver), BundleError::EntryCount);
    let no_records = example_entries()[..5].to_vec();
    assert_eq!(order_refusal(header(1, 1), no_records), BundleError::EntryCount);
    assert!(decode(&gzip(&raw_archive(&with_header(header(1, 0), example_entries()[..5].to_vec())))).is_ok());
}

#[test]
fn an_empty_or_cut_archive_is_refused() {
    assert_eq!(archive_refusal(&END_OF_ARCHIVE), BundleError::EntryOrder);
    let through_manifest = raw_archive(&with_header(header(1, 1), example_entries()[..2].to_vec()));
    assert_eq!(archive_refusal(&through_manifest), BundleError::EntryOrder);
}

fn header_refusal(at: usize, byte: u8) -> BundleError {
    let mut bytes = header(1, 1).encode().to_vec();
    bytes[at] = byte;
    archive_refusal(&raw_archive(&[vec![(EntryName::BundleHeader, bytes)], example_entries()].concat()))
}

#[test]
fn bad_bundle_headers_are_refused() {
    assert_eq!(header_refusal(0, b'X'), BundleError::HeaderMagic);
    assert_eq!(header_refusal(4, 2), BundleError::HeaderVersion);
    assert_eq!(header_refusal(11, 0x1e), BundleError::HeaderVaultId);
    assert_eq!(header_refusal(28, 0), BundleError::HeaderCount);
    assert_eq!(header_refusal(28, 17), BundleError::HeaderCount);
    assert_eq!(header_refusal(35, 0x10), BundleError::HeaderCount);
    let short = [
        vec![(EntryName::BundleHeader, header(1, 1).encode()[..36].to_vec())],
        example_entries(),
    ]
    .concat();
    assert_eq!(archive_refusal(&raw_archive(&short)), BundleError::HeaderLength);
}

#[test]
fn bundle_header_is_checked_before_the_next_entry() {
    let mut bytes = header(1, 1).encode().to_vec();
    bytes[0] = b'X';
    let mut archive = raw_archive(&[(EntryName::BundleHeader, bytes)]);
    archive.truncate(BLOCK_LEN + BUNDLE_HEADER_LEN);
    let mut decoder = BundleDecoder::new();
    assert_eq!(decoder.push(&gzip(&archive)), Err(BundleError::HeaderMagic));
}

#[test]
fn non_zero_padding_is_refused() {
    let mut archive = example_archive();
    archive[BLOCK_LEN + BUNDLE_HEADER_LEN] = 1;
    assert_eq!(archive_refusal(&archive), BundleError::Padding);
    let mut archive = example_archive();
    archive[EXAMPLE_CONFIG_AT + 2 * BLOCK_LEN - 1] = 1;
    assert_eq!(archive_refusal(&archive), BundleError::Padding);
}

#[test]
fn a_missing_end_block_is_refused() {
    let archive = example_archive();
    assert_eq!(archive_refusal(&archive[..archive.len() - BLOCK_LEN]), BundleError::Truncated);
    assert_eq!(archive_refusal(&archive[..EXAMPLE_END_AT]), BundleError::Truncated);
}

#[test]
fn a_non_zero_second_end_block_is_refused() {
    let mut archive = example_archive();
    archive[EXAMPLE_END_AT + BLOCK_LEN + 100] = 1;
    assert_eq!(archive_refusal(&archive), BundleError::EndOfArchive);
}

#[test]
fn bytes_after_the_archive_are_refused() {
    let archive = example_archive();
    assert_eq!(archive_refusal(&[archive.as_slice(), &[0]].concat()), BundleError::ArchiveTrailing);
    assert_eq!(
        archive_refusal(&[archive.as_slice(), &END_OF_ARCHIVE].concat()),
        BundleError::ArchiveTrailing
    );
    let extra_entry = [archive.as_slice(), &entry_header(&EntryName::Config, 0)].concat();
    assert_eq!(archive_refusal(&extra_entry), BundleError::ArchiveTrailing);
}
