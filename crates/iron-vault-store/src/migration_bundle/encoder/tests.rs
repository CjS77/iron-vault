use std::io::Read;

use flate2::read::GzDecoder;

use super::*;
use crate::migration_bundle::ustar::BLOCK_LEN;
use crate::migration_bundle::{BUNDLE_HEADER_LEN, MAX_BUNDLE_LEN};
use crate::{MAX_APPROVERS, MAX_MANIFEST_ENTRIES, VaultId};

const VAULT: &str = "3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b";
const APPROVER: &str = "8d1c6f0e-2b7a-4c59-9e3d-5a4b3c2d1e0f";
const RECORD: &str = "7c9e6679-7425-40de-944b-e07fc1f90ae7";
const OTHER_ID: &str = "9b2d0c4a-1e3f-4a5b-8c6d-7e8f9a0b1c2d";

fn approver(id: &str) -> EntryName {
    EntryName::parse(format!("approver-{id}.age").as_bytes()).unwrap()
}

fn record(id: &str) -> EntryName {
    EntryName::parse(format!("record-{id}.age").as_bytes()).unwrap()
}

fn header(approvers: usize, records: usize) -> BundleHeader {
    let vault_id = VaultId::from_bytes(*uuid::Uuid::parse_str(VAULT).unwrap().as_bytes()).unwrap();
    BundleHeader::new(vault_id, approvers, records).unwrap()
}

/// The entries of [migration bundle v1, "Example"](../../../../../design/storage-formats.md#example-6), at its sizes, after the bundle
/// header.
fn example_entries() -> Vec<(EntryName, Vec<u8>)> {
    let config = b"schema_version = 1\n".to_vec();
    [
        (EntryName::ExportedIdentity, vec![0xa1; 256]),
        (EntryName::Manifest, vec![0xa2; 466]),
        (EntryName::ApprovalState, vec![0xa3; 546]),
        (EntryName::Config, config),
        (approver(APPROVER), vec![0xa4; 471]),
        (record(RECORD), vec![0xa5; 389]),
    ]
    .into()
}

fn encode(header: BundleHeader, entries: &[(EntryName, Vec<u8>)]) -> Result<Vec<u8>, EncodeError> {
    let mut encoder = BundleEncoder::new(Vec::new(), header)?;
    entries.iter().try_for_each(|(name, bytes)| encoder.write_entry(*name, bytes))?;
    encoder.finish()
}

fn gunzip(bundle: &[u8]) -> Vec<u8> {
    let mut archive = Vec::new();
    GzDecoder::new(bundle).read_to_end(&mut archive).unwrap();
    archive
}

fn text(bytes: &[u8]) -> &str {
    std::str::from_utf8(bytes).unwrap()
}

#[test]
fn example_archive_matches_the_documented_layout() {
    let archive = gunzip(&encode(header(1, 1), &example_entries()).unwrap());
    assert_eq!(archive.len(), 8_704);
    let expected = [
        (0, "bundle-header", "00000000045", Some("010356")),
        (1_024, "exported-identity.age", "00000000400", None),
        (2_048, "manifest.age", "00000000722", None),
        (3_072, "approval.age", "00000001042", None),
        (4_608, "config.toml", "00000000023", Some("010072")),
        (
            5_632,
            "approver-8d1c6f0e-2b7a-4c59-9e3d-5a4b3c2d1e0f.age",
            "00000000727",
            Some("015333"),
        ),
        (
            6_656,
            "record-7c9e6679-7425-40de-944b-e07fc1f90ae7.age",
            "00000000605",
            Some("014503"),
        ),
    ];
    expected.into_iter().for_each(|(offset, name, size, checksum)| {
        let block = &archive[offset..offset + BLOCK_LEN];
        assert_eq!(text(&block[..name.len()]), name);
        assert_eq!(block[name.len()], 0, "{name}");
        assert_eq!(text(&block[124..135]), size, "{name}");
        checksum
            .into_iter()
            .for_each(|checksum| assert_eq!(text(&block[148..154]), checksum, "{name}"));
    });
    assert_eq!(&archive[512..512 + BUNDLE_HEADER_LEN], header(1, 1).encode());
    assert!(archive[7_680..].iter().all(|&byte| byte == 0));
}

#[test]
fn padding_is_zero_bytes() {
    let archive = gunzip(&encode(header(1, 1), &example_entries()).unwrap());
    assert!(archive[512 + BUNDLE_HEADER_LEN..1_024].iter().all(|&byte| byte == 0));
    assert!(archive[3_584 + 546..4_608].iter().all(|&byte| byte == 0));
}

#[test]
fn gzip_header_has_no_flags_and_no_time() {
    let bundle = encode(header(1, 1), &example_entries()).unwrap();
    assert_eq!(bundle[..4], [0x1f, 0x8b, 8, 0]);
    assert_eq!(bundle[4..8], [0; 4]);
}

#[test]
fn same_entries_give_the_same_bytes() {
    let entries = example_entries();
    assert_eq!(encode(header(1, 1), &entries).unwrap(), encode(header(1, 1), &entries).unwrap());
}

fn refusal(header: BundleHeader, entries: &[(EntryName, Vec<u8>)]) -> EncodeError {
    encode(header, entries).unwrap_err()
}

fn with(entries: Vec<(EntryName, Vec<u8>)>, at: usize, entry: (EntryName, Vec<u8>)) -> Vec<(EntryName, Vec<u8>)> {
    let mut entries = entries;
    entries.insert(at, entry);
    entries
}

#[test]
fn entries_out_of_order_are_refused() {
    let mut swapped = example_entries();
    swapped.swap(1, 2);
    assert!(matches!(
        refusal(header(1, 1), &swapped),
        EncodeError::OutOfOrder(EntryName::ApprovalState)
    ));
    let repeated = with(example_entries(), 1, (EntryName::ExportedIdentity, vec![0; 256]));
    assert!(matches!(
        refusal(header(1, 1), &repeated),
        EncodeError::OutOfOrder(EntryName::ExportedIdentity)
    ));
    let second_header = with(example_entries(), 0, (EntryName::BundleHeader, header(1, 1).encode().to_vec()));
    assert!(matches!(
        refusal(header(1, 1), &second_header),
        EncodeError::OutOfOrder(EntryName::BundleHeader)
    ));
}

#[test]
fn missing_config_is_refused() {
    let entries: Vec<_> = example_entries()
        .into_iter()
        .filter(|(name, _)| *name != EntryName::Config)
        .collect();
    assert!(matches!(
        refusal(header(1, 1), &entries),
        EncodeError::OutOfOrder(EntryName::Approver(_))
    ));
}

#[test]
fn repeated_approver_or_record_is_refused() {
    let approver_twice = with(example_entries(), 5, (approver(APPROVER), vec![0; 10]));
    assert!(matches!(
        refusal(header(2, 1), &approver_twice),
        EncodeError::OutOfOrder(EntryName::Approver(_))
    ));
    let record_twice = with(example_entries(), 6, (record(RECORD), vec![0; 10]));
    assert!(matches!(
        refusal(header(1, 2), &record_twice),
        EncodeError::OutOfOrder(EntryName::Record(_))
    ));
    let descending = with(example_entries(), 5, (record(OTHER_ID), vec![0; 10]));
    assert!(matches!(
        refusal(header(1, 2), &descending),
        EncodeError::OutOfOrder(EntryName::Record(_))
    ));
}

#[test]
fn counts_that_differ_from_the_header_are_refused() {
    assert!(matches!(
        refusal(header(1, 0), &example_entries()),
        EncodeError::Extra(EntryName::Record(_))
    ));
    assert!(matches!(refusal(header(1, 2), &example_entries()), EncodeError::Incomplete));
    assert!(matches!(
        refusal(header(2, 1), &example_entries()),
        EncodeError::OutOfOrder(EntryName::Record(_))
    ));
    let through_approver = &example_entries()[..5];
    assert!(matches!(refusal(header(2, 0), through_approver), EncodeError::Incomplete));
    let extra_approver = with(through_approver.to_vec(), 5, (approver(OTHER_ID), vec![0; 10]));
    assert!(matches!(
        refusal(header(1, 0), &extra_approver),
        EncodeError::Extra(EntryName::Approver(_))
    ));
}

#[test]
fn entry_over_its_limit_is_refused() {
    let mut entries = example_entries();
    entries[3].1 = vec![b'#'; 61_441];
    let error = refusal(header(1, 1), &entries);
    assert!(matches!(
        error,
        EncodeError::TooLarge {
            entry: EntryName::Config,
            len: 61_441,
            limit: 61_440
        }
    ));
    let mut entries = example_entries();
    entries[0].1 = vec![0; 1_024];
    assert!(encode(header(1, 1), &entries).is_ok());
}

#[test]
fn full_bundle_archive_fits_the_bundle_limit() {
    let blocks = |limit: u64| (1 + limit.div_ceil(BLOCK_LEN as u64)) * BLOCK_LEN as u64;
    let fixed = [
        EntryName::BundleHeader,
        EntryName::ExportedIdentity,
        EntryName::Manifest,
        EntryName::ApprovalState,
        EntryName::Config,
    ];
    let fixed_len: u64 = fixed.iter().map(|name| blocks(name.size_limit())).sum();
    let approvers = MAX_APPROVERS as u64 * blocks(approver(APPROVER).size_limit());
    let records = MAX_MANIFEST_ENTRIES as u64 * blocks(record(RECORD).size_limit());
    let archive = fixed_len + approvers + records + END_OF_ARCHIVE.len() as u64;
    assert_eq!(archive, 271_692_800);
    let stored_gzip_overhead = 18 + 5 * archive.div_ceil(65_535);
    assert!(archive + stored_gzip_overhead <= MAX_BUNDLE_LEN);
}
