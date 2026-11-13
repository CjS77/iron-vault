// SPDX-License-Identifier: MPL-2.0
use std::io::{Read, Write};

use flate2::read::GzDecoder;
use flate2::{Compression, GzBuilder};
use proptest::prelude::*;

use super::*;
use crate::VaultId;
use crate::migration_bundle::ustar::{BLOCK_LEN, END_OF_ARCHIVE, entry_header, padding_len};
use crate::migration_bundle::{BUNDLE_HEADER_LEN, BundleEncoder};

mod archive_rules;
mod gzip_rules;

const VAULT: &str = "3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b";
const APPROVER: &str = "8d1c6f0e-2b7a-4c59-9e3d-5a4b3c2d1e0f";
const RECORD: &str = "7c9e6679-7425-40de-944b-e07fc1f90ae7";
const SECOND_ID: &str = "9b2d0c4a-1e3f-4a5b-8c6d-7e8f9a0b1c2d";
const THIRD_ID: &str = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";

/// The archive offsets of the example bundle's header blocks, from
/// [migration bundle v1, "Example"](../../../../../design/storage-formats.md#example-6).
const EXAMPLE_HEADERS: [usize; 7] = [0, 1_024, 2_048, 3_072, 4_608, 5_632, 6_656];
const EXAMPLE_CONFIG_AT: usize = 4_608;
const EXAMPLE_END_AT: usize = 7_680;

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

/// Bytes that do not compress, so compressed and archive offsets stay close.
fn noise(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[0]
        })
        .collect()
}

/// The entries of [migration bundle v1, "Example"](../../../../../design/storage-formats.md#example-6), at its sizes,
/// after the bundle header.
fn example_entries() -> Vec<(EntryName, Vec<u8>)> {
    vec![
        (EntryName::ExportedIdentity, noise(1, 256)),
        (EntryName::Manifest, noise(2, 466)),
        (EntryName::ApprovalState, noise(3, 546)),
        (EntryName::Config, b"schema_version = 1\n".to_vec()),
        (approver(APPROVER), noise(4, 471)),
        (record(RECORD), noise(5, 389)),
    ]
}

/// A larger bundle: two approvers and three records, one empty and one at the record size limit.
fn larger_entries() -> Vec<(EntryName, Vec<u8>)> {
    let mut entries = example_entries();
    entries.truncate(5);
    entries.extend([
        (approver(SECOND_ID), noise(6, 2048)),
        (record(RECORD), noise(7, 65_536)),
        (record(SECOND_ID), Vec::new()),
        (record(THIRD_ID), noise(8, 1_000)),
    ]);
    entries
}

fn encode(header: BundleHeader, entries: &[(EntryName, Vec<u8>)]) -> Vec<u8> {
    let mut encoder = BundleEncoder::new(Vec::new(), header).unwrap();
    entries.iter().for_each(|(name, bytes)| encoder.write_entry(*name, bytes).unwrap());
    encoder.finish().unwrap()
}

fn example_bundle() -> Vec<u8> {
    encode(header(1, 1), &example_entries())
}

fn gunzip(bundle: &[u8]) -> Vec<u8> {
    let mut archive = Vec::new();
    GzDecoder::new(bundle).read_to_end(&mut archive).unwrap();
    archive
}

fn gzip(archive: &[u8]) -> Vec<u8> {
    let mut encoder = GzBuilder::new().mtime(0).write(Vec::new(), Compression::fast());
    encoder.write_all(archive).unwrap();
    encoder.finish().unwrap()
}

/// Builds an archive of these entries in the order given, without the encoder's order checks, and the end blocks.
fn raw_archive(entries: &[(EntryName, Vec<u8>)]) -> Vec<u8> {
    let mut archive: Vec<u8> = entries
        .iter()
        .flat_map(|(name, bytes)| {
            let size = u32::try_from(bytes.len()).unwrap();
            [entry_header(name, size).to_vec(), bytes.clone(), vec![0; padding_len(bytes.len())]].concat()
        })
        .collect();
    archive.extend_from_slice(&END_OF_ARCHIVE);
    archive
}

/// Returns `entries` after a bundle header with these counts.
fn with_header(header: BundleHeader, entries: Vec<(EntryName, Vec<u8>)>) -> Vec<(EntryName, Vec<u8>)> {
    [vec![(EntryName::BundleHeader, header.encode().to_vec())], entries].concat()
}

fn decode_in(bundle: &[u8], piece: usize) -> Result<DecodedBundle, BundleError> {
    let mut decoder = BundleDecoder::new();
    bundle.chunks(piece).try_for_each(|chunk| decoder.push(chunk))?;
    decoder.finish()
}

fn decode(bundle: &[u8]) -> Result<DecodedBundle, BundleError> {
    decode_in(bundle, bundle.len().max(1))
}

/// Returns the refusal of this archive, gzipped as the encoder would.
fn archive_refusal(archive: &[u8]) -> BundleError {
    decode(&gzip(archive)).unwrap_err()
}

#[test]
fn every_piece_size_decodes_the_same_bundle() {
    let entries = larger_entries();
    let bundle = encode(header(2, 3), &entries);
    let expected = decode(&bundle).unwrap();
    assert_eq!(expected.header(), header(2, 3));
    assert!(expected.entries().map(|(name, _)| name).eq(entries.iter().map(|(name, _)| *name)));
    assert!(
        expected
            .entries()
            .map(|(_, bytes)| bytes)
            .eq(entries.iter().map(|(_, bytes)| bytes.as_slice()))
    );
    [1, 7, 65_536]
        .into_iter()
        .for_each(|piece| assert_eq!(decode_in(&bundle, piece).as_ref(), Ok(&expected), "{piece}"));
}

#[test]
fn example_bundle_round_trips() {
    let decoded = decode(&example_bundle()).unwrap();
    assert_eq!(decoded.entry(&EntryName::Config), Some(b"schema_version = 1\n".as_slice()));
    assert_eq!(decoded.entry(&EntryName::BundleHeader), None);
    assert_eq!(decoded.entries().count(), 6);
}

#[test]
fn stopping_after_the_config_never_decodes_the_records() {
    // Everything after the config is a junk block that would be refused if it were ever decoded.
    let mut archive = raw_archive(&with_header(header(1, 1), example_entries()[..4].to_vec()));
    archive.truncate(archive.len() - END_OF_ARCHIVE.len());
    archive.extend(noise(9, 4 * BLOCK_LEN));
    let bundle = gzip(&archive);
    let mut decoder = BundleDecoder::new();
    let pushed = 1 + bundle
        .iter()
        .position(|byte| {
            decoder.push(&[*byte]).unwrap();
            decoder.entry(&EntryName::Config).is_some()
        })
        .unwrap();
    assert!(pushed < bundle.len());
    assert_eq!(decoder.entry(&EntryName::Config), Some(b"schema_version = 1\n".as_slice()));
    assert_eq!(decoder.entry(&EntryName::Manifest).map(<[u8]>::len), Some(466));
    assert_eq!(decoder.push(&bundle[pushed..]), Err(BundleError::EntryName));
}

#[test]
fn a_refused_decoder_refuses_every_later_call() {
    let mut decoder = BundleDecoder::new();
    assert_eq!(decoder.push(&[0x1f, 0x8b, 9, 0, 0, 0, 0, 0, 0, 0]), Err(BundleError::GzipHeader));
    assert_eq!(decoder.push(&example_bundle()), Err(BundleError::GzipHeader));
    assert_eq!(decoder.finish(), Err(BundleError::GzipHeader));
}

#[test]
fn decompression_bomb_is_refused_as_it_passes_the_bound() {
    let zeros: Vec<_> = [RECORD, SECOND_ID, THIRD_ID]
        .into_iter()
        .map(|id| (record(id), vec![0; 65_536]))
        .collect();
    let entries = [example_entries()[..5].to_vec(), zeros].concat();
    let bundle = encode(header(1, 3), &entries);
    let bound = 100_000;
    assert!((bundle.len() as u64) < bound / 20);
    let mut decoder = BundleDecoder::with_max_len(bound);
    assert_eq!(decoder.push(&bundle), Err(BundleError::TooLarge));
    assert_eq!(decoder.gzip.archive_len(), bound + 1);
    assert!(decode_in(&bundle, 1).is_ok());
}

#[test]
fn compressed_bytes_past_the_bound_are_refused_before_decoding() {
    let bundle = example_bundle();
    let mut decoder = BundleDecoder::with_max_len(bundle.len() as u64 - 1);
    assert_eq!(decoder.push(&bundle), Err(BundleError::TooLarge));
    assert_eq!(decoder.gzip.archive_len(), 0);
}

#[test]
fn a_bundle_at_the_bound_is_accepted() {
    let bundle = example_bundle();
    let archive_len = gunzip(&bundle).len() as u64;
    let mut decoder = BundleDecoder::with_max_len(archive_len.max(bundle.len() as u64));
    decoder.push(&bundle).unwrap();
    assert!(decoder.finish().is_ok());
}

#[test]
fn rule_names_are_distinct() {
    let errors = [
        BundleError::TooLarge,
        BundleError::GzipHeader,
        BundleError::GzipFlags,
        BundleError::Deflate,
        BundleError::GzipCrc,
        BundleError::GzipSize,
        BundleError::GzipTrailing,
        BundleError::Truncated,
        BundleError::EntryName,
        BundleError::EntryHeader,
        BundleError::EntryOrder,
        BundleError::EntryCount,
        BundleError::EntrySize,
        BundleError::Padding,
        BundleError::EndOfArchive,
        BundleError::ArchiveTrailing,
        BundleError::HeaderLength,
        BundleError::HeaderMagic,
        BundleError::HeaderVersion,
        BundleError::HeaderVaultId,
        BundleError::HeaderCount,
    ];
    let names: std::collections::BTreeSet<_> = errors.iter().map(BundleError::rule).collect();
    assert_eq!(names.len(), errors.len());
}

/// Sets a header block's checksum to the one its other bytes give, so a test reaches the field it altered.
fn rechecksum(block: &mut [u8]) {
    block[148..156].copy_from_slice(b"        ");
    let sum: u32 = block[..BLOCK_LEN].iter().map(|&byte| u32::from(byte)).sum();
    block[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn arbitrary_names_never_yield_an_entry_outside_the_list(
        at in 0..EXAMPLE_HEADERS.len(),
        name in prop::collection::vec(any::<u8>(), 0..=100),
    ) {
        let mut archive = gunzip(&example_bundle());
        let block = &mut archive[EXAMPLE_HEADERS[at]..EXAMPLE_HEADERS[at] + BLOCK_LEN];
        block[..100].fill(0);
        block[..name.len()].copy_from_slice(&name);
        rechecksum(block);
        if let Ok(decoded) = decode(&gzip(&archive)) {
            prop_assert_eq!(decoded, decode(&example_bundle()).unwrap());
        }
    }

    #[test]
    fn arbitrary_header_blocks_never_yield_an_entry_outside_the_list(
        at in 0..EXAMPLE_HEADERS.len(),
        bytes in prop::collection::vec(any::<u8>(), BLOCK_LEN),
    ) {
        let mut archive = gunzip(&example_bundle());
        archive[EXAMPLE_HEADERS[at]..EXAMPLE_HEADERS[at] + BLOCK_LEN].copy_from_slice(&bytes);
        if let Ok(decoded) = decode(&gzip(&archive)) {
            prop_assert_eq!(decoded, decode(&example_bundle()).unwrap());
        }
    }
}
