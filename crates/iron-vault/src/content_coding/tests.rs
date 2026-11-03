use std::io::Write;

use flate2::Compression;
use flate2::write::{DeflateEncoder, GzEncoder, ZlibEncoder};

use super::*;

const CODINGS: [ContentCoding; 3] = [ContentCoding::Gzip, ContentCoding::Deflate, ContentCoding::Br];

/// Compressible, deterministic text of about `len` bytes with no long runs.
fn text(len: usize) -> Vec<u8> {
    (0..)
        .flat_map(|n: u32| format!("line {n} of the body, {} \n", n.wrapping_mul(2_654_435_761) % 9973).into_bytes())
        .take(len)
        .collect()
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn zlib(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn raw_deflate(data: &[u8]) -> Vec<u8> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn brotli(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut encoder = ::brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
        encoder.write_all(data).unwrap();
    }
    out
}

fn encode(coding: ContentCoding, data: &[u8]) -> Vec<u8> {
    match coding {
        ContentCoding::Gzip => gzip(data),
        ContentCoding::Deflate => zlib(data),
        ContentCoding::Br => brotli(data),
    }
}

/// A gzip member that uses every optional header field, including the header CRC-16.
fn gzip_all_header_fields(data: &[u8]) -> Vec<u8> {
    let mut header = vec![0x1f, 0x8b, 8, FHCRC | FEXTRA | FNAME | FCOMMENT, 1, 2, 3, 4, 0, 3];
    header.extend_from_slice(&[5, 0, b'a', b'b', b'c', b'd', b'e']);
    header.extend_from_slice(b"name.txt\0a comment\0");
    let mut crc = flate2::Crc::new();
    crc.update(&header);
    header.extend_from_slice(&(crc.sum() as u16).to_le_bytes());
    let mut body_crc = flate2::Crc::new();
    body_crc.update(data);
    let mut member = header;
    member.extend(raw_deflate(data));
    member.extend_from_slice(&body_crc.sum().to_le_bytes());
    member.extend_from_slice(&body_crc.amount().to_le_bytes());
    member
}

const FHCRC: u8 = 0x02;
const FEXTRA: u8 = 0x04;
const FNAME: u8 = 0x08;
const FCOMMENT: u8 = 0x10;

/// Decodes `chunks` in turn and ends the body, checking every piece against the size bound.
fn decode(coding: ContentCoding, chunks: &[&[u8]]) -> Result<Vec<u8>, DecodeError> {
    let mut decoder = ResponseDecoder::new(coding);
    let mut out = Vec::new();
    chunks.iter().try_for_each(|chunk| {
        decoder.push(chunk).try_for_each(|piece| {
            let piece = piece?;
            assert!(!piece.is_empty() && piece.len() <= PIECE_SIZE, "piece of {}", piece.len());
            out.extend_from_slice(&piece);
            Ok(())
        })
    })?;
    decoder.finish()?;
    Ok(out)
}

#[test]
fn each_coding_round_trips_a_body_larger_than_a_piece() {
    let data = text(3 * PIECE_SIZE + 123);
    CODINGS.iter().for_each(|&coding| {
        assert_eq!(decode(coding, &[&encode(coding, &data)]).unwrap(), data, "{coding:?}");
    });
}

#[test]
fn every_split_of_the_compressed_bytes_decodes_like_the_whole() {
    let data = text(2000);
    let bodies = [
        (ContentCoding::Gzip, gzip(&data)),
        (ContentCoding::Gzip, gzip_all_header_fields(&data)),
        (ContentCoding::Gzip, [gzip(&data), gzip(&data)].concat()),
        (ContentCoding::Deflate, zlib(&data)),
        (ContentCoding::Br, brotli(&data)),
    ];
    bodies.iter().for_each(|(coding, body)| {
        let expected = decode(*coding, &[body]).unwrap();
        assert!(expected.starts_with(&data));
        (0..=body.len()).for_each(|at| {
            let (head, tail) = body.split_at(at);
            assert_eq!(decode(*coding, &[head, tail]).unwrap(), expected, "{coding:?} split at {at}");
        });
    });
}

#[test]
fn a_byte_at_a_time_decodes_like_the_whole() {
    let data = text(1500);
    CODINGS.iter().for_each(|&coding| {
        let body = encode(coding, &data);
        let chunks: Vec<&[u8]> = body.chunks(1).collect();
        assert_eq!(decode(coding, &chunks).unwrap(), data, "{coding:?}");
    });
}

#[test]
fn gzip_decodes_every_member_in_turn() {
    let (first, second) = (text(5000), text(70_000));
    let body = [gzip(&first), gzip_all_header_fields(&second), gzip(b"")].concat();
    let expected = [first, second].concat();
    assert_eq!(decode(ContentCoding::Gzip, &[&body]).unwrap(), expected);
}

#[test]
fn a_bomb_never_yields_a_piece_larger_than_the_step_size() {
    // The compressed body is a few KiB to a few tens of KiB; its output is 16 MiB.
    let zeros = vec![0u8; 16 * 1024 * 1024];
    CODINGS.iter().for_each(|&coding| {
        let body = encode(coding, &zeros);
        let mut decoder = ResponseDecoder::new(coding);
        let pieces: Vec<Bytes> = decoder.push(&body).take(4).collect::<Result<_, _>>().unwrap();
        assert_eq!(pieces.len(), 4, "{coding:?}");
        assert!(pieces.iter().all(|piece| piece.len() == PIECE_SIZE), "{coding:?}");
        // Giving up mid-chunk is not a clean end of the body.
        assert_eq!(decoder.finish(), Err(DecodeError::Abandoned), "{coding:?}");
    });
}

#[test]
fn a_truncated_stream_fails_at_finish_not_before() {
    let data = text(3000);
    CODINGS.iter().for_each(|&coding| {
        let body = encode(coding, &data);
        (0..body.len()).for_each(|cut| {
            let mut decoder = ResponseDecoder::new(coding);
            decoder
                .push(&body[..cut])
                .for_each(|piece| assert!(piece.is_ok(), "{coding:?} cut at {cut}"));
            assert_eq!(decoder.finish(), Err(DecodeError::Truncated), "{coding:?} cut at {cut}");
        });
    });
}

#[test]
fn an_empty_body_is_truncated() {
    CODINGS
        .iter()
        .for_each(|&coding| assert_eq!(ResponseDecoder::new(coding).finish(), Err(DecodeError::Truncated)));
}

#[test]
fn corrupt_bytes_fail_at_push() {
    let data = text(3000);
    let flipped = |mut body: Vec<u8>, at: usize| {
        body[at] ^= 0x55;
        body
    };
    let gz = gzip(&data);
    let zl = zlib(&data);
    let cases = [
        (ContentCoding::Gzip, flipped(gz.clone(), 0)),
        (ContentCoding::Gzip, flipped(gz.clone(), 2)),
        (ContentCoding::Gzip, flipped(gz.clone(), gz.len() - 8)),
        (ContentCoding::Gzip, flipped(gz.clone(), gz.len() - 1)),
        (ContentCoding::Deflate, flipped(zl.clone(), 0)),
        (ContentCoding::Deflate, flipped(zl.clone(), zl.len() - 1)),
        (ContentCoding::Br, vec![0xff; 64]),
    ];
    cases.iter().enumerate().for_each(|(n, (coding, body))| {
        let mut decoder = ResponseDecoder::new(*coding);
        let result: Result<Vec<Bytes>, _> = decoder.push(body).collect();
        assert_eq!(result.err(), Some(DecodeError::Corrupt), "case {n}: {coding:?}");
    });
}

#[test]
fn a_bad_gzip_header_crc_is_corrupt() {
    let mut body = gzip_all_header_fields(&text(100));
    // Ten fixed bytes, a seven-byte extra field, a nine-byte name and a ten-byte comment come before the CRC-16.
    let crc_at = 10 + 7 + 9 + 10;
    body[crc_at] ^= 1;
    assert_eq!(decode(ContentCoding::Gzip, &[&body]), Err(DecodeError::Corrupt));
}

#[test]
fn bytes_after_the_stream_are_trailing_data() {
    let data = text(500);
    CODINGS.iter().for_each(|&coding| {
        let body = encode(coding, &data);
        for garbage in [&b"x"[..], b"\0\0\0\0"] {
            assert_eq!(
                decode(coding, &[&body, garbage]),
                Err(DecodeError::TrailingData),
                "{coding:?} {garbage:?}"
            );
            let joined = [body.as_slice(), garbage].concat();
            assert_eq!(
                decode(coding, &[&joined]),
                Err(DecodeError::TrailingData),
                "{coding:?} {garbage:?} joined"
            );
        }
    });
}

#[test]
fn garbage_after_a_gzip_member_with_the_magic_still_fails() {
    let body = [gzip(b"abc"), vec![0x1f, 0x8b, 9, 0, 0, 0, 0, 0, 0, 0]].concat();
    assert_eq!(decode(ContentCoding::Gzip, &[&body]), Err(DecodeError::Corrupt));
}

#[test]
fn raw_deflate_under_deflate_is_an_error() {
    for data in [text(3000), b"hello".to_vec(), Vec::new()] {
        let raw = raw_deflate(&data);
        let mut decoder = ResponseDecoder::new(ContentCoding::Deflate);
        let result: Result<Vec<Bytes>, _> = decoder.push(&raw).collect();
        let outcome = result.map(|_| ()).and_then(|()| decoder.finish());
        assert!(outcome.is_err(), "raw deflate of {} bytes was accepted", data.len());
    }
}

#[test]
fn a_failed_decoder_keeps_failing() {
    let mut decoder = ResponseDecoder::new(ContentCoding::Gzip);
    assert_eq!(decoder.push(b"not gzip at all").next(), Some(Err(DecodeError::Corrupt)));
    assert_eq!(decoder.push(&gzip(b"fine")).next(), Some(Err(DecodeError::Corrupt)));
    assert_eq!(decoder.finish(), Err(DecodeError::Corrupt));
}

#[test]
fn errors_and_debug_output_carry_no_body_bytes() {
    let mut decoder = ResponseDecoder::new(ContentCoding::Gzip);
    let _ = decoder.push(&gzip(b"MARKER-body-bytes")).count();
    assert!(!format!("{decoder:?}").contains("MARKER"));
    assert!(!DecodeError::Corrupt.to_string().contains("MARKER"));
}

#[test]
fn the_brotli_large_window_extension_is_refused() {
    // Header bits for a large-window stream asking for a 2^30-byte window; RFC 7932 stops at 2^24 - 16.
    let mut decoder = ResponseDecoder::new(ContentCoding::Br);
    assert_eq!(decoder.push(&[0x11, 0x0f, 0x00, 0x00]).next(), Some(Err(DecodeError::Corrupt)));
}
