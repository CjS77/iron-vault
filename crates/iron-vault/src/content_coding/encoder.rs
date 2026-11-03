//! Response encoders: recompress a scrubbed body for a caller whose `Accept-Encoding` forbids `identity` (spec §3.8, Q-6).
//!
//! A [`ResponseEncoder`] is push-based like the [`ResponseDecoder`](super::ResponseDecoder). Every
//! [`push`](ResponseEncoder::push) ends in a sync flush, so the bytes returned so far decode to exactly the bytes pushed
//! so far. That keeps a streamed response (SSE) streaming: an encoder that waited for a full block would hold events back
//! and defeat the scrubber's minimal hold-back (§9). The price is a few bytes of framing per chunk.
//!
//! The encoder's input is already scrubbed, so it holds no secret material. Its buffers are not wiped and it must not be
//! added to the secret tables in `design/secret-handling.md`.
//!
//! `deflate` is the zlib format of RFC 1950, as the decoder reads it. Compression levels are moderate because the work is
//! per request on the hot path: gzip and deflate use level 6, zlib's own default and the usual ratio/speed balance, and
//! brotli uses quality 4, which compresses text well at a fraction of the cost of the default quality 11. Brotli's
//! window is 2^18 bytes, which bounds the encoder's memory per response.

use std::io::{self, Write};

use bytes::Bytes;
use flate2::Compression;
use flate2::write::{GzEncoder, ZlibEncoder};

use super::ContentCoding;

/// zlib's default level; see the module documentation.
const DEFLATE_LEVEL: u32 = 6;
/// Brotli quality; see the module documentation.
const BROTLI_QUALITY: u32 = 4;
/// Brotli's log2 window size; see the module documentation.
const BROTLI_LGWIN: u32 = 18;
/// Brotli's internal buffer size for the writer API; it affects speed only.
const BROTLI_BUFFER: usize = 4096;

/// Why a body could not be encoded. The sinks are in-memory vectors, so this means the compression library failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("response body could not be compressed")]
pub struct EncodeError;

impl From<io::Error> for EncodeError {
    fn from(_: io::Error) -> Self {
        Self
    }
}

/// One coding's writer over an in-memory sink.
enum Writer {
    Gzip(GzEncoder<Vec<u8>>),
    Deflate(ZlibEncoder<Vec<u8>>),
    Br(Box<brotli::CompressorWriter<Vec<u8>>>),
}

impl Writer {
    fn new(coding: ContentCoding) -> Self {
        let level = Compression::new(DEFLATE_LEVEL);
        match coding {
            ContentCoding::Gzip => Self::Gzip(GzEncoder::new(Vec::new(), level)),
            ContentCoding::Deflate => Self::Deflate(ZlibEncoder::new(Vec::new(), level)),
            ContentCoding::Br => Self::Br(Box::new(brotli::CompressorWriter::new(
                Vec::new(),
                BROTLI_BUFFER,
                BROTLI_QUALITY,
                BROTLI_LGWIN,
            ))),
        }
    }

    /// Writes `chunk`, sync-flushes, and takes the compressed bytes produced so far.
    fn push(&mut self, chunk: &[u8]) -> io::Result<Vec<u8>> {
        match self {
            Self::Gzip(w) => Self::flushed(w, chunk, |w| w.get_mut()),
            Self::Deflate(w) => Self::flushed(w, chunk, |w| w.get_mut()),
            Self::Br(w) => Self::flushed(w.as_mut(), chunk, |w| w.get_mut()),
        }
    }

    fn flushed<W: Write>(w: &mut W, chunk: &[u8], sink: impl FnOnce(&mut W) -> &mut Vec<u8>) -> io::Result<Vec<u8>> {
        w.write_all(chunk)?;
        w.flush()?;
        Ok(std::mem::take(sink(w)))
    }
}

/// The per-response streaming encoder for one [`ContentCoding`].
///
/// Call [`push`](Self::push) with each scrubbed chunk and send what it returns, then [`finish`](Self::finish) at the end
/// of the body. After an error the encoder is unusable and the response must be aborted.
pub struct ResponseEncoder {
    writer: Writer,
}

impl ResponseEncoder {
    /// An encoder for one response body in `coding`.
    pub fn new(coding: ContentCoding) -> Self {
        Self {
            writer: Writer::new(coding),
        }
    }

    /// Compresses `chunk` and sync-flushes, returning the bytes to send now. Decoding everything returned so far yields
    /// exactly the input pushed so far. An empty chunk returns nothing, since a flush would only add framing.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Bytes, EncodeError> {
        if chunk.is_empty() {
            return Ok(Bytes::new());
        }
        Ok(Bytes::from(self.writer.push(chunk)?))
    }

    /// Ends the stream and returns the remaining bytes, including the trailer. A body that was never pushed to becomes a
    /// valid empty stream.
    pub fn finish(self) -> Result<Bytes, EncodeError> {
        let out = match self.writer {
            Writer::Gzip(w) => w.finish()?,
            Writer::Deflate(w) => w.finish()?,
            Writer::Br(w) => w.into_inner(),
        };
        Ok(Bytes::from(out))
    }
}

impl std::fmt::Debug for ResponseEncoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseEncoder").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content_coding::ResponseDecoder;

    const CODINGS: [ContentCoding; 3] = [ContentCoding::Gzip, ContentCoding::Deflate, ContentCoding::Br];

    /// Compressible, deterministic text of `len` bytes.
    fn text(len: usize) -> Vec<u8> {
        (0..)
            .flat_map(|n: u32| format!("data: event {n} {}\n\n", n.wrapping_mul(2_654_435_761) % 9973).into_bytes())
            .take(len)
            .collect()
    }

    /// Decodes a stream that may be incomplete, returning the plaintext so far.
    fn decode_prefix(coding: ContentCoding, bytes: &[u8]) -> Vec<u8> {
        let mut decoder = ResponseDecoder::new(coding);
        decoder.push(bytes).flat_map(|piece| piece.unwrap()).collect()
    }

    fn encode_chunked(coding: ContentCoding, data: &[u8], size: usize) -> Vec<u8> {
        let mut encoder = ResponseEncoder::new(coding);
        let mut out: Vec<u8> = data.chunks(size).flat_map(|c| encoder.push(c).unwrap()).collect();
        out.extend_from_slice(&encoder.finish().unwrap());
        out
    }

    #[test]
    fn round_trips_through_the_decoder_over_several_chunkings() {
        let data = text(300_000);
        for coding in CODINGS {
            // One-byte chunks are slow to compress, so that chunking covers a prefix.
            for (size, len) in [
                (1, 2000),
                (7, data.len()),
                (1000, data.len()),
                (65_536, data.len()),
                (data.len(), data.len()),
            ] {
                let expected = &data[..len];
                let encoded = encode_chunked(coding, expected, size);
                let mut decoder = ResponseDecoder::new(coding);
                let decoded: Vec<u8> = decoder.push(&encoded).flat_map(|p| p.unwrap()).collect();
                decoder.finish().unwrap();
                assert_eq!(decoded, expected, "{coding:?} chunked by {size}");
            }
        }
    }

    #[test]
    fn every_push_is_decodable_up_to_that_point() {
        let data = text(20_000);
        for coding in CODINGS {
            let mut encoder = ResponseEncoder::new(coding);
            let mut sent = Vec::new();
            data.chunks(333).enumerate().for_each(|(i, chunk)| {
                sent.extend_from_slice(&encoder.push(chunk).unwrap());
                let pushed = &data[..((i + 1) * 333).min(data.len())];
                assert_eq!(decode_prefix(coding, &sent), pushed, "{coding:?} after chunk {i}");
            });
        }
    }

    #[test]
    fn an_empty_body_is_a_valid_empty_stream() {
        for coding in CODINGS {
            let encoded = ResponseEncoder::new(coding).finish().unwrap();
            let mut decoder = ResponseDecoder::new(coding);
            assert_eq!(decoder.push(&encoded).flat_map(|p| p.unwrap()).count(), 0, "{coding:?}");
            decoder.finish().unwrap();
        }
    }

    #[test]
    fn empty_chunks_emit_nothing() {
        for coding in CODINGS {
            assert!(ResponseEncoder::new(coding).push(&[]).unwrap().is_empty());
        }
    }
}
