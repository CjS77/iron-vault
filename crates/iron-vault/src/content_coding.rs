//! Response decoders: turn a content-coded response body back into the bytes the scrubber screens (spec §3.8, Q-6, §9).
//!
//! A compressed body hides an echoed secret from the scrubber, so the service decodes `gzip`, `deflate` and `br` before
//! scrubbing. Like the [`Scrubber`](crate::scrub::Scrubber), a [`ResponseDecoder`] is push-based: each upstream chunk goes
//! in, decoded bytes come out, and no body is buffered whole. A small chunk can expand a thousandfold, so
//! [`push`](ResponseDecoder::push) yields its output in pieces of at most [`PIECE_SIZE`] bytes, produced one at a time as
//! the caller pulls them. The caller checks its size budget between pieces and stops pulling when one runs out.
//!
//! The codings are decoded strictly, so a body that is not exactly what its `Content-Encoding` claims is an error rather
//! than a guess:
//!
//! - `gzip` (RFC 1952): one or more members back to back, each with its CRC-32 and length checked. Bytes after the last
//!   member are [`DecodeError::TrailingData`]. A header's optional fields are skipped and its CRC-16, when present, is
//!   checked.
//! - `deflate`: the zlib format that RFC 9110 §8.4.1.2 defines (RFC 1950), Adler-32 checked. Raw deflate, which some
//!   servers send by mistake, is [`DecodeError::Corrupt`]; guessing between the two would let a body choose how it is
//!   read. Bytes after the zlib trailer are [`DecodeError::TrailingData`].
//! - `br` (RFC 7932): one brotli stream. The large-window extension is refused, which keeps the window to 16 MiB. Bytes
//!   after the stream's last meta-block are [`DecodeError::TrailingData`].
//!
//! An empty body is not a complete stream in any of these codings, so [`finish`](ResponseDecoder::finish) reports it as
//! truncated; whether a response with no body is decoded at all is the caller's rule.
//!
//! The decoders' windows hold plaintext response data, which may echo a secret before the scrubber has seen it. Each
//! window is wiped when the decoder is dropped (see `design/secret-handling.md`), and neither a [`DecodeError`] nor a
//! `Debug` output carries any body byte.

mod br;
mod gzip;

use std::fmt;

use bytes::Bytes;
use flate2::{Decompress, FlushDecompress};
use zeroize::Zeroizing;

#[cfg(test)]
mod tests;

/// The largest piece [`ResponseDecoder::push`] yields: small enough that checking a budget between pieces bounds the
/// memory one chunk can use, large enough that the per-piece cost is negligible.
pub const PIECE_SIZE: usize = 64 * 1024;

/// A content coding the service decodes: the `Content-Encoding` an upstream applied to a response body. `identity` is
/// not a variant, because a body with no coding needs no decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentCoding {
    /// `gzip`, RFC 1952, possibly several members.
    Gzip,
    /// `deflate`, the zlib format of RFC 1950.
    Deflate,
    /// `br`, RFC 7932.
    Br,
}

/// Why a body could not be decoded. It names the failure and never carries a body byte, because decoded bytes may hold
/// the secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    /// The bytes are not valid for the coding, or a checksum or length does not match.
    #[error("response body is not valid for its content coding")]
    Corrupt,
    /// The body ended before the coded stream did.
    #[error("response body ended before its coded stream did")]
    Truncated,
    /// Bytes followed the end of the coded stream.
    #[error("response body continues after its coded stream ended")]
    TrailingData,
    /// The output of an earlier [`push`](ResponseDecoder::push) was dropped before it ended, so input was lost.
    #[error("response decoder abandoned part of its input")]
    Abandoned,
}

/// What one engine call did.
#[derive(Debug, Clone, Copy, Default)]
struct Step {
    /// Input bytes used.
    consumed: usize,
    /// Output bytes written.
    produced: usize,
}

/// One coding's decoder. `step` may leave input unused when `out` fills or the coded stream ends; the caller offers the
/// rest again. A call that uses no input and writes no output means the engine needs more input.
trait Engine: Send {
    /// Decodes some of `input` into `out`, which is never empty.
    fn step(&mut self, input: &[u8], out: &mut [u8]) -> Result<Step, DecodeError>;
    /// Whether the coded stream has ended cleanly, so a body ending now is complete.
    fn is_complete(&self) -> bool;
}

/// The per-response streaming decoder for one [`ContentCoding`].
///
/// Call [`push`](Self::push) with each upstream chunk and drain the pieces it yields, then [`finish`](Self::finish) at
/// the end of the body. `finish` consumes the decoder and fails unless the coded stream ended, so a truncated body never
/// looks complete. After any error the decoder is unusable: every later `push` and `finish` repeats it.
pub struct ResponseDecoder {
    coding: ContentCoding,
    engine: Box<dyn Engine>,
    /// Where each piece is decoded before it is copied out; wiped on drop because it holds plaintext.
    out: Zeroizing<Vec<u8>>,
    failed: Option<DecodeError>,
}

impl ResponseDecoder {
    /// A decoder for one response body in `coding`.
    pub fn new(coding: ContentCoding) -> Self {
        let engine: Box<dyn Engine> = match coding {
            ContentCoding::Gzip => Box::new(gzip::Gzip::new()),
            ContentCoding::Deflate => Box::new(Inflate::new(true)),
            ContentCoding::Br => Box::new(br::Brotli::new()),
        };
        Self {
            coding,
            engine,
            out: Zeroizing::new(vec![0; PIECE_SIZE]),
            failed: None,
        }
    }

    /// Decodes the next chunk of the body, yielding the output in pieces of at most [`PIECE_SIZE`] bytes.
    ///
    /// Each piece is decoded only when the iterator is advanced, so a caller that stops after a few pieces has decoded
    /// no more than that. Dropping the iterator before it ends abandons the rest of the chunk and poisons the decoder
    /// with [`DecodeError::Abandoned`]: the caller is giving up on the response.
    pub fn push<'a>(&'a mut self, chunk: &'a [u8]) -> Pieces<'a> {
        Pieces {
            decoder: self,
            input: chunk,
            ended: false,
        }
    }

    /// Ends the body. Fails with [`DecodeError::Truncated`] unless the coded stream has ended.
    pub fn finish(self) -> Result<(), DecodeError> {
        match self.failed {
            Some(error) => Err(error),
            None if self.engine.is_complete() => Ok(()),
            None => Err(DecodeError::Truncated),
        }
    }
}

impl fmt::Debug for ResponseDecoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResponseDecoder")
            .field("coding", &self.coding)
            .field("failed", &self.failed)
            .finish()
    }
}

/// The pieces one [`ResponseDecoder::push`] decodes, each at most [`PIECE_SIZE`] bytes and never empty.
pub struct Pieces<'a> {
    decoder: &'a mut ResponseDecoder,
    input: &'a [u8],
    /// Whether the iterator returned its last item, so dropping it loses no input.
    ended: bool,
}

impl Pieces<'_> {
    /// Ends the iteration after `error`, which the decoder keeps and repeats.
    fn fail(&mut self, error: DecodeError) -> Option<Result<Bytes, DecodeError>> {
        self.ended = true;
        self.decoder.failed = Some(error);
        Some(Err(error))
    }
}

impl Iterator for Pieces<'_> {
    type Item = Result<Bytes, DecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(error) = self.decoder.failed.filter(|_| !self.ended) {
            return self.fail(error);
        }
        while !self.ended {
            let decoder = &mut *self.decoder;
            let step = match decoder.engine.step(self.input, &mut decoder.out) {
                Ok(step) => step,
                Err(error) => return self.fail(error),
            };
            self.input = self.input.get(step.consumed..).unwrap_or_default();
            match (step.produced, step.consumed) {
                (0, 0) if self.input.is_empty() => self.ended = true,
                // The engine can neither use the input nor make output; treating it as finished would drop the input.
                (0, 0) => return self.fail(DecodeError::Corrupt),
                (0, _) => {}
                (produced, _) => return Some(Ok(Bytes::copy_from_slice(self.decoder.out.get(..produced).unwrap_or_default()))),
            }
        }
        None
    }
}

impl Drop for Pieces<'_> {
    fn drop(&mut self) {
        if !self.ended {
            self.decoder.failed.get_or_insert(DecodeError::Abandoned);
        }
    }
}

/// A deflate stream, zlib-wrapped or raw, decoded through flate2's low-level API so each call's output is bounded by the
/// buffer it is given.
struct Inflate {
    inner: Decompress,
    zlib: bool,
    ended: bool,
}

impl Inflate {
    fn new(zlib: bool) -> Self {
        Self {
            inner: Decompress::new(zlib),
            zlib,
            ended: false,
        }
    }

    /// Readies the decoder for another stream. flate2 zeroes its 32 KiB window on reset.
    fn restart(&mut self) {
        self.inner.reset(self.zlib);
        self.ended = false;
    }

    fn run(&mut self, input: &[u8], out: &mut [u8]) -> Result<Step, DecodeError> {
        let (before_in, before_out) = (self.inner.total_in(), self.inner.total_out());
        let status = self
            .inner
            .decompress(input, out, FlushDecompress::None)
            .map_err(|_| DecodeError::Corrupt)?;
        self.ended = status == flate2::Status::StreamEnd;
        Ok(Step {
            consumed: usize::try_from(self.inner.total_in() - before_in).map_err(|_| DecodeError::Corrupt)?,
            produced: usize::try_from(self.inner.total_out() - before_out).map_err(|_| DecodeError::Corrupt)?,
        })
    }
}

impl Engine for Inflate {
    fn step(&mut self, input: &[u8], out: &mut [u8]) -> Result<Step, DecodeError> {
        match (self.ended, input.is_empty()) {
            (false, _) => self.run(input, out),
            (true, true) => Ok(Step::default()),
            (true, false) => Err(DecodeError::TrailingData),
        }
    }

    fn is_complete(&self) -> bool {
        self.ended
    }
}

impl Drop for Inflate {
    fn drop(&mut self) {
        self.restart();
    }
}
