//! Response decoders: turn a content-coded response body back into the bytes the scrubber screens (spec §11, Q-6, implementation spec §3).
//!
//! A compressed body hides an echoed secret from the scrubber, so the service decodes `gzip`, `deflate` and `br` before
//! scrubbing. Like the [`Scrubber`](crate::scrub::Scrubber), a [`ResponseDecoder`] is fed each upstream chunk in turn
//! and no body is buffered whole. A small chunk can expand a thousandfold, so
//! [`next_piece`](ResponseDecoder::next_piece) yields the output in pieces of at most [`PIECE_SIZE`] bytes, each decoded
//! only when it is pulled. The caller checks its size budget between pieces and stops pulling when one runs out, and
//! can send each piece on before pulling the next, so a response is held in memory one piece at a time.
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
//! The decoders' windows hold plaintext response data, which may echo a secret before the scrubber has seen it. The brotli
//! buffers and the piece buffer are wiped by `Zeroizing` when the decoder is dropped. The gzip and deflate window is
//! wiped by miniz_oxide's reset with ordinary (non-volatile) stores that `black_box` keeps the compiler from removing, so
//! that wipe is best-effort (see `design/secret-handling.md`). Neither a [`DecodeError`] nor a `Debug` output carries any
//! body byte.

mod br;
mod budget;
mod decisions;
mod encoder;
mod gzip;

use std::fmt;

use bytes::{Buf, Bytes};
use flate2::{Decompress, FlushDecompress};
use zeroize::Zeroizing;

pub use budget::{BudgetExceeded, DecompressionBudget};
pub use decisions::{UPSTREAM_ACCEPT_ENCODING, UnsupportedCoding, choose_emitted, parse_content_encoding, rewrite_headers};
pub use encoder::{EncodeError, ResponseEncoder};

#[cfg(test)]
mod tests;

/// The largest piece [`ResponseDecoder::next_piece`] yields: small enough that checking a budget between pieces bounds the
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
    /// A chunk was fed, or the body ended, before the previous chunk's pieces were all pulled, so input was lost.
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

impl Step {
    /// This step if it fits the buffers it was given. A library that claims more than that is not trusted: slicing by the
    /// claim would drop input or release bytes that are not output, so the body fails closed.
    fn within(self, input: usize, out: usize) -> Result<Self, DecodeError> {
        if self.consumed <= input && self.produced <= out {
            Ok(self)
        } else {
            Err(DecodeError::Corrupt)
        }
    }
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
/// [`feed`](Self::feed) each upstream chunk, then pull its output with [`next_piece`](Self::next_piece) until it returns
/// `None`; [`finish`](Self::finish) ends the body. The decoder owns the chunk it was fed, so a caller can pull one piece,
/// do other work or return to its executor, and come back for the next: nothing is decoded ahead of the pull. After any
/// error the decoder is unusable: every later `next_piece` and `finish` repeats it.
pub struct ResponseDecoder {
    coding: ContentCoding,
    engine: Box<dyn Engine>,
    /// Where each piece is decoded before it is copied out; wiped on drop because it holds plaintext.
    out: Zeroizing<Vec<u8>>,
    /// The part of the fed chunk the engine has not used yet.
    pending: Bytes,
    /// Whether a fed chunk still has output to pull: the engine may hold output after it has used all its input.
    active: bool,
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
            pending: Bytes::new(),
            active: false,
            failed: None,
        }
    }

    /// Takes the next chunk of the body. Feeding before the previous chunk's pieces were all pulled loses input, so it
    /// poisons the decoder with [`DecodeError::Abandoned`].
    pub fn feed(&mut self, chunk: Bytes) {
        if self.active {
            self.failed.get_or_insert(DecodeError::Abandoned);
        }
        self.pending = chunk;
        self.active = true;
    }

    /// Decodes the fed chunk's next piece, at most [`PIECE_SIZE`] bytes and never empty; `None` once the chunk is used up.
    /// A failed decoder returns its error once per chunk.
    pub fn next_piece(&mut self) -> Option<Result<Bytes, DecodeError>> {
        if let Some(error) = self.failed.filter(|_| self.active) {
            return self.fail(error);
        }
        while self.active {
            let stepped = self.engine.step(&self.pending, &mut self.out);
            let step = match stepped.and_then(|step| step.within(self.pending.len(), self.out.len())) {
                Ok(step) => step,
                Err(error) => return self.fail(error),
            };
            // `within` has checked that the engine used no more than it was given.
            self.pending.advance(step.consumed);
            match (step.produced, step.consumed) {
                (0, 0) if self.pending.is_empty() => self.active = false,
                // The engine can neither use the input nor make output; treating it as finished would drop the input.
                (0, 0) => return self.fail(DecodeError::Corrupt),
                (0, _) => {}
                (produced, _) => return Some(Ok(Bytes::copy_from_slice(self.out.get(..produced).unwrap_or_default()))),
            }
        }
        None
    }

    /// Decodes `chunk` in one call: [`feed`](Self::feed) it and iterate its pieces. Dropping the iterator early leaves
    /// the rest of the chunk fed, which [`finish`](Self::finish) reports as abandoned.
    #[must_use = "dropping the pieces unread abandons the chunk and poisons the decoder"]
    pub fn push(&mut self, chunk: &[u8]) -> impl Iterator<Item = Result<Bytes, DecodeError>> {
        self.feed(Bytes::copy_from_slice(chunk));
        std::iter::from_fn(|| self.next_piece())
    }

    /// Ends the body. Fails with [`DecodeError::Truncated`] unless the coded stream has ended, and with
    /// [`DecodeError::Abandoned`] if a fed chunk was not pulled to its end.
    pub fn finish(self) -> Result<(), DecodeError> {
        match self.failed {
            Some(error) => Err(error),
            None if self.active => Err(DecodeError::Abandoned),
            None if self.engine.is_complete() => Ok(()),
            None => Err(DecodeError::Truncated),
        }
    }

    /// Ends the fed chunk after `error`, which the decoder keeps and repeats.
    fn fail(&mut self, error: DecodeError) -> Option<Result<Bytes, DecodeError>> {
        self.active = false;
        self.pending = Bytes::new();
        self.failed = Some(error);
        Some(Err(error))
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
        Step {
            consumed: usize::try_from(self.inner.total_in() - before_in).map_err(|_| DecodeError::Corrupt)?,
            produced: usize::try_from(self.inner.total_out() - before_out).map_err(|_| DecodeError::Corrupt)?,
        }
        .within(input.len(), out.len())
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
        // miniz_oxide 0.9.1 zeroes the window with plain stores (`state.dict = [0; ...]`) right before the Box is freed,
        // which the compiler may remove as dead stores; `black_box` makes it treat the zeroed state as used.
        std::hint::black_box(&self.inner);
    }
}
