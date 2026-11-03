//! The brotli engine (RFC 7932), over the low-level stream call of the decompressor that `brotli` re-exports.

use brotli::enc::StandardAlloc;
use brotli::{Allocator, BrotliDecompressStream, BrotliResult, BrotliState, SliceWrapper, SliceWrapperMut};
use zeroize::Zeroizing;

use super::{DecodeError, Engine, Step};

/// The allocator for the decoder's byte buffers, whose largest is the window (up to 16 MiB of plaintext). The standard
/// allocator frees without wiping; these buffers wipe themselves when dropped.
#[derive(Default)]
struct WipingAlloc;

/// A byte buffer that is zeroed when dropped.
#[derive(Default)]
struct WipingCells(Zeroizing<Vec<u8>>);

impl SliceWrapper<u8> for WipingCells {
    fn slice(&self) -> &[u8] {
        &self.0
    }
}

impl SliceWrapperMut<u8> for WipingCells {
    fn slice_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Allocator<u8> for WipingAlloc {
    type AllocatedMemory = WipingCells;

    fn alloc_cell(&mut self, len: usize) -> WipingCells {
        WipingCells(Zeroizing::new(vec![0; len]))
    }

    fn free_cell(&mut self, _data: WipingCells) {}
}

type State = BrotliState<WipingAlloc, StandardAlloc, StandardAlloc>;

/// One brotli stream.
pub(super) struct Brotli {
    // Boxed because the state is large and the decoder is moved.
    state: Box<State>,
    ended: bool,
}

impl Brotli {
    pub(super) fn new() -> Self {
        // `new` would accept the large-window extension, whose window can reach 1 GiB; RFC 7932 stops at 16 MiB.
        Self {
            state: Box::new(State::new_strict(WipingAlloc, StandardAlloc::default(), StandardAlloc::default())),
            ended: false,
        }
    }

    fn run(&mut self, input: &[u8], out: &mut [u8]) -> Result<Step, DecodeError> {
        let (mut available_in, mut consumed) = (input.len(), 0);
        let (mut available_out, mut produced, mut total_out) = (out.len(), 0, 0);
        let result = BrotliDecompressStream(
            &mut available_in,
            &mut consumed,
            input,
            &mut available_out,
            &mut produced,
            out,
            &mut total_out,
            &mut self.state,
        );
        match result {
            BrotliResult::ResultSuccess => self.ended = true,
            BrotliResult::NeedsMoreInput | BrotliResult::NeedsMoreOutput => {}
            BrotliResult::ResultFailure => return Err(DecodeError::Corrupt),
        }
        Ok(Step { consumed, produced })
    }
}

impl Engine for Brotli {
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
