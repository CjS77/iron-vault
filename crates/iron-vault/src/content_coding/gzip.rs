//! The gzip engine (RFC 1952): members back to back, each a header, a raw deflate stream and a CRC-32 and length trailer.
//!
//! flate2's own gzip decoders are pull-based readers; this one parses the framing byte by byte so it can be fed any
//! split of the stream, and leaves only the deflate stream to flate2's low-level API.

use flate2::Crc;

use super::{DecodeError, Engine, Inflate, Step};

const FHCRC: u8 = 0x02;
const FEXTRA: u8 = 0x04;
const FNAME: u8 = 0x08;
const FCOMMENT: u8 = 0x10;
/// The flag bits RFC 1952 reserves; a header that sets one is not one this decoder understands.
const RESERVED: u8 = 0xe0;
const FIXED_HEADER_LEN: u8 = 10;
const TRAILER_LEN: usize = 8;

/// Where the header parser is. The optional fields come in this order, each present only if its flag is set.
#[derive(Debug, Clone, Copy)]
enum Stage {
    /// The first ten bytes: magic, method, flags, and fields this decoder ignores. Holds how many have been read.
    Fixed(u8),
    /// The two-byte length of the extra field: bytes read so far, length so far.
    ExtraLen(u8, u16),
    /// The extra field: bytes left.
    Extra(u16),
    /// The zero-terminated file name.
    Name,
    /// The zero-terminated comment.
    Comment,
    /// The header CRC-16: bytes read so far, value so far.
    Check(u8, u16),
}

impl Stage {
    /// The first optional field at or after position `from` in header order whose flag is set; `None` ends the header.
    fn optional(flags: u8, from: usize) -> Option<Stage> {
        [
            (FEXTRA, Stage::ExtraLen(0, 0)),
            (FNAME, Stage::Name),
            (FCOMMENT, Stage::Comment),
            (FHCRC, Stage::Check(0, 0)),
        ]
        .into_iter()
        .skip(from)
        .find(|(flag, _)| flags & flag != 0)
        .map(|(_, stage)| stage)
    }
}

/// One member's header, parsed a byte at a time.
struct Header {
    stage: Stage,
    flags: u8,
    /// Over the header bytes, for the optional CRC-16.
    crc: Crc,
    /// Whether an earlier member ended, so a wrong magic is trailing data rather than a corrupt first member.
    after_member: bool,
}

impl Header {
    fn new(after_member: bool) -> Self {
        Self {
            stage: Stage::Fixed(0),
            flags: 0,
            crc: Crc::new(),
            after_member,
        }
    }

    /// Reads header bytes from `input` until the header ends; returns how many it used and whether it ended.
    fn feed(&mut self, input: &[u8]) -> Result<(usize, bool), DecodeError> {
        for (used, &byte) in input.iter().enumerate() {
            if self.byte(byte)? {
                return Ok((used + 1, true));
            }
        }
        Ok((input.len(), false))
    }

    /// Reads one header byte; true when it was the header's last.
    fn byte(&mut self, byte: u8) -> Result<bool, DecodeError> {
        // The CRC-16 covers every header byte before itself. Hashing a long name byte by byte is wasted without the flag.
        if matches!(self.stage, Stage::Fixed(_)) || (self.flags & FHCRC != 0 && !matches!(self.stage, Stage::Check(..))) {
            self.crc.update(&[byte]);
        }
        match self.stage {
            Stage::Fixed(at) => self.fixed(at, byte),
            Stage::ExtraLen(seen, len) => {
                let len = len | u16::from(byte) << (8 * seen);
                match (seen, len) {
                    (0, _) => self.stage = Stage::ExtraLen(1, len),
                    (_, 0) => return Ok(self.advance(1)),
                    _ => self.stage = Stage::Extra(len),
                }
                Ok(false)
            }
            Stage::Extra(left) if left > 1 => {
                self.stage = Stage::Extra(left - 1);
                Ok(false)
            }
            Stage::Extra(_) => Ok(self.advance(1)),
            Stage::Name => Ok(byte == 0 && self.advance(2)),
            Stage::Comment => Ok(byte == 0 && self.advance(3)),
            Stage::Check(0, _) => {
                self.stage = Stage::Check(1, u16::from(byte));
                Ok(false)
            }
            Stage::Check(_, low) => {
                let expected = low | u16::from(byte) << 8;
                // Only the low 16 bits of the running CRC-32 are stored.
                if self.crc.sum() as u16 == expected {
                    Ok(true)
                } else {
                    Err(DecodeError::Corrupt)
                }
            }
        }
    }

    /// Checks fixed header byte `at` and moves on after the tenth.
    fn fixed(&mut self, at: u8, byte: u8) -> Result<bool, DecodeError> {
        let wrong_magic = if self.after_member {
            DecodeError::TrailingData
        } else {
            DecodeError::Corrupt
        };
        match at {
            0 if byte != 0x1f => return Err(wrong_magic),
            1 if byte != 0x8b => return Err(wrong_magic),
            // Method 8 is deflate, the only one RFC 1952 defines.
            2 if byte != 8 => return Err(DecodeError::Corrupt),
            3 if byte & RESERVED != 0 => return Err(DecodeError::Corrupt),
            3 => self.flags = byte,
            _ => {}
        }
        self.stage = Stage::Fixed(at + 1);
        Ok(at + 1 == FIXED_HEADER_LEN && self.advance(0))
    }

    /// Moves to the next optional field at or after `from`; true when there is none and the header is complete.
    fn advance(&mut self, from: usize) -> bool {
        Stage::optional(self.flags, from).map(|stage| self.stage = stage).is_none()
    }
}

/// Where the engine is in the stream.
enum State {
    Header(Header),
    /// Inside a member's deflate stream.
    Body,
    /// The eight trailer bytes: those read so far and how many, then the CRC-32 and length of the member's output.
    Trailer([u8; TRAILER_LEN], usize, u32, u32),
    /// After a member: the next byte starts another member, or is trailing data.
    Between,
}

/// A gzip stream of one or more members.
pub(super) struct Gzip {
    state: State,
    inflate: Inflate,
    /// Over the current member's output.
    crc: Crc,
}

impl Gzip {
    pub(super) fn new() -> Self {
        Self {
            state: State::Header(Header::new(false)),
            inflate: Inflate::new(false),
            crc: Crc::new(),
        }
    }

    fn header(&mut self, input: &[u8]) -> Result<Step, DecodeError> {
        let State::Header(header) = &mut self.state else {
            return Ok(Step::default());
        };
        let (consumed, done) = header.feed(input)?;
        if done {
            self.inflate.restart();
            self.crc.reset();
            self.state = State::Body;
        }
        Ok(Step { consumed, produced: 0 })
    }

    fn body(&mut self, input: &[u8], out: &mut [u8]) -> Result<Step, DecodeError> {
        let step = self.inflate.run(input, out)?;
        // `run` has checked that `produced` fits `out`.
        self.crc.update(out.get(..step.produced).unwrap_or_default());
        if self.inflate.ended {
            self.state = State::Trailer([0; TRAILER_LEN], 0, self.crc.sum(), self.crc.amount());
        }
        Ok(step)
    }

    fn trailer(&mut self, input: &[u8]) -> Result<Step, DecodeError> {
        let State::Trailer(read, len, crc, size) = &mut self.state else {
            return Ok(Step::default());
        };
        let consumed = input.len().min(TRAILER_LEN - *len);
        read.iter_mut().skip(*len).zip(input).for_each(|(slot, &byte)| *slot = byte);
        *len += consumed;
        if *len == TRAILER_LEN {
            let (stored_crc, stored_size) = read.split_at(4);
            // Both are little-endian; the length is of the uncompressed data modulo 2^32.
            if stored_crc != crc.to_le_bytes() || stored_size != size.to_le_bytes() {
                return Err(DecodeError::Corrupt);
            }
            self.state = State::Between;
        }
        Ok(Step { consumed, produced: 0 })
    }
}

impl Engine for Gzip {
    fn step(&mut self, input: &[u8], out: &mut [u8]) -> Result<Step, DecodeError> {
        if matches!(self.state, State::Between) && !input.is_empty() {
            self.state = State::Header(Header::new(true));
        }
        match self.state {
            State::Header(_) => self.header(input),
            State::Body => self.body(input, out),
            State::Trailer(..) => self.trailer(input),
            State::Between => Ok(Step::default()),
        }
    }

    fn is_complete(&self) -> bool {
        matches!(self.state, State::Between)
    }
}
