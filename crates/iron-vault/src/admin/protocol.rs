//! The admin protocol's frames and their pure codec (`design/admin-protocol.md`). Nothing here does I/O: the transport
//! hands [`decode`] the bytes it has read and sends what [`encode`] writes.

mod body;
mod fields;
#[cfg(test)]
mod tests;

use std::fmt;

use thiserror::Error;
use zeroize::Zeroizing;

/// The protocol version this code writes and the only one it reads.
pub const PROTOCOL_VERSION: u16 = 1;
/// The largest body a frame may carry; a declared length above it is refused before any body byte is read.
pub const MAX_BODY_LEN: usize = 64 * 1024;
/// The fixed header size: version (2), kind (1), body length (4).
pub const HEADER_LEN: usize = 7;

/// One command with its arguments, sent by the CLI as the first frame of an exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdminRequest {
    /// Does nothing; the service answers with success. Command ID 1.
    Ping,
}

/// The service asking the CLI to collect one value from the owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prompt {
    /// The text the CLI shows the owner.
    pub label: String,
    /// Whether the value is secret, so the CLI turns terminal echo off while the owner types.
    pub secret: bool,
}

/// The bytes the owner typed in answer to a prompt: a secret-bearing type (`design/secret-handling.md`).
///
/// It has no `Clone`, `Display` or serde impl, and its `Debug` shows no byte, so the value cannot be copied, printed
/// or serialized by accident. Its buffer clears itself on drop.
pub struct OwnerInput(Zeroizing<Vec<u8>>);

impl OwnerInput {
    /// Wraps a value already held in a clearing buffer, so building one never leaves an unwiped copy.
    pub fn new(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }

    /// The typed bytes, for the operation that turns them into its own secret type.
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for OwnerInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OwnerInput([REDACTED])")
    }
}

/// The final frame of an exchange.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdminResponse {
    /// The command completed.
    Success,
    /// The command failed. The message is the service's own text and never contains owner input.
    Error {
        /// The stable code scripts act on.
        code: ErrorCode,
        /// Text for the owner; it may change between releases.
        message: String,
    },
}

/// The stable reason an admin response reports an error; the numbers are part of the protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    /// The request frame's protocol version is not the service's.
    UnsupportedVersion = 1,
    /// The frame broke a rule of the protocol.
    MalformedFrame = 2,
    /// The command ID is not one the service knows.
    UnknownCommand = 3,
    /// A well-formed frame arrived out of turn in the exchange.
    UnexpectedFrame = 4,
}

/// One message of the admin protocol. It holds owner input when it is an owner-input frame, so it is secret-bearing
/// and has no `Clone`.
#[derive(Debug)]
pub enum Frame {
    /// Kind 1, CLI to service.
    Request(AdminRequest),
    /// Kind 2, service to CLI.
    Prompt(Prompt),
    /// Kind 3, CLI to service.
    OwnerInput(OwnerInput),
    /// Kind 4 (success) or 5 (error), service to CLI.
    Response(AdminResponse),
}

/// What [`decode`] found at the start of its input.
#[derive(Debug)]
pub enum Decoded {
    /// A whole frame, and how many input bytes it used; any bytes after those belong to the next frame.
    Frame {
        /// The decoded frame.
        frame: Frame,
        /// The frame's encoded length.
        used: usize,
    },
    /// The input is a valid but incomplete prefix: at least this many more bytes are needed to make progress.
    NeedMore(usize),
}

/// Why a frame could not be encoded or decoded. Variants name protocol numbers, never body bytes, so no error can
/// carry owner input into a log or a response message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum FrameError {
    /// The frame's protocol version is not [`PROTOCOL_VERSION`].
    #[error("unsupported admin protocol version {0}; this side speaks version {PROTOCOL_VERSION}")]
    UnsupportedVersion(u16),
    /// The frame kind is not one this version defines.
    #[error("unknown admin frame kind {0}")]
    UnknownKind(u8),
    /// The body is longer than [`MAX_BODY_LEN`].
    #[error("admin frame body is longer than {MAX_BODY_LEN} bytes")]
    BodyTooLong,
    /// A field's header or value runs past the end of the body.
    #[error("admin frame field runs past the end of the body")]
    TruncatedField,
    /// A tag appears twice.
    #[error("admin frame field tag {0} is repeated")]
    DuplicateTag(u16),
    /// A tag is lower than the one before it.
    #[error("admin frame field tag {0} is out of order")]
    TagOutOfOrder(u16),
    /// A tag this frame kind does not define.
    #[error("unknown admin frame field tag {0}")]
    UnknownTag(u16),
    /// A field this frame kind requires is absent.
    #[error("admin frame field tag {0} is missing")]
    MissingField(u16),
    /// A fixed-width field has the wrong length, or a flag is neither 0 nor 1.
    #[error("admin frame field tag {0} has an invalid value")]
    InvalidValue(u16),
    /// A text field is not UTF-8.
    #[error("admin frame field tag {0} is not UTF-8")]
    InvalidUtf8(u16),
    /// The command ID is not one this version defines.
    #[error("unknown admin command {0}")]
    UnknownCommand(u16),
    /// The error code is not one this version defines.
    #[error("unknown admin error code {0}")]
    UnknownErrorCode(u16),
}

/// The frame kind byte, which selects how the body is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FrameKind {
    Request = 1,
    Prompt = 2,
    OwnerInput = 3,
    Success = 4,
    Error = 5,
}

impl FrameKind {
    fn from_byte(byte: u8) -> Result<Self, FrameError> {
        [Self::Request, Self::Prompt, Self::OwnerInput, Self::Success, Self::Error]
            .into_iter()
            .find(|kind| *kind as u8 == byte)
            .ok_or(FrameError::UnknownKind(byte))
    }
}

/// Appends `frame`'s one encoding to `out`. A caller sending owner input passes a clearing buffer, because the encoding
/// holds the value; `out` is grown once, before writing, so no partial copy is left behind in a freed allocation.
pub fn encode(frame: &Frame, out: &mut Vec<u8>) -> Result<(), FrameError> {
    match frame {
        Frame::Request(request) => put_frame(out, FrameKind::Request, &body::encode_request(*request)),
        Frame::Prompt(prompt) => put_frame(out, FrameKind::Prompt, &body::encode_prompt(prompt)),
        Frame::OwnerInput(input) => put_frame(out, FrameKind::OwnerInput, input.expose_secret()),
        Frame::Response(AdminResponse::Success) => put_frame(out, FrameKind::Success, &[]),
        Frame::Response(AdminResponse::Error { code, message }) => put_frame(out, FrameKind::Error, &body::encode_error(*code, message)),
    }
}

/// Reads the frame at the start of `bytes`: a whole frame and its length, a request for more bytes, or the first rule
/// the input breaks. The header is checked (version, then kind, then length) before any body byte is looked at.
pub fn decode(bytes: &[u8]) -> Result<Decoded, FrameError> {
    let Some(header) = bytes.first_chunk::<HEADER_LEN>() else {
        return Ok(Decoded::NeedMore(HEADER_LEN - bytes.len()));
    };
    let (kind, body_len) = read_header(header)?;
    let used = HEADER_LEN + body_len;
    let Some(body) = bytes.get(HEADER_LEN..used) else {
        return Ok(Decoded::NeedMore(used - bytes.len()));
    };
    let frame = match kind {
        FrameKind::Request => Frame::Request(body::decode_request(body)?),
        FrameKind::Prompt => Frame::Prompt(body::decode_prompt(body)?),
        // The one copy of the value: straight from the received bytes into its clearing buffer, sized exactly.
        FrameKind::OwnerInput => Frame::OwnerInput(OwnerInput::new(Zeroizing::new(body.to_vec()))),
        FrameKind::Success => Frame::Response(body::decode_success(body)?),
        FrameKind::Error => Frame::Response(body::decode_error(body)?),
    };
    Ok(Decoded::Frame { frame, used })
}

fn put_frame(out: &mut Vec<u8>, kind: FrameKind, body: &[u8]) -> Result<(), FrameError> {
    let len = u32::try_from(body.len())
        .ok()
        .filter(|_| body.len() <= MAX_BODY_LEN)
        .ok_or(FrameError::BodyTooLong)?;
    out.reserve(HEADER_LEN + body.len());
    out.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    out.push(kind as u8);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    Ok(())
}

/// The frame kind and body length, after the version check, so a newer peer is told its version is unsupported even
/// when its kinds are unknown here.
fn read_header(header: &[u8; HEADER_LEN]) -> Result<(FrameKind, usize), FrameError> {
    let [v0, v1, kind, l0, l1, l2, l3] = *header;
    let version = u16::from_be_bytes([v0, v1]);
    if version != PROTOCOL_VERSION {
        return Err(FrameError::UnsupportedVersion(version));
    }
    let kind = FrameKind::from_byte(kind)?;
    let body_len = usize::try_from(u32::from_be_bytes([l0, l1, l2, l3]))
        .ok()
        .filter(|len| *len <= MAX_BODY_LEN)
        .ok_or(FrameError::BodyTooLong)?;
    Ok((kind, body_len))
}
