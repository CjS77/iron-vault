// SPDX-License-Identifier: MPL-2.0
//! Encodes and decodes the helper response `IVTR` v1: a status byte, then the fields that status carries
//! ([TPM approval signer: helper protocol](../../../design/tpm-approval-signer.md#helper-protocol)).
//!
//! The helper writes exactly one response per connection, and the service turns each status into what it tells the
//! owner, such as a wrong PIN or a wait before the TPM accepts another try.

use crate::frame::framed;
use crate::request::{put_key, read_key};
use crate::wire::Reader;
use crate::{PUBLIC_KEY_LEN, ProtocolError, SIGNATURE_LEN, TpmKeyParts};

const MAGIC: [u8; 4] = *b"IVTR";
const VERSION: u8 = 1;

/// Answers one helper request.
///
/// The helper sends each refusal that needs no authorization ([`NotThisTpm`](Self::NotThisTpm),
/// [`KeyMismatch`](Self::KeyMismatch), [`WeakDaSettings`](Self::WeakDaSettings), [`RefusedMessage`](Self::RefusedMessage),
/// [`Malformed`](Self::Malformed)) before it runs any authorized TPM command, so these refusals spend no
/// dictionary-attack try.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// `00`: the key exists.
    Created {
        /// The parts the service keeps in the key blob.
        key: TpmKeyParts,
        /// The key's uncompressed SEC1 point, to pin.
        public_key: [u8; PUBLIC_KEY_LEN],
    },
    /// `01`: the message is signed.
    Signed {
        /// `r ‖ s` with low `s`.
        signature: [u8; SIGNATURE_LEN],
    },
    /// `02`: the TPM refused the authorization value; one try spent.
    WrongPin,
    /// `03`: the TPM is in lockout, or the lockout reserve withheld the try.
    LockedOut {
        /// Whole seconds until the helper would try again.
        wait_seconds: u64,
    },
    /// `04`: the primary's name differs from the blob's: another TPM, or this one after a clear.
    NotThisTpm,
    /// `05`: the loaded key's attributes or point are not the pinned key's.
    KeyMismatch,
    /// `06`: the TPM's dictionary-attack settings would not limit guessing enough.
    WeakDaSettings,
    /// `07`: the message is none of the three the helper signs.
    RefusedMessage,
    /// `08`: any other failure.
    TpmError {
        /// The TPM or TSS response code; 0 when the failure was the TSS wrapper's own, with no response code.
        code: u32,
    },
    /// `09`: the request does not decode.
    Malformed,
}

impl Response {
    /// Returns the status byte that opens the encoded response.
    pub fn status(&self) -> u8 {
        match self {
            Response::Created { .. } => 0x00,
            Response::Signed { .. } => 0x01,
            Response::WrongPin => 0x02,
            Response::LockedOut { .. } => 0x03,
            Response::NotThisTpm => 0x04,
            Response::KeyMismatch => 0x05,
            Response::WeakDaSettings => 0x06,
            Response::RefusedMessage => 0x07,
            Response::TpmError { .. } => 0x08,
            Response::Malformed => 0x09,
        }
    }

    /// Encodes the response as a frame, refusing one over the frame limit.
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut body = MAGIC.to_vec();
        body.extend([VERSION, self.status()]);
        match self {
            Response::Created { key, public_key } => {
                put_key(&mut body, key);
                body.extend_from_slice(public_key);
            }
            Response::Signed { signature } => body.extend_from_slice(signature),
            Response::LockedOut { wait_seconds } => body.extend_from_slice(&wait_seconds.to_be_bytes()),
            Response::TpmError { code } => body.extend_from_slice(&code.to_be_bytes()),
            _ => {}
        }
        framed(&body).map(|frame| frame.to_vec())
    }

    /// Decodes a frame body, accepting only the response's one encoding.
    pub fn decode(body: &[u8]) -> Result<Self, ProtocolError> {
        let mut reader = Reader::with_header(body, MAGIC, VERSION)?;
        let response = match reader.u8()? {
            0x00 => Response::Created {
                key: read_key(&mut reader)?,
                public_key: reader.array()?,
            },
            0x01 => Response::Signed {
                signature: reader.array()?,
            },
            0x02 => Response::WrongPin,
            0x03 => Response::LockedOut {
                wait_seconds: u64::from_be_bytes(reader.array()?),
            },
            0x04 => Response::NotThisTpm,
            0x05 => Response::KeyMismatch,
            0x06 => Response::WeakDaSettings,
            0x07 => Response::RefusedMessage,
            0x08 => Response::TpmError {
                code: u32::from_be_bytes(reader.array()?),
            },
            0x09 => Response::Malformed,
            other => return Err(ProtocolError::UnknownStatus(other)),
        };
        reader.finish()?;
        Ok(response)
    }
}
