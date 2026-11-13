// SPDX-License-Identifier: MPL-2.0
//! Encodes and decodes the helper request `IVTQ` v1, the one message the service sends on each helper connection
//! ([TPM approval signer: helper protocol](../../../design/tpm-approval-signer.md#helper-protocol)).
//!
//! ```text
//! "IVTQ" | version 01 | 01 create | auth value (32 bytes)
//! "IVTQ" | version 01 | 02 sign   | auth value (32 bytes) | primary name | public | private | pinned key (65) | message
//! ```
//!
//! The primary name, public area, private area and message are each a `u64` length, then the bytes.

use zeroize::Zeroizing;

use crate::frame::framed;
use crate::wire::{Reader, put_field};
use crate::{PUBLIC_KEY_LEN, ProtocolError, TpmAuthValue, TpmKeyParts};

const MAGIC: [u8; 4] = *b"IVTQ";
const VERSION: u8 = 1;
const CREATE: u8 = 0x01;
const SIGN: u8 = 0x02;

/// Asks the TPM signing helper to create or use a TPM approval key. Each connection carries exactly one request.
#[derive(Debug)]
pub enum Request {
    /// `01`: create a TPM approval key under this authorization value.
    Create {
        /// The new key's authorization value.
        auth: TpmAuthValue,
    },
    /// `02`: sign a message with an existing key.
    Sign(SignRequest),
}

/// Carries what the helper needs to load a TPM approval key, check it and sign one message.
#[derive(Debug)]
pub struct SignRequest {
    /// The key's authorization value.
    pub auth: TpmAuthValue,
    /// The key's parts, from its key blob.
    pub key: TpmKeyParts,
    /// The pinned approver's public key, which the loaded key must be.
    pub pinned_key: [u8; PUBLIC_KEY_LEN],
    /// The message to sign. The helper signs only the three payloads it recognises. Decoding does not judge the
    /// message, so a request with any other message still decodes and gets its own refusal,
    /// [`Response::RefusedMessage`](crate::Response::RefusedMessage).
    pub message: Vec<u8>,
}

impl Request {
    /// Encodes the request as a frame, refusing one over the frame limit.
    ///
    /// The frame is zeroized on drop because it holds the authorization value.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        let mut body = Zeroizing::new(MAGIC.to_vec());
        body.push(VERSION);
        match self {
            Request::Create { auth } => {
                body.push(CREATE);
                body.extend_from_slice(auth.as_bytes());
            }
            Request::Sign(sign) => {
                body.push(SIGN);
                body.extend_from_slice(sign.auth.as_bytes());
                put_key(&mut body, &sign.key);
                body.extend_from_slice(&sign.pinned_key);
                put_field(&mut body, &sign.message);
            }
        }
        framed(&body)
    }

    /// Decodes a frame body, accepting only the request's one encoding.
    pub fn decode(body: &[u8]) -> Result<Self, ProtocolError> {
        let mut reader = Reader::with_header(body, MAGIC, VERSION)?;
        let request = match reader.u8()? {
            CREATE => Request::Create {
                auth: TpmAuthValue::from_bytes(reader.array()?),
            },
            SIGN => Request::Sign(SignRequest {
                auth: TpmAuthValue::from_bytes(reader.array()?),
                key: read_key(&mut reader)?,
                pinned_key: reader.array()?,
                message: reader.field()?,
            }),
            other => return Err(ProtocolError::UnknownOperation(other)),
        };
        reader.finish()?;
        Ok(request)
    }
}

/// Appends a key's three parts as fields: primary name, public area, private area.
pub(crate) fn put_key(out: &mut Vec<u8>, key: &TpmKeyParts) {
    put_field(out, &key.primary_name);
    put_field(out, &key.public);
    put_field(out, &key.private);
}

/// Reads a key's three parts, in [`put_key`]'s order.
pub(crate) fn read_key(reader: &mut Reader<'_>) -> Result<TpmKeyParts, ProtocolError> {
    Ok(TpmKeyParts {
        primary_name: reader.field()?,
        public: reader.field()?,
        private: reader.field()?,
    })
}
