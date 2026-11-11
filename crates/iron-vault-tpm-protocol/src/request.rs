//! The helper request `IVTQ` v1 (`design/tpm-approval-signer.md` "Helper protocol").

use zeroize::Zeroizing;

use crate::frame::framed;
use crate::wire::{Reader, put_field};
use crate::{PUBLIC_KEY_LEN, ProtocolError, TpmAuthValue, TpmKeyParts};

const MAGIC: [u8; 4] = *b"IVTQ";
const VERSION: u8 = 1;
const CREATE: u8 = 0x01;
const SIGN: u8 = 0x02;

/// One request to the TPM signing helper; one per connection.
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

/// The fields of a sign request.
#[derive(Debug)]
pub struct SignRequest {
    /// The key's authorization value.
    pub auth: TpmAuthValue,
    /// The key's parts, from its key blob.
    pub key: TpmKeyParts,
    /// The pinned approver's public key, which the loaded key must be.
    pub pinned_key: [u8; PUBLIC_KEY_LEN],
    /// The message to sign. The helper signs only the three it recognises, and decoding does not judge it, so a
    /// request with any other message still decodes and gets its own refusal.
    pub message: Vec<u8>,
}

impl Request {
    /// The request as a frame, refused when it is over the frame limit. Zeroized on drop: it holds the authorization
    /// value.
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

    /// The request a frame body holds, accepted only in its one encoding.
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
