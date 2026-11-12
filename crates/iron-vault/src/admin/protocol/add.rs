//! `add`'s arguments and success result ([admin protocol: add](../../../../../design/admin-protocol.md#add)), which `replace` shares.
//! Only the bounds are checked here: the host stays text, and the service parses the name, the hosts and the material
//! it prompts for.

use iron_vault_policy::{CredentialKind, Port};
use iron_vault_store::RecordId;

use super::fields::{self, Field, exact, read_text};
use super::{AdminRequest, FrameError, MAX_ORIGIN_HOST_LEN, MAX_ORIGINS, RequestedOrigin};

const TAG_COMMAND: u16 = super::body::TAG_COMMAND;
const TAG_NAME: u16 = 2;
const TAG_KIND: u16 = 3;
const TAG_ORIGINS: u16 = 4;
const TAG_RECORD_ID: u16 = 2;

const KIND_STATIC: u8 = 1;
const KIND_BASIC: u8 = 2;

const INVALID_ORIGINS: FrameError = FrameError::InvalidValue(TAG_ORIGINS);

/// Encodes the request body. Out-of-bounds origins are refused here, so the encoder never writes a body the decoder
/// would refuse.
pub(super) fn encode_request(command: u16, name: &str, kind: CredentialKind, origins: &[RequestedOrigin]) -> Result<Vec<u8>, FrameError> {
    let mut out = Vec::new();
    fields::put(&mut out, TAG_COMMAND, &command.to_be_bytes());
    fields::put(&mut out, TAG_NAME, name.as_bytes());
    fields::put(&mut out, TAG_KIND, &[kind_byte(kind)]);
    fields::put(&mut out, TAG_ORIGINS, &encode_origins(origins)?);
    Ok(out)
}

/// Builds the request `command` names from the decoded name, kind and origins.
pub(super) fn decode_request(
    fields: &[Field<'_>],
    command: fn(String, CredentialKind, Vec<RequestedOrigin>) -> AdminRequest,
) -> Result<AdminRequest, FrameError> {
    let [_, name, kind, origins] = exact(fields, [TAG_COMMAND, TAG_NAME, TAG_KIND, TAG_ORIGINS])?;
    Ok(command(read_text(TAG_NAME, name)?, read_kind(kind)?, decode_origins(origins)?))
}

/// Encodes the success body: the command it answers, then the new record's ID.
pub(super) fn encode_result(command: u16, record_id: RecordId) -> Vec<u8> {
    let mut out = Vec::new();
    fields::put(&mut out, TAG_COMMAND, &command.to_be_bytes());
    fields::put(&mut out, TAG_RECORD_ID, record_id.as_bytes());
    out
}

/// Reads the new record's ID from a success body.
pub(super) fn decode_result(fields: &[Field<'_>]) -> Result<RecordId, FrameError> {
    let [_, record_id] = exact(fields, [TAG_COMMAND, TAG_RECORD_ID])?;
    <[u8; 16]>::try_from(record_id)
        .ok()
        .and_then(|bytes| RecordId::from_bytes(bytes).ok())
        .ok_or(FrameError::InvalidValue(TAG_RECORD_ID))
}

fn kind_byte(kind: CredentialKind) -> u8 {
    match kind {
        CredentialKind::Static => KIND_STATIC,
        CredentialKind::Basic => KIND_BASIC,
    }
}

fn read_kind(value: &[u8]) -> Result<CredentialKind, FrameError> {
    match value {
        [KIND_STATIC] => Ok(CredentialKind::Static),
        [KIND_BASIC] => Ok(CredentialKind::Basic),
        _ => Err(FrameError::InvalidValue(TAG_KIND)),
    }
}

/// Encodes the origins: a `u8` count, then per origin a `u8` host length, the host and a `u16` port.
///
/// ```text
/// count  host len  host               port
/// 01     0b        "example.com"      01 bb      one origin, example.com:443
/// ```
fn encode_origins(origins: &[RequestedOrigin]) -> Result<Vec<u8>, FrameError> {
    let count = u8::try_from(origins.len())
        .ok()
        .filter(|count| (1..=MAX_ORIGINS).contains(&usize::from(*count)))
        .ok_or(INVALID_ORIGINS)?;
    origins.iter().try_fold(vec![count], |mut out, origin| {
        let len = u8::try_from(origin.host.len())
            .ok()
            .filter(|len| (1..=MAX_ORIGIN_HOST_LEN).contains(&usize::from(*len)))
            .ok_or(INVALID_ORIGINS)?;
        out.push(len);
        out.extend_from_slice(origin.host.as_bytes());
        out.extend_from_slice(&origin.port.get().to_be_bytes());
        Ok(out)
    })
}

fn decode_origins(value: &[u8]) -> Result<Vec<RequestedOrigin>, FrameError> {
    let (&count, mut rest) = value.split_first().ok_or(INVALID_ORIGINS)?;
    if !(1..=MAX_ORIGINS).contains(&usize::from(count)) {
        return Err(INVALID_ORIGINS);
    }
    let origins = (0..count)
        .map(|_| {
            let (origin, after) = read_origin(rest)?;
            rest = after;
            Ok(origin)
        })
        .collect::<Result<Vec<_>, FrameError>>()?;
    rest.is_empty().then_some(origins).ok_or(INVALID_ORIGINS)
}

fn read_origin(bytes: &[u8]) -> Result<(RequestedOrigin, &[u8]), FrameError> {
    let (&len, rest) = bytes.split_first().ok_or(INVALID_ORIGINS)?;
    if !(1..=MAX_ORIGIN_HOST_LEN).contains(&usize::from(len)) {
        return Err(INVALID_ORIGINS);
    }
    let (host, rest) = rest.split_at_checked(usize::from(len)).ok_or(INVALID_ORIGINS)?;
    let (port, rest) = rest.split_first_chunk::<2>().ok_or(INVALID_ORIGINS)?;
    let port = Port::try_from(u16::from_be_bytes(*port)).map_err(|_| INVALID_ORIGINS)?;
    let host = read_text(TAG_ORIGINS, host)?;
    Ok((RequestedOrigin { host, port }, rest))
}
