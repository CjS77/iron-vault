//! The `list` result: whether a vault is open, then one entry per credential with its kind and permitted origins
//! (`design/admin-protocol.md#list`). Names, kinds, hosts and ports only: no type here can hold a secret value or a
//! record digest.

use iron_vault_policy::{CredentialKind, Host, Port};

use super::fields::{self, Field, exact, read_flag};
use super::status::{put_name, read_standing, standing_code, take_in, take_name_in};
use super::{AdminResponse, FrameError};
use crate::standing::{CredentialStanding, RecordSummary, Standing};

const TAG_COMMAND: u16 = super::body::TAG_COMMAND;
const TAG_OPEN: u16 = 2;
const TAG_ENTRIES: u16 = 3;

const KIND_UNKNOWN: u8 = 0;
const KIND_STATIC: u8 = 1;
const KIND_BASIC: u8 = 2;

const INVALID_ENTRIES: FrameError = FrameError::InvalidValue(TAG_ENTRIES);

/// The success body: the command it answers, the vault-open flag, then the entries. `None` is no open vault and no
/// entries. An entry the wire cannot carry (a healthy credential without its summary, or more origins than a byte
/// counts) is refused, never truncated.
pub(super) fn encode_result(command: u16, credentials: Option<&[CredentialStanding]>) -> Result<Vec<u8>, FrameError> {
    let entries = credentials.map_or(Ok(Vec::new()), encode_entries)?;
    let mut out = Vec::new();
    fields::put(&mut out, TAG_COMMAND, &command.to_be_bytes());
    fields::put(&mut out, TAG_OPEN, &[u8::from(credentials.is_some())]);
    fields::put(&mut out, TAG_ENTRIES, &entries);
    Ok(out)
}

pub(super) fn decode_result(fields: &[Field<'_>]) -> Result<AdminResponse, FrameError> {
    let [_, open, entries] = exact(fields, [TAG_COMMAND, TAG_OPEN, TAG_ENTRIES])?;
    let credentials = if read_flag(TAG_OPEN, open)? {
        Some(decode_entries(entries)?)
    } else {
        entries.is_empty().then_some(()).ok_or(INVALID_ENTRIES)?;
        None
    };
    Ok(AdminResponse::List { credentials })
}

fn encode_entries(credentials: &[CredentialStanding]) -> Result<Vec<u8>, FrameError> {
    credentials.iter().try_fold(Vec::new(), |mut out, credential| {
        put_name(&mut out, credential.name.as_str());
        out.push(standing_code(credential.standing));
        let summary = credential.summary.as_ref();
        if (credential.standing == Standing::Healthy) != summary.is_some() {
            return Err(INVALID_ENTRIES);
        }
        out.push(summary.map_or(KIND_UNKNOWN, |summary| kind_code(summary.kind)));
        out.push(summary.map_or(Ok(0), |summary| u8::try_from(summary.origins.len()).map_err(|_| INVALID_ENTRIES))?);
        summary.iter().flat_map(|summary| &summary.origins).try_for_each(|(host, port)| {
            let host = host.to_string();
            out.push(u8::try_from(host.len()).map_err(|_| INVALID_ENTRIES)?);
            out.extend_from_slice(host.as_bytes());
            out.extend_from_slice(&port.get().to_be_bytes());
            Ok::<_, FrameError>(())
        })?;
        Ok(out)
    })
}

fn decode_entries(mut rest: &[u8]) -> Result<Vec<CredentialStanding>, FrameError> {
    std::iter::from_fn(|| (!rest.is_empty()).then(|| take_entry(&mut rest))).collect()
}

/// A damaged record has no kind and no origins; a healthy one has a kind and at least one origin.
fn take_entry(rest: &mut &[u8]) -> Result<CredentialStanding, FrameError> {
    let name = take_name_in(TAG_ENTRIES, rest)?;
    let [standing, kind, count] = *take_in(TAG_ENTRIES, rest, 3)?.first_chunk::<3>().ok_or(INVALID_ENTRIES)?;
    let standing = read_standing(standing).map_err(|_| INVALID_ENTRIES)?;
    let summary = match (standing, read_kind(kind)?) {
        (Standing::Damaged(_), None) if count == 0 => None,
        (Standing::Healthy, Some(kind)) if count > 0 => Some(RecordSummary {
            kind,
            origins: (0..count).map(|_| take_origin(rest)).collect::<Result<_, _>>()?,
        }),
        _ => return Err(INVALID_ENTRIES),
    };
    Ok(CredentialStanding {
        name,
        standing,
        unavailable_routes: Vec::new(),
        summary,
    })
}

fn take_origin(rest: &mut &[u8]) -> Result<(Host, Port), FrameError> {
    let host = take_name_in::<Host>(TAG_ENTRIES, rest)?;
    let port = <[u8; 2]>::try_from(take_in(TAG_ENTRIES, rest, 2)?).map_err(|_| INVALID_ENTRIES)?;
    Ok((host, Port::try_from(u16::from_be_bytes(port)).map_err(|_| INVALID_ENTRIES)?))
}

fn kind_code(kind: CredentialKind) -> u8 {
    match kind {
        CredentialKind::Static => KIND_STATIC,
        CredentialKind::Basic => KIND_BASIC,
    }
}

/// `None` is the unknown kind of a damaged record.
fn read_kind(code: u8) -> Result<Option<CredentialKind>, FrameError> {
    match code {
        KIND_UNKNOWN => Ok(None),
        KIND_STATIC => Ok(Some(CredentialKind::Static)),
        KIND_BASIC => Ok(Some(CredentialKind::Basic)),
        _ => Err(INVALID_ENTRIES),
    }
}

#[cfg(test)]
mod tests;
