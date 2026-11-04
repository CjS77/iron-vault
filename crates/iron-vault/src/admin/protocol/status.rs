//! The `status` result: the status report and its field encoding (`design/admin-protocol.md#status`).
//!
//! The report holds names, versions and fixed categories only. No type here can hold a secret value, a record digest or
//! a permitted origin, so the response cannot leak one however it is built.

use std::str::FromStr;

use iron_vault_policy::{CredentialName, RouteName};
use iron_vault_store::{RecordDamage, VaultId};

use super::fields::{self, exact, read_text};
use super::{FrameError, body::TAG_COMMAND};
use crate::deployment::DeploymentProfile;
use crate::hardening::MemoryProtection;
use crate::service_state::{FailureReason, ServiceState};

const TAG_STATE: u16 = 2;
const TAG_REASON: u16 = 3;
const TAG_PROFILE: u16 = 4;
const TAG_VAULT_ID: u16 = 5;
const TAG_COMMITTED: u16 = 6;
const TAG_RESERVED: u16 = 7;
const TAG_MEMORY: u16 = 8;
const TAG_MEMORY_DETAIL: u16 = 9;
const TAG_CREDENTIALS: u16 = 10;

/// What the service answers `status` with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusReport {
    /// The service state; an Unavailable state carries its redacted reason.
    pub state: ServiceState,
    /// How this build is installed.
    pub profile: DeploymentProfile,
    /// The vault, or that it is locked.
    pub vault: VaultStatus,
    /// What process hardening achieved.
    pub memory: MemoryStatus,
}

/// The vault's lock state, and what is known only while it is unlocked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultStatus {
    /// The vault identity is not in memory, so the vault ID, the approval versions and the credentials are unknown. The
    /// service is also here in Unavailable, where the failed check dropped the vault.
    Locked,
    /// The vault is open.
    Unlocked(UnlockedVault),
}

/// What is sealed behind the vault identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnlockedVault {
    /// The vault's GUID.
    pub id: VaultId,
    /// The committed approval version, or `None` before any approval.
    pub committed: Option<u64>,
    /// The highest version any approval attempt has reserved.
    pub highest_reserved: u64,
    /// Every credential in the vault manifest, in name order.
    pub credentials: Vec<CredentialStatus>,
}

/// One credential's standing and the routes it makes unavailable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialStatus {
    /// The credential's name.
    pub name: CredentialName,
    /// Whether its record loaded.
    pub standing: Standing,
    /// The routes that cannot serve because of it, in name order.
    pub unavailable_routes: Vec<RouteName>,
}

/// Whether a credential record can serve requests (glossary: *Credential standing*).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// The record loaded.
    Healthy,
    /// The manifest lists the record but it did not load.
    Damaged(RecordDamage),
}

/// Whether the service's memory is kept out of swap. Only `Locked` is protection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoryStatus {
    /// Memory is locked against swap.
    Locked,
    /// Memory was not locked, for the reason given.
    Unavailable(String),
    /// This platform has no memory-locking adapter.
    Unsupported,
}

impl From<&MemoryProtection> for MemoryStatus {
    fn from(memory: &MemoryProtection) -> Self {
        match memory {
            MemoryProtection::Locked => Self::Locked,
            MemoryProtection::Unavailable(why) => Self::Unavailable(why.to_string()),
            MemoryProtection::Unsupported => Self::Unsupported,
        }
    }
}

/// `status`'s success body: the command it answers, then the report's fields.
pub(super) fn encode(command: u16, report: &StatusReport) -> Vec<u8> {
    let (state, reason) = state_codes(report.state);
    let (id, committed, reserved, credentials) = match &report.vault {
        VaultStatus::Locked => (Vec::new(), 0, 0, Vec::new()),
        VaultStatus::Unlocked(vault) => (
            vault.id.as_bytes().to_vec(),
            vault.committed.unwrap_or(0),
            vault.highest_reserved,
            encode_credentials(&vault.credentials),
        ),
    };
    let (memory, detail) = match &report.memory {
        MemoryStatus::Locked => (1, ""),
        MemoryStatus::Unavailable(why) => (2, why.as_str()),
        MemoryStatus::Unsupported => (3, ""),
    };
    let mut out = Vec::new();
    fields::put(&mut out, TAG_COMMAND, &command.to_be_bytes());
    fields::put(&mut out, TAG_STATE, &[state]);
    fields::put(&mut out, TAG_REASON, &[reason]);
    fields::put(&mut out, TAG_PROFILE, &[profile_code(report.profile)]);
    fields::put(&mut out, TAG_VAULT_ID, &id);
    fields::put(&mut out, TAG_COMMITTED, &committed.to_be_bytes());
    fields::put(&mut out, TAG_RESERVED, &reserved.to_be_bytes());
    fields::put(&mut out, TAG_MEMORY, &[memory]);
    fields::put(&mut out, TAG_MEMORY_DETAIL, detail.as_bytes());
    fields::put(&mut out, TAG_CREDENTIALS, &credentials);
    out
}

/// Reads the report from a success body's fields, which must be exactly the command and the report's.
pub(super) fn decode(fields: &[fields::Field<'_>]) -> Result<StatusReport, FrameError> {
    let [_, state, reason, profile, id, committed, reserved, memory, detail, credentials] = exact(
        fields,
        [
            TAG_COMMAND,
            TAG_STATE,
            TAG_REASON,
            TAG_PROFILE,
            TAG_VAULT_ID,
            TAG_COMMITTED,
            TAG_RESERVED,
            TAG_MEMORY,
            TAG_MEMORY_DETAIL,
            TAG_CREDENTIALS,
        ],
    )?;
    Ok(StatusReport {
        state: read_state(state, reason)?,
        profile: read_profile(profile)?,
        vault: read_vault(
            id,
            read_u64(TAG_COMMITTED, committed)?,
            read_u64(TAG_RESERVED, reserved)?,
            credentials,
        )?,
        memory: read_memory(memory, detail)?,
    })
}

fn state_codes(state: ServiceState) -> (u8, u8) {
    match state {
        ServiceState::Starting => (1, 0),
        ServiceState::Locked => (2, 0),
        ServiceState::Checking => (3, 0),
        ServiceState::Ready => (4, 0),
        ServiceState::Unavailable(FailureReason::PolicyInvalid) => (5, 1),
        ServiceState::Unavailable(FailureReason::RecoveryNeeded) => (5, 2),
        ServiceState::Stopped => (6, 0),
    }
}

fn read_state(state: &[u8], reason: &[u8]) -> Result<ServiceState, FrameError> {
    match (state, reason) {
        ([1], [0]) => Ok(ServiceState::Starting),
        ([2], [0]) => Ok(ServiceState::Locked),
        ([3], [0]) => Ok(ServiceState::Checking),
        ([4], [0]) => Ok(ServiceState::Ready),
        ([5], [1]) => Ok(ServiceState::Unavailable(FailureReason::PolicyInvalid)),
        ([5], [2]) => Ok(ServiceState::Unavailable(FailureReason::RecoveryNeeded)),
        ([6], [0]) => Ok(ServiceState::Stopped),
        _ => Err(FrameError::InvalidValue(TAG_STATE)),
    }
}

fn profile_code(profile: DeploymentProfile) -> u8 {
    match profile {
        DeploymentProfile::Protected => 1,
        DeploymentProfile::Development => 2,
    }
}

fn read_profile(value: &[u8]) -> Result<DeploymentProfile, FrameError> {
    match value {
        [1] => Ok(DeploymentProfile::Protected),
        [2] => Ok(DeploymentProfile::Development),
        _ => Err(FrameError::InvalidValue(TAG_PROFILE)),
    }
}

fn read_u64(tag: u16, value: &[u8]) -> Result<u64, FrameError> {
    <[u8; 8]>::try_from(value)
        .map(u64::from_be_bytes)
        .map_err(|_| FrameError::InvalidValue(tag))
}

/// An empty vault ID is a locked vault, which has nothing else to report; anything else must be a whole unlocked vault.
fn read_vault(id: &[u8], committed: u64, reserved: u64, credentials: &[u8]) -> Result<VaultStatus, FrameError> {
    if id.is_empty() {
        let nothing = committed == 0 && reserved == 0 && credentials.is_empty();
        return nothing.then_some(VaultStatus::Locked).ok_or(FrameError::InvalidValue(TAG_VAULT_ID));
    }
    let id = <[u8; 16]>::try_from(id)
        .ok()
        .and_then(|bytes| VaultId::from_bytes(bytes).ok())
        .ok_or(FrameError::InvalidValue(TAG_VAULT_ID))?;
    Ok(VaultStatus::Unlocked(UnlockedVault {
        id,
        committed: (committed != 0).then_some(committed),
        highest_reserved: reserved,
        credentials: decode_credentials(credentials)?,
    }))
}

fn read_memory(kind: &[u8], detail: &[u8]) -> Result<MemoryStatus, FrameError> {
    match (kind, detail) {
        ([1], []) => Ok(MemoryStatus::Locked),
        ([2], _) => read_text(TAG_MEMORY_DETAIL, detail).map(MemoryStatus::Unavailable),
        ([3], []) => Ok(MemoryStatus::Unsupported),
        _ => Err(FrameError::InvalidValue(TAG_MEMORY)),
    }
}

/// Each entry: name length, name, standing, route count (`u16`), then each route's length and name.
fn encode_credentials(credentials: &[CredentialStatus]) -> Vec<u8> {
    let mut out = Vec::new();
    credentials.iter().for_each(|credential| {
        put_name(&mut out, credential.name.as_str());
        out.push(standing_code(credential.standing));
        out.extend_from_slice(&u16::try_from(credential.unavailable_routes.len()).unwrap_or(u16::MAX).to_be_bytes());
        credential
            .unavailable_routes
            .iter()
            .for_each(|route| put_name(&mut out, route.as_str()));
    });
    out
}

/// A name is at most 64 bytes, so its length fits the byte.
fn put_name(out: &mut Vec<u8>, name: &str) {
    out.push(u8::try_from(name.len()).unwrap_or(u8::MAX));
    out.extend_from_slice(name.as_bytes());
}

fn standing_code(standing: Standing) -> u8 {
    match standing {
        Standing::Healthy => 0,
        Standing::Damaged(RecordDamage::Missing) => 1,
        Standing::Damaged(RecordDamage::Substituted) => 2,
        Standing::Damaged(RecordDamage::Unreadable) => 3,
    }
}

fn read_standing(code: u8) -> Result<Standing, FrameError> {
    match code {
        0 => Ok(Standing::Healthy),
        1 => Ok(Standing::Damaged(RecordDamage::Missing)),
        2 => Ok(Standing::Damaged(RecordDamage::Substituted)),
        3 => Ok(Standing::Damaged(RecordDamage::Unreadable)),
        _ => Err(invalid_credentials()),
    }
}

fn invalid_credentials() -> FrameError {
    FrameError::InvalidValue(TAG_CREDENTIALS)
}

fn decode_credentials(mut rest: &[u8]) -> Result<Vec<CredentialStatus>, FrameError> {
    std::iter::from_fn(|| (!rest.is_empty()).then(|| take_credential(&mut rest))).collect()
}

fn take_credential(rest: &mut &[u8]) -> Result<CredentialStatus, FrameError> {
    let name = take_name(rest)?;
    let standing = read_standing(take(rest, 1)?[0])?;
    let count = u16::from_be_bytes(<[u8; 2]>::try_from(take(rest, 2)?).map_err(|_| invalid_credentials())?);
    let unavailable_routes = (0..count).map(|_| take_name(rest)).collect::<Result<_, _>>()?;
    Ok(CredentialStatus {
        name,
        standing,
        unavailable_routes,
    })
}

fn take_name<T: FromStr>(rest: &mut &[u8]) -> Result<T, FrameError> {
    let len = usize::from(take(rest, 1)?[0]);
    let text = std::str::from_utf8(take(rest, len)?).map_err(|_| invalid_credentials())?;
    text.parse().map_err(|_| invalid_credentials())
}

/// The first `n` bytes of `rest`, which then starts after them.
fn take<'a>(rest: &mut &'a [u8], n: usize) -> Result<&'a [u8], FrameError> {
    let (head, tail) = rest.split_at_checked(n).ok_or_else(invalid_credentials)?;
    *rest = tail;
    Ok(head)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(vault: VaultStatus) -> StatusReport {
        StatusReport {
            state: ServiceState::Ready,
            profile: DeploymentProfile::Protected,
            vault,
            memory: MemoryStatus::Locked,
        }
    }

    fn decoded(body: &[u8]) -> Result<StatusReport, FrameError> {
        decode(&fields::parse(body)?)
    }

    fn credential(name: &str, standing: Standing, routes: &[&str]) -> CredentialStatus {
        CredentialStatus {
            name: name.parse().unwrap(),
            standing,
            unavailable_routes: routes.iter().map(|route| route.parse().unwrap()).collect(),
        }
    }

    fn unlocked(credentials: Vec<CredentialStatus>) -> VaultStatus {
        VaultStatus::Unlocked(UnlockedVault {
            id: VaultId::new_random(),
            committed: Some(3),
            highest_reserved: 4,
            credentials,
        })
    }

    #[test]
    fn every_report_shape_round_trips() {
        let credentials = vec![
            credential("brave", Standing::Healthy, &[]),
            credential("fx", Standing::Damaged(RecordDamage::Missing), &["fx", "fx-alt"]),
            credential("venice", Standing::Damaged(RecordDamage::Substituted), &["venice"]),
            credential("zed", Standing::Damaged(RecordDamage::Unreadable), &[]),
        ];
        let states = [
            ServiceState::Starting,
            ServiceState::Locked,
            ServiceState::Checking,
            ServiceState::Ready,
            ServiceState::Unavailable(FailureReason::PolicyInvalid),
            ServiceState::Unavailable(FailureReason::RecoveryNeeded),
            ServiceState::Stopped,
        ];
        let memories = [
            MemoryStatus::Locked,
            MemoryStatus::Unavailable("mlockall failed: Cannot allocate memory".to_owned()),
            MemoryStatus::Unsupported,
        ];
        states.into_iter().for_each(|state| {
            memories.iter().for_each(|memory| {
                [VaultStatus::Locked, unlocked(credentials.clone()), unlocked(Vec::new())]
                    .into_iter()
                    .for_each(|vault| {
                        let report = StatusReport {
                            state,
                            memory: memory.clone(),
                            ..report(vault)
                        };
                        assert_eq!(decoded(&encode(6, &report)), Ok(report));
                    });
            });
        });
    }

    #[test]
    fn a_locked_vault_with_a_version_or_credentials_is_refused() {
        [(1, 0, &[][..]), (0, 1, &[]), (0, 0, &[0])]
            .into_iter()
            .for_each(|(committed, reserved, credentials)| {
                assert_eq!(
                    read_vault(&[], committed, reserved, credentials),
                    Err(FrameError::InvalidValue(TAG_VAULT_ID))
                );
            });
    }

    #[test]
    fn an_unavailable_state_without_a_reason_is_refused() {
        let mut body = encode(6, &report(VaultStatus::Locked));
        // The state field's value is the byte after its 6-byte header, which follows the 8-byte command field.
        body[8 + 6] = 5;
        assert_eq!(decoded(&body), Err(FrameError::InvalidValue(TAG_STATE)));
    }

    #[test]
    fn a_truncated_credential_list_is_refused() {
        let credentials = vec![credential("fx", Standing::Damaged(RecordDamage::Missing), &["fx"])];
        let full = encode_credentials(&credentials);
        (1..full.len()).for_each(|cut| assert!(decode_credentials(&full[..cut]).is_err(), "cut at {cut}"));
    }

    #[test]
    fn a_credential_name_that_is_not_a_name_is_refused() {
        let mut bytes = vec![2];
        bytes.extend_from_slice(b"A!");
        bytes.extend_from_slice(&[0, 0, 0]);
        assert_eq!(decode_credentials(&bytes), Err(FrameError::InvalidValue(TAG_CREDENTIALS)));
    }
}
