//! The `status` result: the status report and its field encoding (`design/admin-protocol.md#status`).
//!
//! The report holds names, versions and fixed categories only. No type here can hold a secret value, a record digest or
//! a permitted origin, so the response cannot leak one however it is built.

use std::str::FromStr;

use iron_vault_store::{RecordDamage, VaultId};

use super::fields::{self, exact, read_profile, read_text, read_u64};
use super::host_unlock_status;
use super::recovery_status::{self, RecoveryStatus};
use super::{FrameError, body::TAG_COMMAND};
use crate::deployment::DeploymentProfile;
use crate::hardening::MemoryProtection;
use crate::listener_failure::{ListenerFailure, ListenerFailureReason};
use crate::service_context::HostUnlockOutcome;
use crate::service_state::{FailureReason, ServiceState};
use crate::standing::{CredentialStanding, RouteFault, RouteFaultKind, Standing};

const TAG_STATE: u16 = 2;
const TAG_REASON: u16 = 3;
const TAG_PROFILE: u16 = 4;
const TAG_VAULT_ID: u16 = 5;
const TAG_COMMITTED: u16 = 6;
const TAG_RESERVED: u16 = 7;
const TAG_MEMORY: u16 = 8;
const TAG_MEMORY_DETAIL: u16 = 9;
const TAG_CREDENTIALS: u16 = 10;
const TAG_ROUTE_FAULTS: u16 = 11;
const TAG_INITIALIZATION: u16 = 12;
const TAG_LISTENER_FAILURES: u16 = 19;

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
    /// What the recovery check record says; known in every state, because the record is plaintext.
    pub recovery: RecoveryStatus,
    /// What the startup host unlock came to; `None` in a profile that tries none (Development).
    pub host_unlock_outcome: Option<HostUnlockOutcome>,
    /// Each listener the config names that is not open, in name order, with a fixed reason; empty when all are open. The
    /// service state is unchanged by one: the other listeners keep serving.
    pub listener_failures: Vec<ListenerFailure>,
}

/// The vault's lock state, and what is known only while it is unlocked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultStatus {
    /// An initialized vault is not open, so the vault ID, the approval versions and the credentials are unknown. The service is also
    /// here in Unavailable, where the failed check dropped the vault, though the service context keeps the vault identity.
    Locked,
    /// Nothing of a vault is on disk, so there is nothing to unlock; `iron-vault init` creates one.
    NotInitialized,
    /// An initialization started and never finished; `iron-vault init` run again starts it over.
    InitializationUnfinished,
    /// An import started and never finished; `iron-vault import` run again starts it over.
    ImportUnfinished,
    /// A reset was interrupted after its commit point; `iron-vault reset` run again finishes it, and every other command
    /// refuses.
    ResetUnfinished,
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
    pub credentials: Vec<CredentialStanding>,
    /// Every route unavailable for a cause of its own, in name order.
    pub route_faults: Vec<RouteFault>,
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
    let (initialization, id, committed, reserved, credentials, faults) = match &report.vault {
        VaultStatus::Locked => (0, Vec::new(), 0, 0, Vec::new(), Vec::new()),
        VaultStatus::NotInitialized => (1, Vec::new(), 0, 0, Vec::new(), Vec::new()),
        VaultStatus::InitializationUnfinished => (2, Vec::new(), 0, 0, Vec::new(), Vec::new()),
        VaultStatus::ResetUnfinished => (3, Vec::new(), 0, 0, Vec::new(), Vec::new()),
        VaultStatus::ImportUnfinished => (4, Vec::new(), 0, 0, Vec::new(), Vec::new()),
        VaultStatus::Unlocked(vault) => (
            0,
            vault.id.as_bytes().to_vec(),
            vault.committed.unwrap_or(0),
            vault.highest_reserved,
            encode_credentials(&vault.credentials),
            encode_route_faults(&vault.route_faults),
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
    fields::put(&mut out, TAG_PROFILE, &[fields::profile_code(report.profile)]);
    fields::put(&mut out, TAG_VAULT_ID, &id);
    fields::put(&mut out, TAG_COMMITTED, &committed.to_be_bytes());
    fields::put(&mut out, TAG_RESERVED, &reserved.to_be_bytes());
    fields::put(&mut out, TAG_MEMORY, &[memory]);
    fields::put(&mut out, TAG_MEMORY_DETAIL, detail.as_bytes());
    fields::put(&mut out, TAG_CREDENTIALS, &credentials);
    fields::put(&mut out, TAG_ROUTE_FAULTS, &faults);
    fields::put(&mut out, TAG_INITIALIZATION, &[initialization]);
    recovery_status::encode(&mut out, &report.recovery);
    fields::put(
        &mut out,
        host_unlock_status::TAG_OUTCOME,
        &host_unlock_status::encode(report.host_unlock_outcome),
    );
    fields::put(
        &mut out,
        TAG_LISTENER_FAILURES,
        &encode_listener_failures(&report.listener_failures),
    );
    out
}

/// Reads the report from a success body's fields, which must be exactly the command and the report's.
pub(super) fn decode(fields: &[fields::Field<'_>]) -> Result<StatusReport, FrameError> {
    let [
        _,
        state,
        reason,
        profile,
        id,
        committed,
        reserved,
        memory,
        detail,
        credentials,
        faults,
        initialization,
        recovery,
        recovery_time,
        recovery_days,
        recovery_due,
        recovery_detail,
        host_unlock,
        listener_failures,
    ] = exact(
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
            TAG_ROUTE_FAULTS,
            TAG_INITIALIZATION,
            recovery_status::TAG_RECORD,
            recovery_status::TAG_TIME,
            recovery_status::TAG_DAYS,
            recovery_status::TAG_DUE,
            recovery_status::TAG_DETAIL,
            host_unlock_status::TAG_OUTCOME,
            TAG_LISTENER_FAILURES,
        ],
    )?;
    Ok(StatusReport {
        state: read_state(state, reason)?,
        profile: read_profile(TAG_PROFILE, profile)?,
        vault: read_vault(
            initialization,
            id,
            read_u64(TAG_COMMITTED, committed)?,
            read_u64(TAG_RESERVED, reserved)?,
            SealedLists { credentials, faults },
        )?,
        memory: read_memory(memory, detail)?,
        recovery: recovery_status::decode(recovery_status::Raw {
            record: recovery,
            time: recovery_time,
            days: recovery_days,
            due: recovery_due,
            detail: recovery_detail,
        })?,
        host_unlock_outcome: host_unlock_status::decode(host_unlock)?,
        listener_failures: decode_listener_failures(listener_failures)?,
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

/// The encoded lists sealed behind the vault identity.
struct SealedLists<'a> {
    credentials: &'a [u8],
    faults: &'a [u8],
}

/// An empty vault ID is a vault that is not open, which has nothing else to report; anything else must be a whole unlocked
/// vault, whose initialization code is `0`.
fn read_vault(initialization: &[u8], id: &[u8], committed: u64, reserved: u64, lists: SealedLists<'_>) -> Result<VaultStatus, FrameError> {
    let SealedLists { credentials, faults } = lists;
    if id.is_empty() {
        let nothing = committed == 0 && reserved == 0 && credentials.is_empty() && faults.is_empty();
        let closed = match initialization {
            [0] => VaultStatus::Locked,
            [1] => VaultStatus::NotInitialized,
            [2] => VaultStatus::InitializationUnfinished,
            [3] => VaultStatus::ResetUnfinished,
            [4] => VaultStatus::ImportUnfinished,
            _ => return Err(FrameError::InvalidValue(TAG_INITIALIZATION)),
        };
        return nothing.then_some(closed).ok_or(FrameError::InvalidValue(TAG_VAULT_ID));
    }
    if initialization != [0] {
        return Err(FrameError::InvalidValue(TAG_INITIALIZATION));
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
        route_faults: decode_route_faults(faults)?,
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
fn encode_credentials(credentials: &[CredentialStanding]) -> Vec<u8> {
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
pub(super) fn put_name(out: &mut Vec<u8>, name: &str) {
    out.push(u8::try_from(name.len()).unwrap_or(u8::MAX));
    out.extend_from_slice(name.as_bytes());
}

pub(super) fn standing_code(standing: Standing) -> u8 {
    match standing {
        Standing::Healthy => 0,
        Standing::Damaged(RecordDamage::Missing) => 1,
        Standing::Damaged(RecordDamage::Substituted) => 2,
        Standing::Damaged(RecordDamage::Unreadable) => 3,
    }
}

pub(super) fn read_standing(code: u8) -> Result<Standing, FrameError> {
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

fn decode_credentials(mut rest: &[u8]) -> Result<Vec<CredentialStanding>, FrameError> {
    std::iter::from_fn(|| (!rest.is_empty()).then(|| take_credential(&mut rest))).collect()
}

fn take_credential(rest: &mut &[u8]) -> Result<CredentialStanding, FrameError> {
    let name = take_name(rest)?;
    let standing = read_standing(take(rest, 1)?[0])?;
    let count = u16::from_be_bytes(<[u8; 2]>::try_from(take(rest, 2)?).map_err(|_| invalid_credentials())?);
    let unavailable_routes = (0..count).map(|_| take_name(rest)).collect::<Result<_, _>>()?;
    Ok(CredentialStanding {
        name,
        standing,
        unavailable_routes,
        summary: None,
    })
}

fn take_name<T: FromStr>(rest: &mut &[u8]) -> Result<T, FrameError> {
    take_name_in(TAG_CREDENTIALS, rest)
}

/// A length-prefixed name from the list in field `tag`.
pub(super) fn take_name_in<T: FromStr>(tag: u16, rest: &mut &[u8]) -> Result<T, FrameError> {
    let len = usize::from(take_in(tag, rest, 1)?[0]);
    let text = std::str::from_utf8(take_in(tag, rest, len)?).map_err(|_| FrameError::InvalidValue(tag))?;
    text.parse().map_err(|_| FrameError::InvalidValue(tag))
}

/// The first `n` bytes of `rest`, which then starts after them.
fn take<'a>(rest: &mut &'a [u8], n: usize) -> Result<&'a [u8], FrameError> {
    take_in(TAG_CREDENTIALS, rest, n)
}

/// [`take`] for the list in field `tag`.
pub(super) fn take_in<'a>(tag: u16, rest: &mut &'a [u8], n: usize) -> Result<&'a [u8], FrameError> {
    let (head, tail) = rest.split_at_checked(n).ok_or(FrameError::InvalidValue(tag))?;
    *rest = tail;
    Ok(head)
}

/// Each entry: name length, name, fault code.
fn encode_route_faults(faults: &[RouteFault]) -> Vec<u8> {
    let mut out = Vec::new();
    faults.iter().for_each(|route| {
        put_name(&mut out, route.name.as_str());
        out.push(fault_code(route.kind));
    });
    out
}

fn fault_code(fault: RouteFaultKind) -> u8 {
    match fault {
        RouteFaultKind::PinnedCaUnavailable => 1,
    }
}

fn decode_route_faults(mut rest: &[u8]) -> Result<Vec<RouteFault>, FrameError> {
    std::iter::from_fn(|| (!rest.is_empty()).then(|| take_route_fault(&mut rest))).collect()
}

fn take_route_fault(rest: &mut &[u8]) -> Result<RouteFault, FrameError> {
    let name = take_name_in(TAG_ROUTE_FAULTS, rest)?;
    let kind = match take_in(TAG_ROUTE_FAULTS, rest, 1)? {
        [1] => RouteFaultKind::PinnedCaUnavailable,
        _ => return Err(FrameError::InvalidValue(TAG_ROUTE_FAULTS)),
    };
    Ok(RouteFault { name, kind })
}

/// Each entry: name length, name, reason code.
fn encode_listener_failures(failures: &[ListenerFailure]) -> Vec<u8> {
    let mut out = Vec::new();
    failures.iter().for_each(|failure| {
        put_name(&mut out, failure.name.as_str());
        out.push(failure.reason.code());
    });
    out
}

fn decode_listener_failures(mut rest: &[u8]) -> Result<Vec<ListenerFailure>, FrameError> {
    std::iter::from_fn(|| (!rest.is_empty()).then(|| take_listener_failure(&mut rest))).collect()
}

fn take_listener_failure(rest: &mut &[u8]) -> Result<ListenerFailure, FrameError> {
    let name = take_name_in(TAG_LISTENER_FAILURES, rest)?;
    let code = take_in(TAG_LISTENER_FAILURES, rest, 1)?[0];
    let reason = ListenerFailureReason::from_code(code).ok_or(FrameError::InvalidValue(TAG_LISTENER_FAILURES))?;
    Ok(ListenerFailure { name, reason })
}

#[cfg(test)]
mod tests {
    use iron_vault_store::UtcSecond;

    use super::*;

    fn report(vault: VaultStatus) -> StatusReport {
        StatusReport {
            state: ServiceState::Ready,
            profile: DeploymentProfile::Protected,
            vault,
            memory: MemoryStatus::Locked,
            recovery: RecoveryStatus::NeverChecked {
                since: UtcSecond::from_unix_seconds(1_800_000_000).unwrap(),
                days: 3,
                due: false,
            },
            host_unlock_outcome: Some(HostUnlockOutcome::UnsealFailed),
            listener_failures: Vec::new(),
        }
    }

    fn decoded(body: &[u8]) -> Result<StatusReport, FrameError> {
        decode(&fields::parse(body)?)
    }

    fn credential(name: &str, standing: Standing, routes: &[&str]) -> CredentialStanding {
        CredentialStanding {
            name: name.parse().unwrap(),
            standing,
            unavailable_routes: routes.iter().map(|route| route.parse().unwrap()).collect(),
            summary: None,
        }
    }

    fn unlocked(credentials: Vec<CredentialStanding>) -> VaultStatus {
        with_faults(credentials, Vec::new())
    }

    fn with_faults(credentials: Vec<CredentialStanding>, route_faults: Vec<RouteFault>) -> VaultStatus {
        VaultStatus::Unlocked(UnlockedVault {
            id: VaultId::new_random(),
            committed: Some(3),
            highest_reserved: 4,
            credentials,
            route_faults,
        })
    }

    fn pinned_ca(route: &str) -> RouteFault {
        RouteFault {
            name: route.parse().unwrap(),
            kind: RouteFaultKind::PinnedCaUnavailable,
        }
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
                let faults = vec![pinned_ca("fx"), pinned_ca("internal")];
                [
                    VaultStatus::Locked,
                    VaultStatus::NotInitialized,
                    VaultStatus::InitializationUnfinished,
                    VaultStatus::ResetUnfinished,
                    VaultStatus::ImportUnfinished,
                    unlocked(credentials.clone()),
                    unlocked(Vec::new()),
                    with_faults(credentials.clone(), faults.clone()),
                    with_faults(Vec::new(), faults),
                ]
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
    fn every_recovery_shape_round_trips() {
        let time = UtcSecond::from_unix_seconds(1_800_000_000).unwrap();
        [
            RecoveryStatus::Unknown {
                detail: "no check record yet".to_owned(),
                due: false,
            },
            RecoveryStatus::Unknown {
                detail: "the check record is unusable (not_toml)".to_owned(),
                due: true,
            },
            RecoveryStatus::NeverChecked {
                since: time,
                days: 0,
                due: false,
            },
            RecoveryStatus::NeverChecked {
                since: time,
                days: 97,
                due: true,
            },
            RecoveryStatus::Checked {
                last_checked: time,
                days: 37,
                due: false,
            },
            RecoveryStatus::Checked {
                last_checked: time,
                days: 97,
                due: true,
            },
        ]
        .into_iter()
        .for_each(|recovery| {
            let report = StatusReport {
                recovery,
                ..report(VaultStatus::Locked)
            };
            assert_eq!(decoded(&encode(6, &report)), Ok(report));
        });
    }

    #[test]
    fn an_unknown_record_with_a_time_or_no_detail_is_refused() {
        let unknown = |time: u64, detail: &[u8]| decode_recovery([0], time.to_be_bytes(), [0; 8], detail);
        assert_eq!(unknown(5, b"x"), Err(FrameError::InvalidValue(recovery_status::TAG_RECORD)));
        assert_eq!(unknown(0, b""), Err(FrameError::InvalidValue(recovery_status::TAG_RECORD)));
        assert_eq!(
            decode_recovery([3], [0; 8], [0; 8], b""),
            Err(FrameError::InvalidValue(recovery_status::TAG_RECORD))
        );
    }

    fn decode_recovery(record: [u8; 1], time: [u8; 8], days: [u8; 8], detail: &[u8]) -> Result<RecoveryStatus, FrameError> {
        recovery_status::decode(recovery_status::Raw {
            record: &record,
            time: &time,
            days: &days,
            due: &[0],
            detail,
        })
    }

    #[test]
    fn a_locked_vault_with_a_version_credentials_or_route_faults_is_refused() {
        [(1, 0, &[][..], &[][..]), (0, 1, &[], &[]), (0, 0, &[0], &[]), (0, 0, &[], &[0])]
            .into_iter()
            .for_each(|(committed, reserved, credentials, faults)| {
                assert_eq!(
                    read_vault(&[0], &[], committed, reserved, SealedLists { credentials, faults }),
                    Err(FrameError::InvalidValue(TAG_VAULT_ID))
                );
            });
    }

    #[test]
    fn a_truncated_or_unknown_route_fault_is_refused() {
        let full = encode_route_faults(&[pinned_ca("fx")]);
        (1..full.len()).for_each(|cut| {
            assert_eq!(
                decode_route_faults(&full[..cut]),
                Err(FrameError::InvalidValue(TAG_ROUTE_FAULTS)),
                "cut at {cut}"
            );
        });
        [0, 2].into_iter().for_each(|code| {
            let mut bytes = full.clone();
            *bytes.last_mut().unwrap() = code;
            assert_eq!(
                decode_route_faults(&bytes),
                Err(FrameError::InvalidValue(TAG_ROUTE_FAULTS)),
                "code {code}"
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

    #[test]
    fn listener_failures_round_trip_and_an_empty_list_is_an_empty_field() {
        let failures = ListenerFailureReason::ALL
            .iter()
            .enumerate()
            .map(|(index, reason)| ListenerFailure {
                name: format!("l{index}").parse().unwrap(),
                reason: *reason,
            })
            .collect::<Vec<_>>();
        let full = StatusReport {
            listener_failures: failures,
            ..report(VaultStatus::Locked)
        };
        assert_eq!(decoded(&encode(6, &full)), Ok(full));
        assert!(encode_listener_failures(&[]).is_empty());
    }

    #[test]
    fn an_unknown_listener_failure_code_is_refused() {
        let mut body = encode_listener_failures(&[ListenerFailure {
            name: "a".parse().unwrap(),
            reason: ListenerFailureReason::BindRefused,
        }]);
        body.last_mut().map(|code| *code = 0);
        assert_eq!(
            take_listener_failure(&mut body.as_slice()),
            Err(FrameError::InvalidValue(TAG_LISTENER_FAILURES))
        );
    }
}
