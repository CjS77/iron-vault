use proptest::prelude::*;
use zeroize::Zeroizing;

use super::fields::FIELD_HEADER_LEN;
use super::*;
use crate::deployment::DeploymentProfile;
use crate::secret_types_tests::MARKER;
use crate::service_context::{HostUnlockOutcome, HostUnlockRefusal};
use crate::service_state::{FailureReason, ServiceState};
use crate::standing::{CredentialStanding, RouteFault, RouteFaultKind, Standing};
use iron_vault_policy::caller_token::CALLER_TOKEN_LEN;
use iron_vault_policy::{CallerToken, CredentialKind, Port, TokenHash};
use iron_vault_store::{ApproverId, RecipientRole, RecordDamage, RecordId, UtcSecond, VaultId};

/// The longest prompt label: the body bound less three field headers and the one-byte secret and switchable flags.
const MAX_LABEL: usize = MAX_BODY_LEN - 3 * FIELD_HEADER_LEN - 2;
/// The longest error message: the body bound less two field headers and the two-byte error code.
const MAX_MESSAGE: usize = MAX_BODY_LEN - 2 * FIELD_HEADER_LEN - 2;

fn encoded(frame: &Frame) -> Vec<u8> {
    let mut out = Vec::new();
    encode(frame, &mut out).unwrap();
    out
}

fn decoded(bytes: &[u8]) -> (Frame, usize) {
    match decode(bytes).unwrap() {
        Decoded::Frame { frame, used } => (frame, used),
        Decoded::NeedMore(n) => panic!("needs {n} more bytes"),
    }
}

fn decode_err(bytes: &[u8]) -> FrameError {
    decode(bytes).unwrap_err()
}

/// Compares frames field by field; `Frame` has no `PartialEq`, because comparing owner input belongs in tests only.
fn same(a: &Frame, b: &Frame) -> bool {
    match (a, b) {
        (Frame::Request(a), Frame::Request(b)) => a == b,
        (Frame::Prompt(a), Frame::Prompt(b)) => a == b,
        (Frame::OwnerInput(a), Frame::OwnerInput(b)) => a.expose_secret() == b.expose_secret(),
        (Frame::Response(a), Frame::Response(b)) => same_response(a, b),
        (Frame::Notice(a), Frame::Notice(b)) => a == b,
        (Frame::Reveal(a), Frame::Reveal(b)) => a.expose_secret() == b.expose_secret(),
        (Frame::Switch, Frame::Switch) => true,
        (Frame::BundleData(a), Frame::BundleData(b)) => a == b,
        _ => false,
    }
}

/// Compares responses field by field; `AdminResponse` has no `PartialEq`, because `caller-token`'s result holds a
/// token, which is compared by its hash.
fn same_response(a: &AdminResponse, b: &AdminResponse) -> bool {
    use AdminResponse as R;
    match (a, b) {
        (R::Success, R::Success) => true,
        (R::Ping { profile: a }, R::Ping { profile: b }) => a == b,
        (R::Status(a), R::Status(b)) => a == b,
        (R::ConfigApprove(a), R::ConfigApprove(b)) => a == b,
        (R::Lock { cleared: a, persisted: p }, R::Lock { cleared: b, persisted: q }) => (a, p) == (b, q),
        (R::Unlock { owner_lock_removed: a }, R::Unlock { owner_lock_removed: b }) => a == b,
        (R::Add { record_id: a }, R::Add { record_id: b }) | (R::Replace { record_id: a }, R::Replace { record_id: b }) => a == b,
        (R::CallerToken { token: a }, R::CallerToken { token: b }) => TokenHash::of(a) == TokenHash::of(b),
        (
            R::Init {
                vault_id: a,
                version: v,
                recipients: r,
            },
            R::Init {
                vault_id: b,
                version: w,
                recipients: s,
            },
        ) => a == b && v == w && r == s,
        (
            R::RecoveryCheck {
                vault_id: a,
                checked_at: t,
                recorded: r,
            },
            R::RecoveryCheck {
                vault_id: b,
                checked_at: u,
                recorded: q,
            },
        ) => a == b && t == u && r == q,
        (
            R::Export {
                vault_id: a,
                records: n,
                bytes: x,
            },
            R::Export {
                vault_id: b,
                records: m,
                bytes: y,
            },
        ) => (a, n, x) == (b, m, y),
        (R::Import(a), R::Import(b)) => a == b,
        (R::RecipientList { entries: a }, R::RecipientList { entries: b }) => a == b,
        (
            R::RecipientAdd {
                recipient: a,
                recipients: n,
            },
            R::RecipientAdd {
                recipient: b,
                recipients: m,
            },
        ) => a == b && n == m,
        (R::RecipientRemove { recipients: a }, R::RecipientRemove { recipients: b }) => a == b,
        (
            R::ForgetMachine {
                independence: a,
                recovery: r,
            },
            R::ForgetMachine {
                independence: b,
                recovery: s,
            },
        ) => a == b && r == s,
        (R::ApproverAdd { approver: a, approvers: n }, R::ApproverAdd { approver: b, approvers: m }) => a == b && n == m,
        (R::ApproverRemove { approvers: a }, R::ApproverRemove { approvers: b }) => a == b,
        (
            R::Reset {
                vault_id: a,
                removed: n,
                foreign: f,
                cleared: c,
                finish_uncertain: u,
            },
            R::Reset {
                vault_id: b,
                removed: m,
                foreign: g,
                cleared: d,
                finish_uncertain: v,
            },
        ) => (a, n, f, c, u) == (b, m, g, d, v),
        (R::Error { code: a, message: m }, R::Error { code: b, message: n }) => a == b && m == n,
        _ => false,
    }
}

fn owner_input(bytes: &[u8]) -> Frame {
    Frame::OwnerInput(OwnerInput::new(Zeroizing::new(bytes.to_vec())))
}

fn reveal(bytes: &[u8]) -> Frame {
    Frame::Reveal(RevealedSecret::new(Zeroizing::new(bytes.to_vec())))
}

fn prompt(label: &str, secret: bool) -> Frame {
    Frame::Prompt(Prompt {
        label: label.to_owned(),
        secret,
        switchable: false,
    })
}

fn error(code: ErrorCode, message: &str) -> Frame {
    Frame::Response(AdminResponse::Error {
        code,
        message: message.to_owned(),
    })
}

/// A frame with any header values, for refusals the encoder can never produce.
fn raw(version: u16, kind: u8, body: &[u8]) -> Vec<u8> {
    let len = u32::try_from(body.len()).unwrap();
    [&version.to_be_bytes()[..], &[kind], &len.to_be_bytes(), body].concat()
}

fn field(tag: u16, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    fields::put(&mut out, tag, value);
    out
}

fn body(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.concat()
}

/// Asserts the frame round-trips: one decode uses every byte, gives the same value, and re-encodes to the same bytes.
fn assert_round_trips(frame: &Frame) {
    let bytes = encoded(frame);
    assert_eq!(encoded(frame), bytes, "encoding is deterministic");
    let (back, used) = decoded(&bytes);
    assert_eq!(used, bytes.len());
    assert!(same(frame, &back), "{frame:?} decoded as {back:?}");
    assert_eq!(encoded(&back), bytes);
}

fn text(max: usize) -> impl Strategy<Value = String> {
    prop_oneof![Just(String::new()), "\\PC{0,64}", Just("é".repeat(max / 2)), Just("a".repeat(max))]
}

fn error_code() -> impl Strategy<Value = ErrorCode> {
    prop_oneof![
        Just(ErrorCode::UnsupportedVersion),
        Just(ErrorCode::MalformedFrame),
        Just(ErrorCode::UnknownCommand),
        Just(ErrorCode::UnexpectedFrame),
        Just(ErrorCode::NotAdminPrincipal),
        Just(ErrorCode::Busy),
        Just(ErrorCode::ConfigInvalid),
        Just(ErrorCode::Declined),
        Just(ErrorCode::ApprovalDenied),
        Just(ErrorCode::ApprovalUnavailable),
        Just(ErrorCode::ApprovalFailed),
        Just(ErrorCode::CommittedNotActive),
        Just(ErrorCode::WrongState),
        Just(ErrorCode::UnlockDenied),
        Just(ErrorCode::UnlockFailed),
        Just(ErrorCode::UnlockedUnavailable),
        Just(ErrorCode::AlreadyInitialized),
        Just(ErrorCode::PassphraseRejected),
        Just(ErrorCode::InitFailed),
        Just(ErrorCode::NameTaken),
        Just(ErrorCode::CredentialInvalid),
        Just(ErrorCode::VaultWriteFailed),
        Just(ErrorCode::UnknownCredential),
        Just(ErrorCode::CredentialInUse),
        Just(ErrorCode::RandomSourceFailed),
        Just(ErrorCode::ListTooLarge),
        Just(ErrorCode::MemoryUnprotected),
        Just(ErrorCode::MigrationDenied),
        Just(ErrorCode::MigrationUnavailable),
        Just(ErrorCode::RecoveryKeyInvalid),
        Just(ErrorCode::RecoveryCheckFailed),
        Just(ErrorCode::RecoveryCheckUnavailable),
        Just(ErrorCode::MigrationRateLimited),
        Just(ErrorCode::UnlockRateLimited),
        Just(ErrorCode::RecipientInventoryDamaged),
        Just(ErrorCode::RecipientInvalid),
        Just(ErrorCode::RecipientEnrolled),
        Just(ErrorCode::UnknownRecipient),
        Just(ErrorCode::RecipientSetInvalid),
        Just(ErrorCode::ApproverInvalid),
        Just(ErrorCode::ApproverSetInvalid),
        Just(ErrorCode::ApproverKindUnavailable),
        Just(ErrorCode::TpmLockedOut),
        Just(ErrorCode::MachineNotForgotten),
    ]
}

fn config_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        prop::collection::vec(any::<u8>(), 0..256),
        Just(MAX_CONFIG_LEN).prop_map(|len| vec![b'#'; len]),
    ]
}

fn owner_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        prop::collection::vec(any::<u8>(), 0..256),
        Just(MAX_BODY_LEN).prop_map(|len| vec![0xa5; len]),
    ]
}

fn any_frame() -> impl Strategy<Value = Frame> {
    prop_oneof![
        prop_oneof![
            Just(AdminRequest::Ping),
            Just(AdminRequest::Status),
            Just(AdminRequest::Unlock),
            Just(AdminRequest::Lock),
            Just(AdminRequest::Reset),
            any::<bool>().prop_map(|host_unlock| AdminRequest::Init { host_unlock }),
            any::<bool>().prop_map(|host_unlock| AdminRequest::Import { host_unlock }),
            Just(AdminRequest::Export),
            Just(AdminRequest::RecoveryCheck),
            Just(AdminRequest::RecipientList),
            (
                text(256).prop_filter("an owner key is never empty", |key| !key.is_empty()),
                text(256)
            )
                .prop_map(|(recipient, label)| AdminRequest::RecipientAdd { recipient, label }),
            (
                text(256).prop_filter("an owner key is never empty", |key| !key.is_empty()),
                text(256)
            )
                .prop_map(|(recipient, label)| AdminRequest::RecipientAddHostUnlock { recipient, label }),
            text(256).prop_map(|label| AdminRequest::RecipientAddRecovery { label }),
            text(256).prop_map(|recipient| AdminRequest::RecipientRemove { recipient }),
            text(256).prop_map(|recipient| AdminRequest::ForgetMachine { recipient }),
            (
                prop_oneof![
                    Just(RequestedSignerKind::Software),
                    Just(RequestedSignerKind::Tpm),
                    Just(RequestedSignerKind::Hardware)
                ],
                text(256)
            )
                .prop_map(|(kind, label)| AdminRequest::ApproverAdd { kind, label }),
            any::<[u8; 16]>().prop_map(|approver| AdminRequest::ApproverRemove { approver }),
            add_request(),
            replace_request(),
            text(256).prop_map(|name| AdminRequest::Rm { name }),
            config_bytes().prop_map(|bytes| AdminRequest::ConfigApprove(ProposedConfig::new(bytes).unwrap())),
        ]
        .prop_map(Frame::Request),
        text(MAX_NOTICE_LEN).prop_map(|text| Frame::Notice(Notice { text })),
        (any::<u64>(), any::<[u8; 32]>(), text(256)).prop_map(|(version, digest, headline)| Frame::Response(AdminResponse::ConfigApprove(
            ApprovalResult { version, digest, headline }
        ))),
        (text(MAX_LABEL), any::<bool>(), any::<bool>()).prop_map(|(label, secret, switchable)| Frame::Prompt(Prompt {
            label,
            secret,
            switchable
        })),
        Just(()).prop_map(|()| Frame::Switch),
        prop::collection::vec(any::<u8>(), 0..256).prop_map(|bytes| Frame::BundleData(BundleChunk::new(bytes).unwrap())),
        (any::<[u8; 16]>(), any::<u64>(), any::<u64>()).prop_map(|(bytes, records, size)| Frame::Response(AdminResponse::Export {
            vault_id: VaultId::from_bytes(v4_bytes(bytes)).unwrap(),
            records,
            bytes: size
        })),
        (any::<[u8; 16]>(), any::<[u64; 3]>(), any::<[u8; 32]>(), any::<bool>()).prop_map(
            |(bytes, [records, version, highest_reserved], digest, host)| {
                Frame::Response(AdminResponse::Import(import_result(
                    bytes,
                    [records, version, highest_reserved],
                    digest,
                    host,
                )))
            }
        ),
        owner_bytes().prop_map(|bytes| owner_input(&bytes)),
        owner_bytes()
            .prop_filter("a reveal is never empty", |bytes| !bytes.is_empty())
            .prop_map(|bytes| reveal(&bytes)),
        Just(()).prop_map(|()| Frame::Response(AdminResponse::Success)),
        prop_oneof![
            Just(DeploymentProfile::Protected),
            Just(DeploymentProfile::Development),
            Just(DeploymentProfile::Container)
        ]
        .prop_map(|profile| Frame::Response(AdminResponse::Ping { profile })),
        (any::<bool>(), any::<bool>()).prop_map(|(cleared, persisted)| Frame::Response(AdminResponse::Lock { cleared, persisted })),
        any::<bool>().prop_map(|owner_lock_removed| Frame::Response(AdminResponse::Unlock { owner_lock_removed })),
        any::<u8>().prop_map(|recipients| Frame::Response(AdminResponse::RecipientAdd {
            recipient: "age1csc5wgcsw68jdz8uxh9sramjkys02nk8qf740lpywzvlzm9pjf7qxffk4e".parse().unwrap(),
            recipients
        })),
        any::<u8>().prop_map(|recipients| Frame::Response(AdminResponse::RecipientRemove { recipients })),
        (proptest::option::of("\\PC{1,80}"), recovery_status())
            .prop_map(|(independence, recovery)| Frame::Response(AdminResponse::ForgetMachine { independence, recovery })),
        (any::<[u8; 16]>(), any::<u8>()).prop_map(|(bytes, approvers)| Frame::Response(AdminResponse::ApproverAdd {
            approver: ApproverId::from_bytes(v4_bytes(bytes)).unwrap(),
            approvers
        })),
        any::<u8>().prop_map(|approvers| Frame::Response(AdminResponse::ApproverRemove { approvers })),
        (
            proptest::option::of(any::<[u8; 16]>()),
            any::<u64>(),
            proptest::collection::vec("[ -~]{1,40}", 0..4),
            any::<bool>(),
            any::<bool>()
        )
            .prop_map(
                |(bytes, removed, foreign, cleared, finish_uncertain)| Frame::Response(AdminResponse::Reset {
                    vault_id: bytes.map(|bytes| VaultId::from_bytes(v4_bytes(bytes)).unwrap()),
                    removed,
                    foreign,
                    cleared,
                    finish_uncertain
                })
            ),
        any::<[u8; 16]>().prop_map(|bytes| Frame::Response(AdminResponse::Add { record_id: v4(bytes) })),
        any::<[u8; 16]>().prop_map(|bytes| Frame::Response(AdminResponse::Replace { record_id: v4(bytes) })),
        any::<[u8; 32]>().prop_map(|bytes| Frame::Response(AdminResponse::CallerToken {
            token: CallerToken::from_bytes(bytes)
        })),
        (any::<[u8; 16]>(), any::<u64>(), any::<bool>()).prop_map(|(bytes, version, host)| Frame::Response(AdminResponse::Init {
            vault_id: VaultId::from_bytes(v4_bytes(bytes)).unwrap(),
            version,
            recipients: enrolled(host),
        })),
        (any::<[u8; 16]>(), any::<u64>(), any::<bool>()).prop_map(|(bytes, checked_at, recorded)| {
            Frame::Response(AdminResponse::RecoveryCheck {
                vault_id: VaultId::from_bytes(v4_bytes(bytes)).unwrap(),
                checked_at,
                recorded,
            })
        }),
        status_report().prop_map(|report| Frame::Response(AdminResponse::Status(Box::new(report)))),
        (error_code(), text(MAX_MESSAGE)).prop_map(|(code, message)| Frame::Response(AdminResponse::Error { code, message })),
    ]
}

/// The record ID with `bytes`' randomness and the version 4, RFC 9562 variant bits set.
fn v4(bytes: [u8; 16]) -> RecordId {
    RecordId::from_bytes(v4_bytes(bytes)).unwrap()
}

/// `bytes` with the version 4, RFC 9562 variant bits set.
fn v4_bytes(mut bytes: [u8; 16]) -> [u8; 16] {
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    bytes
}

/// Any status report the service could send: every state, profile and memory status, and a locked or unlocked vault.
fn status_report() -> impl Strategy<Value = StatusReport> {
    let state = prop_oneof![
        Just(ServiceState::Starting),
        Just(ServiceState::Locked),
        Just(ServiceState::Checking),
        Just(ServiceState::Ready),
        Just(ServiceState::Unavailable(FailureReason::PolicyInvalid)),
        Just(ServiceState::Unavailable(FailureReason::RecoveryNeeded)),
        Just(ServiceState::Stopped),
    ];
    let profile = prop_oneof![
        Just(DeploymentProfile::Protected),
        Just(DeploymentProfile::Development),
        Just(DeploymentProfile::Container)
    ];
    let memory = prop_oneof![
        Just(MemoryStatus::Locked),
        "\\PC{0,64}".prop_map(MemoryStatus::Unavailable),
        Just(MemoryStatus::Unsupported),
    ];
    let vault = prop_oneof![
        Just(VaultStatus::Locked),
        Just(VaultStatus::NotInitialized),
        Just(VaultStatus::InitializationUnfinished),
        Just(VaultStatus::ResetUnfinished),
        Just(VaultStatus::ImportUnfinished),
        unlocked_vault().prop_map(VaultStatus::Unlocked)
    ];
    (state, profile, vault, memory, recovery_status(), host_unlock_outcome()).prop_map(
        |(state, profile, vault, memory, recovery, host_unlock_outcome)| StatusReport {
            state,
            profile,
            vault,
            memory,
            recovery,
            host_unlock_outcome,
        },
    )
}

/// Any startup host unlock outcome, or none.
fn host_unlock_outcome() -> impl Strategy<Value = Option<HostUnlockOutcome>> {
    let refusals = [
        HostUnlockRefusal::MemoryUnprotected,
        HostUnlockRefusal::Untrusted,
        HostUnlockRefusal::Unreadable,
        HostUnlockRefusal::NotAnIdentity,
        HostUnlockRefusal::NotInitialized,
        HostUnlockRefusal::NotARecipient,
    ];
    prop_oneof![
        Just(None),
        Just(Some(HostUnlockOutcome::Unlocked)),
        Just(Some(HostUnlockOutcome::Absent)),
        Just(Some(HostUnlockOutcome::UnsealFailed)),
        Just(Some(HostUnlockOutcome::OwnerLocked)),
        proptest::sample::select(refusals.to_vec()).prop_map(|refusal| Some(HostUnlockOutcome::Refused(refusal))),
    ]
}

/// Any recovery check part of a report.
fn recovery_status() -> impl Strategy<Value = RecoveryStatus> {
    let time = (0..=253_402_300_799u64).prop_map(|seconds| UtcSecond::from_unix_seconds(seconds).unwrap());
    prop_oneof![
        ("\\PC{1,64}", any::<bool>()).prop_map(|(detail, due)| RecoveryStatus::Unknown { detail, due }),
        (time.clone(), any::<u64>(), any::<bool>()).prop_map(|(since, days, due)| RecoveryStatus::NeverChecked { since, days, due }),
        (time, any::<u64>(), any::<bool>()).prop_map(|(last_checked, days, due)| RecoveryStatus::Checked { last_checked, days, due }),
    ]
}

/// A credential or route name: 1 to 64 bytes of `[a-z0-9_-]`, starting with a letter.
fn name<T: std::str::FromStr<Err: std::fmt::Debug> + std::fmt::Debug>() -> impl Strategy<Value = T> {
    "[a-z][a-z0-9_-]{0,63}".prop_map(|name| name.parse().unwrap())
}

fn unlocked_vault() -> impl Strategy<Value = UnlockedVault> {
    let credentials = prop::collection::vec(credential_standing(), 0..4);
    let faults = prop::collection::vec(
        name().prop_map(|name| RouteFault {
            name,
            kind: RouteFaultKind::PinnedCaUnavailable,
        }),
        0..4,
    );
    (any::<[u8; 16]>(), prop::option::of(1u64..), any::<u64>(), credentials, faults).prop_map(
        |(id, committed, highest_reserved, credentials, route_faults)| UnlockedVault {
            id: VaultId::from_bytes(v4_bytes(id)).unwrap(),
            committed,
            highest_reserved,
            credentials,
            route_faults,
        },
    )
}

fn credential_standing() -> impl Strategy<Value = CredentialStanding> {
    let standing = prop_oneof![
        Just(Standing::Healthy),
        Just(Standing::Damaged(RecordDamage::Missing)),
        Just(Standing::Damaged(RecordDamage::Substituted)),
        Just(Standing::Damaged(RecordDamage::Unreadable)),
    ];
    (name(), standing, prop::collection::vec(name(), 0..4)).prop_map(|(name, standing, unavailable_routes)| CredentialStanding {
        name,
        standing,
        unavailable_routes,
        summary: None,
    })
}

fn requested_origin() -> impl Strategy<Value = RequestedOrigin> {
    let host = prop_oneof!["[a-z0-9.\\-]{1,64}", "\\PC{1,40}", Just("h".repeat(MAX_ORIGIN_HOST_LEN))];
    (host, 1u16..).prop_map(|(host, port)| RequestedOrigin {
        host,
        port: Port::try_from(port).unwrap(),
    })
}

fn add_request() -> impl Strategy<Value = AdminRequest> {
    let kind = prop_oneof![Just(CredentialKind::Static), Just(CredentialKind::Basic)];
    let origins = prop::collection::vec(requested_origin(), 1..=MAX_ORIGINS);
    (text(256), kind, origins).prop_map(|(name, kind, origins)| AdminRequest::Add { name, kind, origins })
}

fn replace_request() -> impl Strategy<Value = AdminRequest> {
    add_request().prop_map(|request| match request {
        AdminRequest::Add { name, kind, origins } => AdminRequest::Replace { name, kind, origins },
        other => other,
    })
}

/// A body of arbitrary fields with small tags, so the structured fuzz below often reaches the body decoders.
fn field_soup() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec((0u16..4, prop::collection::vec(any::<u8>(), 0..4)), 0..4)
        .prop_map(|parts| parts.iter().flat_map(|(tag, value)| field(*tag, value)).collect())
}

proptest! {
    #[test]
    fn every_frame_round_trips(frame in any_frame()) {
        assert_round_trips(&frame);
    }

    #[test]
    fn every_status_report_round_trips(report in status_report()) {
        assert_round_trips(&Frame::Response(AdminResponse::Status(Box::new(report))));
    }

    #[test]
    fn bytes_after_a_frame_are_left_for_the_next(frame in any_frame(), extra in prop::collection::vec(any::<u8>(), 1..16)) {
        let bytes = encoded(&frame);
        let (_, used) = decoded(&[&bytes[..], &extra].concat());
        prop_assert_eq!(used, bytes.len());
    }

    #[test]
    fn random_bytes_never_panic_and_accepted_frames_re_encode_exactly(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
        if let Ok(Decoded::Frame { frame, used }) = decode(&bytes) {
            prop_assert_eq!(encoded(&frame), &bytes[..used]);
        }
    }

    #[test]
    fn random_bodies_never_panic_and_accepted_frames_re_encode_exactly(kind in 0u8..10, body in field_soup()) {
        let bytes = raw(PROTOCOL_VERSION, kind, &body);
        if let Ok(Decoded::Frame { frame, used }) = decode(&bytes) {
            prop_assert_eq!(used, bytes.len());
            prop_assert_eq!(encoded(&frame), bytes);
        }
    }
}

#[test]
fn every_frame_kind_round_trips_with_its_kind_byte() {
    let frames = [
        (Frame::Request(AdminRequest::Ping), 1),
        (prompt("Passphrase", true), 2),
        (owner_input(b"typed"), 3),
        (Frame::Response(AdminResponse::Success), 4),
        (error(ErrorCode::MalformedFrame, "bad frame"), 5),
        (
            Frame::Notice(Notice {
                text: "summary\n".to_owned(),
            }),
            6,
        ),
        (reveal(b"AGE-SECRET-KEY-1"), 7),
        (Frame::Switch, 8),
        (Frame::BundleData(BundleChunk::new(b"bundle".to_vec()).unwrap()), 9),
    ];
    frames.iter().for_each(|(frame, kind)| {
        assert_eq!(encoded(frame)[2], *kind);
        assert_round_trips(frame);
    });
}

#[test]
fn ping_has_the_documented_encoding() {
    let expected = [0, 1, 1, 0, 0, 0, 8, 0, 1, 0, 0, 0, 2, 0, 1];
    assert_eq!(encoded(&Frame::Request(AdminRequest::Ping)), expected);
}

#[test]
fn status_has_command_id_6() {
    let expected = [0, 1, 1, 0, 0, 0, 8, 0, 1, 0, 0, 0, 2, 0, 6];
    assert_eq!(encoded(&Frame::Request(AdminRequest::Status)), expected);
    assert_eq!(AdminRequest::Status.command(), AdminCommand::Status);
    assert_eq!(AdminCommand::Status.name(), "status");
}

#[test]
fn a_status_request_takes_no_arguments() {
    let with_argument = body(&[field(1, &[0, 6]), field(2, b"x")]);
    assert_eq!(decode_err(&raw(1, 1, &with_argument)), FrameError::UnknownTag(2));
}

#[test]
fn a_status_result_with_a_field_missing_or_extra_is_refused() {
    let report = StatusReport {
        state: ServiceState::Locked,
        profile: DeploymentProfile::Protected,
        vault: VaultStatus::Locked,
        memory: MemoryStatus::Locked,
        recovery: RecoveryStatus::Unknown {
            detail: "no check record yet".to_owned(),
            due: false,
        },
        host_unlock_outcome: None,
    };
    let frame = Frame::Response(AdminResponse::Status(Box::new(report)));
    assert_round_trips(&frame);
    let mut full = encoded(&frame);
    let extra = field(19, b"x");
    full.extend_from_slice(&extra);
    let length = u32::try_from(full.len() - HEADER_LEN).unwrap().to_be_bytes();
    full[3..HEADER_LEN].copy_from_slice(&length);
    assert_eq!(decode_err(&full), FrameError::UnknownTag(19));
    assert_eq!(decode_err(&raw(1, 4, &field(1, &[0, 6]))), FrameError::MissingField(2));
}

#[test]
fn ping_result_has_the_documented_encoding() {
    let protected = [0, 1, 4, 0, 0, 0, 15, 0, 1, 0, 0, 0, 2, 0, 1, 0, 2, 0, 0, 0, 1, 1];
    assert_eq!(
        encoded(&Frame::Response(AdminResponse::Ping {
            profile: DeploymentProfile::Protected
        })),
        protected
    );
    let (development, _) = decoded(&raw(1, 4, &body(&[field(1, &[0, 1]), field(2, &[2])])));
    assert!(same(
        &development,
        &Frame::Response(AdminResponse::Ping {
            profile: DeploymentProfile::Development
        })
    ));
    let (container, _) = decoded(&raw(1, 4, &body(&[field(1, &[0, 1]), field(2, &[3])])));
    assert!(same(
        &container,
        &Frame::Response(AdminResponse::Ping {
            profile: DeploymentProfile::Container
        })
    ));
}

#[test]
fn lock_has_the_documented_encoding() {
    assert_eq!(
        encoded(&Frame::Request(AdminRequest::Lock)),
        [0, 1, 1, 0, 0, 0, 8, 0, 1, 0, 0, 0, 2, 0, 5]
    );
    let cleared = [
        0, 1, 4, 0, 0, 0, 22, 0, 1, 0, 0, 0, 2, 0, 5, 0, 2, 0, 0, 0, 1, 1, 0, 3, 0, 0, 0, 1, 0,
    ];
    let lock = |cleared, persisted| Frame::Response(AdminResponse::Lock { cleared, persisted });
    assert_eq!(encoded(&lock(true, false)), cleared);
    let (held, _) = decoded(&raw(1, 4, &body(&[field(1, &[0, 5]), field(2, &[0]), field(3, &[1])])));
    assert!(same(&held, &lock(false, true)));
}

#[test]
fn unlock_has_the_documented_result() {
    let removed = Frame::Response(AdminResponse::Unlock { owner_lock_removed: true });
    assert_eq!(
        encoded(&removed),
        [0, 1, 4, 0, 0, 0, 15, 0, 1, 0, 0, 0, 2, 0, 4, 0, 2, 0, 0, 0, 1, 1]
    );
    let (kept, _) = decoded(&raw(1, 4, &body(&[field(1, &[0, 4]), field(2, &[0])])));
    assert!(same(&kept, &Frame::Response(AdminResponse::Unlock { owner_lock_removed: false })));
    assert_eq!(decode_err(&raw(1, 4, &field(1, &[0, 4]))), FrameError::MissingField(2));
}

#[test]
fn lock_takes_no_arguments_and_its_result_needs_a_flag() {
    let with_argument = body(&[field(1, &[0, 5]), field(2, b"x")]);
    assert_eq!(decode_err(&raw(1, 1, &with_argument)), FrameError::UnknownTag(2));
    assert_eq!(decode_err(&raw(1, 4, &field(1, &[0, 5]))), FrameError::MissingField(2));
    let no_persisted = body(&[field(1, &[0, 5]), field(2, &[1])]);
    assert_eq!(decode_err(&raw(1, 4, &no_persisted)), FrameError::MissingField(3));
    let not_a_flag = body(&[field(1, &[0, 5]), field(2, &[2]), field(3, &[1])]);
    assert_eq!(decode_err(&raw(1, 4, &not_a_flag)), FrameError::InvalidValue(2));
}

#[test]
fn wrong_state_is_error_code_13() {
    assert_eq!(ErrorCode::WrongState as u16, 13);
    assert_eq!(ErrorCode::WrongState.name(), "wrong-state");
    assert_round_trips(&error(ErrorCode::WrongState, "cannot lock"));
}

#[test]
fn a_success_result_must_name_a_command_with_a_result_and_a_known_profile() {
    let no_command = field(2, &[1]);
    assert_eq!(decode_err(&raw(1, 4, &no_command)), FrameError::MissingField(1));
    let unknown = body(&[field(1, &[0, 23]), field(2, &[1])]);
    assert_eq!(decode_err(&raw(1, 4, &unknown)), FrameError::UnknownCommand(23));
    let without_profile = field(1, &[0, 1]);
    assert_eq!(decode_err(&raw(1, 4, &without_profile)), FrameError::MissingField(2));
    [&[][..], &[0], &[4], &[1, 1]].into_iter().for_each(|profile| {
        let bad = body(&[field(1, &[0, 1]), field(2, profile)]);
        assert_eq!(decode_err(&raw(1, 4, &bad)), FrameError::InvalidValue(2));
    });
}

#[test]
fn frame_errors_map_to_the_codes_the_service_answers_with() {
    assert_eq!(
        ErrorCode::for_frame_error(FrameError::UnsupportedVersion(2)),
        ErrorCode::UnsupportedVersion
    );
    assert_eq!(ErrorCode::for_frame_error(FrameError::UnknownCommand(9)), ErrorCode::UnknownCommand);
    [FrameError::BodyTooLong, FrameError::UnknownKind(9), FrameError::MissingField(1)]
        .into_iter()
        .for_each(|error| assert_eq!(ErrorCode::for_frame_error(error), ErrorCode::MalformedFrame));
}

#[test]
fn a_request_names_its_command() {
    assert_eq!(AdminRequest::Ping.command(), AdminCommand::Ping);
    assert_eq!(AdminCommand::Ping.name(), "ping");
    assert_eq!(AdminRequest::Unlock.command(), AdminCommand::Unlock);
    assert_eq!(AdminCommand::Unlock.name(), "unlock");
    assert_eq!(AdminRequest::Lock.command(), AdminCommand::Lock);
    assert_eq!((AdminCommand::Lock as u16, AdminCommand::Lock.name()), (5, "lock"));
}

#[test]
fn unlock_has_the_documented_encoding() {
    let expected = [0, 1, 1, 0, 0, 0, 8, 0, 1, 0, 0, 0, 2, 0, 4];
    assert_eq!(encoded(&Frame::Request(AdminRequest::Unlock)), expected);
    let with_argument = body(&[field(1, &[0, 4]), field(2, b"x")]);
    assert_eq!(decode_err(&raw(1, 1, &with_argument)), FrameError::UnknownTag(2));
}

#[test]
fn the_unlock_error_codes_have_their_documented_numbers_and_names() {
    [
        (ErrorCode::WrongState, 13, "wrong-state"),
        (ErrorCode::UnlockDenied, 14, "unlock-denied"),
        (ErrorCode::UnlockFailed, 15, "unlock-failed"),
        (ErrorCode::UnlockedUnavailable, 16, "unlocked-unavailable"),
        (ErrorCode::MemoryUnprotected, 27, "memory-unprotected"),
    ]
    .into_iter()
    .for_each(|(code, number, name)| {
        assert_eq!((code as u16, code.name()), (number, name));
        assert_round_trips(&error(code, "m"));
    });
}

#[test]
fn empty_values_round_trip() {
    [prompt("", false), owner_input(b""), error(ErrorCode::UnknownCommand, "")]
        .iter()
        .for_each(assert_round_trips);
}

#[test]
fn maximum_length_values_round_trip_and_one_more_byte_is_refused() {
    assert_round_trips(&prompt(&"a".repeat(MAX_LABEL), false));
    assert_round_trips(&error(ErrorCode::UnexpectedFrame, &"a".repeat(MAX_MESSAGE)));
    assert_round_trips(&owner_input(&vec![0; MAX_BODY_LEN]));
    [
        prompt(&"a".repeat(MAX_LABEL + 1), false),
        error(ErrorCode::UnexpectedFrame, &"a".repeat(MAX_MESSAGE + 1)),
        owner_input(&vec![0; MAX_BODY_LEN + 1]),
    ]
    .iter()
    .for_each(|frame| assert_eq!(encode(frame, &mut Vec::new()), Err(FrameError::BodyTooLong)));
}

#[test]
fn a_refused_encoding_appends_nothing() {
    let mut out = vec![9];
    assert!(encode(&owner_input(&vec![0; MAX_BODY_LEN + 1]), &mut out).is_err());
    assert_eq!(out, [9]);
}

#[test]
fn every_truncated_prefix_asks_for_the_missing_bytes() {
    let bytes = encoded(&prompt("Passphrase", true));
    (0..bytes.len()).for_each(|len| {
        let wanted = if len < HEADER_LEN { HEADER_LEN - len } else { bytes.len() - len };
        assert!(
            matches!(decode(&bytes[..len]), Ok(Decoded::NeedMore(n)) if n == wanted),
            "prefix {len}"
        );
    });
}

#[test]
fn an_oversized_length_is_refused_from_the_header_alone() {
    let header = |len: u32| [&[0, 1, 3][..], &len.to_be_bytes()].concat();
    assert_eq!(
        decode_err(&header(u32::try_from(MAX_BODY_LEN).unwrap() + 1)),
        FrameError::BodyTooLong
    );
    assert_eq!(decode_err(&header(u32::MAX)), FrameError::BodyTooLong);
    assert!(matches!(
        decode(&header(u32::try_from(MAX_BODY_LEN).unwrap())),
        Ok(Decoded::NeedMore(MAX_BODY_LEN))
    ));
}

#[test]
fn an_unsupported_version_is_refused_before_the_kind() {
    let ping = encoded(&Frame::Request(AdminRequest::Ping));
    assert_eq!(decode_err(&raw(0, 1, &ping[HEADER_LEN..])), FrameError::UnsupportedVersion(0));
    assert_eq!(decode_err(&raw(2, 1, &ping[HEADER_LEN..])), FrameError::UnsupportedVersion(2));
    assert_eq!(decode_err(&raw(2, 99, &[])), FrameError::UnsupportedVersion(2));
}

#[test]
fn unknown_frame_kinds_are_refused() {
    [0, 10, 255]
        .into_iter()
        .for_each(|kind| assert_eq!(decode_err(&raw(1, kind, &[])), FrameError::UnknownKind(kind)));
}

#[test]
fn unknown_tags_are_refused() {
    let request = body(&[field(1, &[0, 1]), field(2, b"")]);
    assert_eq!(decode_err(&raw(1, 1, &request)), FrameError::UnknownTag(2));
    let prompt = body(&[field(1, b"label"), field(2, &[1]), field(3, &[0]), field(4, b"")]);
    assert_eq!(decode_err(&raw(1, 2, &prompt)), FrameError::UnknownTag(4));
    let ping_result = body(&[field(1, &[0, 1]), field(2, &[1]), field(3, b"")]);
    assert_eq!(decode_err(&raw(1, 4, &ping_result)), FrameError::UnknownTag(3));
    let error = body(&[field(0, b""), field(1, &[0, 1]), field(2, b"m")]);
    assert_eq!(decode_err(&raw(1, 5, &error)), FrameError::UnknownTag(0));
}

#[test]
fn unknown_commands_are_refused_whatever_follows() {
    assert_eq!(decode_err(&raw(1, 1, &field(1, &[0, 23]))), FrameError::UnknownCommand(23));
    let with_arguments = body(&[field(1, &[0xff, 0xff]), field(2, b"argument")]);
    assert_eq!(decode_err(&raw(1, 1, &with_arguments)), FrameError::UnknownCommand(0xffff));
}

#[test]
fn duplicate_and_out_of_order_tags_are_refused() {
    let duplicate = body(&[field(1, b"label"), field(1, b"label"), field(2, &[1])]);
    assert_eq!(decode_err(&raw(1, 2, &duplicate)), FrameError::DuplicateTag(1));
    let reordered = body(&[field(2, &[1]), field(1, b"label")]);
    assert_eq!(decode_err(&raw(1, 2, &reordered)), FrameError::TagOutOfOrder(1));
}

#[test]
fn missing_fields_are_refused() {
    assert_eq!(decode_err(&raw(1, 1, &[])), FrameError::MissingField(1));
    assert_eq!(decode_err(&raw(1, 2, &field(1, b"label"))), FrameError::MissingField(2));
    let without_switchable = body(&[field(1, b"label"), field(2, &[1])]);
    assert_eq!(decode_err(&raw(1, 2, &without_switchable)), FrameError::MissingField(3));
    assert_eq!(decode_err(&raw(1, 5, &field(2, b"message"))), FrameError::MissingField(1));
}

#[test]
fn invalid_utf8_is_refused() {
    let prompt = body(&[field(1, &[0xff]), field(2, &[0]), field(3, &[0])]);
    assert_eq!(decode_err(&raw(1, 2, &prompt)), FrameError::InvalidUtf8(1));
    let error = body(&[field(1, &[0, 2]), field(2, &[0xc3])]);
    assert_eq!(decode_err(&raw(1, 5, &error)), FrameError::InvalidUtf8(2));
}

#[test]
fn malformed_fixed_width_values_and_flags_are_refused() {
    assert_eq!(decode_err(&raw(1, 1, &field(1, &[0, 0, 1]))), FrameError::InvalidValue(1));
    [&[][..], &[2], &[1, 0]].into_iter().for_each(|flag| {
        let prompt = body(&[field(1, b"label"), field(2, flag), field(3, &[0])]);
        assert_eq!(decode_err(&raw(1, 2, &prompt)), FrameError::InvalidValue(2));
        let prompt = body(&[field(1, b"label"), field(2, &[1]), field(3, flag)]);
        assert_eq!(decode_err(&raw(1, 2, &prompt)), FrameError::InvalidValue(3));
    });
    let error = body(&[field(1, &[2]), field(2, b"m")]);
    assert_eq!(decode_err(&raw(1, 5, &error)), FrameError::InvalidValue(1));
}

#[test]
fn unknown_error_codes_are_refused() {
    [0, 51, 0xffff].into_iter().for_each(|code: u16| {
        let error = body(&[field(1, &code.to_be_bytes()), field(2, b"m")]);
        assert_eq!(decode_err(&raw(1, 5, &error)), FrameError::UnknownErrorCode(code));
    });
}

#[test]
fn fields_that_run_past_the_body_are_refused() {
    assert_eq!(decode_err(&raw(1, 2, &[0, 1, 0, 0, 0])), FrameError::TruncatedField);
    assert_eq!(decode_err(&raw(1, 2, &[0, 1, 0, 0, 0, 9, b'x'])), FrameError::TruncatedField);
    let after_a_good_field = body(&[field(1, b"label"), vec![0, 2]]);
    assert_eq!(decode_err(&raw(1, 2, &after_a_good_field)), FrameError::TruncatedField);
}

#[test]
fn no_error_carries_the_bytes_of_the_frame_it_refused() {
    let marker = MARKER.as_bytes();
    let refused = [
        raw(2, 3, marker),
        raw(1, 10, marker),
        raw(1, 1, &body(&[field(1, &[0, 1]), field(2, marker)])),
        raw(1, 1, &body(&[field(1, &[0, 9]), field(2, marker)])),
        raw(1, 2, &body(&[field(1, &[marker, &[0xff][..]].concat()), field(2, &[1])])),
        raw(1, 2, &body(&[field(1, marker), field(1, marker)])),
        raw(1, 2, &[&field(1, marker)[..], &[0, 2, 0, 0, 0, 99], marker].concat()),
        raw(1, 4, &field(7, marker)),
        raw(2, 7, marker),
    ];
    refused.iter().for_each(|bytes| {
        let error = decode_err(bytes);
        [format!("{error}"), format!("{error:?}"), format!("{error:#?}")]
            .iter()
            .for_each(|text| assert!(!text.contains(MARKER), "{text}"));
    });
}

/// An `add` request body with `origins` as the raw origins value.
fn add_body(origins: &[u8]) -> Vec<u8> {
    body(&[field(1, &[0, 8]), field(2, b"fx"), field(3, &[1]), field(4, origins)])
}

/// One origin in its wire form.
fn origin_bytes(host: &[u8], port: u16) -> Vec<u8> {
    [&[u8::try_from(host.len()).unwrap()][..], host, &port.to_be_bytes()].concat()
}

fn fx_origin() -> RequestedOrigin {
    RequestedOrigin {
        host: "api.fx.example".to_owned(),
        port: Port::HTTPS,
    }
}

#[test]
fn add_has_command_id_8_and_the_documented_encoding() {
    let request = AdminRequest::Add {
        name: "fx".to_owned(),
        kind: CredentialKind::Basic,
        origins: vec![fx_origin()],
    };
    assert_eq!((AdminCommand::Add as u16, request.command().name()), (8, "add"));
    let origins = [&[1][..], &origin_bytes(b"api.fx.example", 443)].concat();
    let expected = body(&[field(1, &[0, 8]), field(2, b"fx"), field(3, &[2]), field(4, &origins)]);
    assert_eq!(encoded(&Frame::Request(request.clone())), raw(1, 1, &expected));
    assert_round_trips(&Frame::Request(request));
}

#[test]
fn the_add_result_carries_the_raw_record_id() {
    let record_id = v4([7; 16]);
    let expected = body(&[field(1, &[0, 8]), field(2, record_id.as_bytes())]);
    assert_eq!(encoded(&Frame::Response(AdminResponse::Add { record_id })), raw(1, 4, &expected));
    let short = body(&[field(1, &[0, 8]), field(2, &[7; 15])]);
    assert_eq!(decode_err(&raw(1, 4, &short)), FrameError::InvalidValue(2));
    let not_v4 = body(&[field(1, &[0, 8]), field(2, &[0; 16])]);
    assert_eq!(decode_err(&raw(1, 4, &not_v4)), FrameError::InvalidValue(2));
}

#[test]
fn add_origin_counts_outside_1_to_32_are_refused() {
    let one = origin_bytes(b"h", 443);
    let many = |count: u8| [&[count][..], &one.repeat(usize::from(count))].concat();
    assert!(decode(&raw(1, 1, &add_body(&many(32)))).is_ok());
    [many(0), many(33), Vec::new()]
        .iter()
        .for_each(|origins| assert_eq!(decode_err(&raw(1, 1, &add_body(origins))), FrameError::InvalidValue(4)));
}

#[test]
fn add_hosts_must_be_1_to_253_bytes_of_text_and_ports_non_zero() {
    let max = "h".repeat(MAX_ORIGIN_HOST_LEN);
    assert!(decode(&raw(1, 1, &add_body(&[&[1][..], &origin_bytes(max.as_bytes(), 1)].concat()))).is_ok());
    let refused = [
        ([&[1][..], &origin_bytes(b"", 443)].concat(), FrameError::InvalidValue(4)),
        ([&[1][..], &origin_bytes(&[b'h'; 254], 443)].concat(), FrameError::InvalidValue(4)),
        ([&[1][..], &origin_bytes(b"h", 0)].concat(), FrameError::InvalidValue(4)),
        ([&[1][..], &origin_bytes(&[0xff], 443)].concat(), FrameError::InvalidUtf8(4)),
    ];
    refused
        .iter()
        .for_each(|(origins, error)| assert_eq!(decode_err(&raw(1, 1, &add_body(origins))), *error));
}

#[test]
fn add_origins_must_be_whole_with_nothing_after_them() {
    let whole = [&[1][..], &origin_bytes(b"h", 443)].concat();
    [&[&whole[..], &[0][..]].concat(), &whole[..whole.len() - 1], &[1, 5, b'h']]
        .iter()
        .for_each(|origins| assert_eq!(decode_err(&raw(1, 1, &add_body(origins))), FrameError::InvalidValue(4)));
}

#[test]
fn add_refuses_an_unknown_kind_and_a_missing_field() {
    let origins = [&[1][..], &origin_bytes(b"h", 443)].concat();
    [&[0][..], &[3], &[], &[1, 1]].into_iter().for_each(|kind| {
        let request = body(&[field(1, &[0, 8]), field(2, b"fx"), field(3, kind), field(4, &origins)]);
        assert_eq!(decode_err(&raw(1, 1, &request)), FrameError::InvalidValue(3));
    });
    let no_kind = body(&[field(1, &[0, 8]), field(2, b"fx"), field(4, &origins)]);
    assert_eq!(decode_err(&raw(1, 1, &no_kind)), FrameError::MissingField(3));
    let no_origins = body(&[field(1, &[0, 8]), field(2, b"fx"), field(3, &[1])]);
    assert_eq!(decode_err(&raw(1, 1, &no_origins)), FrameError::MissingField(4));
    let reordered = body(&[field(1, &[0, 8]), field(3, &[1]), field(2, b"fx"), field(4, &origins)]);
    assert_eq!(decode_err(&raw(1, 1, &reordered)), FrameError::TagOutOfOrder(2));
}

#[test]
fn add_requests_out_of_bounds_are_not_encoded() {
    let request = |origins: Vec<RequestedOrigin>| {
        Frame::Request(AdminRequest::Add {
            name: "fx".to_owned(),
            kind: CredentialKind::Static,
            origins,
        })
    };
    let long_host = RequestedOrigin {
        host: "h".repeat(MAX_ORIGIN_HOST_LEN + 1),
        port: Port::HTTPS,
    };
    [
        request(Vec::new()),
        request(vec![fx_origin(); MAX_ORIGINS + 1]),
        request(vec![long_host]),
    ]
    .iter()
    .for_each(|frame| assert_eq!(encode(frame, &mut Vec::new()), Err(FrameError::InvalidValue(4))));
}

#[test]
fn the_reset_error_codes_have_their_documented_numbers_and_names() {
    [
        (ErrorCode::NothingToReset, 49, "nothing-to-reset"),
        (ErrorCode::ResetFailed, 50, "reset-failed"),
    ]
    .into_iter()
    .for_each(|(code, number, name)| {
        assert_eq!((code as u16, code.name()), (number, name));
        assert_round_trips(&error(code, "m"));
    });
}

#[test]
fn the_tpm_lockout_error_code_has_its_documented_number_and_name() {
    let code = ErrorCode::TpmLockedOut;
    assert_eq!((code as u16, code.name()), (51, "tpm-locked-out"));
    assert_round_trips(&error(code, "m"));
}

#[test]
fn the_forget_machine_error_code_has_its_documented_number_and_name() {
    let code = ErrorCode::MachineNotForgotten;
    assert_eq!((code as u16, code.name()), (52, "machine-not-forgotten"));
    assert_round_trips(&error(code, "m"));
}

#[test]
fn the_add_error_codes_have_their_documented_numbers_and_names() {
    [
        (ErrorCode::NameTaken, 20, "name-taken"),
        (ErrorCode::CredentialInvalid, 21, "credential-invalid"),
        (ErrorCode::VaultWriteFailed, 22, "vault-write-failed"),
    ]
    .into_iter()
    .for_each(|(code, number, name)| {
        assert_eq!((code as u16, code.name()), (number, name));
        assert_round_trips(&error(code, "m"));
    });
}

#[test]
fn replace_has_command_id_10_and_adds_encoding() {
    let request = AdminRequest::Replace {
        name: "fx".to_owned(),
        kind: CredentialKind::Basic,
        origins: vec![fx_origin()],
    };
    assert_eq!((AdminCommand::Replace as u16, request.command().name()), (10, "replace"));
    let origins = [&[1][..], &origin_bytes(b"api.fx.example", 443)].concat();
    let expected = body(&[field(1, &[0, 10]), field(2, b"fx"), field(3, &[2]), field(4, &origins)]);
    assert_eq!(encoded(&Frame::Request(request.clone())), raw(1, 1, &expected));
    assert_round_trips(&Frame::Request(request));
    let no_origin = body(&[field(1, &[0, 10]), field(2, b"fx"), field(3, &[1]), field(4, &[0])]);
    assert_eq!(decode_err(&raw(1, 1, &no_origin)), FrameError::InvalidValue(4));
}

#[test]
fn the_replace_result_carries_the_raw_record_id_under_its_own_command() {
    let record_id = v4([9; 16]);
    let expected = body(&[field(1, &[0, 10]), field(2, record_id.as_bytes())]);
    let frame = Frame::Response(AdminResponse::Replace { record_id });
    assert_eq!(encoded(&frame), raw(1, 4, &expected));
    assert_round_trips(&frame);
    let not_v4 = body(&[field(1, &[0, 10]), field(2, &[0; 16])]);
    assert_eq!(decode_err(&raw(1, 4, &not_v4)), FrameError::InvalidValue(2));
}

#[test]
fn list_has_command_id_9_no_arguments_and_its_own_error_code() {
    let request = Frame::Request(AdminRequest::List);
    assert_eq!(encoded(&request), [0, 1, 1, 0, 0, 0, 8, 0, 1, 0, 0, 0, 2, 0, 9]);
    assert_round_trips(&request);
    assert_eq!((AdminCommand::List as u16, AdminCommand::List.name()), (9, "list"));
    assert_eq!(
        (ErrorCode::ListTooLarge as u16, ErrorCode::ListTooLarge.name()),
        (26, "list-too-large")
    );
    assert_round_trips(&error(ErrorCode::ListTooLarge, "m"));
}

#[test]
fn rm_has_command_id_11_carries_the_name_and_has_no_result() {
    let request = Frame::Request(AdminRequest::Rm {
        name: "old_key".to_owned(),
    });
    assert_eq!(encoded(&request), raw(1, 1, &body(&[field(1, &[0, 11]), field(2, b"old_key")])));
    assert_round_trips(&request);
    assert_eq!((AdminCommand::Rm as u16, AdminCommand::Rm.name()), (11, "rm"));
    assert_eq!(request_command(&request), Some(AdminCommand::Rm));
    assert_round_trips(&Frame::Response(AdminResponse::Success));
}

#[test]
fn rm_refuses_a_request_without_exactly_a_name() {
    let without_name = raw(1, 1, &field(1, &[0, 11]));
    let extra = raw(1, 1, &body(&[field(1, &[0, 11]), field(2, b"a"), field(3, b"b")]));
    [without_name, extra].iter().for_each(|bytes| assert!(decode(bytes).is_err()));
}

#[test]
fn the_vault_change_error_codes_have_their_documented_numbers_and_names() {
    [
        (ErrorCode::UnknownCredential, 23, "unknown-credential"),
        (ErrorCode::CredentialInUse, 24, "credential-in-use"),
    ]
    .into_iter()
    .for_each(|(code, number, name)| {
        assert_eq!((code as u16, code.name()), (number, name));
        assert_round_trips(&error(code, "m"));
    });
}

fn request_command(frame: &Frame) -> Option<AdminCommand> {
    match frame {
        Frame::Request(request) => Some(request.command()),
        _ => None,
    }
}

fn config_approve(config: &[u8]) -> Frame {
    Frame::Request(AdminRequest::ConfigApprove(ProposedConfig::new(config.to_vec()).unwrap()))
}

#[test]
fn config_approve_has_command_id_2_and_carries_the_exact_bytes() {
    let expected = [&[0, 1, 1, 0, 0, 0, 17, 0, 1, 0, 0, 0, 2, 0, 2, 0, 2, 0, 0, 0, 3][..], b"a\0\xff"].concat();
    assert_eq!(encoded(&config_approve(b"a\0\xff")), expected);
    assert_eq!(AdminCommand::ConfigApprove.name(), "config approve");
    assert_round_trips(&config_approve(b""));
}

#[test]
fn a_config_over_the_limit_is_refused_by_the_decoder_and_cannot_be_built() {
    assert!(ProposedConfig::new(vec![b'#'; MAX_CONFIG_LEN + 1]).is_none());
    let longest = body(&[field(1, &[0, 2]), field(2, &vec![b'#'; MAX_CONFIG_LEN])]);
    assert!(decode(&raw(1, 1, &longest)).is_ok());
    let over = body(&[field(1, &[0, 2]), field(2, &vec![b'#'; MAX_CONFIG_LEN + 1])]);
    assert_eq!(decode_err(&raw(1, 1, &over)), FrameError::InvalidValue(2));
}

#[test]
fn config_approve_needs_its_config_and_nothing_else() {
    assert_eq!(decode_err(&raw(1, 1, &field(1, &[0, 2]))), FrameError::MissingField(2));
    let extra = body(&[field(1, &[0, 2]), field(2, b"x"), field(3, b"sig")]);
    assert_eq!(decode_err(&raw(1, 1, &extra)), FrameError::UnknownTag(3));
}

#[test]
fn a_proposed_config_never_shows_its_bytes_in_debug() {
    let shown = format!(
        "{:?}",
        AdminRequest::ConfigApprove(ProposedConfig::new(MARKER.as_bytes().to_vec()).unwrap())
    );
    assert!(!shown.contains(MARKER), "{shown}");
}

#[test]
fn the_approval_result_has_the_documented_fields_and_widths() {
    let result = body(&[
        field(1, &[0, 2]),
        field(2, &7u64.to_be_bytes()),
        field(3, &[0xab; 32]),
        field(4, b"callers: none"),
    ]);
    let (frame, _) = decoded(&raw(1, 4, &result));
    let expected = AdminResponse::ConfigApprove(ApprovalResult {
        version: 7,
        digest: [0xab; 32],
        headline: "callers: none".to_owned(),
    });
    assert!(same(&frame, &Frame::Response(expected)));
    let short_digest = body(&[
        field(1, &[0, 2]),
        field(2, &7u64.to_be_bytes()),
        field(3, &[0xab; 31]),
        field(4, b""),
    ]);
    assert_eq!(decode_err(&raw(1, 4, &short_digest)), FrameError::InvalidValue(3));
    let short_version = body(&[field(1, &[0, 2]), field(2, &[7]), field(3, &[0xab; 32]), field(4, b"")]);
    assert_eq!(decode_err(&raw(1, 4, &short_version)), FrameError::InvalidValue(2));
}

#[test]
fn the_approval_error_codes_have_their_documented_numbers_and_names() {
    [
        (ErrorCode::ConfigInvalid, 7, "config-invalid"),
        (ErrorCode::Declined, 8, "declined"),
        (ErrorCode::ApprovalDenied, 9, "approval-denied"),
        (ErrorCode::ApprovalUnavailable, 10, "approval-unavailable"),
        (ErrorCode::ApprovalFailed, 11, "approval-failed"),
        (ErrorCode::CommittedNotActive, 12, "committed-not-active"),
    ]
    .iter()
    .for_each(|(code, number, name)| {
        assert_eq!((*code as u16, code.name()), (*number, *name));
        assert_round_trips(&error(*code, name));
    });
}

#[test]
fn a_notice_needs_its_text_as_utf8() {
    assert_eq!(decode_err(&raw(1, 6, &[])), FrameError::MissingField(1));
    assert_eq!(decode_err(&raw(1, 6, &field(1, &[0xff]))), FrameError::InvalidUtf8(1));
    assert_round_trips(&Frame::Notice(Notice {
        text: "a".repeat(MAX_NOTICE_LEN),
    }));
}

#[test]
fn long_text_splits_into_notices_that_fit_and_join_back_exactly() {
    let text = format!("{}é{}", "a".repeat(MAX_NOTICE_LEN - 1), "b\n".repeat(MAX_NOTICE_LEN / 2));
    let notices = Notice::split(&text);
    assert_eq!(notices.len(), 3);
    assert_eq!(
        notices[0].text.len(),
        MAX_NOTICE_LEN - 1,
        "the split falls before the two-byte character"
    );
    notices.iter().for_each(|notice| assert_round_trips(&Frame::Notice(notice.clone())));
    assert_eq!(notices.iter().map(|notice| notice.text.as_str()).collect::<String>(), text);
    assert!(Notice::split("").is_empty());
}

#[test]
fn a_reveal_carries_its_value_unframed_and_round_trips() {
    let bytes = encoded(&reveal(MARKER.as_bytes()));
    assert_eq!(bytes, raw(PROTOCOL_VERSION, 7, MARKER.as_bytes()));
    assert_round_trips(&reveal(MARKER.as_bytes()));
    assert_round_trips(&reveal(&vec![0xa5; MAX_BODY_LEN]));
    let mut direct = Vec::new();
    encode_reveal(MARKER.as_bytes(), &mut direct).unwrap();
    assert_eq!(direct, bytes, "encoding from the bytes matches encoding the frame");
}

#[test]
fn a_reveal_over_the_body_bound_is_refused_at_the_header() {
    let header = [&[0, 1, 7][..], &(u32::try_from(MAX_BODY_LEN).unwrap() + 1).to_be_bytes()].concat();
    assert_eq!(decode_err(&header), FrameError::BodyTooLong);
    let mut out = vec![9];
    assert_eq!(encode_reveal(&vec![0; MAX_BODY_LEN + 1], &mut out), Err(FrameError::BodyTooLong));
    assert_eq!(out, [9], "a refused reveal appends nothing");
}

#[test]
fn a_switchable_prompt_round_trips_with_its_flag_at_tag_3() {
    let switchable = Frame::Prompt(Prompt {
        label: "Approval passphrase for \"laptop\"".to_owned(),
        secret: true,
        switchable: true,
    });
    assert_round_trips(&switchable);
    assert!(encoded(&switchable).ends_with(&field(3, &[1])));
    assert!(encoded(&prompt("Type yes", false)).ends_with(&field(3, &[0])));
}

#[test]
fn a_switch_frame_is_a_bare_header_and_a_body_is_malformed() {
    assert_eq!(encoded(&Frame::Switch), raw(1, 8, &[]));
    assert_eq!(decode_err(&raw(1, 8, &[0])), FrameError::UnexpectedBody(8));
    assert_eq!(ErrorCode::for_frame_error(FrameError::UnexpectedBody(8)), ErrorCode::MalformedFrame);
}

#[test]
fn an_empty_reveal_is_refused_both_ways() {
    assert_eq!(decode_err(&raw(1, 7, &[])), FrameError::EmptyBody(7));
    assert_eq!(encode(&reveal(b""), &mut Vec::new()), Err(FrameError::EmptyBody(7)));
}

/// The roles a vault is initialized with, with the host unlock role when `host` is set.
fn enrolled(host: bool) -> Vec<RecipientRole> {
    [RecipientRole::Operational, RecipientRole::Recovery]
        .into_iter()
        .chain(host.then_some(RecipientRole::HostUnlock))
        .collect()
}

#[test]
fn init_has_command_id_7_and_takes_the_host_unlock_flag() {
    let init = |host_unlock| AdminRequest::Init { host_unlock };
    assert_eq!((AdminCommand::Init as u16, init(false).command().name()), (7, "init"));
    [false, true].iter().for_each(|flag| {
        let request = Frame::Request(init(*flag));
        assert_eq!(
            encoded(&request),
            raw(1, 1, &body(&[field(1, &[0, 7]), field(2, &[u8::from(*flag)])]))
        );
        assert_round_trips(&request);
    });
    let refused = [
        (body(&[field(1, &[0, 7])]), FrameError::MissingField(2)),
        (body(&[field(1, &[0, 7]), field(2, &[2])]), FrameError::InvalidValue(2)),
        (
            body(&[field(1, &[0, 7]), field(2, &[0]), field(3, b"x")]),
            FrameError::UnknownTag(3),
        ),
    ];
    refused
        .iter()
        .for_each(|(request, error)| assert_eq!(decode_err(&raw(1, 1, request)), *error));
}

#[test]
fn the_init_result_carries_the_raw_vault_id_the_committed_version_and_the_recipient_roles() {
    let vault_id = VaultId::from_bytes(v4_bytes([9; 16])).unwrap();
    let expected = body(&[
        field(1, &[0, 7]),
        field(2, vault_id.as_bytes()),
        field(3, &1u64.to_be_bytes()),
        field(4, &[1, 2, 6]),
    ]);
    let result = Frame::Response(AdminResponse::Init {
        vault_id,
        version: 1,
        recipients: enrolled(true),
    });
    assert_eq!(encoded(&result), raw(1, 4, &expected));
    assert_round_trips(&result);
    let refused = [
        (
            body(&[field(1, &[0, 7]), field(2, &[9; 15]), field(3, &[0; 8]), field(4, &[1])]),
            FrameError::InvalidValue(2),
        ),
        (
            body(&[field(1, &[0, 7]), field(2, &[0; 16]), field(3, &[0; 8]), field(4, &[1])]),
            FrameError::InvalidValue(2),
        ),
        (
            body(&[field(1, &[0, 7]), field(2, vault_id.as_bytes()), field(3, &[1]), field(4, &[1])]),
            FrameError::InvalidValue(3),
        ),
        (
            body(&[field(1, &[0, 7]), field(2, vault_id.as_bytes()), field(3, &[0; 8]), field(4, &[4])]),
            FrameError::InvalidValue(4),
        ),
        (
            body(&[field(1, &[0, 7]), field(2, vault_id.as_bytes()), field(3, &[0; 8])]),
            FrameError::MissingField(4),
        ),
    ];
    refused
        .iter()
        .for_each(|(result, error)| assert_eq!(decode_err(&raw(1, 4, result)), *error));
}

#[test]
fn the_init_error_codes_have_their_documented_numbers_and_names() {
    [
        (ErrorCode::AlreadyInitialized, 17, "already-initialized"),
        (ErrorCode::PassphraseRejected, 18, "passphrase-rejected"),
        (ErrorCode::InitFailed, 19, "init-failed"),
    ]
    .into_iter()
    .for_each(|(code, number, name)| {
        assert_eq!((code as u16, code.name()), (number, name));
        assert_round_trips(&error(code, "m"));
    });
}

#[test]
fn caller_token_has_command_id_3_and_takes_no_arguments() {
    assert_eq!(
        (AdminCommand::CallerToken as u16, AdminRequest::CallerToken.command().name()),
        (3, "caller-token")
    );
    assert_eq!(encoded(&Frame::Request(AdminRequest::CallerToken)), raw(1, 1, &field(1, &[0, 3])));
    let with_argument = body(&[field(1, &[0, 3]), field(2, b"x")]);
    assert_eq!(decode_err(&raw(1, 1, &with_argument)), FrameError::UnknownTag(2));
}

/// A valid token's text: `ivt_`, then 43 base64url characters of which the last is a canonical ending.
fn token_text() -> String {
    format!("ivt_{}A", "Mk".repeat(21))
}

#[test]
fn the_caller_token_result_carries_the_token_text_and_round_trips() {
    let text = token_text();
    assert_eq!(text.len(), CALLER_TOKEN_LEN);
    let token = CallerToken::parse(text.as_bytes()).unwrap();
    let result = Frame::Response(AdminResponse::CallerToken { token });
    assert_eq!(encoded(&result), raw(1, 4, &body(&[field(1, &[0, 3]), field(2, text.as_bytes())])));
    assert_round_trips(&result);
}

#[test]
fn a_caller_token_result_with_an_invalid_token_is_malformed_and_names_no_token_byte() {
    let text = token_text();
    let replaced = |at: usize, byte: u8| {
        let mut bytes = text.clone().into_bytes();
        bytes[at] = byte;
        bytes
    };
    let refused = [
        text.as_bytes()[..CALLER_TOKEN_LEN - 1].to_vec(),
        [text.as_bytes(), b"A"].concat(),
        replaced(10, b'+'),
        replaced(CALLER_TOKEN_LEN - 1, b'B'),
        replaced(0, b'x'),
    ];
    refused.iter().for_each(|token| {
        let error = decode_err(&raw(1, 4, &body(&[field(1, &[0, 3]), field(2, token)])));
        assert_eq!(error, FrameError::InvalidValue(2));
        assert_eq!(ErrorCode::for_frame_error(error), ErrorCode::MalformedFrame);
        let message = error.to_string();
        assert!(!message.contains("Mk") && !message.contains("ivt_"), "{message}");
    });
}

#[test]
fn the_caller_token_error_code_has_its_documented_number_and_name() {
    let code = ErrorCode::RandomSourceFailed;
    assert_eq!((code as u16, code.name()), (25, "random-source-failed"));
    assert_round_trips(&error(code, "m"));
}

#[test]
fn recovery_check_has_the_documented_command_result_and_error_codes() {
    assert_eq!(
        (AdminCommand::RecoveryCheck as u16, AdminRequest::RecoveryCheck.command().name()),
        (12, "recovery check")
    );
    assert_eq!(
        encoded(&Frame::Request(AdminRequest::RecoveryCheck)),
        raw(1, 1, &field(1, &[0, 12]))
    );
    let vault_id = VaultId::from_bytes(v4_bytes([7; 16])).unwrap();
    let result = Frame::Response(AdminResponse::RecoveryCheck {
        vault_id,
        checked_at: 1_700_000_000,
        recorded: false,
    });
    let expected = body(&[
        field(1, &[0, 12]),
        field(2, vault_id.as_bytes()),
        field(3, &1_700_000_000u64.to_be_bytes()),
        field(4, &[0]),
    ]);
    assert_eq!(encoded(&result), raw(1, 4, &expected));
    assert_round_trips(&result);
    [
        (ErrorCode::RecoveryKeyInvalid, 30, "recovery-key-invalid"),
        (ErrorCode::RecoveryCheckFailed, 31, "recovery-check-failed"),
        (ErrorCode::RecoveryCheckUnavailable, 32, "recovery-check-unavailable"),
        (ErrorCode::UnlockRateLimited, 34, "unlock-rate-limited"),
        (ErrorCode::RecipientInventoryDamaged, 39, "recipient-inventory-damaged"),
    ]
    .into_iter()
    .for_each(|(code, number, name)| {
        assert_eq!((code as u16, code.name()), (number, name));
        assert_round_trips(&error(code, "m"));
    });
}

#[test]
fn recipient_list_has_its_documented_command_id() {
    assert_eq!(
        (AdminCommand::RecipientList as u16, AdminRequest::RecipientList.command().name()),
        (13, "recipient list")
    );
    assert_eq!(
        encoded(&Frame::Request(AdminRequest::RecipientList)),
        raw(1, 1, &field(1, &[0, 13]))
    );
}

#[test]
fn the_migration_error_codes_have_their_documented_numbers_and_names() {
    [
        (ErrorCode::MigrationDenied, 28, "migration-denied"),
        (ErrorCode::MigrationUnavailable, 29, "migration-unavailable"),
        (ErrorCode::MigrationRateLimited, 33, "migration-rate-limited"),
    ]
    .into_iter()
    .for_each(|(code, number, name)| {
        assert_eq!((code as u16, code.name()), (number, name));
        assert_round_trips(&error(code, "m"));
    });
}

#[test]
fn recipient_remove_has_its_documented_ids_and_bodies() {
    let request = AdminRequest::RecipientRemove {
        recipient: "age1x".to_owned(),
    };
    assert_eq!(
        (AdminCommand::RecipientRemove as u16, request.command().name()),
        (15, "recipient remove")
    );
    assert_eq!(
        encoded(&Frame::Request(request)),
        raw(1, 1, &[field(1, &[0, 15]), field(2, b"age1x")].concat())
    );
    assert_eq!(
        encoded(&Frame::Response(AdminResponse::RecipientRemove { recipients: 2 })),
        raw(1, 4, &[field(1, &[0, 15]), field(2, &[2])].concat())
    );
    [
        (ErrorCode::RecipientInvalid, 35, "recipient-invalid"),
        (ErrorCode::RecipientEnrolled, 36, "recipient-enrolled"),
        (ErrorCode::UnknownRecipient, 37, "unknown-recipient"),
        (ErrorCode::RecipientSetInvalid, 38, "recipient-set-invalid"),
    ]
    .into_iter()
    .for_each(|(code, number, name)| {
        assert_eq!((code as u16, code.name()), (number, name));
        assert_round_trips(&error(code, "m"));
    });
}

#[test]
fn a_recipient_count_of_any_other_width_is_refused() {
    let body = raw(1, 4, &[field(1, &[0, 15]), field(2, &[0, 2])].concat());
    assert_eq!(decode_err(&body), FrameError::InvalidValue(2));
}

#[test]
fn approver_add_has_its_documented_ids_and_bodies() {
    let request = AdminRequest::ApproverAdd {
        kind: RequestedSignerKind::Software,
        label: "backup".to_owned(),
    };
    assert_eq!((AdminCommand::ApproverAdd as u16, request.command().name()), (17, "approver add"));
    assert_eq!(
        encoded(&Frame::Request(request)),
        raw(1, 1, &[field(1, &[0, 17]), field(2, &[1]), field(3, b"backup")].concat())
    );
    let id = ApproverId::from_bytes(v4_bytes([7; 16])).unwrap();
    assert_eq!(
        encoded(&Frame::Response(AdminResponse::ApproverAdd {
            approver: id,
            approvers: 2
        })),
        raw(1, 4, &[field(1, &[0, 17]), field(2, id.as_bytes()), field(3, &[2])].concat())
    );
    [
        (ErrorCode::ApproverInvalid, 40, "approver-invalid"),
        (ErrorCode::ApproverSetInvalid, 42, "approver-set-invalid"),
        (ErrorCode::ApproverKindUnavailable, 44, "approver-kind-unavailable"),
    ]
    .into_iter()
    .for_each(|(code, number, name)| {
        assert_eq!((code as u16, code.name()), (number, name));
        assert_round_trips(&error(code, "m"));
    });
}

#[test]
fn approver_remove_has_its_documented_ids_and_bodies() {
    let request = AdminRequest::ApproverRemove { approver: [7; 16] };
    assert_eq!(
        (AdminCommand::ApproverRemove as u16, request.command().name()),
        (18, "approver remove")
    );
    assert_eq!(
        encoded(&Frame::Request(request)),
        raw(1, 1, &[field(1, &[0, 18]), field(2, &[7; 16])].concat())
    );
    assert_eq!(
        encoded(&Frame::Response(AdminResponse::ApproverRemove { approvers: 1 })),
        raw(1, 4, &[field(1, &[0, 18]), field(2, &[1])].concat())
    );
    [
        (ErrorCode::UnknownApprover, 41, "unknown-approver"),
        (ErrorCode::ApproverInUse, 43, "approver-in-use"),
    ]
    .into_iter()
    .for_each(|(code, number, name)| {
        assert_eq!((code as u16, code.name()), (number, name));
        assert_round_trips(&error(code, "m"));
    });
}

#[test]
fn an_approver_id_that_is_not_16_bytes_is_a_malformed_frame() {
    [&[7; 15][..], &[7; 17], &[]].into_iter().for_each(|id| {
        let body = raw(1, 1, &[field(1, &[0, 18]), field(2, id)].concat());
        assert_eq!(decode_err(&body), FrameError::InvalidValue(2));
    });
}

#[test]
fn an_approver_kind_outside_its_codes_is_a_malformed_frame() {
    [0, 4, 255].into_iter().for_each(|kind| {
        let body = raw(1, 1, &[field(1, &[0, 17]), field(2, &[kind]), field(3, b"backup")].concat());
        assert_eq!(decode_err(&body), FrameError::InvalidValue(2));
    });
    let wide = raw(1, 1, &[field(1, &[0, 17]), field(2, &[0, 1]), field(3, b"backup")].concat());
    assert_eq!(decode_err(&wide), FrameError::InvalidValue(2));
}

fn import_result(vault_id: [u8; 16], [records, version, highest_reserved]: [u64; 3], digest: [u8; 32], host: bool) -> ImportResult {
    ImportResult {
        vault_id: VaultId::from_bytes(v4_bytes(vault_id)).unwrap(),
        records,
        version,
        highest_reserved,
        digest,
        recipients: enrolled(host),
    }
}

fn chunk(len: usize) -> Frame {
    Frame::BundleData(BundleChunk::new(vec![0xa5; len]).unwrap())
}

#[test]
fn a_bundle_data_frame_is_its_bytes_unframed_with_kind_9() {
    [0, 1, MAX_BODY_LEN].into_iter().for_each(|len| {
        let frame = chunk(len);
        assert_eq!(encoded(&frame), raw(1, 9, &vec![0xa5; len]));
        assert_round_trips(&frame);
    });
    let end = Frame::BundleData(BundleChunk::end());
    assert_eq!(encoded(&end), raw(1, 9, &[]));
    assert!(matches!(decoded(&encoded(&end)).0, Frame::BundleData(chunk) if chunk.is_end()));
}

#[test]
fn a_bundle_data_frame_over_the_body_bound_is_refused_both_ways() {
    assert!(BundleChunk::new(vec![0; MAX_BODY_LEN + 1]).is_none());
    assert_eq!(
        encode_bundle_data(&vec![0; MAX_BODY_LEN + 1], &mut Vec::new()),
        Err(FrameError::BodyTooLong)
    );
    let header = raw(1, 9, &[])[..HEADER_LEN - 4]
        .iter()
        .copied()
        .chain(u32::try_from(MAX_BODY_LEN + 1).unwrap().to_be_bytes())
        .collect::<Vec<_>>();
    assert_eq!(decode_err(&header), FrameError::BodyTooLong);
}

#[test]
fn a_bundle_chunk_shows_only_its_length_in_debug() {
    assert_eq!(
        format!("{:?}", BundleChunk::new(MARKER.as_bytes().to_vec()).unwrap()),
        format!("BundleChunk({} bytes)", MARKER.len())
    );
}

#[test]
fn export_has_command_id_19_and_takes_no_arguments() {
    assert_eq!((AdminCommand::Export as u16, AdminRequest::Export.command().name()), (19, "export"));
    let request = Frame::Request(AdminRequest::Export);
    assert_eq!(encoded(&request), raw(1, 1, &field(1, &[0, 19])));
    assert_round_trips(&request);
    assert_eq!(
        decode_err(&raw(1, 1, &body(&[field(1, &[0, 19]), field(2, &[0])]))),
        FrameError::UnknownTag(2)
    );
}

#[test]
fn import_has_command_id_20_and_takes_the_host_unlock_flag_at_tag_2() {
    let import = |host_unlock| AdminRequest::Import { host_unlock };
    assert_eq!((AdminCommand::Import as u16, import(false).command().name()), (20, "import"));
    [false, true].iter().for_each(|flag| {
        let request = Frame::Request(import(*flag));
        assert_eq!(
            encoded(&request),
            raw(1, 1, &body(&[field(1, &[0, 20]), field(2, &[u8::from(*flag)])]))
        );
        assert_round_trips(&request);
    });
    let refused = [
        (body(&[field(1, &[0, 20])]), FrameError::MissingField(2)),
        (body(&[field(1, &[0, 20]), field(2, &[2])]), FrameError::InvalidValue(2)),
        (body(&[field(1, &[0, 20]), field(2, &[0, 0])]), FrameError::InvalidValue(2)),
        (
            body(&[field(1, &[0, 20]), field(2, &[0]), field(3, b"x")]),
            FrameError::UnknownTag(3),
        ),
    ];
    refused
        .iter()
        .for_each(|(request, error)| assert_eq!(decode_err(&raw(1, 1, request)), *error));
}

#[test]
fn the_export_result_carries_the_vault_id_the_record_count_and_the_byte_count() {
    let vault_id = VaultId::from_bytes(v4_bytes([7; 16])).unwrap();
    let result = Frame::Response(AdminResponse::Export {
        vault_id,
        records: 3,
        bytes: 4096,
    });
    let expected = body(&[
        field(1, &[0, 19]),
        field(2, vault_id.as_bytes()),
        field(3, &3u64.to_be_bytes()),
        field(4, &4096u64.to_be_bytes()),
    ]);
    assert_eq!(encoded(&result), raw(1, 4, &expected));
    assert_round_trips(&result);
    let refused = [
        (
            body(&[field(1, &[0, 19]), field(2, &[7; 15]), field(3, &[0; 8]), field(4, &[0; 8])]),
            FrameError::InvalidValue(2),
        ),
        (
            body(&[
                field(1, &[0, 19]),
                field(2, vault_id.as_bytes()),
                field(3, &[0; 4]),
                field(4, &[0; 8]),
            ]),
            FrameError::InvalidValue(3),
        ),
        (
            body(&[
                field(1, &[0, 19]),
                field(2, vault_id.as_bytes()),
                field(3, &[0; 8]),
                field(4, &[0; 4]),
            ]),
            FrameError::InvalidValue(4),
        ),
        (
            body(&[field(1, &[0, 19]), field(2, vault_id.as_bytes()), field(3, &[0; 8])]),
            FrameError::MissingField(4),
        ),
    ];
    refused
        .iter()
        .for_each(|(result, error)| assert_eq!(decode_err(&raw(1, 4, result)), *error));
}

#[test]
fn the_import_result_carries_the_versions_the_config_digest_and_the_recipient_roles() {
    let result = import_result([7; 16], [3, 1, 2], [0xd1; 32], true);
    let expected = body(&[
        field(1, &[0, 20]),
        field(2, result.vault_id.as_bytes()),
        field(3, &3u64.to_be_bytes()),
        field(4, &1u64.to_be_bytes()),
        field(5, &2u64.to_be_bytes()),
        field(6, &[0xd1; 32]),
        field(7, &[1, 2, 6]),
    ]);
    let frame = Frame::Response(AdminResponse::Import(result.clone()));
    assert_eq!(encoded(&frame), raw(1, 4, &expected));
    assert_round_trips(&frame);
    let with = |tag: u16, value: &[u8]| {
        let fields = [
            (2, result.vault_id.as_bytes().to_vec()),
            (3, 3u64.to_be_bytes().to_vec()),
            (4, 1u64.to_be_bytes().to_vec()),
            (5, 2u64.to_be_bytes().to_vec()),
            (6, vec![0xd1; 32]),
            (7, vec![1]),
        ]
        .map(|(t, v)| if t == tag { field(t, value) } else { field(t, &v) });
        raw(1, 4, &[field(1, &[0, 20])].into_iter().chain(fields).collect::<Vec<_>>().concat())
    };
    [(2, &[7; 15][..]), (3, &[0; 7]), (4, &[0; 9]), (5, &[]), (6, &[0; 31]), (7, &[4])]
        .into_iter()
        .for_each(|(tag, value)| assert_eq!(decode_err(&with(tag, value)), FrameError::InvalidValue(tag)));
}

#[test]
fn the_bundle_error_codes_have_their_documented_numbers_and_names() {
    [
        (ErrorCode::ExportFailed, 45, "export-failed"),
        (ErrorCode::BundleInvalid, 46, "bundle-invalid"),
        (ErrorCode::ImportDenied, 47, "import-denied"),
        (ErrorCode::ImportFailed, 48, "import-failed"),
    ]
    .into_iter()
    .for_each(|(code, number, name)| {
        assert_eq!((code as u16, code.name()), (number, name));
        assert_round_trips(&error(code, "m"));
    });
}

#[test]
fn the_state_gate_admits_export_only_in_ready_and_import_only_in_locked() {
    use crate::service_state::{FailureReason, ServiceState};
    let states = [
        ServiceState::Starting,
        ServiceState::Locked,
        ServiceState::Checking,
        ServiceState::Ready,
        ServiceState::Unavailable(FailureReason::PolicyInvalid),
        ServiceState::Stopped,
    ];
    let admitted = |command: AdminCommand| {
        states
            .into_iter()
            .filter(|state| state.admin_allows(command.operation()))
            .collect::<Vec<_>>()
    };
    assert_eq!(admitted(AdminCommand::Export), [ServiceState::Ready]);
    assert_eq!(admitted(AdminCommand::Import), [ServiceState::Locked]);
}

#[test]
fn forget_machine_has_command_id_22_one_key_argument_and_a_fixed_result() {
    let request = AdminRequest::ForgetMachine {
        recipient: "age1abc".to_owned(),
    };
    assert_eq!(
        (AdminCommand::ForgetMachine as u16, request.command().name()),
        (22, "forget-machine")
    );
    assert_eq!(
        encoded(&Frame::Request(request)),
        raw(1, 1, &body(&[field(1, &[0, 22]), field(2, b"age1abc")]))
    );
    let result = AdminResponse::ForgetMachine {
        independence: None,
        recovery: RecoveryStatus::Unknown {
            detail: "no check record yet".to_owned(),
            due: false,
        },
    };
    assert_eq!(
        encoded(&Frame::Response(result)),
        raw(
            1,
            4,
            &body(&[
                field(1, &[0, 22]),
                field(2, b""),
                field(13, &[0]),
                field(14, &[0; 8]),
                field(15, &[0; 8]),
                field(16, &[0]),
                field(17, b"no check record yet"),
            ])
        )
    );
}
