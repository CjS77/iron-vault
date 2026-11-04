use proptest::prelude::*;
use zeroize::Zeroizing;

use super::fields::FIELD_HEADER_LEN;
use super::*;
use crate::deployment::DeploymentProfile;
use crate::secret_types_tests::MARKER;
use iron_vault_policy::{CredentialKind, Port};
use iron_vault_store::RecordId;

/// The longest prompt label: the body bound less two field headers and the one-byte secret flag.
const MAX_LABEL: usize = MAX_BODY_LEN - 2 * FIELD_HEADER_LEN - 1;
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
        (Frame::Response(a), Frame::Response(b)) => a == b,
        _ => false,
    }
}

fn owner_input(bytes: &[u8]) -> Frame {
    Frame::OwnerInput(OwnerInput::new(Zeroizing::new(bytes.to_vec())))
}

fn prompt(label: &str, secret: bool) -> Frame {
    Frame::Prompt(Prompt {
        label: label.to_owned(),
        secret,
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
        Just(ErrorCode::WrongState),
        Just(ErrorCode::UnlockDenied),
        Just(ErrorCode::UnlockFailed),
        Just(ErrorCode::UnlockedUnavailable),
        Just(ErrorCode::NameTaken),
        Just(ErrorCode::CredentialInvalid),
        Just(ErrorCode::VaultWriteFailed),
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
            add_request(),
        ]
        .prop_map(Frame::Request),
        (text(MAX_LABEL), any::<bool>()).prop_map(|(label, secret)| Frame::Prompt(Prompt { label, secret })),
        owner_bytes().prop_map(|bytes| owner_input(&bytes)),
        Just(AdminResponse::Success).prop_map(Frame::Response),
        prop_oneof![Just(DeploymentProfile::Protected), Just(DeploymentProfile::Development)]
            .prop_map(|profile| Frame::Response(AdminResponse::Ping { profile })),
        any::<bool>().prop_map(|cleared| Frame::Response(AdminResponse::Lock { cleared })),
        any::<[u8; 16]>().prop_map(|bytes| Frame::Response(AdminResponse::Add { record_id: v4(bytes) })),
        (error_code(), text(MAX_MESSAGE)).prop_map(|(code, message)| Frame::Response(AdminResponse::Error { code, message })),
    ]
}

/// The record ID with `bytes`' randomness and the version 4, RFC 9562 variant bits set.
fn v4(mut bytes: [u8; 16]) -> RecordId {
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    RecordId::from_bytes(bytes).unwrap()
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
    fn random_bodies_never_panic_and_accepted_frames_re_encode_exactly(kind in 0u8..7, body in field_soup()) {
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
        state: crate::service_state::ServiceState::Locked,
        profile: DeploymentProfile::Protected,
        vault: VaultStatus::Locked,
        memory: MemoryStatus::Locked,
    };
    let frame = Frame::Response(AdminResponse::Status(Box::new(report)));
    assert_round_trips(&frame);
    let mut full = encoded(&frame);
    let extra = field(11, b"x");
    full.extend_from_slice(&extra);
    let length = u32::try_from(full.len() - HEADER_LEN).unwrap().to_be_bytes();
    full[3..HEADER_LEN].copy_from_slice(&length);
    assert_eq!(decode_err(&full), FrameError::UnknownTag(11));
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
}

#[test]
fn lock_has_the_documented_encoding() {
    assert_eq!(
        encoded(&Frame::Request(AdminRequest::Lock)),
        [0, 1, 1, 0, 0, 0, 8, 0, 1, 0, 0, 0, 2, 0, 5]
    );
    let cleared = [0, 1, 4, 0, 0, 0, 15, 0, 1, 0, 0, 0, 2, 0, 5, 0, 2, 0, 0, 0, 1, 1];
    assert_eq!(encoded(&Frame::Response(AdminResponse::Lock { cleared: true })), cleared);
    let (held, _) = decoded(&raw(1, 4, &body(&[field(1, &[0, 5]), field(2, &[0])])));
    assert!(same(&held, &Frame::Response(AdminResponse::Lock { cleared: false })));
}

#[test]
fn lock_takes_no_arguments_and_its_result_needs_a_flag() {
    let with_argument = body(&[field(1, &[0, 5]), field(2, b"x")]);
    assert_eq!(decode_err(&raw(1, 1, &with_argument)), FrameError::UnknownTag(2));
    assert_eq!(decode_err(&raw(1, 4, &field(1, &[0, 5]))), FrameError::MissingField(2));
    let not_a_flag = body(&[field(1, &[0, 5]), field(2, &[2])]);
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
    let unknown = body(&[field(1, &[0, 9]), field(2, &[1])]);
    assert_eq!(decode_err(&raw(1, 4, &unknown)), FrameError::UnknownCommand(9));
    let without_profile = field(1, &[0, 1]);
    assert_eq!(decode_err(&raw(1, 4, &without_profile)), FrameError::MissingField(2));
    [&[][..], &[0], &[3], &[1, 1]].into_iter().for_each(|profile| {
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
    [0, 6, 255]
        .into_iter()
        .for_each(|kind| assert_eq!(decode_err(&raw(1, kind, &[])), FrameError::UnknownKind(kind)));
}

#[test]
fn unknown_tags_are_refused() {
    let request = body(&[field(1, &[0, 1]), field(2, b"")]);
    assert_eq!(decode_err(&raw(1, 1, &request)), FrameError::UnknownTag(2));
    let prompt = body(&[field(1, b"label"), field(2, &[1]), field(3, b"")]);
    assert_eq!(decode_err(&raw(1, 2, &prompt)), FrameError::UnknownTag(3));
    let ping_result = body(&[field(1, &[0, 1]), field(2, &[1]), field(3, b"")]);
    assert_eq!(decode_err(&raw(1, 4, &ping_result)), FrameError::UnknownTag(3));
    let error = body(&[field(0, b""), field(1, &[0, 1]), field(2, b"m")]);
    assert_eq!(decode_err(&raw(1, 5, &error)), FrameError::UnknownTag(0));
}

#[test]
fn unknown_commands_are_refused_whatever_follows() {
    assert_eq!(decode_err(&raw(1, 1, &field(1, &[0, 2]))), FrameError::UnknownCommand(2));
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
    assert_eq!(decode_err(&raw(1, 5, &field(2, b"message"))), FrameError::MissingField(1));
}

#[test]
fn invalid_utf8_is_refused() {
    let prompt = body(&[field(1, &[0xff]), field(2, &[0])]);
    assert_eq!(decode_err(&raw(1, 2, &prompt)), FrameError::InvalidUtf8(1));
    let error = body(&[field(1, &[0, 2]), field(2, &[0xc3])]);
    assert_eq!(decode_err(&raw(1, 5, &error)), FrameError::InvalidUtf8(2));
}

#[test]
fn malformed_fixed_width_values_and_flags_are_refused() {
    assert_eq!(decode_err(&raw(1, 1, &field(1, &[0, 0, 1]))), FrameError::InvalidValue(1));
    [&[][..], &[2], &[1, 0]].into_iter().for_each(|flag| {
        let prompt = body(&[field(1, b"label"), field(2, flag)]);
        assert_eq!(decode_err(&raw(1, 2, &prompt)), FrameError::InvalidValue(2));
    });
    let error = body(&[field(1, &[2]), field(2, b"m")]);
    assert_eq!(decode_err(&raw(1, 5, &error)), FrameError::InvalidValue(1));
}

#[test]
fn unknown_error_codes_are_refused() {
    [0, 7, 0xffff].into_iter().for_each(|code: u16| {
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
        raw(1, 9, marker),
        raw(1, 1, &body(&[field(1, &[0, 1]), field(2, marker)])),
        raw(1, 1, &body(&[field(1, &[0, 9]), field(2, marker)])),
        raw(1, 2, &body(&[field(1, &[marker, &[0xff][..]].concat()), field(2, &[1])])),
        raw(1, 2, &body(&[field(1, marker), field(1, marker)])),
        raw(1, 2, &[&field(1, marker)[..], &[0, 2, 0, 0, 0, 99], marker].concat()),
        raw(1, 4, &field(7, marker)),
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
