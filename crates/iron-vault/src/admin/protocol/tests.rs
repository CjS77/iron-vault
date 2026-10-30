use proptest::prelude::*;
use zeroize::Zeroizing;

use super::fields::FIELD_HEADER_LEN;
use super::*;
use crate::secret_types_tests::MARKER;

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
        Just(AdminRequest::Ping).prop_map(Frame::Request),
        (text(MAX_LABEL), any::<bool>()).prop_map(|(label, secret)| Frame::Prompt(Prompt { label, secret })),
        owner_bytes().prop_map(|bytes| owner_input(&bytes)),
        Just(AdminResponse::Success).prop_map(Frame::Response),
        (error_code(), text(MAX_MESSAGE)).prop_map(|(code, message)| Frame::Response(AdminResponse::Error { code, message })),
    ]
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
    assert_eq!(decode_err(&raw(1, 4, &field(1, b""))), FrameError::UnknownTag(1));
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
    [0, 5, 0xffff].into_iter().for_each(|code: u16| {
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
