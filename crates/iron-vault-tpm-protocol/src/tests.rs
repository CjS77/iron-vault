// SPDX-License-Identifier: MPL-2.0
use std::io::Cursor;

use super::*;

const APPROVER: [u8; 16] = [7; 16];

fn key() -> TpmKeyParts {
    TpmKeyParts {
        primary_name: vec![0x00, 0x0b, 1, 2, 3],
        public: vec![4; 90],
        private: vec![5; 126],
    }
}

fn auth() -> TpmAuthValue {
    TpmAuthValue::from_bytes([9; 32])
}

fn sign_request(message: Vec<u8>) -> Request {
    Request::Sign(SignRequest {
        auth: auth(),
        key: key(),
        pinned_key: [4; PUBLIC_KEY_LEN],
        message,
    })
}

/// Encodes, reads the frame back and decodes it.
fn round_trip_request(request: &Request) -> Request {
    let frame = request.encode().unwrap();
    Request::decode(&read_frame(&mut Cursor::new(frame.to_vec())).unwrap()).unwrap()
}

fn round_trip_response(response: &Response) -> Response {
    let frame = response.encode().unwrap();
    Response::decode(&read_frame(&mut Cursor::new(frame)).unwrap()).unwrap()
}

fn body(request: &Request) -> Vec<u8> {
    request.encode().unwrap()[4..].to_vec()
}

fn every_response() -> Vec<Response> {
    vec![
        Response::Created {
            key: key(),
            public_key: [4; PUBLIC_KEY_LEN],
        },
        Response::Signed {
            signature: [1; SIGNATURE_LEN],
        },
        Response::WrongPin,
        Response::LockedOut { wait_seconds: 1200 },
        Response::NotThisTpm,
        Response::KeyMismatch,
        Response::WeakDaSettings,
        Response::RefusedMessage,
        Response::TpmError { code: 0x0000_098e },
        Response::Malformed,
    ]
}

#[test]
fn a_create_request_round_trips() {
    match round_trip_request(&Request::Create { auth: auth() }) {
        Request::Create { auth: decoded } => assert_eq!(decoded.as_bytes(), auth().as_bytes()),
        other => panic!("decoded {other:?}"),
    }
}

#[test]
fn a_sign_request_round_trips() {
    match round_trip_request(&sign_request(b"IVPP message".to_vec())) {
        Request::Sign(sign) => {
            assert_eq!(sign.auth.as_bytes(), auth().as_bytes());
            assert_eq!(
                (sign.key, sign.pinned_key, sign.message),
                (key(), [4; PUBLIC_KEY_LEN], b"IVPP message".to_vec())
            );
        }
        other => panic!("decoded {other:?}"),
    }
}

#[test]
fn every_response_round_trips_with_its_status() {
    let responses = every_response();
    responses
        .iter()
        .for_each(|response| assert_eq!(&round_trip_response(response), response));
    let statuses: Vec<u8> = responses.iter().map(Response::status).collect();
    assert_eq!(statuses, (0x00..=0x09).collect::<Vec<u8>>());
}

#[test]
fn a_frame_over_the_limit_is_refused_before_its_body() {
    let mut frame = ((MAX_FRAME_LEN + 1) as u32).to_be_bytes().to_vec();
    frame.extend(vec![0; 16]);
    assert!(matches!(read_frame(&mut Cursor::new(frame)), Err(ProtocolError::TooLarge { len, .. }) if len == MAX_FRAME_LEN + 1));
    let request = sign_request(vec![0; MAX_FRAME_LEN]);
    assert!(matches!(request.encode(), Err(ProtocolError::TooLarge { .. })));
}

#[test]
fn a_frame_shorter_than_its_length_is_refused() {
    let mut frame = 10u32.to_be_bytes().to_vec();
    frame.extend([0; 9]);
    assert!(matches!(read_frame(&mut Cursor::new(frame)), Err(ProtocolError::Io(_))));
}

#[test]
fn an_unknown_operation_is_refused() {
    let mut bytes = body(&Request::Create { auth: auth() });
    bytes[5] = 0x03;
    assert!(matches!(Request::decode(&bytes), Err(ProtocolError::UnknownOperation(0x03))));
}

#[test]
fn an_unknown_status_is_refused() {
    let mut bytes = Response::WrongPin.encode().unwrap()[4..].to_vec();
    bytes[5] = 0x0a;
    assert!(matches!(Response::decode(&bytes), Err(ProtocolError::UnknownStatus(0x0a))));
}

#[test]
fn another_version_or_magic_is_refused() {
    let mut bytes = body(&Request::Create { auth: auth() });
    bytes[4] = 2;
    assert!(matches!(Request::decode(&bytes), Err(ProtocolError::UnsupportedVersion(2))));
    let response = Response::WrongPin.encode().unwrap()[4..].to_vec();
    assert!(matches!(Request::decode(&response), Err(ProtocolError::WrongMagic)));
}

#[test]
fn a_truncated_field_is_refused_at_every_length() {
    let bytes = body(&sign_request(b"IVMA".to_vec()));
    (0..bytes.len()).for_each(|len| assert!(Request::decode(&bytes[..len]).is_err(), "decoded {len} bytes"));
    let mut long_field = bytes.clone();
    let message_len = long_field.len() - 4 - 8;
    long_field[message_len..message_len + 8].copy_from_slice(&5u64.to_be_bytes());
    assert!(matches!(Request::decode(&long_field), Err(ProtocolError::LengthPastEnd)));
    let created = Response::Created {
        key: key(),
        public_key: [4; PUBLIC_KEY_LEN],
    }
    .encode()
    .unwrap()[4..]
        .to_vec();
    assert!(matches!(
        Response::decode(&created[..created.len() - 1]),
        Err(ProtocolError::Truncated)
    ));
}

#[test]
fn trailing_bytes_are_refused() {
    let mut bytes = body(&Request::Create { auth: auth() });
    bytes.push(0);
    assert!(matches!(Request::decode(&bytes), Err(ProtocolError::TrailingBytes)));
}

#[test]
fn a_key_blob_round_trips_for_its_approver() {
    let blob = TpmKeyBlob::new(APPROVER, key());
    assert_eq!(TpmKeyBlob::decode(&blob.encode().unwrap(), &APPROVER).unwrap(), blob);
}

#[test]
fn a_key_blob_with_a_wrong_magic_is_refused() {
    let mut bytes = TpmKeyBlob::new(APPROVER, key()).encode().unwrap();
    bytes[3] = b'Q';
    assert!(matches!(TpmKeyBlob::decode(&bytes, &APPROVER), Err(ProtocolError::WrongMagic)));
}

#[test]
fn a_key_blob_for_another_approver_is_refused() {
    let bytes = TpmKeyBlob::new(APPROVER, key()).encode().unwrap();
    assert!(matches!(TpmKeyBlob::decode(&bytes, &[8; 16]), Err(ProtocolError::ApproverMismatch)));
}

#[test]
fn a_key_blob_over_the_limit_is_refused() {
    let big = TpmKeyParts {
        private: vec![0; MAX_TPM_KEY_BLOB_LEN],
        ..key()
    };
    assert!(matches!(
        TpmKeyBlob::new(APPROVER, big).encode(),
        Err(ProtocolError::TooLarge { .. })
    ));
    let oversized = vec![0; MAX_TPM_KEY_BLOB_LEN + 1];
    assert!(matches!(
        TpmKeyBlob::decode(&oversized, &APPROVER),
        Err(ProtocolError::TooLarge { len, limit: MAX_TPM_KEY_BLOB_LEN }) if len == MAX_TPM_KEY_BLOB_LEN + 1
    ));
}
