use super::super::{Decoded, Frame};
use super::*;

const KEY: &str = "age1v4q6gqhc84l6yrmyeqcske956a65frdww5rc4jnrdfhkpsdglqksx4muhw";

fn field(tag: u16, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    fields::put(&mut out, tag, value);
    out
}

fn raw(kind: u8, body: &[u8]) -> Vec<u8> {
    [
        &1u16.to_be_bytes()[..],
        &[kind],
        &u32::try_from(body.len()).unwrap().to_be_bytes(),
        body,
    ]
    .concat()
}

fn request(source: &[u8], recipient: &str, label: &str) -> Vec<u8> {
    raw(
        1,
        &[
            field(1, &14u16.to_be_bytes()),
            field(TAG_SOURCE, source),
            field(TAG_RECIPIENT, recipient.as_bytes()),
            field(TAG_LABEL, label.as_bytes()),
        ]
        .concat(),
    )
}

fn decode(bytes: &[u8]) -> Result<Frame, FrameError> {
    match super::super::decode(bytes)? {
        Decoded::Frame { frame, .. } => Ok(frame),
        Decoded::NeedMore(_) => panic!("the frame is whole"),
    }
}

fn encoded(frame: &Frame) -> Vec<u8> {
    let mut out = Vec::new();
    super::super::encode(frame, &mut out).unwrap();
    out
}

#[test]
fn the_request_is_command_14_with_source_1_the_key_and_the_label() {
    let request_frame = Frame::Request(AdminRequest::RecipientAdd {
        recipient: KEY.to_owned(),
        label: "bob's new laptop".to_owned(),
    });
    assert_eq!(encoded(&request_frame), request(&[1], KEY, "bob's new laptop"));
    match decode(&request(&[1], KEY, "bob's new laptop")) {
        Ok(Frame::Request(AdminRequest::RecipientAdd { recipient, label })) => {
            assert_eq!((recipient.as_str(), label.as_str()), (KEY, "bob's new laptop"))
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn another_source_or_an_empty_key_is_a_malformed_frame_but_a_bad_key_or_label_is_the_services_to_judge() {
    assert!(matches!(decode(&request(&[4], "", "x")), Err(FrameError::InvalidValue(TAG_SOURCE))));
    assert!(matches!(
        decode(&request(&[3], "", "x")),
        Err(FrameError::InvalidValue(TAG_RECIPIENT))
    ));
    assert!(matches!(
        decode(&request(&[2], KEY, "x")),
        Err(FrameError::InvalidValue(TAG_RECIPIENT))
    ));
    assert!(matches!(
        decode(&request(&[0], KEY, "x")),
        Err(FrameError::InvalidValue(TAG_SOURCE))
    ));
    assert!(matches!(
        decode(&request(&[1], "", "x")),
        Err(FrameError::InvalidValue(TAG_RECIPIENT))
    ));
    assert!(matches!(
        decode(&request(&[1], "not a key", "")),
        Ok(Frame::Request(AdminRequest::RecipientAdd { .. }))
    ));
}

#[test]
fn a_host_unlock_key_is_source_3_with_the_key_and_the_label() {
    let frame = Frame::Request(AdminRequest::RecipientAddHostUnlock {
        recipient: KEY.to_owned(),
        label: "host unlock, new TPM".to_owned(),
    });
    assert_eq!(encoded(&frame), request(&[3], KEY, "host unlock, new TPM"));
    match decode(&request(&[3], KEY, "host unlock, new TPM")) {
        Ok(Frame::Request(AdminRequest::RecipientAddHostUnlock { recipient, label })) => {
            assert_eq!((recipient.as_str(), label.as_str()), (KEY, "host unlock, new TPM"))
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_new_recovery_key_is_source_2_with_an_empty_key() {
    let frame = Frame::Request(AdminRequest::RecipientAddRecovery {
        label: "recovery key 2026".to_owned(),
    });
    assert_eq!(encoded(&frame), request(&[2], "", "recovery key 2026"));
    assert!(matches!(
        decode(&request(&[2], "", "recovery key 2026")),
        Ok(Frame::Request(AdminRequest::RecipientAddRecovery { label })) if label == "recovery key 2026"
    ));
}

#[test]
fn the_result_is_the_key_as_text_then_the_count() {
    let result = Frame::Response(AdminResponse::RecipientAdd {
        recipient: KEY.parse().unwrap(),
        recipients: 3,
    });
    let expected = [
        field(1, &14u16.to_be_bytes()),
        field(TAG_RESULT_RECIPIENT, KEY.as_bytes()),
        field(TAG_RECIPIENTS, &[3]),
    ]
    .concat();
    assert_eq!(encoded(&result), raw(4, &expected));
    let bad_key = [
        field(1, &14u16.to_be_bytes()),
        field(TAG_RESULT_RECIPIENT, b"age1nope"),
        field(TAG_RECIPIENTS, &[3]),
    ]
    .concat();
    assert!(matches!(
        decode(&raw(4, &bad_key)),
        Err(FrameError::InvalidValue(TAG_RESULT_RECIPIENT))
    ));
}
