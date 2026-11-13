// SPDX-License-Identifier: MPL-2.0
use super::super::{Decoded, Frame, FrameKind, put_frame};
use super::*;

const IDS: [&str; 2] = ["4b0e3d2c-1a9f-4e8d-8c7b-6a5f4e3d2c1b", "8d1c6f0e-2b7a-4c59-9e3d-5a4b3c2d1e0f"];

fn id(text: &str) -> ApproverId {
    ApproverId::from_bytes(*uuid::Uuid::parse_str(text).unwrap().as_bytes()).unwrap()
}

fn entry(text: &str, active: bool, label: &str, seconds: u64) -> ApproverEntry {
    ApproverEntry {
        id: id(text),
        kind: SignerKind::Software,
        active,
        label: ApproverLabel::new(label).unwrap(),
        enrolled_at: UtcSecond::from_unix_seconds(seconds).unwrap(),
    }
}

fn entries() -> Vec<ApproverEntry> {
    vec![
        entry(IDS[0], true, "backup passphrase", 1_794_132_764),
        entry(IDS[1], false, "approval passphrase", 1_793_958_553),
    ]
}

fn frame(entries: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    fields::put(&mut body, TAG_COMMAND, &16u16.to_be_bytes());
    fields::put(&mut body, TAG_ENTRIES, entries);
    let mut out = Vec::new();
    put_frame(&mut out, FrameKind::Success, &body).unwrap();
    out
}

fn decoded(bytes: &[u8]) -> Result<Vec<ApproverEntry>, FrameError> {
    match super::super::decode(bytes)? {
        Decoded::Frame {
            frame: Frame::Response(AdminResponse::ApproverList { entries }),
            ..
        } => Ok(entries),
        other => panic!("expected an approver list, got {other:?}"),
    }
}

fn encoded(entries: Vec<ApproverEntry>) -> Vec<u8> {
    let mut out = Vec::new();
    super::super::encode(&Frame::Response(AdminResponse::ApproverList { entries }), &mut out).unwrap();
    out
}

/// One entry in the documented layout: ID, kind code, active flag, label length and label, then the time.
fn raw_entry(text: &str, kind: u8, active: u8, label: &str, seconds: u64) -> Vec<u8> {
    let mut out = uuid::Uuid::parse_str(text).unwrap().as_bytes().to_vec();
    out.extend_from_slice(&[kind, active, u8::try_from(label.len()).unwrap()]);
    out.extend_from_slice(label.as_bytes());
    out.extend_from_slice(&seconds.to_be_bytes());
    out
}

#[test]
fn entries_round_trip_in_order() {
    assert_eq!(decoded(&encoded(entries())).unwrap(), entries());
    assert_eq!(decoded(&encoded(Vec::new())).unwrap(), Vec::new());
}

#[test]
fn the_wire_layout_is_the_documented_one() {
    let expected = [
        raw_entry(IDS[0], 1, 1, "backup passphrase", 1_794_132_764),
        raw_entry(IDS[1], 1, 0, "approval passphrase", 1_793_958_553),
    ]
    .concat();
    assert_eq!(encoded(entries()), frame(&expected));
}

#[test]
fn a_malformed_entry_is_refused() {
    let good = raw_entry(IDS[0], 1, 1, "x", 1);
    let unknown_kind = raw_entry(IDS[0], 9, 1, "x", 1);
    let bad_flag = raw_entry(IDS[0], 1, 2, "x", 1);
    let empty_label = raw_entry(IDS[0], 1, 1, "", 1);
    let out_of_range = raw_entry(IDS[0], 1, 1, "x", u64::MAX);
    let truncated = good[..good.len() - 1].to_vec();
    [unknown_kind, bad_flag, empty_label, out_of_range, truncated]
        .iter()
        .for_each(|entries| assert!(decoded(&frame(entries)).is_err()));
}
