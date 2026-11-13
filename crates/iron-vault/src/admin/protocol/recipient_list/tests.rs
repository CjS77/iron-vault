// SPDX-License-Identifier: MPL-2.0
use super::super::{Decoded, Frame, FrameKind, put_frame};
use super::*;

const KEYS: [&str; 3] = [
    "age1csc5wgcsw68jdz8uxh9sramjkys02nk8qf740lpywzvlzm9pjf7qxffk4e",
    "age1jy4a0t77ngkqdm42qqd3xuja9zrjsy6f62u49qw06tza9z9rxpxqwf95ly",
    "age1v4q6gqhc84l6yrmyeqcske956a65frdww5rc4jnrdfhkpsdglqksx4muhw",
];

fn entry(key: &str, role: RecipientRole, label: &str, seconds: u64) -> RecipientEntry {
    RecipientEntry::new(
        key.parse().unwrap(),
        role,
        RecipientLabel::new(label).unwrap(),
        UtcSecond::from_unix_seconds(seconds).unwrap(),
    )
}

fn entries() -> Vec<RecipientEntry> {
    vec![
        entry(KEYS[0], RecipientRole::Recovery, "recovery key", 1_793_958_553),
        entry(KEYS[1], RecipientRole::Operational, "vault passphrase", 1_793_958_553),
        entry(KEYS[2], RecipientRole::Added, "bob's new laptop", 1_794_060_171),
    ]
}

fn frame(entries: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    fields::put(&mut body, TAG_COMMAND, &13u16.to_be_bytes());
    fields::put(&mut body, TAG_ENTRIES, entries);
    let mut out = Vec::new();
    put_frame(&mut out, FrameKind::Success, &body).unwrap();
    out
}

fn decoded(bytes: &[u8]) -> Result<Vec<RecipientEntry>, FrameError> {
    match super::super::decode(bytes)? {
        Decoded::Frame {
            frame: Frame::Response(AdminResponse::RecipientList { entries }),
            ..
        } => Ok(entries),
        other => panic!("expected a recipient list, got {other:?}"),
    }
}

fn encoded(entries: Vec<RecipientEntry>) -> Vec<u8> {
    let mut out = Vec::new();
    super::super::encode(&Frame::Response(AdminResponse::RecipientList { entries }), &mut out).unwrap();
    out
}

/// One entry in the documented layout: key length and key, role code, label length and label, then the time.
fn raw_entry(key: &str, role: u8, label: &str, seconds: u64) -> Vec<u8> {
    let mut out = vec![u8::try_from(key.len()).unwrap()];
    out.extend_from_slice(key.as_bytes());
    out.push(role);
    out.push(u8::try_from(label.len()).unwrap());
    out.extend_from_slice(label.as_bytes());
    out.extend_from_slice(&seconds.to_be_bytes());
    out
}

#[test]
fn entries_round_trip_in_inventory_order() {
    assert_eq!(decoded(&encoded(entries())).unwrap(), entries());
    assert_eq!(decoded(&encoded(Vec::new())).unwrap(), Vec::new());
}

#[test]
fn the_wire_layout_is_the_documented_one() {
    let expected = [
        raw_entry(KEYS[0], 2, "recovery key", 1_793_958_553),
        raw_entry(KEYS[1], 1, "vault passphrase", 1_793_958_553),
        raw_entry(KEYS[2], 3, "bob's new laptop", 1_794_060_171),
    ]
    .concat();
    assert_eq!(encoded(entries()), frame(&expected));
}

#[test]
fn a_malformed_entry_is_refused() {
    let good = raw_entry(KEYS[0], 2, "recovery key", 1);
    let bad_role = raw_entry(KEYS[0], 9, "recovery key", 1);
    let empty_label = raw_entry(KEYS[0], 2, "", 1);
    let not_a_key = raw_entry("age1nothing", 2, "x", 1);
    let out_of_range = raw_entry(KEYS[0], 2, "x", u64::MAX);
    let truncated = good[..good.len() - 1].to_vec();
    [bad_role, empty_label, not_a_key, out_of_range, truncated]
        .iter()
        .for_each(|entries| assert!(decoded(&frame(entries)).is_err()));
}
