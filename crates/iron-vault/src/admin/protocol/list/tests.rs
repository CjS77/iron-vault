use proptest::prelude::*;

use super::super::{Decoded, Frame, FrameKind, put_frame};
use super::*;
use iron_vault_store::RecordDamage;

fn response_frame(entries: &[u8], open: u8) -> Vec<u8> {
    let mut body = Vec::new();
    fields::put(&mut body, TAG_COMMAND, &9u16.to_be_bytes());
    fields::put(&mut body, TAG_OPEN, &[open]);
    fields::put(&mut body, TAG_ENTRIES, entries);
    let mut out = Vec::new();
    put_frame(&mut out, FrameKind::Success, &body).unwrap();
    out
}

fn decoded(bytes: &[u8]) -> Result<AdminResponse, FrameError> {
    match super::super::decode(bytes)? {
        Decoded::Frame {
            frame: Frame::Response(response),
            ..
        } => Ok(response),
        other => panic!("expected a response, got {other:?}"),
    }
}

/// The list a decoded response carries. `AdminResponse` has no `PartialEq`, since it can hold a caller token.
fn listed(response: AdminResponse) -> Option<Vec<CredentialStanding>> {
    match response {
        AdminResponse::List { credentials } => credentials,
        other => panic!("expected a list, got {other:?}"),
    }
}

fn encoded(credentials: Option<Vec<CredentialStanding>>) -> Result<Vec<u8>, FrameError> {
    let mut out = Vec::new();
    super::super::encode(&Frame::Response(AdminResponse::List { credentials }), &mut out).map(|()| out)
}

fn entry(name: &str, standing: Standing, summary: Option<RecordSummary>) -> CredentialStanding {
    CredentialStanding {
        name: name.parse().unwrap(),
        standing,
        unavailable_routes: Vec::new(),
        summary,
    }
}

fn healthy_entry(name: &str, kind: CredentialKind, origins: &[(&str, u16)]) -> CredentialStanding {
    let origins = origins
        .iter()
        .map(|(host, port)| (host.parse().unwrap(), Port::try_from(*port).unwrap()))
        .collect();
    entry(name, Standing::Healthy, Some(RecordSummary { kind, origins }))
}

fn arbitrary_entry() -> impl Strategy<Value = CredentialStanding> {
    let name = "[a-z][a-z0-9_-]{0,63}";
    let kind = prop_oneof![Just(CredentialKind::Static), Just(CredentialKind::Basic)];
    let host = prop_oneof![
        "[a-z][a-z0-9]{0,20}\\.example",
        Just("[::1]".to_owned()),
        Just("203.0.113.7".to_owned())
    ];
    let origins = prop::collection::vec((host, 1u16..), 1..4);
    let damage = prop_oneof![
        Just(RecordDamage::Missing),
        Just(RecordDamage::Substituted),
        Just(RecordDamage::Unreadable)
    ];
    prop_oneof![
        (name, kind, origins).prop_map(|(name, kind, origins)| {
            let origins = origins.iter().map(|(host, port)| (host.as_str(), *port)).collect::<Vec<_>>();
            healthy_entry(&name, kind, &origins)
        }),
        (name, damage).prop_map(|(name, damage)| entry(&name, Standing::Damaged(damage), None)),
    ]
}

proptest! {
    #[test]
    fn a_list_round_trips(credentials in prop::option::of(prop::collection::vec(arbitrary_entry(), 0..5))) {
        let bytes = encoded(credentials.clone()).unwrap();
        prop_assert_eq!(listed(decoded(&bytes).unwrap()), credentials);
    }
}

#[test]
fn a_name_of_length_zero_or_sixty_five_is_refused() {
    for len in [0usize, 65] {
        let mut entries = vec![u8::try_from(len).unwrap()];
        entries.extend(std::iter::repeat_n(b'a', len));
        entries.extend([1, 1, 1, 1, b'h', 0x01, 0xbb]);
        assert_eq!(decoded(&response_frame(&entries, 1)).err(), Some(INVALID_ENTRIES), "length {len}");
    }
}

#[test]
fn origins_with_an_unknown_kind_are_refused() {
    let entries = [1, b'a', 1, 0, 1, 1, b'h', 0x01, 0xbb];
    assert_eq!(decoded(&response_frame(&entries, 1)).err(), Some(INVALID_ENTRIES));
}

#[test]
fn a_healthy_entry_without_kind_or_origins_and_a_damaged_one_with_them_are_refused() {
    let healthy_unknown = [1, b'a', 0, 0, 0];
    let damaged_known = [1, b'a', 1, 1, 1, 1, b'h', 0x01, 0xbb];
    for entries in [&healthy_unknown[..], &damaged_known[..]] {
        assert_eq!(decoded(&response_frame(entries, 1)).err(), Some(INVALID_ENTRIES));
    }
}

#[test]
fn entries_without_an_open_vault_and_a_truncated_entry_are_refused() {
    let one = [1, b'a', 1, 1, 1, 1, b'h', 0x01, 0xbb];
    assert_eq!(decoded(&response_frame(&one, 0)).err(), Some(INVALID_ENTRIES));
    assert_eq!(decoded(&response_frame(&one[..8], 1)).err(), Some(INVALID_ENTRIES));
}

#[test]
fn a_closed_vault_has_the_flag_clear_and_no_entries() {
    assert_eq!(listed(decoded(&response_frame(&[], 0)).unwrap()), None);
    assert_eq!(listed(decoded(&response_frame(&[], 1)).unwrap()), Some(Vec::new()));
}

#[test]
fn a_list_too_long_for_one_frame_is_refused_never_truncated() {
    let one = healthy_entry("a", CredentialKind::Static, &[("h.example", 443)]);
    let credentials = vec![one; 10_000];
    assert_eq!(encoded(Some(credentials)), Err(FrameError::BodyTooLong));
}

#[test]
fn a_healthy_entry_without_its_summary_is_not_encoded() {
    assert_eq!(encoded(Some(vec![entry("a", Standing::Healthy, None)])), Err(INVALID_ENTRIES));
}
