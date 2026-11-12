//! Compile-time and `Debug` checks for this crate's secret-bearing types ([spec §14][s14], [inventory][inv]).
//!
//! A type that gains `Clone`, `Copy`, `Display` or a serde impl would start copying, printing or writing the secret it
//! holds; each assertion below turns that change into a build failure.
//!
//! [s14]: ../../../design/iron-vault-specification.md#14-recipients-startup-and-memory
//! [inv]: ../../../design/secret-handling.md#inventory

use std::fmt::{Debug, Display};

use serde::{Deserialize, Serialize};
use static_assertions::{assert_impl_all, assert_not_impl_any};
use zeroize::Zeroizing;

use crate::admin::protocol::{AdminResponse, Decoded, Frame, OwnerInput, RevealedSecret};
use crate::pipeline::{Prepared, RequestHead};
use crate::serving_snapshot::{ServingSnapshot, SnapshotHolder};
use iron_vault_policy::CallerToken;

assert_not_impl_any!(OwnerInput: Clone, Copy, Display, Serialize, Deserialize<'static>);
assert_not_impl_any!(RevealedSecret: Clone, Copy, Display, Serialize, Deserialize<'static>);
assert_not_impl_any!(AdminResponse: Clone, Copy, PartialEq, Display, Serialize, Deserialize<'static>);
assert_not_impl_any!(Frame: Clone, Copy, Display, Serialize, Deserialize<'static>);
assert_not_impl_any!(Decoded: Clone, Copy, Display, Serialize, Deserialize<'static>);
assert_not_impl_any!(ServingSnapshot: Clone, Copy, Display, Serialize, Deserialize<'static>);
assert_impl_all!(ServingSnapshot: Send, Sync);
assert_not_impl_any!(RequestHead: Clone, Copy, Display, Serialize, Deserialize<'static>);
assert_not_impl_any!(Prepared: Clone, Copy, Display, Serialize, Deserialize<'static>);
assert_not_impl_any!(SnapshotHolder: Clone, Copy, Display, Serialize, Deserialize<'static>);
assert_not_impl_any!(crate::scrub::Scrubber<'static>: Clone, Copy, Display, Serialize, Deserialize<'static>);
assert_not_impl_any!(crate::content_coding::ResponseDecoder: Clone, Copy, Display, Serialize, Deserialize<'static>);
#[cfg(target_os = "linux")]
assert_not_impl_any!(crate::listener_tls::ListenerTls: Clone, Copy, Display, Serialize, Deserialize<'static>);
#[cfg(target_os = "linux")]
assert_not_impl_any!(crate::proxy_handler::ResponseContext: Clone, Copy, Debug, Display, Serialize, Deserialize<'static>);
#[cfg(target_os = "linux")]
assert_not_impl_any!(crate::proxy_handler::RelayedBody: Clone, Copy, Debug, Display, Serialize, Deserialize<'static>);

/// Distinctive enough that a match in `Debug` output can only be the secret leaking.
pub(crate) const MARKER: &str = "MARKER-secret-5d1c9e";

/// Asserts that neither `Debug` form of `value` contains the marker, nor any of its bytes as a decimal byte list.
pub(crate) fn assert_hides_marker(value: &impl Debug) {
    let as_byte_list = format!("{:?}", MARKER.as_bytes());
    let inner = as_byte_list.trim_start_matches('[').trim_end_matches(']');
    [format!("{value:?}"), format!("{value:#?}")].iter().for_each(|debug| {
        assert!(!debug.contains(MARKER), "{debug}");
        assert!(!debug.replace(char::is_whitespace, "").contains(&inner.replace(' ', "")), "{debug}");
    });
}

fn owner_input() -> OwnerInput {
    OwnerInput::new(Zeroizing::new(MARKER.as_bytes().to_vec()))
}

#[test]
fn owner_input_debug_hides_the_value() {
    assert_hides_marker(&owner_input());
}

#[test]
fn frames_holding_owner_input_hide_the_value() {
    assert_hides_marker(&Frame::OwnerInput(owner_input()));
    assert_hides_marker(&Decoded::Frame {
        frame: Frame::OwnerInput(owner_input()),
        used: 0,
    });
}

fn revealed_secret() -> RevealedSecret {
    RevealedSecret::new(Zeroizing::new(MARKER.as_bytes().to_vec()))
}

#[test]
fn revealed_secret_debug_hides_the_value() {
    assert_hides_marker(&revealed_secret());
}

#[test]
fn frames_holding_a_revealed_secret_hide_the_value() {
    assert_hides_marker(&Frame::Reveal(revealed_secret()));
    assert_hides_marker(&Decoded::Frame {
        frame: Frame::Reveal(revealed_secret()),
        used: 0,
    });
}

/// A caller token whose text holds the marker: `ivt_`, the marker with its `-` kept and padded with `A` to 43
/// base64url characters, which end canonically in `A`.
fn marker_token() -> CallerToken {
    let body = format!("{MARKER:A<43}");
    CallerToken::parse(format!("ivt_{body}").as_bytes()).unwrap()
}

#[test]
fn a_caller_token_response_hides_the_token() {
    assert_hides_marker(&AdminResponse::CallerToken { token: marker_token() });
    assert_hides_marker(&Frame::Response(AdminResponse::CallerToken { token: marker_token() }));
}

#[test]
fn scrubber_debug_hides_its_patterns_and_held_bytes() {
    let mut scrubber = crate::scrub::Scrubber::with_patterns([MARKER.as_bytes()]);
    let released = scrubber.push(&MARKER.as_bytes()[..MARKER.len() - 1]);
    assert!(released.is_empty());
    assert_hides_marker(&scrubber);
}

#[test]
fn response_decoder_debug_hides_the_plaintext_in_its_window() {
    use std::io::Write;

    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(MARKER.as_bytes()).unwrap();
    let body = encoder.finish().unwrap();
    let mut decoder = crate::content_coding::ResponseDecoder::new(crate::content_coding::ContentCoding::Gzip);
    let decoded: Vec<u8> = decoder.push(&body).flat_map(|piece| piece.unwrap()).collect();
    assert_eq!(decoded, MARKER.as_bytes());
    assert_hides_marker(&decoder);
}
