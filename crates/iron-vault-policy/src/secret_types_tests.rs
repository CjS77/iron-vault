//! Compile-time and `Debug` checks for this crate's secret-bearing types (spec §3.11, `design/secret-handling.md`).
//!
//! A type that gains `Clone`, `Copy`, `Display` or a serde impl would start copying, printing or writing the secret it
//! holds; each assertion below turns that change into a build failure. A trait a type legitimately has is left out of
//! its assertion, with the reason beside it.

use std::fmt::Display;

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use static_assertions::assert_not_impl_any;

use crate::{CheckedRequest, HeaderName, HeaderValue, OutgoingHeaders, OutgoingRequest, SlotValue, UpstreamTarget};

assert_not_impl_any!(SlotValue: Clone, Copy, Display, Serialize, Deserialize<'static>);
assert_not_impl_any!(OutgoingRequest: Clone, Copy, Display, Serialize, Deserialize<'static>);
assert_not_impl_any!(CheckedRequest: Clone, Copy, Display, Serialize, Deserialize<'static>);

// `Clone` is derived on the three below and is not asserted: a clone is a second buffer with the same wipe-on-drop
// (`HeaderValue`'s `Drop`), so it adds a copy but never an unwiped one. Whether the derives can go is a separate
// ticket; no production code clones them today.
assert_not_impl_any!(HeaderValue: Copy, Display, Serialize, Deserialize<'static>);
assert_not_impl_any!(OutgoingHeaders: Copy, Display, Serialize, Deserialize<'static>);
// `UpstreamTarget` holds the filled query in a `url::Url`, which is never wiped: see the residual copies in
// `design/secret-handling.md`.
assert_not_impl_any!(UpstreamTarget: Copy, Display, Serialize, Deserialize<'static>);

/// Distinctive enough that a match in `Debug` output can only be the secret leaking.
const MARKER: &str = "MARKER-secret-5d1c9e";

/// Both `Debug` forms of `value`.
fn debug_forms(value: &impl std::fmt::Debug) -> [String; 2] {
    [format!("{value:?}"), format!("{value:#?}")]
}

fn assert_redacted(value: &impl std::fmt::Debug) {
    debug_forms(value).iter().for_each(|debug| assert!(!debug.contains(MARKER), "{debug}"));
}

#[test]
fn slot_value_debug_hides_the_secret() {
    assert_redacted(&SlotValue::new(SecretString::from(MARKER)).unwrap());
}

#[test]
fn header_value_debug_hides_the_secret() {
    assert_redacted(&HeaderValue::try_from(MARKER).unwrap());
}

#[test]
fn outgoing_headers_debug_hides_every_value() {
    let mut headers = OutgoingHeaders::new();
    headers.insert("Authorization".parse::<HeaderName>().unwrap(), HeaderValue::try_from(MARKER).unwrap()).unwrap();
    assert_redacted(&headers);
}
