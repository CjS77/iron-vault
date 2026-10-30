//! Compile-time and `Debug` checks for this crate's secret-bearing types (spec §3.11, `design/secret-handling.md`).
//!
//! A type that gains `Clone`, `Copy`, `Display` or a serde impl would start copying, printing or writing the secret it
//! holds; each assertion below turns that change into a build failure.

use std::fmt::{Debug, Display};

use serde::{Deserialize, Serialize};
use static_assertions::assert_not_impl_any;
use zeroize::Zeroizing;

use crate::admin::protocol::{Decoded, Frame, OwnerInput};

assert_not_impl_any!(OwnerInput: Clone, Copy, Display, Serialize, Deserialize<'static>);
assert_not_impl_any!(Frame: Clone, Copy, Display, Serialize, Deserialize<'static>);
assert_not_impl_any!(Decoded: Clone, Copy, Display, Serialize, Deserialize<'static>);

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
