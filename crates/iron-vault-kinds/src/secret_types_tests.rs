//! Compile-time and `Debug` checks for this crate's secret-bearing types (spec §3.11, `design/secret-handling.md`).
//!
//! A type that gains `Clone`, `Copy`, `Display` or a serde impl would start copying, printing or writing the secret it
//! holds; each assertion below turns that change into a build failure.

use std::fmt::{Debug, Display};

use iron_vault_policy::SlotValue;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use static_assertions::assert_not_impl_any;

use crate::{CredentialMaterial, Resolution, ScrubPatterns};

assert_not_impl_any!(CredentialMaterial: Clone, Copy, Display, Serialize, Deserialize<'static>);
assert_not_impl_any!(ScrubPatterns: Clone, Copy, Display, Serialize, Deserialize<'static>);
assert_not_impl_any!(Resolution: Clone, Copy, Display, Serialize, Deserialize<'static>);

/// Distinctive enough that a match in `Debug` output can only be the secret leaking.
const MARKER: &str = "MARKER-secret-5d1c9e";

fn assert_redacted(value: &impl Debug) {
    [format!("{value:?}"), format!("{value:#?}")]
        .iter()
        .for_each(|debug| assert!(!debug.contains(MARKER), "{debug}"));
}

fn patterns() -> ScrubPatterns {
    let mut patterns = ScrubPatterns::default();
    patterns.insert_encodings(MARKER);
    patterns
}

#[test]
fn credential_material_debug_hides_every_field() {
    assert_redacted(&CredentialMaterial::Static {
        key: SecretString::from(MARKER),
    });
    assert_redacted(&CredentialMaterial::Basic {
        username: SecretString::from(MARKER),
        password: SecretString::from(MARKER),
    });
}

#[test]
fn scrub_patterns_debug_hides_every_pattern() {
    assert_redacted(&patterns());
}

#[test]
fn resolution_debug_hides_the_value_and_patterns() {
    assert_redacted(&Resolution::new(SlotValue::new(SecretString::from(MARKER)).unwrap(), patterns()));
}
