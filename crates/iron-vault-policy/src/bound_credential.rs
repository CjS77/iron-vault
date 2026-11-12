//! Pairs a slot value with the permitted origins of the credential record it came from, for the final
//! outgoing-request check
//! ([spec §6](../../../design/iron-vault-specification.md#6-credential-records-and-configuration),
//! [§9](../../../design/iron-vault-specification.md#9-url-header-and-slot-rules),
//! [future spec §2.2](../../../design/future-specifications.md#22-credential-kinds)).

use std::collections::BTreeSet;

use crate::host::Host;
use crate::port::Port;
use crate::slot_value::SlotValue;

/// A borrowed slot value and the permitted origins of the same credential record: the one credential input of
/// [`final_check`](crate::final_check()).
///
/// Destinations are bound to the record
/// ([§6](../../../design/iron-vault-specification.md#6-credential-records-and-configuration)), so the final check
/// must compare the upstream with the origins of the record whose secret it is sending. One value carrying both means
/// the caller hands over a single record's view, not two arguments that could come from different records. Get one
/// from the store's `CredentialRecord::resolve`, which borrows the value it resolved and that record's own origins.
/// This crate cannot see records, so [`BoundCredential::new`] stays public, and the pairing relies on callers using
/// the store's method.
///
/// It borrows a slot value, so it is a secret-bearing type. Like every such type it has no `Clone` or `Copy`, so the
/// view cannot outlive the one resolution it was taken from by being duplicated.
#[derive(Debug)]
pub struct BoundCredential<'a> {
    value: &'a SlotValue,
    permitted: &'a BTreeSet<(Host, Port)>,
}

impl<'a> BoundCredential<'a> {
    /// Pairs `value` with `permitted`, which must be the origins of the credential record `value` was resolved from.
    pub fn new(value: &'a SlotValue, permitted: &'a BTreeSet<(Host, Port)>) -> Self {
        Self { value, permitted }
    }

    /// The slot value the route's slot must hold.
    pub fn value(&self) -> &'a SlotValue {
        self.value
    }

    /// The exact host and port pairs the record lets its secret reach.
    pub fn permitted(&self) -> &'a BTreeSet<(Host, Port)> {
        self.permitted
    }
}
