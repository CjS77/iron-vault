//! A slot value bound to the permitted origins of the credential record it came from (spec §3.3, §3.6, §5.2).

use std::collections::BTreeSet;

use crate::host::Host;
use crate::port::Port;
use crate::slot_value::SlotValue;

/// A borrowed slot value and the permitted origins of the same credential record, the one credential input of
/// [`final_check`](crate::final_check).
///
/// Destinations are bound to the record (R-4), so the final check must compare the upstream with the origins of the
/// record whose secret it is sending. Taking both through one value lets the caller hand over a single record's view
/// rather than two arguments that could come from different records. The store's `CredentialRecord::resolve` is the
/// intended way to get one: it borrows the value it resolved and that record's own origins. This crate cannot see
/// records, so [`BoundCredential::new`] stays public and the pairing rests on callers using the store's method.
///
/// It borrows a slot value, so it is a secret-bearing type, and the register's rule that no such type has `Clone` or
/// `Copy` keeps the view from being duplicated beyond the one resolution it was taken from.
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
