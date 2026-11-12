//! The `static` kind: sends a stored provider key, unchanged, in a `header` or `query` slot
//! ([future spec §2.2](../../../design/future-specifications.md#22-credential-kinds)).
//!
//! For example, the key `sk-123` on a route whose slot is `{ header = "Authorization", format = "Bearer {}" }` becomes
//! `Authorization: Bearer sk-123`. This module returns only `sk-123`; slot filling in `iron-vault-policy` applies the
//! format.

use iron_vault_policy::{AuthorizedRequest, Slot, SlotValue};
use secrecy::{ExposeSecret, SecretString};

use crate::resolve::{KindError, Resolution, slot_kind};
use crate::scrub::ScrubPatterns;

/// The kind's name in errors.
const KIND: &str = "static";

/// Returns the stored key as the slot value, with its scrub patterns.
///
/// Fails with [`KindError::SlotMismatch`] for a `basic` slot, which needs a username and password that a `static` key
/// does not have.
pub(crate) fn resolve(key: &SecretString, slot: &Slot, _request: &AuthorizedRequest) -> Result<Resolution, KindError> {
    if matches!(slot, Slot::Basic) {
        return Err(KindError::SlotMismatch {
            kind: KIND,
            slot: slot_kind(slot),
        });
    }
    let value = SlotValue::new(SecretString::from(key.expose_secret()))?;
    let mut patterns = ScrubPatterns::default();
    patterns.insert_encodings(value.expose_secret());
    Ok(Resolution::new(value, patterns))
}
