//! The `static` kind: a stored provider key sent as is in a header or query slot (spec §5.2).

use iron_vault_policy::{AuthorizedRequest, Slot, SlotValue};
use secrecy::{ExposeSecret, SecretString};

use crate::resolve::{KindError, Resolution, slot_kind};
use crate::scrub::ScrubPatterns;

/// The kind's name in errors.
const KIND: &str = "static";

/// The key as the slot value, with its scrub patterns. A Basic slot needs a username and password, which a static
/// key does not have.
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
