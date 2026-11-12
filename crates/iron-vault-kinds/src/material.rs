//! Credential material: the decrypted secret fields of one credential record, in the shape its kind consumes
//! ([spec §6](../../../design/iron-vault-specification.md#6-credential-records-and-configuration),
//! [future spec §2.2](../../../design/future-specifications.md#22-credential-kinds)).
//!
//! The store decrypts a record and builds the material; the kinds in this crate only read it. A kind never sees a file
//! format, and the store never needs to know how a kind uses a field.

use iron_vault_policy::SlotValue;
use secrecy::{ExposeSecret, SecretString};

use crate::basic_kind;
use crate::resolve::KindError;

/// The decrypted secret fields of one credential record, one variant per kind.
///
/// It is a closed enum, so a new kind is a new variant that every `match` in this crate must handle. The store maps a
/// decrypted record into it. `Debug` shows the variant only: every field is a [`secrecy`] type whose own `Debug` is
/// redacted.
#[derive(Debug)]
pub enum CredentialMaterial {
    /// A provider key sent as stored: the `static` kind.
    Static {
        /// The provider key.
        key: SecretString,
    },
    /// A username and password sent as HTTP `Basic` authorization: the `basic` kind.
    Basic {
        /// The username: non-empty and without `:` ([RFC 7617 §2](https://www.rfc-editor.org/rfc/rfc7617#section-2)).
        username: SecretString,
        /// The password; may be empty.
        password: SecretString,
    },
}

impl CredentialMaterial {
    /// Checks the material against its kind's rules, the same ones [`resolve`](crate::resolve()) applies.
    ///
    /// The store calls this when it reads a record, so a record that could never fill a slot fails when it is read,
    /// not on its first request.
    pub fn validate(&self) -> Result<(), KindError> {
        match self {
            CredentialMaterial::Static { key } => Ok(SlotValue::validate(key.expose_secret())?),
            CredentialMaterial::Basic { username, password } => {
                Ok(basic_kind::validate(username.expose_secret(), password.expose_secret())?)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use iron_vault_policy::SlotValueError;

    use super::*;
    use crate::BasicCredentialError;

    fn basic(username: &str, password: &str) -> CredentialMaterial {
        CredentialMaterial::Basic {
            username: username.into(),
            password: password.into(),
        }
    }

    #[test]
    fn static_keys_follow_the_slot_value_rules() {
        assert_eq!(CredentialMaterial::Static { key: "k".into() }.validate(), Ok(()));
        assert_eq!(
            CredentialMaterial::Static { key: "".into() }.validate(),
            Err(KindError::InvalidValue(SlotValueError::Empty))
        );
        assert_eq!(
            CredentialMaterial::Static { key: "a\nb".into() }.validate(),
            Err(KindError::InvalidValue(SlotValueError::ControlChar))
        );
    }

    #[test]
    fn basic_credentials_follow_rfc_7617() {
        assert_eq!(basic("u", "").validate(), Ok(()));
        assert_eq!(
            basic("u:v", "p").validate(),
            Err(KindError::InvalidBasic(BasicCredentialError::ColonInUsername))
        );
        assert_eq!(
            basic("", "p").validate(),
            Err(KindError::InvalidBasic(BasicCredentialError::EmptyUsername))
        );
    }
}
