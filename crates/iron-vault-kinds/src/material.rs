//! The decrypted secret fields a kind consumes (spec §3.3, §5.2).

use secrecy::SecretString;

/// The decrypted secret fields of one credential record, one variant per kind.
///
/// It is a closed enum so that adding a kind is a new variant every `match` in this crate must handle. The store maps
/// a decrypted record into it; this crate never reads records. `Debug` shows the variant only: every field is a
/// [`secrecy`] type whose own `Debug` is redacted.
#[derive(Debug)]
pub enum CredentialMaterial {
    /// A provider key sent as stored (`static`, spec §5.2).
    Static {
        /// The provider key.
        key: SecretString,
    },
    /// A username and password sent as HTTP Basic authorization (`basic`, spec §5.2).
    Basic {
        /// The user-id; non-empty and without `:` (RFC 7617 §2).
        username: SecretString,
        /// The password; may be empty.
        password: SecretString,
    },
}
