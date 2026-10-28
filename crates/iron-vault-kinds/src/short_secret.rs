//! Short secrets: stored secret fields so short that they are probably a mistake (spec §3.8, §3.15, §5.2).
//!
//! A short value is allowed, since only the owner sets values, but it usually means the wrong field was pasted, and
//! response scrubbing blanks every occurrence of it, so a value of a few bytes mangles ordinary response text.

use std::fmt;

use secrecy::ExposeSecret;

use crate::CredentialMaterial;

/// Secret fields shorter than this many bytes are short secrets.
///
/// Eight bytes is below every provider-issued key and token format, so those never warn, yet long enough that a value
/// at or above it rarely occurs by chance in response text the scrubber would blank. A genuine human-chosen Basic
/// password of 6 or 7 characters still warns, rightly: scrubbing will blank it wherever it appears in a response.
pub const SHORT_SECRET_LEN: usize = 8;

/// The secret field of a credential a [`ShortSecret`] names. It never carries the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecretField {
    /// A static credential's key.
    Key,
    /// A Basic credential's username, the secret when the password is empty.
    Username,
    /// A Basic credential's password.
    Password,
}

impl fmt::Display for SecretField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SecretField::Key => "API key",
            SecretField::Username => "username",
            SecretField::Password => "password",
        })
    }
}

/// A secret field shorter than [`SHORT_SECRET_LEN`]: its name and length in bytes, never its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShortSecret {
    /// Which field is short.
    pub field: SecretField,
    /// The field's length in bytes.
    pub len: usize,
}

impl CredentialMaterial {
    /// The secret fields shorter than [`SHORT_SECRET_LEN`], so the store can warn the owner about them.
    ///
    /// A Basic username counts only when the password is empty: then the username is the secret the scrubber watches.
    /// It returns a `Vec` because later kinds may hold several secrets.
    pub fn short_secrets(&self) -> Vec<ShortSecret> {
        let secret = match self {
            CredentialMaterial::Static { key } => (SecretField::Key, key.expose_secret().len()),
            CredentialMaterial::Basic { username, password } => match password.expose_secret().len() {
                0 => (SecretField::Username, username.expose_secret().len()),
                len => (SecretField::Password, len),
            },
        };
        Some(secret)
            .filter(|(_, len)| *len < SHORT_SECRET_LEN)
            .map(|(field, len)| ShortSecret { field, len })
            .into_iter()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(material: &CredentialMaterial) -> Vec<SecretField> {
        material.short_secrets().iter().map(|short| short.field).collect()
    }

    fn basic(username: &str, password: &str) -> CredentialMaterial {
        CredentialMaterial::Basic {
            username: username.into(),
            password: password.into(),
        }
    }

    #[test]
    fn a_short_static_key_is_reported_with_its_length() {
        let material = CredentialMaterial::Static { key: "abc".into() };
        assert_eq!(
            material.short_secrets(),
            [ShortSecret {
                field: SecretField::Key,
                len: 3
            }]
        );
    }

    #[test]
    fn an_eight_byte_static_key_is_not_short() {
        assert_eq!(fields(&CredentialMaterial::Static { key: "abcdefgh".into() }), []);
    }

    #[test]
    fn basic_reports_the_password_or_else_the_username() {
        assert_eq!(fields(&basic("long-username", "pw")), [SecretField::Password]);
        assert_eq!(fields(&basic("u", "long-password")), []);
        assert_eq!(fields(&basic("usr", "")), [SecretField::Username]);
        assert_eq!(fields(&basic("long-username", "")), []);
    }
}
