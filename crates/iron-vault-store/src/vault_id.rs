//! The stable identity of one vault (spec §3.10).

use std::fmt;

use thiserror::Error;
use uuid::{Uuid, Variant, Version};

/// A vault's GUID: a random version 4 UUID generated once, with the vault.
///
/// The vault manifest carries it in clear and inside its encrypted payload, and its MAC covers it, so a manifest copied
/// from another vault is refused. Its text form is the lowercase hyphenated UUID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VaultId(Uuid);

/// Bytes that are not a vault ID. The ID is not secret, but the error carries no input either way.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum VaultIdError {
    /// The UUID is not a random (version 4, RFC 9562 variant) UUID, so the service did not generate it.
    #[error("vault ID is not a random version 4 UUID")]
    NotVersion4,
}

impl VaultId {
    /// A fresh random ID for a newly created vault.
    pub fn new_random() -> Self {
        Self(Uuid::new_v4())
    }

    /// The ID from its 16 raw bytes, as the manifest stores it.
    pub fn from_bytes(bytes: [u8; 16]) -> Result<Self, VaultIdError> {
        let uuid = Uuid::from_bytes(bytes);
        match (uuid.get_version(), uuid.get_variant()) {
            (Some(Version::Random), Variant::RFC4122) => Ok(Self(uuid)),
            _ => Err(VaultIdError::NotVersion4),
        }
    }

    /// The ID's 16 raw bytes, in the order its text form shows them.
    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

impl fmt::Display for VaultId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0.hyphenated(), f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_ids_differ_and_round_trip_through_bytes() {
        let (a, b) = (VaultId::new_random(), VaultId::new_random());
        assert_ne!(a, b);
        assert_eq!(VaultId::from_bytes(*a.as_bytes()), Ok(a));
    }

    #[test]
    fn display_is_lowercase_hyphenated() {
        let bytes = *Uuid::parse_str("7c9e6679-7425-40de-944b-e07fc1f90ae7").unwrap().as_bytes();
        assert_eq!(VaultId::from_bytes(bytes).unwrap().to_string(), "7c9e6679-7425-40de-944b-e07fc1f90ae7");
    }

    #[test]
    fn non_random_uuids_are_rejected() {
        ["00000000-0000-0000-0000-000000000000", "7c9e6679-7425-10de-944b-e07fc1f90ae7", "7c9e6679-7425-40de-c44b-e07fc1f90ae7"]
            .into_iter()
            .map(|text| *Uuid::parse_str(text).unwrap().as_bytes())
            .for_each(|bytes| assert_eq!(VaultId::from_bytes(bytes), Err(VaultIdError::NotVersion4)));
    }
}
