//! The stable identity of one credential record (spec §1.3, §3.3).

use std::fmt;
use std::str::FromStr;

use thiserror::Error;
use uuid::{Uuid, Variant, Version};

/// A credential record's GUID: a random version 4 UUID, new on every add and every replace.
///
/// A replacement gets a fresh ID rather than reusing the name's old one, so the service can tell the record a grant was
/// approved against from one that took its name later (spec §3.3). Its text form is the lowercase hyphenated UUID, and
/// parsing accepts nothing else, so every record has exactly one spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordId(Uuid);

/// Text or bytes that are not a record ID. The ID is not secret, but the error carries no input either way.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RecordIdError {
    /// The text is not a UUID in lowercase hyphenated form.
    #[error("record ID is not a lowercase hyphenated UUID")]
    NotCanonical,
    /// The UUID is not a random (version 4, RFC 9562 variant) UUID, so the service did not generate it.
    #[error("record ID is not a random version 4 UUID")]
    NotVersion4,
}

impl RecordId {
    /// A fresh random ID for a newly added or replacing record.
    pub fn new_random() -> Self {
        Self(Uuid::new_v4())
    }

    /// The ID from its 16 raw bytes, as a record payload stores it.
    pub fn from_bytes(bytes: [u8; 16]) -> Result<Self, RecordIdError> {
        Self::checked(Uuid::from_bytes(bytes))
    }

    /// The ID's 16 raw bytes, in the order its text form shows them.
    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }

    fn checked(uuid: Uuid) -> Result<Self, RecordIdError> {
        match (uuid.get_version(), uuid.get_variant()) {
            (Some(Version::Random), Variant::RFC4122) => Ok(Self(uuid)),
            _ => Err(RecordIdError::NotVersion4),
        }
    }
}

impl FromStr for RecordId {
    type Err = RecordIdError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let uuid = Uuid::try_parse(text).map_err(|_| RecordIdError::NotCanonical)?;
        match uuid.hyphenated().to_string() == text {
            true => Self::checked(uuid),
            false => Err(RecordIdError::NotCanonical),
        }
    }
}

impl fmt::Display for RecordId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0.hyphenated(), f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "7c9e6679-7425-40de-944b-e07fc1f90ae7";

    #[test]
    fn random_ids_differ_and_round_trip_through_text_and_bytes() {
        let (a, b) = (RecordId::new_random(), RecordId::new_random());
        assert_ne!(a, b);
        assert_eq!(a.to_string().parse(), Ok(a));
        assert_eq!(RecordId::from_bytes(*a.as_bytes()), Ok(a));
    }

    #[test]
    fn display_is_lowercase_hyphenated() {
        let id: RecordId = ID.parse().unwrap();
        assert_eq!(id.to_string(), ID);
    }

    #[test]
    fn other_spellings_are_rejected() {
        [
            "7C9E6679-7425-40DE-944B-E07FC1F90AE7",
            "7c9e6679742540de944be07fc1f90ae7",
            "{7c9e6679-7425-40de-944b-e07fc1f90ae7}",
            "urn:uuid:7c9e6679-7425-40de-944b-e07fc1f90ae7",
            " 7c9e6679-7425-40de-944b-e07fc1f90ae7",
            "",
        ]
        .into_iter()
        .for_each(|text| assert_eq!(text.parse::<RecordId>(), Err(RecordIdError::NotCanonical), "{text:?}"));
    }

    #[test]
    fn non_random_uuids_are_rejected() {
        ["00000000-0000-0000-0000-000000000000", "7c9e6679-7425-10de-944b-e07fc1f90ae7", "7c9e6679-7425-40de-c44b-e07fc1f90ae7"]
            .into_iter()
            .for_each(|text| assert_eq!(text.parse::<RecordId>(), Err(RecordIdError::NotVersion4), "{text:?}"));
        assert_eq!(RecordId::from_bytes([0; 16]), Err(RecordIdError::NotVersion4));
    }
}
