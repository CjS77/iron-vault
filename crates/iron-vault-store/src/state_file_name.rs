//! The name of one file in the state directory.

use std::fmt;

use crate::record_id::RecordId;

/// Name of the lock file, which no store write may touch in any letter case.
const LOCK_NAME: &str = "lock";

/// One flat file name inside the state directory, valid on construction.
///
/// Store files sit directly in the state directory, so a durable write only ever fsyncs that one directory. A name
/// never starts with `.`, which keeps it distinct from every temporary name, and is never `lock` in any letter case:
/// on a case-insensitive filesystem `LOCK` names the held lock file, and replacing it would break the single writer.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StateFileName(String);

/// Why a string is not a valid state file name.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StateFileNameError {
    /// The name is empty.
    #[error("state file name is empty")]
    Empty,
    /// The name has a character outside ASCII `[A-Za-z0-9._-]`, such as a path separator.
    #[error("state file name {0:?} may contain only ASCII letters, digits, '.', '_' and '-'")]
    BadCharacter(String),
    /// The name starts with `.`, which temporary names use.
    #[error("state file name {0:?} must not start with '.'")]
    LeadingDot(String),
    /// The name is the state-directory lock file in some letter case.
    #[error("state file name must not be {LOCK_NAME:?} in any letter case")]
    Lock,
}

impl StateFileName {
    /// Validates `name` as a flat state file name.
    pub fn new(name: &str) -> Result<Self, StateFileNameError> {
        match name {
            "" => Err(StateFileNameError::Empty),
            _ if name.eq_ignore_ascii_case(LOCK_NAME) => Err(StateFileNameError::Lock),
            _ if !name.bytes().all(is_name_byte) => Err(StateFileNameError::BadCharacter(name.to_owned())),
            _ if name.starts_with('.') => Err(StateFileNameError::LeadingDot(name.to_owned())),
            _ => Ok(Self(name.to_owned())),
        }
    }

    /// The identity envelope's file, `identity.age`.
    pub fn identity_envelope() -> Self {
        Self("identity.age".to_owned())
    }

    /// The passphrase envelope's file, `operational.age`.
    pub fn passphrase_envelope() -> Self {
        Self("operational.age".to_owned())
    }

    /// The vault manifest's file, `manifest.age`.
    pub fn manifest() -> Self {
        Self("manifest.age".to_owned())
    }

    /// The approval state's file, `approval.age`.
    pub fn approval_state() -> Self {
        Self("approval.age".to_owned())
    }

    /// The approver key envelope's file, `approver.age`.
    pub fn approver_key() -> Self {
        Self("approver.age".to_owned())
    }

    /// The file of the credential record with ID `id`: `record-<id>.age`. A record ID's text uses only `[0-9a-f-]`, so
    /// the name always passes [`StateFileName::new`].
    pub fn record(id: &RecordId) -> Self {
        Self(format!("record-{id}.age"))
    }

    /// The name as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The temporary name a durable replace of this file writes first: `.<name>.tmp`.
    pub(crate) fn temp_name(&self) -> String {
        format!(".{}.tmp", self.0)
    }

    /// The state file whose temporary name is exactly `temp`, if `temp` is one [`StateFileName::temp_name`] can
    /// produce. Any other name, including every other dotfile, gives `None`, so nothing else is taken for a temp file.
    pub(crate) fn from_temp_name(temp: &str) -> Option<Self> {
        let name = Self::new(temp.strip_prefix('.')?.strip_suffix(".tmp")?).ok()?;
        (name.temp_name() == temp).then_some(name)
    }
}

impl fmt::Display for StateFileName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn is_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_flat_ascii_names() {
        ["identity.age", "manifest", "rec-01_a.age", "a..b"].iter().for_each(|n| {
            assert_eq!(StateFileName::new(n).unwrap().as_str(), *n);
        });
    }

    #[test]
    fn rejects_empty() {
        assert_eq!(StateFileName::new(""), Err(StateFileNameError::Empty));
    }

    #[test]
    fn rejects_paths_and_non_ascii() {
        ["../x", "a/b", "a\\b", "café", "a b", "a\0b", ".."].iter().for_each(|n| {
            assert!(StateFileName::new(n).is_err(), "{n:?} accepted");
        });
        assert!(matches!(StateFileName::new("../x"), Err(StateFileNameError::BadCharacter(_))));
        assert!(matches!(StateFileName::new("café"), Err(StateFileNameError::BadCharacter(_))));
    }

    #[test]
    fn rejects_leading_dot() {
        assert!(matches!(StateFileName::new(".hidden"), Err(StateFileNameError::LeadingDot(_))));
    }

    #[test]
    fn rejects_lock() {
        ["lock", "LOCK", "Lock"]
            .iter()
            .for_each(|n| assert_eq!(StateFileName::new(n), Err(StateFileNameError::Lock)));
        assert!(StateFileName::new("lock2").is_ok());
    }

    #[test]
    fn fixed_and_record_names_are_valid_state_file_names() {
        assert_eq!(StateFileName::new("manifest.age"), Ok(StateFileName::manifest()));
        assert_eq!(StateFileName::new("identity.age"), Ok(StateFileName::identity_envelope()));
        assert_eq!(StateFileName::new("operational.age"), Ok(StateFileName::passphrase_envelope()));
        assert_eq!(StateFileName::new("approval.age"), Ok(StateFileName::approval_state()));
        assert_eq!(StateFileName::new("approver.age"), Ok(StateFileName::approver_key()));
        let id: RecordId = "7c9e6679-7425-40de-944b-e07fc1f90ae7".parse().unwrap();
        assert_eq!(
            StateFileName::record(&id).as_str(),
            "record-7c9e6679-7425-40de-944b-e07fc1f90ae7.age"
        );
        (0..32).map(|_| StateFileName::record(&RecordId::new_random())).for_each(|name| {
            assert_eq!(StateFileName::new(name.as_str()).as_ref(), Ok(&name));
        });
    }

    #[test]
    fn temp_name_is_hidden_and_never_a_state_file_name() {
        let temp = StateFileName::new("vault").unwrap().temp_name();
        assert_eq!(temp, ".vault.tmp");
        assert!(StateFileName::new(&temp).is_err());
    }

    #[test]
    fn from_temp_name_inverts_temp_name() {
        ["vault", "a.tmp", "rec-01_a.age"].iter().for_each(|n| {
            let name = StateFileName::new(n).unwrap();
            assert_eq!(StateFileName::from_temp_name(&name.temp_name()), Some(name));
        });
    }

    #[test]
    fn from_temp_name_rejects_everything_else() {
        [
            ".tmp",
            "..tmp",
            "...tmp",
            ".lock.tmp",
            ".LOCK.tmp",
            ".a/b.tmp",
            "a.tmp",
            ".a.tmp~",
            ".a.TMP",
            ".hidden",
            ". .tmp",
            "",
        ]
        .iter()
        .for_each(|n| assert_eq!(StateFileName::from_temp_name(n), None, "{n:?}"));
    }
}
