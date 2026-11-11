//! The name of one file in the state directory.

use std::fmt;

use uuid::Uuid;

use crate::ApproverId;
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

    /// The recipient inventory's file, `recipients.age`.
    pub fn recipient_inventory() -> Self {
        Self("recipients.age".to_owned())
    }

    /// The staged inventory's file, `recipients.age.staged`: the inventory a recipient change writes before the identity
    /// envelope, so a change interrupted after its commit point can be finished from it.
    pub fn staged_recipient_inventory() -> Self {
        Self("recipients.age.staged".to_owned())
    }

    /// The approver key envelope's file for the software approver `id`: `approver-<id>.age`, the ID in lowercase
    /// hyphenated form. Its text uses only `[0-9a-f-]`, so the name always passes [`StateFileName::new`].
    pub fn approver_key(id: ApproverId) -> Self {
        Self(format!("approver-{id}.age"))
    }

    /// The approver ID `name` is the approver key envelope of, if it is exactly [`StateFileName::approver_key`] of a
    /// version 4 UUID. Any other spelling of an ID, such as upper case, names no approver key.
    pub(crate) fn approver_key_id(name: &str) -> Option<ApproverId> {
        approver_file_id(name, ".age", Self::approver_key)
    }

    /// The TPM key blob's file for the TPM approver `id`: `approver-<id>.tpm`, the ID in lowercase hyphenated form, beside
    /// the software approvers' `approver-<id>.age`.
    pub fn tpm_key_blob(id: ApproverId) -> Self {
        Self(format!("approver-{id}.tpm"))
    }

    /// The approver ID `name` is the TPM key blob of, if it is exactly [`StateFileName::tpm_key_blob`] of a version 4
    /// UUID. Any other spelling of an ID names no key blob.
    pub(crate) fn tpm_key_blob_id(name: &str) -> Option<ApproverId> {
        approver_file_id(name, ".tpm", Self::tpm_key_blob)
    }

    /// The empty file `init.unfinished`, which marks a vault initialization that has not finished.
    pub fn unfinished_initialization() -> Self {
        Self("init.unfinished".to_owned())
    }

    /// The empty file `reset.unfinished`, which marks a reset past its commit point that has not finished.
    pub fn unfinished_reset() -> Self {
        Self("reset.unfinished".to_owned())
    }

    /// The owner-lock file, `locked-by-owner`: empty, and while anything is at this name a starting service skips host
    /// unlock. `lock` writes it and a passphrase `unlock` removes it.
    pub fn owner_lock() -> Self {
        Self("locked-by-owner".to_owned())
    }

    /// The recovery check record's file, `recovery.toml`.
    pub fn recovery_check_record() -> Self {
        Self("recovery.toml".to_owned())
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
    pub fn temp_name(&self) -> String {
        crate::durable::temp_name(&self.0)
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

/// The approver ID in `name`, if `name` is exactly `file` of it: `approver-`, the ID, then `suffix`. Comparing with the
/// name `file` builds refuses every other spelling of the same ID.
fn approver_file_id(name: &str, suffix: &str, file: fn(ApproverId) -> StateFileName) -> Option<ApproverId> {
    let uuid = Uuid::try_parse(name.strip_prefix("approver-")?.strip_suffix(suffix)?).ok()?;
    let id = ApproverId::from_bytes(uuid.into_bytes()).ok()?;
    (file(id).as_str() == name).then_some(id)
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
        assert_eq!(StateFileName::new("recipients.age"), Ok(StateFileName::recipient_inventory()));
        assert_eq!(
            StateFileName::new("recipients.age.staged"),
            Ok(StateFileName::staged_recipient_inventory())
        );
        assert_eq!(
            StateFileName::new("init.unfinished"),
            Ok(StateFileName::unfinished_initialization())
        );
        assert_eq!(StateFileName::new("reset.unfinished"), Ok(StateFileName::unfinished_reset()));
        assert_eq!(StateFileName::new("locked-by-owner"), Ok(StateFileName::owner_lock()));
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
    fn approver_key_names_carry_the_lowercase_hyphenated_id() {
        let id = ApproverId::from_bytes(*Uuid::parse_str("8d1c6f0e-2b7a-4c59-9e3d-5a4b3c2d1e0f").unwrap().as_bytes()).unwrap();
        let name = StateFileName::approver_key(id);
        assert_eq!(name.as_str(), "approver-8d1c6f0e-2b7a-4c59-9e3d-5a4b3c2d1e0f.age");
        assert_eq!(StateFileName::new(name.as_str()).as_ref(), Ok(&name));
        assert_eq!(StateFileName::approver_key_id(name.as_str()), Some(id));
        assert_eq!(StateFileName::tpm_key_blob_id(name.as_str()), None);
    }

    #[test]
    fn tpm_key_blob_names_carry_the_lowercase_hyphenated_id() {
        let id = ApproverId::from_bytes(*Uuid::parse_str("5b0e9a1c-7d2f-4e83-b6a4-0c1d2e3f4a5b").unwrap().as_bytes()).unwrap();
        let name = StateFileName::tpm_key_blob(id);
        assert_eq!(name.as_str(), "approver-5b0e9a1c-7d2f-4e83-b6a4-0c1d2e3f4a5b.tpm");
        assert_eq!(StateFileName::new(name.as_str()).as_ref(), Ok(&name));
        assert_eq!(StateFileName::tpm_key_blob_id(name.as_str()), Some(id));
        assert_eq!(StateFileName::approver_key_id(name.as_str()), None);
        [
            "approver-.tpm",
            "approver-5B0E9A1C-7D2F-4E83-B6A4-0C1D2E3F4A5B.tpm",
            "approver-5b0e9a1c7d2f4e83b6a40c1d2e3f4a5b.tpm",
            "approver-5b0e9a1c-7d2f-1e83-b6a4-0c1d2e3f4a5b.tpm",
            "approver-5b0e9a1c-7d2f-4e83-b6a4-0c1d2e3f4a5b.tpm.tmp",
            "approver-5b0e9a1c-7d2f-4e83-b6a4-0c1d2e3f4a5b.age",
        ]
        .iter()
        .for_each(|n| assert_eq!(StateFileName::tpm_key_blob_id(n), None, "{n:?}"));
    }

    #[test]
    fn approver_key_id_rejects_other_names() {
        [
            "approver.age",
            "approver-.age",
            "approver-8D1C6F0E-2B7A-4C59-9E3D-5A4B3C2D1E0F.age",
            "approver-8d1c6f0e2b7a4c599e3d5a4b3c2d1e0f.age",
            "approver-8d1c6f0e-2b7a-1c59-9e3d-5a4b3c2d1e0f.age",
            "approver-8d1c6f0e-2b7a-4c59-9e3d-5a4b3c2d1e0f.age.tmp",
            "record-8d1c6f0e-2b7a-4c59-9e3d-5a4b3c2d1e0f.age",
        ]
        .iter()
        .for_each(|n| assert_eq!(StateFileName::approver_key_id(n), None, "{n:?}"));
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
