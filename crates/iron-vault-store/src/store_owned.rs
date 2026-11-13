// SPDX-License-Identifier: MPL-2.0
//! The store-owned files: every name the store writes in the state and config directories
//! ([removal order](../../../design/reset.md#removal-order)).
//!
//! The list is held here once, so the initialization state, every discard and reset agree on which files are the
//! store's and which are foreign. A design that adds a state file adds one line to [`STATE_FILES`], and reset then
//! removes it with no change of its own.

use crate::vault::is_record_file_name;
use crate::{ConfigFileName, StateFileName};

/// One entry of the store-owned list in the state directory: a file with a fixed name, or a family of names that each
/// carry an ID.
#[derive(Debug, Clone, Copy)]
pub(crate) enum OwnedStateFile {
    /// One file with a fixed name.
    Fixed(fn() -> StateFileName),
    /// Every approver key envelope, `approver-<approver ID>.age`.
    ApproverKeys,
    /// Every TPM key blob, `approver-<approver ID>.tpm`.
    TpmKeyBlobs,
    /// Every record file, `record-<record ID>.age`.
    Records,
}

use OwnedStateFile::{ApproverKeys, Fixed, Records, TpmKeyBlobs};

/// Every store-owned file in the state directory, in the order reset removes them.
///
/// The manifest goes first, so no binary opens the vault once anything else is gone. The identity envelope goes next,
/// so a crash leaves no file a recovery key opens. Reset's own commit point, `reset.unfinished`, goes last.
pub(crate) const STATE_FILES: [OwnedStateFile; 14] = [
    Fixed(StateFileName::manifest),
    Fixed(StateFileName::identity_envelope),
    Fixed(StateFileName::passphrase_envelope),
    Fixed(StateFileName::recipient_inventory),
    Fixed(StateFileName::staged_recipient_inventory),
    ApproverKeys,
    TpmKeyBlobs,
    Fixed(StateFileName::approval_state),
    Records,
    Fixed(StateFileName::recovery_check_record),
    Fixed(StateFileName::unfinished_initialization),
    Fixed(StateFileName::unfinished_import),
    Fixed(StateFileName::owner_lock),
    Fixed(StateFileName::unfinished_reset),
];

/// The store-owned state files whose presence alone is no vault. `recovery.toml` is the record of a vault already gone,
/// and the owner-lock file says only that the owner locked; `init` removes both. Stale temp files are not vault files
/// either.
const NOT_VAULT_FILES: [fn() -> StateFileName; 2] = [StateFileName::recovery_check_record, StateFileName::owner_lock];

/// The config files, in the order every discard removes them: all signatures before any config.
///
/// A signature with no config beside it reads as the owner's file, and `publish` can leave `config.toml` beside
/// `config.toml.sig.staged`, so removing a config while a signature remains could strand that signature after a crash.
pub(crate) const CONFIG_FILES: [ConfigFileName; 4] = [
    ConfigFileName::ActiveSignature,
    ConfigFileName::StagedSignature,
    ConfigFileName::Active,
    ConfigFileName::Pending,
];

impl OwnedStateFile {
    fn matches(self, name: &StateFileName) -> bool {
        match self {
            Fixed(file) => file() == *name,
            ApproverKeys => StateFileName::approver_key_id(name.as_str()).is_some(),
            TpmKeyBlobs => StateFileName::tpm_key_blob_id(name.as_str()).is_some(),
            Records => is_record_file_name(name.as_str()),
        }
    }
}

/// Returns `true` if and only if the store writes a state file named `name`.
pub(crate) fn is_store_owned(name: &StateFileName) -> bool {
    STATE_FILES.iter().any(|entry| entry.matches(name))
}

/// Returns `true` if and only if `name` is a vault file: a store-owned state file other than those whose presence alone
/// is no vault.
///
/// A state directory with no vault file reads Uninitialized, or Unrecognized when a foreign file is there, and has
/// nothing to reset.
pub(crate) fn is_vault_file(name: &str) -> bool {
    StateFileName::new(name).is_ok_and(|file| is_store_owned(&file) && !NOT_VAULT_FILES.iter().any(|not| not() == file))
}

/// Returns the store-owned names among `names`, in the order of [`STATE_FILES`]; every other name is left out.
pub(crate) fn in_removal_order(names: &[StateFileName]) -> Vec<StateFileName> {
    STATE_FILES
        .iter()
        .flat_map(|entry| names.iter().filter(move |name| entry.matches(name)).cloned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A version 4 UUID in lowercase hyphenated form, for the ID in a family's name.
    const ID: &str = "8d1c6f0e-2b7a-4c59-9e3d-5a4b3c2d1e0f";

    /// Returns every name `state_file_name.rs` builds outside its tests: each `Self("…")` literal, and each
    /// `format!("…")` with its placeholder filled by a UUID. They are read from the source, so a constructor added
    /// there without a line in [`STATE_FILES`] fails this test.
    fn constructed_names() -> Vec<String> {
        let source = include_str!("state_file_name.rs");
        let code = source.split("#[cfg(test)]").next().unwrap();
        let literals = |marker: &'static str| {
            code.split(marker)
                .skip(1)
                .map(|rest| rest.split('"').next().unwrap().to_owned())
                .collect::<Vec<_>>()
        };
        let fixed = literals("Self(\"");
        let families = literals("format!(\"").into_iter().map(|pattern| {
            let (head, tail) = pattern.split_once('{').unwrap();
            format!("{head}{ID}{}", tail.split_once('}').unwrap().1)
        });
        fixed.into_iter().chain(families).collect()
    }

    #[test]
    fn every_state_file_name_is_store_owned() {
        let names = constructed_names();
        assert!(names.len() >= 14, "{names:?}");
        names
            .iter()
            .for_each(|name| assert!(is_store_owned(&StateFileName::new(name).unwrap()), "{name} is not store-owned"));
    }

    #[test]
    fn lock_files_and_foreign_names_are_not_store_owned() {
        [
            "notes.txt",
            "record.age",
            "approver-x.age",
            "approver-x.tpm",
            "manifest.age.bak",
            "lost-found",
        ]
        .iter()
        .for_each(|name| assert!(!is_store_owned(&StateFileName::new(name).unwrap()), "{name}"));
        ["lock", "lost+found", ".manifest.age.tmp"]
            .iter()
            .for_each(|name| assert!(!is_vault_file(name), "{name}"));
    }

    #[test]
    fn the_recovery_check_record_and_the_owner_lock_are_the_only_store_owned_files_that_are_no_vault() {
        let not_vault: Vec<_> = constructed_names().into_iter().filter(|name| !is_vault_file(name)).collect();
        assert_eq!(not_vault, ["locked-by-owner", "recovery.toml"]);
    }

    #[test]
    fn removal_order_starts_with_the_manifest_and_ends_with_the_reset_marker() {
        let names: Vec<_> = [
            "reset.unfinished".to_owned(),
            format!("record-{ID}.age"),
            "identity.age".to_owned(),
            "notes.txt".to_owned(),
            format!("approver-{ID}.tpm"),
            format!("approver-{ID}.age"),
            "manifest.age".to_owned(),
            "recovery.toml".to_owned(),
            "locked-by-owner".to_owned(),
        ]
        .iter()
        .map(|name| StateFileName::new(name).unwrap())
        .collect();
        let ordered: Vec<_> = in_removal_order(&names).iter().map(|name| name.to_string()).collect();
        assert_eq!(
            ordered,
            [
                "manifest.age".to_owned(),
                "identity.age".to_owned(),
                format!("approver-{ID}.age"),
                format!("approver-{ID}.tpm"),
                format!("record-{ID}.age"),
                "recovery.toml".to_owned(),
                "locked-by-owner".to_owned(),
                "reset.unfinished".to_owned(),
            ]
        );
    }
}
