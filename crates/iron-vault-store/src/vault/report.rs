//! What opening the vault found besides its healthy records.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use iron_vault_policy::CredentialName;

use crate::StateFileName;

/// Why a record the manifest lists did not load (spec §3.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RecordDamage {
    /// The record file does not exist.
    Missing,
    /// The file is not the one the manifest vouches for: its digest differs (it is then never decrypted), or it decrypts
    /// to a record with another record ID or name.
    Substituted,
    /// The file could not be read or is too large, or its digest matches but it does not decrypt or decode.
    Unreadable,
}

impl RecordDamage {
    /// What an administrator should do about this damage.
    pub fn remediation(self) -> &'static str {
        match self {
            Self::Missing => "restore the file from a backup of this vault, or re-enter the credential with `iron-vault replace`",
            Self::Substituted => {
                "the file does not match the vault manifest and may have been replaced outside Iron Vault; re-enter the credential \
                 with `iron-vault replace` and investigate who can write to the state directory"
            }
            Self::Unreadable => {
                "the file could not be read, is too large, or matches its manifest entry yet does not open, which points to a \
                 damaged vault identity or an Iron Vault bug; check the file's permissions and the vault identity, then restore \
                 the file from a backup of this vault or re-enter the credential with `iron-vault replace`"
            }
        }
    }
}

impl fmt::Display for RecordDamage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Missing => "missing",
            Self::Substituted => "substituted",
            Self::Unreadable => "unreadable",
        })
    }
}

/// The damaged records and unindexed record files found while opening the vault, for `status` and the audit log.
///
/// It holds names, file names and damage only, never file contents, so `Debug` is safe to log.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OpenReport {
    damaged: BTreeMap<CredentialName, RecordDamage>,
    unindexed: BTreeSet<StateFileName>,
}

impl OpenReport {
    pub(super) fn new(damaged: BTreeMap<CredentialName, RecordDamage>, unindexed: BTreeSet<StateFileName>) -> Self {
        Self { damaged, unindexed }
    }

    /// Each record the manifest lists that did not load, by credential name.
    pub fn damaged(&self) -> &BTreeMap<CredentialName, RecordDamage> {
        &self.damaged
    }

    /// Each `record-*.age` file the manifest does not list; none was loaded.
    pub fn unindexed(&self) -> &BTreeSet<StateFileName> {
        &self.unindexed
    }
}
