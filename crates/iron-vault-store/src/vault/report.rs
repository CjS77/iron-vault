//! What opening the vault found besides its healthy records.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use iron_vault_kinds::ShortSecret;
use iron_vault_policy::CredentialName;

use crate::{ErrorKindLabel, RecordId, StateFileName};

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

/// One record the manifest lists that did not load: what the audit log needs to find and fix it, and nothing from the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DamagedRecord {
    /// The credential the manifest names for the record.
    pub credential: CredentialName,
    /// The record the manifest lists.
    pub record_id: RecordId,
    /// The record's file.
    pub file: StateFileName,
    /// Why it did not load.
    pub damage: RecordDamage,
    /// The kind of the read failure, when reading the file failed; `None` when the file was read.
    pub error_kind: Option<ErrorKindLabel>,
}

/// The damaged records and unindexed record files found while opening the vault, for `status` and the audit log.
///
/// It holds names, file names and damage only, never file contents, so `Debug` is safe to log.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OpenReport {
    damaged: BTreeMap<CredentialName, RecordDamage>,
    damaged_records: Vec<DamagedRecord>,
    unindexed: BTreeSet<StateFileName>,
    approval_state_unrecorded: bool,
}

impl OpenReport {
    pub(super) fn new(damaged_records: Vec<DamagedRecord>, unindexed: BTreeSet<StateFileName>, approval_state_unrecorded: bool) -> Self {
        Self {
            damaged: damaged_records.iter().map(|d| (d.credential.clone(), d.damage)).collect(),
            damaged_records,
            unindexed,
            approval_state_unrecorded,
        }
    }

    /// Whether `approval.age` exists but the manifest does not record it: an approval state creation was interrupted
    /// before its manifest write. The service finishes it with `Vault::record_approval_state`.
    pub fn approval_state_unrecorded(&self) -> bool {
        self.approval_state_unrecorded
    }

    /// Each record the manifest lists that did not load, by credential name.
    pub fn damaged(&self) -> &BTreeMap<CredentialName, RecordDamage> {
        &self.damaged
    }

    /// Each record the manifest lists that did not load, with its ID, file and the kind of its read failure, in record ID order.
    pub fn damaged_records(&self) -> &[DamagedRecord] {
        &self.damaged_records
    }

    /// Each `record-*.age` file the manifest does not list; none was loaded.
    pub fn unindexed(&self) -> &BTreeSet<StateFileName> {
        &self.unindexed
    }
}

/// What a vault write did besides its change, for the audit log.
///
/// It holds file names, error kinds, and secret field names and lengths, never a value, so `Debug` is safe to log.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WriteReport {
    removed_unindexed: BTreeSet<StateFileName>,
    left_unindexed: Option<(StateFileName, ErrorKindLabel)>,
    short_secrets: Vec<ShortSecret>,
}

impl WriteReport {
    pub(super) fn new(removed_unindexed: BTreeSet<StateFileName>, left_unindexed: Option<(StateFileName, ErrorKindLabel)>) -> Self {
        Self {
            removed_unindexed,
            left_unindexed,
            short_secrets: Vec::new(),
        }
    }

    pub(super) fn with_short_secrets(mut self, short_secrets: Vec<ShortSecret>) -> Self {
        self.short_secrets = short_secrets;
        self
    }

    /// The secret fields of the record just written that are short: the write stands, but the owner probably pasted
    /// the wrong field, and scrubbing blanks every occurrence of the value.
    pub fn short_secrets(&self) -> &[ShortSecret] {
        &self.short_secrets
    }

    /// The unindexed record files the write removed before it changed anything: left by an interrupted write, or planted.
    pub fn removed_unindexed(&self) -> &BTreeSet<StateFileName> {
        &self.removed_unindexed
    }

    /// The superseded record file the write could not remove after its commit; the next write removes it.
    pub fn left_unindexed(&self) -> Option<&StateFileName> {
        self.left_unindexed.as_ref().map(|(file, _)| file)
    }

    /// Why the superseded record file could not be removed, as a label that holds no error text.
    pub fn left_unindexed_error_kind(&self) -> Option<&ErrorKindLabel> {
        self.left_unindexed.as_ref().map(|(_, kind)| kind)
    }
}
