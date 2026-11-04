//! The names of the data files in the config directory.

use std::fmt;

use crate::MAX_APPROVAL_ENVELOPE_LEN;
use crate::durable::temp_name;

/// The most a config file may hold: 60 KiB.
///
/// The proposed config travels in one admin request frame whose body is at most 64 KiB, less the command and field
/// headers; 60 KiB leaves headroom and is about forty times the specification's example config.
pub const MAX_CONFIG_LEN: usize = 61_440;

/// One of the four data files the approval transaction keeps in the config directory.
///
/// The set is closed, so a name needs no validation and cannot be the lock file. Which of the files the store may
/// write by itself is decided by the functions that take a name: `Pending` and `StagedSignature` are written by a
/// durable replace, `Active` and `ActiveSignature` only by publish.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConfigFileName {
    /// `config.toml`, the active config.
    Active,
    /// `config.toml.sig`, the active config approval.
    ActiveSignature,
    /// `config.toml.pending`, the pending config.
    Pending,
    /// `config.toml.sig.staged`, the staged approval.
    StagedSignature,
}

impl ConfigFileName {
    /// Every data file.
    pub const ALL: [Self; 4] = [Self::Active, Self::ActiveSignature, Self::Pending, Self::StagedSignature];

    /// The file's name in the config directory.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "config.toml",
            Self::ActiveSignature => "config.toml.sig",
            Self::Pending => "config.toml.pending",
            Self::StagedSignature => "config.toml.sig.staged",
        }
    }

    /// The most the file may hold; a read or write beyond it is refused.
    pub const fn max_len(self) -> usize {
        match self {
            Self::Active | Self::Pending => MAX_CONFIG_LEN,
            Self::ActiveSignature | Self::StagedSignature => MAX_APPROVAL_ENVELOPE_LEN,
        }
    }

    /// The temporary name a durable replace of this file writes first: `.<name>.tmp`.
    pub(crate) fn temp_name(self) -> String {
        temp_name(self.as_str())
    }
}

impl fmt::Display for ConfigFileName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_match_the_design() {
        let names: Vec<_> = ConfigFileName::ALL.iter().map(|n| n.as_str()).collect();
        assert_eq!(
            names,
            ["config.toml", "config.toml.sig", "config.toml.pending", "config.toml.sig.staged"]
        );
    }

    #[test]
    fn limits_match_the_design() {
        assert_eq!(MAX_CONFIG_LEN, 61_440);
        assert_eq!(ConfigFileName::Pending.max_len(), MAX_CONFIG_LEN);
        assert_eq!(ConfigFileName::StagedSignature.max_len(), MAX_APPROVAL_ENVELOPE_LEN);
    }

    #[test]
    fn temp_names_are_distinct_dotfiles() {
        let temps: std::collections::BTreeSet<_> = ConfigFileName::ALL.iter().map(|n| n.temp_name()).collect();
        assert_eq!(temps.len(), 4);
        assert!(temps.contains(".config.toml.sig.staged.tmp"));
    }
}
