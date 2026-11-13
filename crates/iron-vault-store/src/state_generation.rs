// SPDX-License-Identifier: MPL-2.0
//! The state generation: one vault-wide count of MAC'd file writes
//! ([spec §12](../../../design/iron-vault-specification.md#12-configuration-approval-and-reload),
//! [§13](../../../design/iron-vault-specification.md#13-vault-structure-and-durable-writes),
//! [storage formats](../../../design/storage-formats.md#state-generation)).
//!
//! The manifest and the approval state each record the state generation they were written at and the other file's
//! (the peer generation) at that moment. A single number covering both is what a TPM monotonic counter can later
//! anchor (outside v0). The recorded peer lets the store detect a restore of one file alone without such a counter
//! (see [`PartialRestore`](crate::PartialRestore)). A run of writes, each one above the newer of both files:
//!
//! ```text
//! write                   manifest.age (state, peer)    approval.age (state, peer)
//! manifest                (1, 0)                        missing
//! approval state          (1, 0)                        (2, 1)
//! manifest                (3, 2)                        (2, 1)
//! manifest                (4, 2)                        (2, 1)
//! approval state          (4, 2)                        (5, 4)
//! ```

use std::fmt;
use std::num::NonZeroU64;

/// A vault-wide count of MAC'd file writes, at which one manifest or approval state was written.
///
/// It is never 0, so a peer generation of 0 on disk can mean "no peer". Every write takes [`StateGeneration::next`] of
/// both files' state generations as they are on disk, read under the state-directory lock that makes the service the
/// only writer, so no two writes share one. It never wraps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StateGeneration(NonZeroU64);

impl StateGeneration {
    /// State generation 1, at which a new vault's first manifest is written.
    pub const FIRST: Self = Self(NonZeroU64::MIN);

    /// Returns the state generation `value`, or `None` for zero.
    pub fn new(value: u64) -> Option<Self> {
        NonZeroU64::new(value).map(Self)
    }

    /// Returns the state generation as an integer.
    pub fn get(self) -> u64 {
        self.0.get()
    }

    /// Returns the state generation the next MAC'd file write takes: one above the newer of the manifest's and the
    /// approval state's current ones. Pass `None` for a file that has not been written. Returns `None` once the count
    /// is exhausted: it never wraps.
    ///
    /// This is the only place a state generation is allocated. Each writer passes its own file's state generation and the
    /// other file's read from disk, so every write of either file is one above the latest write of both.
    pub fn next(manifest: Option<Self>, approval: Option<Self>) -> Option<Self> {
        match manifest.max(approval) {
            None => Some(Self::FIRST),
            Some(newest) => newest.0.checked_add(1).map(Self),
        }
    }
}

impl fmt::Display for StateGeneration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generation(value: u64) -> StateGeneration {
        StateGeneration::new(value).unwrap()
    }

    #[test]
    fn zero_is_not_a_state_generation() {
        assert_eq!(StateGeneration::new(0), None);
        assert_eq!(StateGeneration::new(1), Some(StateGeneration::FIRST));
    }

    #[test]
    fn the_first_write_of_a_vault_takes_the_first_state_generation() {
        assert_eq!(StateGeneration::next(None, None), Some(StateGeneration::FIRST));
    }

    #[test]
    fn next_is_one_above_the_newer_of_both_files_whichever_it_is() {
        assert_eq!(StateGeneration::next(Some(generation(3)), None), Some(generation(4)));
        assert_eq!(StateGeneration::next(None, Some(generation(3))), Some(generation(4)));
        assert_eq!(StateGeneration::next(Some(generation(7)), Some(generation(3))), Some(generation(8)));
        assert_eq!(StateGeneration::next(Some(generation(3)), Some(generation(7))), Some(generation(8)));
    }

    #[test]
    fn next_never_wraps() {
        let last = generation(u64::MAX);
        assert_eq!(StateGeneration::next(Some(last), None), None);
        assert_eq!(StateGeneration::next(Some(generation(1)), Some(last)), None);
        assert_eq!(StateGeneration::next(Some(last), Some(generation(1))), None);
    }
}
