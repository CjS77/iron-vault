//! The state generation: one vault-wide count of MAC'd file writes (spec §3.9, §3.10).
//!
//! The manifest and the approval state each record the state generation they were written at and the other file's at
//! that moment. A single number covering both is what a TPM monotonic counter can later anchor (outside v0), and the
//! recorded peer lets a restore of one file alone be told apart without one. The rule is in
//! `design/storage-formats.md`.

use std::fmt;
use std::num::NonZeroU64;

/// A vault-wide count of MAC'd file writes, at which one manifest or approval state was written.
///
/// Never 0, so a peer generation of 0 on disk can mean "no peer". Every write takes [`StateGeneration::next`], so no two
/// writes share one and it never wraps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StateGeneration(NonZeroU64);

impl StateGeneration {
    /// State generation 1, at which a new vault's first manifest is written.
    pub const FIRST: Self = Self(NonZeroU64::MIN);

    /// The state generation `value`, or `None` for zero.
    pub fn new(value: u64) -> Option<Self> {
        NonZeroU64::new(value).map(Self)
    }

    /// The state generation as an integer.
    pub fn get(self) -> u64 {
        self.0.get()
    }

    /// The state generation the next MAC'd file write takes: one above the newer of the manifest's and the approval
    /// state's current ones, either `None` while that file has not been written. `None` once exhausted: it never wraps.
    ///
    /// This is the only place a state generation is allocated, so every write of either file is one above the latest
    /// write of both.
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
