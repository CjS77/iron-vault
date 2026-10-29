//! The partial restore check: whether the manifest and the approval state on disk are a pair some sequence of writes
//! leaves together (spec §3.9, §3.10).
//!
//! Each write replaces one file, records the other file's current state generation as its peer, and takes a state
//! generation above both. So the file with the higher state generation was written last, and its peer generation must
//! be exactly the other file's state generation. A crash cannot break this: each write is one atomic replace of one
//! file, so the disk holds the old file or the new one, and either agrees with the other file. A pair that disagrees
//! means one file was restored from an older copy, or deleted.
//!
//! Restoring both files together, or restoring the file written last to the copy just before it, leaves a pair that
//! once existed on disk, which this check cannot tell from the current one; outside v0, a TPM monotonic counter
//! anchoring the state generation is what detects that.

use std::fmt;

use thiserror::Error;

use crate::{StateFileName, StateGeneration};

/// The manifest and the approval state on disk are not a pair any sequence of writes leaves: a control file looks
/// restored from an older copy, or deleted. Carries state generations only, never file contents.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PartialRestore {
    /// `file` is not at the state generation the file written after it recorded as its peer.
    Behind {
        /// The control file that disagrees with the other file's record of it.
        file: StateFileName,
        /// The state generation the other file recorded for it; `None` when that file recorded no approval state.
        expected: Option<StateGeneration>,
        /// Its state generation on disk; `None` when it is missing.
        found: Option<StateGeneration>,
    },
    /// Both files are at the same state generation, which no write produces: every write takes one above both.
    SameGeneration(StateGeneration),
}

/// What the operator should do. Repairing the pair automatically would accept the older copy as current (spec §3.9).
const REMEDIATION: &str = "a control file looks restored from an older copy or deleted; \
    recover the vault with the recovery key or reset it, and do not edit or delete state files by hand";

impl PartialRestore {
    /// The control file the error names: the one behind, or the manifest when neither is.
    pub fn file(&self) -> StateFileName {
        match self {
            Self::Behind { file, .. } => file.clone(),
            Self::SameGeneration(_) => StateFileName::manifest(),
        }
    }
}

impl fmt::Display for PartialRestore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Behind { file, expected, found } => {
                let other = other_file(file);
                let found = found.map_or_else(|| "missing".to_owned(), |found| format!("at state generation {found}"));
                let expected = expected.map_or_else(
                    || "records no approval state".to_owned(),
                    |e| format!("expects state generation {e}"),
                );
                write!(f, "{file} is {found}, but {other}, written after it, {expected}; {REMEDIATION}")
            }
            Self::SameGeneration(generation) => write!(
                f,
                "manifest.age and approval.age are both at state generation {generation}, which no write produces; {REMEDIATION}"
            ),
        }
    }
}

/// The control file that is not `file`.
fn other_file(file: &StateFileName) -> StateFileName {
    match *file == StateFileName::manifest() {
        true => StateFileName::approval_state(),
        false => StateFileName::manifest(),
    }
}

/// Refuses a manifest and approval state that no sequence of writes leaves on disk together.
///
/// `manifest` is the manifest's state generation and peer generation; `approval` is the approval state's, or `None`
/// when `approval.age` does not exist. A manifest alone is accepted only if it records no approval state.
pub(crate) fn check_control_generations(
    manifest: (StateGeneration, Option<StateGeneration>),
    approval: Option<(StateGeneration, StateGeneration)>,
) -> Result<(), PartialRestore> {
    let (state, peer) = manifest;
    match approval {
        None => agree(StateFileName::approval_state(), peer, None),
        Some((approval_state, approval_peer)) => match state.cmp(&approval_state) {
            std::cmp::Ordering::Greater => agree(StateFileName::approval_state(), peer, Some(approval_state)),
            std::cmp::Ordering::Less => agree(StateFileName::manifest(), Some(approval_peer), Some(state)),
            std::cmp::Ordering::Equal => Err(PartialRestore::SameGeneration(state)),
        },
    }
}

/// Accepts `file` at `found` only if that is exactly the state generation the file written after it `expected`.
fn agree(file: StateFileName, expected: Option<StateGeneration>, found: Option<StateGeneration>) -> Result<(), PartialRestore> {
    match expected == found {
        true => Ok(()),
        false => Err(PartialRestore::Behind { file, expected, found }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(value: u64) -> StateGeneration {
        StateGeneration::new(value).unwrap()
    }

    fn behind(file: StateFileName, expected: Option<u64>, found: Option<u64>) -> Result<(), PartialRestore> {
        Err(PartialRestore::Behind {
            file,
            expected: expected.map(g),
            found: found.map(g),
        })
    }

    #[test]
    fn a_manifest_alone_is_accepted_only_before_any_approval_state() {
        assert_eq!(check_control_generations((g(1), None), None), Ok(()));
        assert_eq!(check_control_generations((g(7), None), None), Ok(()));
        // The approval state existed at 4 and is gone.
        assert_eq!(
            check_control_generations((g(5), Some(g(4))), None),
            behind(StateFileName::approval_state(), Some(4), None)
        );
    }

    #[test]
    fn a_manifest_written_last_must_record_the_approval_state_exactly() {
        assert_eq!(check_control_generations((g(6), Some(g(5))), Some((g(5), g(3)))), Ok(()));
        // The approval state was restored from the copy at 2.
        assert_eq!(
            check_control_generations((g(6), Some(g(5))), Some((g(2), g(1)))),
            behind(StateFileName::approval_state(), Some(5), Some(2))
        );
        // A peer above the approval state's own state generation: not this approval state's history either.
        assert_eq!(
            check_control_generations((g(6), Some(g(3))), Some((g(5), g(1)))),
            behind(StateFileName::approval_state(), Some(3), Some(5))
        );
        // The manifest recorded no approval state, but one exists.
        assert_eq!(
            check_control_generations((g(6), None), Some((g(5), g(1)))),
            behind(StateFileName::approval_state(), None, Some(5))
        );
    }

    #[test]
    fn an_approval_state_written_last_must_record_the_manifest_exactly() {
        assert_eq!(check_control_generations((g(3), Some(g(2))), Some((g(5), g(3)))), Ok(()));
        // The manifest was restored from the copy at 1.
        assert_eq!(
            check_control_generations((g(1), None), Some((g(5), g(3)))),
            behind(StateFileName::manifest(), Some(3), Some(1))
        );
        // A peer below the manifest's state generation: the manifest is newer than the approval state knows.
        assert_eq!(
            check_control_generations((g(4), Some(g(2))), Some((g(5), g(3)))),
            behind(StateFileName::manifest(), Some(3), Some(4))
        );
    }

    #[test]
    fn two_files_at_one_state_generation_are_refused() {
        assert_eq!(
            check_control_generations((g(4), Some(g(3))), Some((g(4), g(3)))),
            Err(PartialRestore::SameGeneration(g(4)))
        );
        // Even with peers that would agree if the state generations were ordered.
        assert_eq!(
            check_control_generations((g(4), Some(g(4))), Some((g(4), g(4)))),
            Err(PartialRestore::SameGeneration(g(4)))
        );
    }

    #[test]
    fn the_message_names_the_file_both_generations_and_the_remediation() {
        let missing = PartialRestore::Behind {
            file: StateFileName::approval_state(),
            expected: Some(g(4)),
            found: None,
        };
        assert_eq!(
            missing.to_string(),
            format!("approval.age is missing, but manifest.age, written after it, expects state generation 4; {REMEDIATION}")
        );
        let older = PartialRestore::Behind {
            file: StateFileName::manifest(),
            expected: Some(g(3)),
            found: Some(g(1)),
        };
        let shown = older.to_string();
        assert!(
            shown.starts_with("manifest.age is at state generation 1, but approval.age, written after it, expects state generation 3;")
        );
        assert!(shown.contains("recovery key or reset"), "{shown}");
        assert_eq!(PartialRestore::SameGeneration(g(4)).file(), StateFileName::manifest());
    }
}
