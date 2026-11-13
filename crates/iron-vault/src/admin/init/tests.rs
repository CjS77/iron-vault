// SPDX-License-Identifier: MPL-2.0
//! How `init`'s refusals and failures are worded: which step failed, and what the owner does with the recovery key.

use std::io;

use iron_vault_store::{InitStep, StateFileName, WriteError, WriteStep};

use super::*;

fn message(response: &AdminResponse) -> (ErrorCode, &str) {
    match response {
        AdminResponse::Error { code, message } => (*code, message),
        other => panic!("expected an error, got {other:?}"),
    }
}

fn failure(step: InitStep, cause: InitFailure) -> AdminResponse {
    refused(InitRefusal::Failed(InitError::for_tests(step, cause)), true)
}

#[test]
fn a_failed_write_step_is_named_by_number_and_the_key_is_dead() {
    let response = failure(InitStep::IdentityEnvelope, InitFailure::IdentityMismatch);
    let (code, text) = message(&response);
    assert_eq!(code, ErrorCode::InitFailed);
    assert!(
        text.starts_with("init failed at step 2: the identity envelope as read back"),
        "{text}"
    );
    assert!(
        text.contains("run `iron-vault init` again, which discards the unfinished vault"),
        "{text}"
    );
    assert!(text.ends_with(DEAD_RECOVERY_KEY), "{text}");
}

#[test]
fn a_failed_discard_is_named_as_the_discard() {
    let cause = InitFailure::State(InitStateError::State(WriteError::Io {
        step: WriteStep::Remove,
        file: StateFileName::manifest(),
        kind: io::ErrorKind::PermissionDenied,
    }));
    let response = failure(InitStep::Discard, cause);
    let (code, text) = message(&response);
    assert_eq!(code, ErrorCode::InitFailed);
    assert!(text.starts_with("init failed at the discard: "), "{text}");
    assert!(text.ends_with(DEAD_RECOVERY_KEY), "{text}");
}

/// Step 9's unlink landed but its directory fsync failed, so the vault may stand: the owner keeps the key until a re-run
/// decides, and is never told it is dead.
#[test]
fn an_uncertain_commit_point_tells_the_owner_to_keep_the_key() {
    let cause = InitFailure::State(InitStateError::FinishUncertain {
        kind: io::ErrorKind::Other,
    });
    let response = failure(InitStep::Finish, cause);
    let (code, text) = message(&response);
    assert_eq!(code, ErrorCode::InitFailed);
    assert!(text.starts_with("init failed at step 9: init.unfinished is removed"), "{text}");
    assert!(text.ends_with(UNCONFIRMED_RECOVERY_KEY), "{text}");
    assert!(!text.contains(DEAD_RECOVERY_KEY), "{text}");
}

/// A refusal says the key is dead only once a key was shown.
#[test]
fn a_refusal_names_the_dead_key_only_after_the_reveal() {
    let before = refused(InitRefusal::Busy, false);
    let after = refused(InitRefusal::Busy, true);
    assert_eq!(message(&before).0, ErrorCode::Busy);
    assert!(!message(&before).1.contains(DEAD_RECOVERY_KEY), "{before:?}");
    assert!(message(&after).1.ends_with(DEAD_RECOVERY_KEY), "{after:?}");
}
