// SPDX-License-Identifier: MPL-2.0
use iron_vault_store::{RecipientChangeRefusal, RecipientEntry, RecipientLabel, RecoveryKey, UtcSecond};

use super::*;

fn answer(refusal: RemovalRefusal) -> (ErrorCode, String) {
    match refused(refusal) {
        AdminResponse::Error { code, message } => (code, message),
        other => panic!("expected an error, got {other:?}"),
    }
}

fn removed(role: RecipientRole, unfinished: bool) -> RemovedRecipient {
    let (_, key) = RecoveryKey::generate();
    let label = RecipientLabel::new("old laptop").unwrap();
    RemovedRecipient {
        removed: RecipientEntry::new(key, role, label, UtcSecond::from_unix_seconds(0).unwrap()),
        recipients: 2,
        unfinished,
    }
}

#[test]
fn each_refusal_has_the_documented_code() {
    let cases = [
        (RemovalRefusal::NotEnrolled, ErrorCode::UnknownRecipient),
        (
            RemovalRefusal::SetInvalid(RecipientChangeRefusal::NoRecovery),
            ErrorCode::RecipientSetInvalid,
        ),
        (RemovalRefusal::Inventory(RecipientRefusal::Busy), ErrorCode::Busy),
        (
            RemovalRefusal::Failed {
                committed: ChangeCommitted::No,
                cause: "x".to_owned(),
            },
            ErrorCode::VaultWriteFailed,
        ),
    ];
    cases.into_iter().for_each(|(refusal, code)| assert_eq!(answer(refusal).0, code));
}

#[test]
fn a_set_refusal_names_the_rule() {
    let (_, message) = answer(RemovalRefusal::SetInvalid(RecipientChangeRefusal::RemovesOperational));
    assert!(
        message.contains("independence rule") && message.contains("operational"),
        "{message}"
    );
}

#[test]
fn only_an_uncertain_write_says_it_may_have_committed() {
    let failed = |committed| {
        answer(RemovalRefusal::Failed {
            committed,
            cause: "stage failed".to_owned(),
        })
        .1
    };
    assert!(failed(ChangeCommitted::No).ends_with("nothing was changed"));
    assert!(failed(ChangeCommitted::Unknown).contains("may have committed"));
}

#[test]
fn the_completion_always_carries_the_old_copies_sentence() {
    [RecipientRole::Added, RecipientRole::Recovery].into_iter().for_each(|role| {
        let notice = completion(&removed(role, false));
        assert!(
            notice.contains("Old copies of identity.age, and backups, still open with a removed key."),
            "{notice}"
        );
        assert!(notice.contains("rotate the provider credentials"), "{notice}");
    });
}

#[test]
fn the_completion_adds_a_line_only_when_the_role_or_an_unfinished_inventory_needs_one() {
    let recovery = completion(&removed(RecipientRole::Recovery, true));
    assert!(
        recovery.contains("recovery check") && recovery.contains("next recipient command"),
        "{recovery}"
    );
    let added = completion(&removed(RecipientRole::Added, false));
    assert!(
        !added.contains("recovery check") && !added.contains("next recipient command"),
        "{added}"
    );
}

#[test]
fn the_completion_ends_with_a_newline_whatever_lines_it_carries() {
    [(RecipientRole::Added, false), (RecipientRole::Recovery, true)]
        .into_iter()
        .for_each(|(role, unfinished)| assert!(completion(&removed(role, unfinished)).ends_with('\n')));
}
