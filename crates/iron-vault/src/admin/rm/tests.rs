use iron_vault_policy::CredentialKind;
use iron_vault_store::RecordId;

use super::*;
use crate::service_state::ServiceState;
use crate::standing::RecordSummary;
use iron_vault_store::RecordDamage;

fn code_of(refusal: VaultChangeRefusal) -> ErrorCode {
    match refused(refusal) {
        AdminResponse::Error { code, .. } => code,
        other => panic!("expected an error, got {other:?}"),
    }
}

fn name() -> CredentialName {
    "old_key".parse().unwrap()
}

#[test]
fn each_refusal_has_the_documented_code() {
    let cases = [
        (VaultChangeRefusal::Busy, ErrorCode::Busy),
        (VaultChangeRefusal::WrongState(ServiceState::Locked), ErrorCode::WrongState),
        (VaultChangeRefusal::UnknownCredential(name()), ErrorCode::UnknownCredential),
        (
            VaultChangeRefusal::InUse {
                name: name(),
                routes: Vec::new(),
            },
            ErrorCode::CredentialInUse,
        ),
        (VaultChangeRefusal::Invalid("x".to_owned()), ErrorCode::CredentialInvalid),
        (VaultChangeRefusal::Failed("x".to_owned()), ErrorCode::VaultWriteFailed),
        (VaultChangeRefusal::NotActive(ServiceState::Locked), ErrorCode::CommittedNotActive),
        (
            VaultChangeRefusal::ChangeUncertain {
                cause: "x".to_owned(),
                state: ServiceState::Ready,
            },
            ErrorCode::VaultWriteFailed,
        ),
    ];
    cases.into_iter().for_each(|(refusal, code)| assert_eq!(code_of(refusal), code));
}

#[test]
fn the_summary_names_the_record_its_kind_and_origins_and_no_routes() {
    let current = CurrentRecord {
        record_id: RecordId::new_random(),
        standing: Standing::Healthy,
        summary: Some(RecordSummary {
            kind: CredentialKind::Basic,
            origins: vec![
                ("a.example".parse().unwrap(), "443".parse().unwrap()),
                ("b.example".parse().unwrap(), "8443".parse().unwrap()),
            ],
        }),
    };
    let text = summary(&name(), &current);
    assert_eq!(
        text,
        format!(
            "remove credential old_key\n  record: {}\n  kind: basic\n  origins: a.example:443, b.example:8443\n  routes using old_key: none\n",
            current.record_id
        )
    );
}

#[test]
fn a_damaged_records_summary_says_its_kind_and_origins_are_unknown() {
    let current = CurrentRecord {
        record_id: RecordId::new_random(),
        standing: Standing::Damaged(RecordDamage::Missing),
        summary: None,
    };
    let text = summary(&name(), &current);
    assert!(text.contains("kind: unknown (record damaged: missing)"), "{text}");
    assert!(text.contains("origins: unknown"), "{text}");
}
