// SPDX-License-Identifier: MPL-2.0
use super::*;
use crate::service_state::ServiceState;

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
        (
            VaultChangeRefusal::UsedByRoutes {
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
fn a_credential_in_use_names_its_routes_and_not_a_missing_credential() {
    let routes = ["old", "older"].map(|route| route.parse().unwrap()).to_vec();
    let refusal = VaultChangeRefusal::UsedByRoutes { name: name(), routes };

    let AdminResponse::Error { code, message } = refused(refusal) else {
        panic!("expected an error")
    };

    assert_eq!(code, ErrorCode::CredentialInUse);
    assert_eq!(
        message,
        "credential old_key is used by routes old, older; approve a config without those routes, then run `rm` again"
    );
}
