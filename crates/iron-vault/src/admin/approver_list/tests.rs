use super::*;
use crate::service_state::ServiceState;

fn answer(refusal: ApproverListRefusal) -> (ErrorCode, String) {
    match refused(refusal) {
        AdminResponse::Error { code, message } => (code, message),
        other => panic!("expected an error, got {other:?}"),
    }
}

#[test]
fn busy_maps_to_the_busy_code() {
    let (code, message) = answer(ApproverListRefusal::Busy);
    assert_eq!(code, ErrorCode::Busy);
    assert!(message.contains("try again shortly"), "{message}");
}

#[test]
fn wrong_state_names_the_state() {
    let (code, message) = answer(ApproverListRefusal::WrongState(ServiceState::Locked));
    assert_eq!(code, ErrorCode::WrongState);
    assert!(message.contains("only while the service is Ready"), "{message}");
}
