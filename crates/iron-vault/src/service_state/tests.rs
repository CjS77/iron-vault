use super::ServiceEvent as E;
use super::ServiceState as S;
use super::*;

const STATES: [ServiceState; 7] = [
    S::Starting,
    S::Locked,
    S::Checking,
    S::Ready,
    S::Unavailable(FailureReason::PolicyInvalid),
    S::Unavailable(FailureReason::RecoveryNeeded),
    S::Stopped,
];

const EVENTS: [ServiceEvent; 10] = [
    E::InteractiveUnlockRequired,
    E::HostUnlockSucceeded,
    E::UnlockSucceeded,
    E::CheckPassed,
    E::CheckFailed(FailureReason::PolicyInvalid),
    E::CheckFailed(FailureReason::RecoveryNeeded),
    E::Reload,
    E::Lock,
    E::Repaired,
    E::Stop,
];

const OPERATIONS: [AdminOperation; 7] = [
    AdminOperation::Ping,
    AdminOperation::Status,
    AdminOperation::Unlock,
    AdminOperation::Lock,
    AdminOperation::Reload,
    AdminOperation::Repair,
    AdminOperation::VaultChange,
];

/// Every edge of the §3.12 diagram, and nothing else.
fn legal_edges() -> Vec<(ServiceState, ServiceEvent, ServiceState)> {
    let policy = S::Unavailable(FailureReason::PolicyInvalid);
    let recovery = S::Unavailable(FailureReason::RecoveryNeeded);
    vec![
        (S::Starting, E::InteractiveUnlockRequired, S::Locked),
        (S::Starting, E::HostUnlockSucceeded, S::Checking),
        (S::Locked, E::UnlockSucceeded, S::Checking),
        (S::Checking, E::CheckPassed, S::Ready),
        (S::Checking, E::CheckFailed(FailureReason::PolicyInvalid), policy),
        (S::Checking, E::CheckFailed(FailureReason::RecoveryNeeded), recovery),
        (S::Ready, E::Reload, S::Checking),
        (S::Ready, E::Lock, S::Locked),
        (policy, E::Repaired, S::Checking),
        (recovery, E::Repaired, S::Checking),
        (S::Ready, E::Stop, S::Stopped),
    ]
}

#[test]
fn every_diagram_edge_is_taken() {
    legal_edges()
        .into_iter()
        .for_each(|(from, event, to)| assert_eq!(next(from, event), Ok(to), "{from:?} + {event:?}"));
}

#[test]
fn every_other_pair_is_refused() {
    let legal = legal_edges();
    STATES
        .iter()
        .flat_map(|&state| EVENTS.iter().map(move |&event| (state, event)))
        .filter(|&(state, event)| !legal.iter().any(|&(from, e, _)| from == state && e == event))
        .for_each(|(state, event)| assert_eq!(next(state, event), Err(IllegalTransition { state, event }), "{state:?} + {event:?}"));
}

#[test]
fn unavailable_has_no_edge_to_locked() {
    let state = S::Unavailable(FailureReason::RecoveryNeeded);
    assert!(next(state, E::Lock).is_err());
}

#[test]
fn only_ready_serves() {
    STATES.iter().for_each(|&state| {
        assert_eq!(state.request_interface() == RequestInterface::Serve, state == S::Ready, "{state:?}");
    });
}

#[test]
fn refusals_carry_the_redacted_reason() {
    let refuse = |state: ServiceState| state.request_interface();
    assert_eq!(refuse(S::Starting), RequestInterface::Refuse(UnavailableReason::Locked));
    assert_eq!(refuse(S::Locked), RequestInterface::Refuse(UnavailableReason::Locked));
    assert_eq!(refuse(S::Checking), RequestInterface::Refuse(UnavailableReason::Checking));
    assert_eq!(
        refuse(S::Unavailable(FailureReason::PolicyInvalid)),
        RequestInterface::Refuse(UnavailableReason::PolicyInvalid)
    );
    assert_eq!(
        refuse(S::Unavailable(FailureReason::RecoveryNeeded)),
        RequestInterface::Refuse(UnavailableReason::RecoveryNeeded)
    );
    assert_eq!(refuse(S::Stopped), RequestInterface::Closed);
}

#[test]
fn reason_texts_are_fixed() {
    let texts = [
        UnavailableReason::Locked,
        UnavailableReason::PolicyInvalid,
        UnavailableReason::Checking,
        UnavailableReason::RecoveryNeeded,
    ]
    .map(UnavailableReason::as_str);
    assert_eq!(texts, ["locked", "policy invalid", "checking", "recovery needed"]);
}

#[test]
fn only_ready_has_approved_listeners() {
    STATES.iter().for_each(|&state| {
        let expected = match state {
            S::Ready => Some(ListenerProvenance::Approved),
            S::Stopped => None,
            _ => Some(ListenerProvenance::Provisional),
        };
        assert_eq!(state.listener_provenance(), expected, "{state:?}");
    });
}

fn allowed(state: ServiceState) -> Vec<AdminOperation> {
    OPERATIONS.into_iter().filter(|&operation| state.admin_allows(operation)).collect()
}

#[test]
fn admin_commands_follow_the_state() {
    use AdminOperation as A;
    assert_eq!(allowed(S::Starting), [A::Ping, A::Status]);
    assert_eq!(allowed(S::Locked), [A::Ping, A::Status, A::Unlock]);
    assert_eq!(allowed(S::Checking), [A::Ping, A::Status]);
    assert_eq!(allowed(S::Ready), [A::Ping, A::Status, A::Lock, A::Reload, A::VaultChange]);
    assert_eq!(
        allowed(S::Unavailable(FailureReason::PolicyInvalid)),
        [A::Ping, A::Status, A::Repair]
    );
    assert_eq!(
        allowed(S::Unavailable(FailureReason::RecoveryNeeded)),
        [A::Ping, A::Status, A::Repair]
    );
    assert!(allowed(S::Stopped).is_empty());
}
