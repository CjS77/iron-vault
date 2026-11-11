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

const EVENTS: [ServiceEvent; 12] = [
    E::InteractiveUnlockRequired,
    E::HostUnlockSucceeded,
    E::UnlockSucceeded,
    E::CheckPassed,
    E::CheckFailed(FailureReason::PolicyInvalid),
    E::CheckFailed(FailureReason::RecoveryNeeded),
    E::Reload,
    E::ApprovalCommitting,
    E::VaultChanged,
    E::Lock,
    E::Repaired,
    E::Stop,
];

const OPERATIONS: [AdminOperation; 12] = [
    AdminOperation::Ping,
    AdminOperation::Status,
    AdminOperation::Unlock,
    AdminOperation::Lock,
    AdminOperation::Reload,
    AdminOperation::Approve,
    AdminOperation::Repair,
    AdminOperation::VaultChange,
    AdminOperation::Initialize,
    AdminOperation::IssueCallerToken,
    AdminOperation::RecoveryCheck,
    AdminOperation::Reset,
];

/// Every edge of the §15 diagram, and nothing else.
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
        (S::Ready, E::ApprovalCommitting, S::Checking),
        (S::Ready, E::VaultChanged, S::Checking),
        (S::Ready, E::Lock, S::Locked),
        (policy, E::Repaired, S::Checking),
        (recovery, E::Repaired, S::Checking),
        (policy, E::Lock, S::Locked),
        (recovery, E::Lock, S::Locked),
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
fn lock_leads_to_locked_from_every_unavailable_reason() {
    [FailureReason::PolicyInvalid, FailureReason::RecoveryNeeded]
        .into_iter()
        .for_each(|reason| assert_eq!(next(S::Unavailable(reason), E::Lock), Ok(S::Locked), "{reason:?}"));
}

#[test]
fn lock_is_refused_while_starting_checking_or_locked() {
    [S::Starting, S::Checking, S::Locked]
        .into_iter()
        .for_each(|state| assert_eq!(next(state, E::Lock), Err(IllegalTransition { state, event: E::Lock }), "{state:?}"));
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
    assert_eq!(allowed(S::Starting), [A::Ping, A::Status, A::IssueCallerToken]);
    assert_eq!(
        allowed(S::Locked),
        [
            A::Ping,
            A::Status,
            A::Unlock,
            A::Initialize,
            A::IssueCallerToken,
            A::RecoveryCheck,
            A::Reset
        ]
    );
    assert_eq!(allowed(S::Checking), [A::Ping, A::Status, A::IssueCallerToken]);
    assert_eq!(
        allowed(S::Ready),
        [
            A::Ping,
            A::Status,
            A::Lock,
            A::Reload,
            A::Approve,
            A::VaultChange,
            A::IssueCallerToken,
            A::RecoveryCheck,
            A::Reset
        ]
    );
    assert_eq!(
        allowed(S::Unavailable(FailureReason::PolicyInvalid)),
        [A::Ping, A::Status, A::Lock, A::Approve, A::IssueCallerToken, A::Reset]
    );
    assert_eq!(
        allowed(S::Unavailable(FailureReason::RecoveryNeeded)),
        [A::Ping, A::Status, A::Lock, A::Repair, A::IssueCallerToken, A::Reset]
    );
    assert!(allowed(S::Stopped).is_empty());
}
