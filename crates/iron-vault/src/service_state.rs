//! The service state model (specification §3.12): five states, the events that move between them, and what each state
//! allows. Everything here is pure; the runtime that drives transitions and binds sockets calls into it, so it cannot
//! invent a transition the specification's diagram lacks, such as a silent fall back from Locked to weaker storage (R-22).
//!
//! # Listeners before Ready
//!
//! While Locked the configuration cannot be verified, because `approval.age` is sealed to the vault identity. The
//! service still binds the request listeners named in the **unverified** `config.toml`, so callers receive an explicit
//! `503` instead of a refused connection. That is safe because a request listener unlocks nothing (unlock happens only
//! over the admin socket, after the admin-principal check), and in every state other than Ready a request listener
//! answers only `503` with the redacted reason: it never authenticates a caller, selects a route or resolves a
//! credential. On entering Ready the listener set is rebuilt from the verified configuration, so an unapproved listener
//! never serves credentials. The residual risk is accepted: until then a swapped `config.toml` can open an extra port,
//! expose the HTTP and TLS code on it, take a port another service needs, or tell a remote host the vault is locked.
//! [`ServiceState::listener_provenance`] records which set a state has.

#[cfg(test)]
mod tests;

/// Why a check left the service Unavailable (the checks of §3.12: "invalid policy or damaged shared state").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureReason {
    /// The configuration or its approval did not verify.
    PolicyInvalid,
    /// Shared state is damaged, or a committed transaction could not be completed; only repair or recovery clears it.
    RecoveryNeeded,
}

/// The fixed, redacted reason a request listener gives with a `503`. It names a category and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnavailableReason {
    /// The vault identity is not in memory.
    Locked,
    /// The configuration or its approval did not verify.
    PolicyInvalid,
    /// A check is running and no policy is held until it passes.
    Checking,
    /// Shared state is damaged or a committed transaction is unfinished.
    RecoveryNeeded,
}

impl UnavailableReason {
    /// The fixed text a `503` body carries.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Locked => "locked",
            Self::PolicyInvalid => "policy invalid",
            Self::Checking => "checking",
            Self::RecoveryNeeded => "recovery needed",
        }
    }

    /// The reason a request listener gives for a failed check.
    pub const fn from_failure(reason: FailureReason) -> Self {
        match reason {
            FailureReason::PolicyInvalid => Self::PolicyInvalid,
            FailureReason::RecoveryNeeded => Self::RecoveryNeeded,
        }
    }
}

/// Where the service is in its life (specification §3.12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    /// From process start until the service knows whether it can unlock itself.
    Starting,
    /// The vault identity is not in memory; an authorized unlock is awaited.
    Locked,
    /// Storage and the current approval are being verified.
    Checking,
    /// Verified: the only state that serves requests.
    Ready,
    /// A check failed; the service keeps no route policy and answers `503` with the reason.
    Unavailable(FailureReason),
    /// Terminal: the process stopped from Ready and cleared its memory. Not one of the five states; it exists so that
    /// the diagram's final edge is an ordinary transition.
    Stopped,
}

/// Something that happens to the service and may move it to another state.
///
/// Configured key removal (Ready to Locked, specification §3.12) belongs to the YubiKey phase; its event is
/// `KeyRemoved` and it is deliberately not defined yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceEvent {
    /// Startup found that an interactive unlock is required.
    InteractiveUnlockRequired,
    /// A TPM or host unlock succeeded at startup (not reachable in v0 until EP-32).
    HostUnlockSucceeded,
    /// An authorized unlock succeeded.
    UnlockSucceeded,
    /// A check passed: storage and the current approval verify.
    CheckPassed,
    /// A check failed.
    CheckFailed(FailureReason),
    /// An explicit reload was requested.
    Reload,
    /// A config approval started from Ready is about to commit: the admission pause begins. It shares the diagram's one
    /// edge from Ready to Checking with [`Reload`](Self::Reload), so *reload* keeps its one meaning, the SIGHUP operation.
    ApprovalCommitting,
    /// An explicit lock was requested.
    Lock,
    /// An authorized repair, or recovery of a committed transaction, finished. A configuration approval committed from
    /// Unavailable with [`FailureReason::PolicyInvalid`] leaves through this event too (the diagram's "authorized
    /// repair"), so approving needs no edge of its own.
    Repaired,
    /// The service is stopping.
    Stop,
}

/// The pair of state and event that the diagram has no edge for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("illegal service transition: {event:?} in {state:?}")]
pub struct IllegalTransition {
    /// The state the event arrived in.
    pub state: ServiceState,
    /// The refused event.
    pub event: ServiceEvent,
}

/// The state `event` moves `state` to, or the refusal. Implements exactly the §3.12 diagram: a lock is taken from Ready
/// and from Unavailable, so the owner can clear the vault identity an Unavailable service keeps without stopping it.
pub fn next(state: ServiceState, event: ServiceEvent) -> Result<ServiceState, IllegalTransition> {
    use ServiceEvent as E;
    use ServiceState as S;
    match (state, event) {
        (S::Starting, E::InteractiveUnlockRequired) => Ok(S::Locked),
        (S::Starting, E::HostUnlockSucceeded) => Ok(S::Checking),
        (S::Locked, E::UnlockSucceeded) => Ok(S::Checking),
        (S::Checking, E::CheckPassed) => Ok(S::Ready),
        (S::Checking, E::CheckFailed(reason)) => Ok(S::Unavailable(reason)),
        (S::Ready, E::Reload | E::ApprovalCommitting) => Ok(S::Checking),
        (S::Ready, E::Lock) => Ok(S::Locked),
        (S::Ready, E::Stop) => Ok(S::Stopped),
        (S::Unavailable(_), E::Repaired) => Ok(S::Checking),
        (S::Unavailable(_), E::Lock) => Ok(S::Locked),
        _ => Err(IllegalTransition { state, event }),
    }
}

/// What the request interface does with a request in a given state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestInterface {
    /// Authenticate, authorize and forward.
    Serve,
    /// Answer `503` with the redacted reason, before authenticating anyone.
    Refuse(UnavailableReason),
    /// No request interface: the service has stopped.
    Closed,
}

/// Whether the request listener set comes from the unverified or the verified configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerProvenance {
    /// Named in the unverified `config.toml`; the listeners answer only `503`.
    Provisional,
    /// Named in the verified configuration.
    Approved,
}

/// A class of admin command, as the state gate sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminOperation {
    /// Liveness check.
    Ping,
    /// Report service, vault and approval status.
    Status,
    /// Supply the unlock input.
    Unlock,
    /// Clear the in-memory vault identity.
    Lock,
    /// Reload the configuration.
    Reload,
    /// Approve a new configuration; also the way out of an invalid policy.
    Approve,
    /// Authorized repair or recovery of a committed transaction.
    Repair,
    /// Change the vault: credentials, recipients, export and import.
    VaultChange,
    /// Create the vault and approve the initial config. It leaves the service Locked, so it needs no edge of its own.
    Initialize,
    /// Generate a fresh caller token for the owner. It touches neither the vault nor the policy, so it is allowed while
    /// Locked or Unavailable too: the owner can prepare the config that fixes an invalid policy.
    IssueCallerToken,
}

impl ServiceState {
    /// What the request interface does in this state. Only Ready serves.
    pub const fn request_interface(self) -> RequestInterface {
        match self {
            Self::Ready => RequestInterface::Serve,
            Self::Starting | Self::Locked => RequestInterface::Refuse(UnavailableReason::Locked),
            Self::Checking => RequestInterface::Refuse(UnavailableReason::Checking),
            Self::Unavailable(reason) => RequestInterface::Refuse(UnavailableReason::from_failure(reason)),
            Self::Stopped => RequestInterface::Closed,
        }
    }

    /// Whether the admin interface accepts `operation` in this state. Status, ping and issuing a caller token are always
    /// answered while the service runs; every operation that needs the vault waits for Ready, and approving is also offered for an invalid policy, and repair only for damaged state.
    /// Initializing is offered only while Locked, the state a service without a vault starts in.
    /// Lock is offered wherever the vault identity is kept outside Checking: Ready and Unavailable.
    pub const fn admin_allows(self, operation: AdminOperation) -> bool {
        use AdminOperation as A;
        match (self, operation) {
            (Self::Stopped, _) => false,
            (_, A::Ping | A::Status | A::IssueCallerToken) => true,
            (Self::Locked, A::Unlock | A::Initialize) => true,
            (Self::Ready, A::Lock | A::Reload | A::Approve | A::VaultChange) => true,
            (Self::Unavailable(_), A::Lock) => true,
            (Self::Unavailable(FailureReason::PolicyInvalid), A::Approve) => true,
            (Self::Unavailable(FailureReason::RecoveryNeeded), A::Repair) => true,
            _ => false,
        }
    }

    /// Where the request listener set comes from, or `None` once the listeners are closed. Only Ready is approved.
    pub const fn listener_provenance(self) -> Option<ListenerProvenance> {
        match self {
            Self::Ready => Some(ListenerProvenance::Approved),
            Self::Stopped => None,
            _ => Some(ListenerProvenance::Provisional),
        }
    }
}
