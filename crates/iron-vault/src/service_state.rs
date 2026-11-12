//! The service state model from [spec §15](../../../design/iron-vault-specification.md#15-service-states-and-errors):
//! the states the service can be in, the events that move it between them, and what each state lets callers and the
//! owner do. The service context drives it; every transition it makes goes through [`next`], so the service cannot
//! take a transition the spec's diagram lacks, such as a silent fallback from Locked to weaker storage.
//!
//! Everything here is pure: no I/O, no locks, no clock.
//!
//! ```text
//!   ┌──────────┐  HostUnlockSucceeded
//!   │ Starting │ ──────────────────────────────┐
//!   └──────────┘                               │
//!        │ InteractiveUnlockRequired           ↓
//!        ↓                               ┌──────────┐   CheckPassed    ┌───────┐   Stop   ┌─────────┐
//!   ┌────────┐     UnlockSucceeded       │          │ ───────────────→ │       │ ───────→ │ Stopped │
//!   │ Locked │ ────────────────────────→ │ Checking │                  │ Ready │          └─────────┘
//!   └────────┘                           │          │ ←─────────────── │       │
//!      ↑  ↑                              └──────────┘  Reload,         └───────┘
//!      │  │                                │      ↑    ApprovalCommitting,  │
//!      │  │                    CheckFailed │      │    VaultChanged         │
//!      │  │                                ↓      │ Repaired                │
//!      │  │                              ┌─────────────┐                    │
//!      │  └─────────── Lock ──────────── │ Unavailable │                    │
//!      │                                 └─────────────┘                    │
//!      └──────────────────────────────────── Lock ──────────────────────────┘
//! ```
//!
//! Only Ready serves requests ([`ServiceState::request_interface`]); every other state answers `503` with a fixed
//! reason such as `locked` or `checking`. [`ServiceState::admin_allows`] decides which admin commands each state
//! accepts.
//!
//! # Listeners before Ready
//!
//! While Locked the service cannot verify its configuration, because `approval.age` is sealed to the vault identity.
//! It still binds the request listeners named in the **unverified** `config.toml`, so callers receive an explicit `503`
//! and not a refused connection. That is safe because a request listener unlocks nothing: unlock happens only over the
//! admin socket, after the admin-principal check. In every state other than Ready a request listener answers only `503`
//! with the redacted reason; it never authenticates a caller, selects a route or resolves a credential. On entering
//! Ready the service rebuilds the listener set from the verified configuration, so an unapproved listener never serves
//! credentials.
//!
//! This leaves a risk the design accepts: until Ready, a swapped `config.toml` can open an extra port, expose the HTTP
//! and TLS code on it, take a port another service needs, or tell a remote host that the vault is locked.
//! [`ServiceState::listener_provenance`] records which listener set a state has.

#[cfg(test)]
mod tests;

/// Why a config check left the service Unavailable: the "invalid policy or damaged shared state" of
/// [spec §15](../../../design/iron-vault-specification.md#15-service-states-and-errors).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureReason {
    /// The configuration or its approval did not verify.
    PolicyInvalid,
    /// Shared state is damaged, or a committed transaction could not be completed; only repair or recovery clears it.
    RecoveryNeeded,
}

/// The fixed, redacted reason a request listener gives with a `503`. It names a category and nothing else: never a
/// path, a route or a credential.
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
    /// Returns the fixed text a `503` body carries: `locked`, `policy invalid`, `checking` or `recovery needed`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Locked => "locked",
            Self::PolicyInvalid => "policy invalid",
            Self::Checking => "checking",
            Self::RecoveryNeeded => "recovery needed",
        }
    }

    /// Returns the reason a request listener gives while the service is Unavailable for `reason`.
    pub const fn from_failure(reason: FailureReason) -> Self {
        match reason {
            FailureReason::PolicyInvalid => Self::PolicyInvalid,
            FailureReason::RecoveryNeeded => Self::RecoveryNeeded,
        }
    }
}

/// Where the service is in its life
/// ([spec §15](../../../design/iron-vault-specification.md#15-service-states-and-errors)). See the module
/// documentation for the diagram.
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
    /// Terminal: the process stopped from Ready and cleared its memory. The spec draws this as the diagram's end, not
    /// as a state; it is a variant here so that the final edge is an ordinary transition.
    Stopped,
}

/// Something that happens to the service and may move it to another state.
///
/// Configured key removal (Ready to Locked in
/// [spec §15](../../../design/iron-vault-specification.md#15-service-states-and-errors)) belongs to the YubiKey
/// phase. Its event will be `KeyRemoved`, and it is not defined yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceEvent {
    /// Startup found that an interactive unlock is required.
    InteractiveUnlockRequired,
    /// A host unlock succeeded at startup: in the `Protected` and `Container` profiles, the unlock handoff opened the
    /// vault. TPM unlock reaches the service as a host unlock, so it sends this event too.
    HostUnlockSucceeded,
    /// An authorized unlock succeeded.
    UnlockSucceeded,
    /// A check passed: storage and the current approval verify.
    CheckPassed,
    /// A check failed.
    CheckFailed(FailureReason),
    /// An explicit reload was requested.
    Reload,
    /// A config approval started from Ready is about to commit, so the admission pause begins. It takes the diagram's
    /// one edge from Ready to Checking, as [`Reload`](Self::Reload) does, but is a separate event so that *reload*
    /// keeps its one meaning: the SIGHUP operation.
    ApprovalCommitting,
    /// `replace` or `rm` committed a vault change from Ready, and the config check must bring it to serving
    /// ([credential commands: Reaching serving](../../../design/credential-commands.md#reaching-serving)). It takes the
    /// diagram's one edge from Ready to Checking too, as a separate event so that a failed check after a vault change
    /// is never logged as a failed reload.
    VaultChanged,
    /// An explicit lock was requested.
    Lock,
    /// An authorized repair, or recovery of a committed transaction, finished. A config approval committed from
    /// Unavailable with [`FailureReason::PolicyInvalid`] sends this event too, as the diagram's "authorized repair", so
    /// approving needs no edge of its own.
    Repaired,
    /// The service is stopping.
    Stop,
}

/// An event that arrived in a state the diagram draws no edge out of for it. The state does not change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("illegal service transition: {event:?} in {state:?}")]
pub struct IllegalTransition {
    /// The state the event arrived in.
    pub state: ServiceState,
    /// The refused event.
    pub event: ServiceEvent,
}

/// Returns the state `event` moves `state` to, or [`IllegalTransition`] when the diagram has no such edge.
///
/// It implements exactly the [spec §15](../../../design/iron-vault-specification.md#15-service-states-and-errors)
/// diagram. For example, `Lock` moves Ready or Unavailable to Locked, so the owner can clear the vault identity an
/// Unavailable service keeps without stopping it; `Lock` in Checking is refused.
pub fn next(state: ServiceState, event: ServiceEvent) -> Result<ServiceState, IllegalTransition> {
    use ServiceEvent as E;
    use ServiceState as S;
    match (state, event) {
        (S::Starting, E::InteractiveUnlockRequired) => Ok(S::Locked),
        (S::Starting, E::HostUnlockSucceeded) => Ok(S::Checking),
        (S::Locked, E::UnlockSucceeded) => Ok(S::Checking),
        (S::Checking, E::CheckPassed) => Ok(S::Ready),
        (S::Checking, E::CheckFailed(reason)) => Ok(S::Unavailable(reason)),
        (S::Ready, E::Reload | E::ApprovalCommitting | E::VaultChanged) => Ok(S::Checking),
        (S::Ready, E::Lock) => Ok(S::Locked),
        (S::Ready, E::Stop) => Ok(S::Stopped),
        (S::Unavailable(_), E::Repaired) => Ok(S::Checking),
        (S::Unavailable(_), E::Lock) => Ok(S::Locked),
        _ => Err(IllegalTransition { state, event }),
    }
}

/// What the request interface does with a request in a given state, as [`ServiceState::request_interface`] answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestInterface {
    /// Authenticate, authorize and forward.
    Serve,
    /// Answer `503` with the redacted reason, before authenticating anyone.
    Refuse(UnavailableReason),
    /// No request interface: the service has stopped.
    Closed,
}

/// Which configuration the request listener set comes from: the unverified `config.toml` or the verified config
/// (glossary: *Listener provenance*).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerProvenance {
    /// Named in the unverified `config.toml`; the listeners answer only `503`.
    Provisional,
    /// Named in the verified configuration.
    Approved,
}

/// A class of admin command, as [`ServiceState::admin_allows`] sees it. Several commands share one class: for example
/// `add`, `replace`, `rm`, `export`, `forget-machine` and every `recipient` and `approver` command are a
/// [`VaultChange`](Self::VaultChange).
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
    /// Change the vault: credentials, recipients, approvers and export.
    VaultChange,
    /// Create the vault and approve the initial config, for `init` and `import`. It leaves the service Locked, so it
    /// needs no edge of its own.
    Initialize,
    /// Generate a fresh caller token for the owner. It touches neither the vault nor the policy, so it is allowed while
    /// Locked or Unavailable too: the owner can prepare the config that fixes an invalid policy.
    IssueCallerToken,
    /// Prove that the owner's recovery key opens the vault. It changes no service state and keeps no key, so it is
    /// allowed while Locked, where it is most useful, and Ready.
    RecoveryCheck,
    /// Discard the vault and the config ([reset](../../../design/reset.md)). It is the way out when no owner factor
    /// works, so it is offered wherever the service has started: Locked, Ready and Unavailable. It locks first, which
    /// sends `Lock` from Ready and Unavailable; from Locked there is nothing to withdraw. So it needs no edge of its
    /// own.
    Reset,
}

impl ServiceState {
    /// Returns what the request interface does in this state. Only Ready serves; Starting refuses as Locked does, and
    /// Stopped has no request interface.
    pub const fn request_interface(self) -> RequestInterface {
        match self {
            Self::Ready => RequestInterface::Serve,
            Self::Starting | Self::Locked => RequestInterface::Refuse(UnavailableReason::Locked),
            Self::Checking => RequestInterface::Refuse(UnavailableReason::Checking),
            Self::Unavailable(reason) => RequestInterface::Refuse(UnavailableReason::from_failure(reason)),
            Self::Stopped => RequestInterface::Closed,
        }
    }

    /// Returns `true` if and only if the admin interface accepts `operation` in this state.
    ///
    /// ```text
    /// operation                        Starting  Locked  Checking  Ready  Unavailable          Stopped
    /// Ping, Status, IssueCallerToken   yes       yes     yes       yes    yes                  no
    /// Unlock, Initialize               no        yes     no        no     no                   no
    /// RecoveryCheck                    no        yes     no        yes    no                   no
    /// Reset                            no        yes     no        yes    yes                  no
    /// Lock                             no        no      no        yes    yes                  no
    /// Reload, VaultChange              no        no      no        yes    no                   no
    /// Approve                          no        no      no        yes    PolicyInvalid only   no
    /// Repair                           no        no      no        no     RecoveryNeeded only  no
    /// ```
    ///
    /// Initializing is offered only while Locked, the state a service without a vault starts in. Lock is offered
    /// wherever the vault identity is kept outside Checking.
    pub const fn admin_allows(self, operation: AdminOperation) -> bool {
        use AdminOperation as A;
        match (self, operation) {
            (Self::Stopped, _) => false,
            (_, A::Ping | A::Status | A::IssueCallerToken) => true,
            (Self::Locked, A::Unlock | A::Initialize) => true,
            (Self::Locked | Self::Ready, A::RecoveryCheck) => true,
            (Self::Locked | Self::Ready | Self::Unavailable(_), A::Reset) => true,
            (Self::Ready, A::Lock | A::Reload | A::Approve | A::VaultChange) => true,
            (Self::Unavailable(_), A::Lock) => true,
            (Self::Unavailable(FailureReason::PolicyInvalid), A::Approve) => true,
            (Self::Unavailable(FailureReason::RecoveryNeeded), A::Repair) => true,
            _ => false,
        }
    }

    /// Returns where the request listener set comes from: `Approved` in Ready, `Provisional` in every other running
    /// state, and `None` once Stopped has closed the listeners.
    pub const fn listener_provenance(self) -> Option<ListenerProvenance> {
        match self {
            Self::Ready => Some(ListenerProvenance::Approved),
            Self::Stopped => None,
            _ => Some(ListenerProvenance::Provisional),
        }
    }
}
