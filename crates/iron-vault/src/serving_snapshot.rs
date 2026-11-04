//! The serving snapshot: everything one request is served with, swapped as a unit (specification §3.5, §3.9).
//!
//! A request takes its [`Admission`] once with [`SnapshotHolder::load`] and uses only that, so the route it was
//! authorized against, the credential record it resolves, the client it sends with and the limiter it was charged by
//! always come from one activation. A reload replaces the whole snapshot; requests that already loaded the old one finish
//! on it, and none loads it after the replacement. When no snapshot is held, the admission is a refusal with a redacted
//! reason, and a snapshot withdrawn from its requests tells them to stop ([`ServingSnapshot::withdrawn`]).

use std::sync::{Arc, PoisonError, RwLock};

use iron_vault_policy::{ActivePolicy, CredentialName, RateLimiter, RouteName};
use iron_vault_store::{CredentialRecord, Vault};
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};

use crate::service_state::{FailureReason, UnavailableReason};
use crate::upstream::clients::UpstreamClients;

/// The active policy, the vault's healthy records, the upstream clients and the rate limiter for one activation.
///
/// Immutable once built: there is no way to change any part, so a reload builds a new snapshot instead. `Debug`
/// delegates to the vault's, which shows credential names and never material.
#[derive(Debug)]
pub struct ServingSnapshot {
    policy: ActivePolicy,
    vault: Vault,
    clients: UpstreamClients,
    limiter: RateLimiter,
    /// Fired when the holder that serves the snapshot ends its epoch. A snapshot no holder serves is never withdrawn.
    withdrawn: CancellationToken,
}

/// Why a policy and a vault cannot form one snapshot: a route's availability disagrees with whether the vault holds a
/// healthy record for its credential.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SnapshotError {
    /// The policy marks the route available, but the vault has no healthy record for its credential, so a request
    /// would reach the route with nothing to resolve.
    #[error("route {route} is available in the policy, but the vault has no healthy record for its credential")]
    AvailableWithoutRecord {
        /// The route whose availability disagrees.
        route: RouteName,
    },
    /// The policy marks the route unavailable, but the vault holds a healthy record for its credential, so the
    /// policy was activated against another vault or this vault in another state.
    #[error("route {route} is unavailable in the policy, but the vault holds a healthy record for its credential")]
    UnavailableWithRecord {
        /// The route whose availability disagrees.
        route: RouteName,
    },
}

impl ServingSnapshot {
    /// Joins the four parts, after checking that `policy` was activated against `vault`'s catalog.
    ///
    /// Activation records no fingerprint of its catalog, so the check is the one the policy does expose: a route is
    /// available exactly when the vault holds a healthy record for its credential. That catches a policy activated
    /// against another vault or before a record was damaged or repaired, which is the mix that would send a request to
    /// a route with no record to resolve. It cannot tell two vaults with the same healthy names apart, and it does not
    /// compare permitted origins or kinds; the clients and the limiter carry no identity to check at all.
    pub fn new(policy: ActivePolicy, vault: Vault, clients: UpstreamClients, limiter: RateLimiter) -> Result<Self, SnapshotError> {
        let mismatch = policy
            .config()
            .routes()
            .iter()
            .map(|(name, route)| (name, policy.is_available(name), vault.record(route.credential()).is_some()))
            .find(|(_, available, healthy)| available != healthy);
        match mismatch {
            Some((route, true, _)) => Err(SnapshotError::AvailableWithoutRecord { route: route.clone() }),
            Some((route, false, _)) => Err(SnapshotError::UnavailableWithRecord { route: route.clone() }),
            None => Ok(Self {
                policy,
                vault,
                clients,
                limiter,
                withdrawn: CancellationToken::new(),
            }),
        }
    }

    /// The snapshot, withdrawn with every other snapshot of `epoch`.
    fn in_epoch(mut self, epoch: &CancellationToken) -> Self {
        self.withdrawn = epoch.child_token();
        self
    }

    /// The policy requests are authorized against.
    pub fn policy(&self) -> &ActivePolicy {
        &self.policy
    }

    /// The healthy record named `credential`, for resolving the value and its permitted origins together.
    pub fn record(&self, credential: &CredentialName) -> Option<&CredentialRecord> {
        self.vault.record(credential)
    }

    /// The upstream clients built for the policy.
    pub fn clients(&self) -> &UpstreamClients {
        &self.clients
    }

    /// The rate limiter built for the policy.
    pub fn limiter(&self) -> &RateLimiter {
        &self.limiter
    }

    /// Completes once the holder withdraws this snapshot (a failed check or a lock), and at once if it already has. A
    /// request running on the snapshot stops when it does, where the transport permits (specification §3.9).
    pub fn withdrawn(&self) -> WaitForCancellationFutureOwned {
        self.withdrawn.clone().cancelled_owned()
    }

    /// Whether the holder has withdrawn this snapshot.
    pub fn is_withdrawn(&self) -> bool {
        self.withdrawn.is_cancelled()
    }
}

/// What a request's one load from the [`SnapshotHolder`] returns, and so what it is admitted to.
#[derive(Debug, Clone)]
pub enum Admission {
    /// Serve the request from this snapshot, which it keeps to its end.
    Serve(Arc<ServingSnapshot>),
    /// Answer `503` with this reason; the request is not admitted.
    Refuse(UnavailableReason),
}

impl Admission {
    /// The snapshot to serve from, or `None` when the request is refused.
    pub fn snapshot(self) -> Option<Arc<ServingSnapshot>> {
        match self {
            Self::Serve(snapshot) => Some(snapshot),
            Self::Refuse(_) => None,
        }
    }
}

/// The value new requests are admitted by: *serve* with the current snapshot, or *refuse* with a redacted reason.
///
/// A lock around that one value rather than an atomic pointer: the lock is held only to clone or store it, so a request
/// never waits on another's work. A request's load and every store each take the lock once, so a request sees exactly one
/// value and no request is admitted to a snapshot after a store that replaced it. Every service state transition stores
/// the value its [`request_interface`](crate::service_state::ServiceState::request_interface) names, so the reason a `503`
/// carries has one source.
///
/// Every snapshot served hangs off one withdrawal epoch. Storing any refusal but [`Checking`](UnavailableReason::Checking)
/// ends the epoch: every snapshot served since the last such refusal is withdrawn, including an old one a request is still
/// streaming from after a reload, and the next snapshot starts a new epoch. *Checking* withdraws nothing, because a check
/// that passes ends on a new snapshot and the requests admitted before the pause finish on the old one.
#[derive(Debug)]
pub struct SnapshotHolder {
    current: RwLock<Held>,
}

/// What the holder holds: the value a load returns, and the epoch the snapshots it serves belong to.
#[derive(Debug)]
struct Held {
    admission: Admission,
    epoch: CancellationToken,
}

impl SnapshotHolder {
    /// A holder that serves `snapshot`.
    pub fn new(snapshot: ServingSnapshot) -> Self {
        let epoch = CancellationToken::new();
        Self {
            current: RwLock::new(Held {
                admission: Admission::Serve(Arc::new(snapshot.in_epoch(&epoch))),
                epoch,
            }),
        }
    }

    /// A holder that refuses with `reason` until a snapshot is served, for a service that has none yet.
    pub fn refusing(reason: UnavailableReason) -> Self {
        Self {
            current: RwLock::new(Held {
                admission: Admission::Refuse(reason),
                epoch: CancellationToken::new(),
            }),
        }
    }

    /// The request's admission. The proxy handler calls this once per request, before identifying the caller, and keeps
    /// the result to the end of the request.
    pub fn load(&self) -> Admission {
        // A poisoned lock still holds a whole value, since the guarded code only clones or assigns one.
        self.current.read().unwrap_or_else(PoisonError::into_inner).admission.clone()
    }

    /// Makes `snapshot` the one every later [`load`](Self::load) returns; requests holding the old one finish on it.
    pub fn serve(&self, snapshot: ServingSnapshot) {
        let mut current = self.current.write().unwrap_or_else(PoisonError::into_inner);
        current.admission = Admission::Serve(Arc::new(snapshot.in_epoch(&current.epoch)));
    }

    /// Makes every later [`load`](Self::load) refuse with `reason`. Any reason but *checking* also withdraws every
    /// snapshot served, so no old route policy is kept (specification §3.9).
    pub fn refuse(&self, reason: UnavailableReason) {
        let mut current = self.current.write().unwrap_or_else(PoisonError::into_inner);
        if reason != UnavailableReason::Checking {
            std::mem::replace(&mut current.epoch, CancellationToken::new()).cancel();
        }
        current.admission = Admission::Refuse(reason);
    }

    /// Starts an admission pause: one store of *refuse* `checking`, after which no request is admitted until the returned
    /// guard ends the pause.
    ///
    /// The commit of a new approval takes the guard by reference, so it cannot run without the pause in place.
    pub fn pause(&self) -> AdmissionPause<'_> {
        self.refuse(UnavailableReason::Checking);
        AdmissionPause { holder: self }
    }
}

/// Proof that new requests are not being admitted: held from the pause's start until the config check that follows ends
/// it, by [`resume`](Self::resume) or [`fail`](Self::fail).
///
/// Dropping it without ending the pause leaves the holder refusing with *checking*, so an error path that forgets to end
/// it keeps the service closed rather than reopening it on a policy nobody checked.
#[derive(Debug)]
#[must_use = "dropping the pause leaves requests refused with `checking`"]
pub struct AdmissionPause<'a> {
    holder: &'a SnapshotHolder,
}

impl AdmissionPause<'_> {
    /// Ends the pause on a passed check: later requests are admitted to `snapshot`, and those admitted before the pause
    /// finish on the old one.
    pub fn resume(self, snapshot: ServingSnapshot) {
        self.holder.serve(snapshot);
    }

    /// Ends the pause on a failed check: later requests are refused with the failure's reason, and the old snapshot is
    /// withdrawn.
    pub fn fail(self, reason: FailureReason) {
        self.holder.refuse(UnavailableReason::from_failure(reason));
    }
}

#[cfg(test)]
pub(crate) mod tests;
