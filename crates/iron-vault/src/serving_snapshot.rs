//! The serving snapshot: everything one request is served with, swapped as a unit (specification §3.5, §3.9).
//!
//! A request takes its [`Admission`] once with [`SnapshotHolder::load`] and uses only that, so the route it was
//! authorized against, the credential record it resolves, the client it sends with and the limiter it was charged by
//! always come from one activation. A reload replaces the whole snapshot; requests that already loaded the old one finish
//! on it, and none loads it after the replacement. When no snapshot is held, the admission is a refusal with a redacted
//! reason, and a snapshot withdrawn from its requests tells them to stop ([`ServingSnapshot::withdrawn`]).

use std::collections::VecDeque;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use iron_vault_policy::{ActivePolicy, CatalogEntry, CredentialCatalog, CredentialName, RateLimiter, RouteName, UnavailableCause};
use iron_vault_store::{CredentialRecord, OpenReport, RecordId, Vault};
use tokio::sync::oneshot;
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};

use crate::service_state::{FailureReason, UnavailableReason};
use crate::standing::{CredentialStanding, RecordSummary, RouteFault, RouteFaultKind, Standing};
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
    /// Dropped with the snapshot, and declared last so that every other field, the vault among them, is already dropped
    /// when the holder's [`Withdrawn`] sees it go.
    released: Option<oneshot::Sender<()>>,
}

/// Why a policy and a vault cannot form one snapshot: whether a route is unavailable through its credential disagrees
/// with whether the vault holds a healthy record for it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SnapshotError {
    /// The policy does not mark the route's credential unusable, but the vault has no healthy record for it, so a
    /// request could reach the route with nothing to resolve.
    #[error("route {route} is available in the policy, but the vault has no healthy record for its credential")]
    AvailableWithoutRecord {
        /// The route whose availability disagrees.
        route: RouteName,
    },
    /// The policy marks the route's credential unusable, but the vault holds a healthy record for it, so the policy
    /// was activated against another vault or this vault in another state.
    #[error("route {route} is unavailable in the policy, but the vault holds a healthy record for its credential")]
    UnavailableWithRecord {
        /// The route whose availability disagrees.
        route: RouteName,
    },
}

/// The kind and permitted origins of a healthy record, without its material.
fn summary_of(record: &CredentialRecord) -> RecordSummary {
    RecordSummary {
        kind: record.kind(),
        origins: record.origins().iter().cloned().collect(),
    }
}

impl ServingSnapshot {
    /// Joins the four parts, after checking that `policy` was activated against `vault`'s catalog.
    ///
    /// Activation records no fingerprint of its catalog, so the check is the one the policy does expose: a route is
    /// unavailable through its credential exactly when the vault holds no healthy record for it. A route unavailable
    /// only through its pinned CA has a healthy record. That catches a policy activated
    /// against another vault or before a record was damaged or repaired, which is the mix that would send a request to
    /// a route with no record to resolve. It cannot tell two vaults with the same healthy names apart, and it does not
    /// compare permitted origins or kinds; the clients and the limiter carry no identity to check at all.
    pub fn new(policy: ActivePolicy, vault: Vault, clients: UpstreamClients, limiter: RateLimiter) -> Result<Self, SnapshotError> {
        let mismatch = policy
            .config()
            .routes()
            .iter()
            .map(|(name, route)| {
                let usable = !policy.is_unavailable_for(name, UnavailableCause::CredentialUnusable);
                (name, usable, vault.record(route.credential()).is_some())
            })
            .find(|(_, usable, healthy)| usable != healthy);
        match mismatch {
            Some((route, true, _)) => Err(SnapshotError::AvailableWithoutRecord { route: route.clone() }),
            Some((route, false, _)) => Err(SnapshotError::UnavailableWithRecord { route: route.clone() }),
            None => Ok(Self {
                policy,
                vault,
                clients,
                limiter,
                withdrawn: CancellationToken::new(),
                released: None,
            }),
        }
    }

    /// The snapshot, withdrawn with every other snapshot of `epoch`, and the signal that it has been dropped.
    fn in_epoch(mut self, epoch: &CancellationToken) -> (Self, oneshot::Receiver<()>) {
        let (released, dropped) = oneshot::channel();
        self.withdrawn = epoch.child_token();
        self.released = Some(released);
        (self, dropped)
    }

    /// The policy requests are authorized against.
    pub fn policy(&self) -> &ActivePolicy {
        &self.policy
    }

    /// The healthy record named `credential`, for resolving the value and its permitted origins together.
    pub fn record(&self, credential: &CredentialName) -> Option<&CredentialRecord> {
        self.vault.record(credential)
    }

    /// Every credential the vault manifest lists, in name order, with the routes its standing makes unavailable.
    ///
    /// `opened` is the report from opening this snapshot's vault: only it knows why a record did not load.
    pub fn credential_standings(&self, opened: &OpenReport) -> Vec<CredentialStanding> {
        let names = self
            .vault
            .manifest()
            .entries()
            .values()
            .map(|entry| entry.name())
            .collect::<BTreeSet<_>>();
        names
            .into_iter()
            .map(|name| CredentialStanding {
                name: name.clone(),
                standing: opened.damaged().get(name).copied().map_or(Standing::Healthy, Standing::Damaged),
                unavailable_routes: self.unavailable_routes_of(name),
                summary: self.vault.record(name).map(summary_of),
            })
            .collect()
    }

    /// The record ID of every credential the vault manifest lists, damaged ones included, for a vault change's summary.
    pub fn record_ids(&self) -> BTreeMap<CredentialName, RecordId> {
        let entries = self.vault.manifest().entries().iter();
        entries.map(|(id, entry)| (entry.name().clone(), *id)).collect()
    }

    /// The routes `credential` makes unavailable; a route unavailable only through its pinned CA is not one of them.
    fn unavailable_routes_of(&self, credential: &CredentialName) -> Vec<RouteName> {
        let routes = self.policy.config().routes().iter();
        routes
            .filter(|(route, config)| {
                config.credential() == credential && self.policy.is_unavailable_for(route, UnavailableCause::CredentialUnusable)
            })
            .map(|(route, _)| route.clone())
            .collect()
    }

    /// Every route unavailable for a cause of its own, in name order: today a pinned CA that could not be loaded.
    pub fn route_faults(&self) -> Vec<RouteFault> {
        let routes = self.policy.unavailable_routes().iter();
        routes
            .filter(|(_, causes)| causes.contains(&UnavailableCause::PinnedCaUnavailable))
            .map(|(route, _)| RouteFault {
                name: route.clone(),
                kind: RouteFaultKind::PinnedCaUnavailable,
            })
            .collect()
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
    #[cfg(test)]
    pub(crate) fn is_withdrawn(&self) -> bool {
        self.withdrawn.is_cancelled()
    }
}

/// The catalog of the vault the snapshot's policy was activated against, which the vault change check overlays: it
/// answers exactly for every name the policy's routes use.
impl CredentialCatalog for ServingSnapshot {
    fn entry(&self, name: &CredentialName) -> CatalogEntry {
        self.vault.entry(name)
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

/// The value new requests are admitted by: *serve* with the current snapshot, or *refuse* with a redacted reason.
///
/// A lock around that one value rather than an atomic pointer: the lock is held only to clone or store it, so a request
/// never waits on another's work. A request's load and every store each take the lock once, so a request sees exactly one
/// value and no request is admitted to a snapshot after a store that replaced it.
///
/// Callers must store, on every service state transition, the value that the new state's
/// [`request_interface`](crate::service_state::ServiceState::request_interface) names, so the reason a `503` carries has
/// one source.
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
    /// For each snapshot served in this epoch, the signal that it has been dropped.
    served: VecDeque<oneshot::Receiver<()>>,
}

impl SnapshotHolder {
    /// A holder that serves `snapshot`.
    pub fn new(snapshot: ServingSnapshot) -> Self {
        let holder = Self::refusing(UnavailableReason::Checking);
        holder.serve(snapshot);
        holder
    }

    /// A holder that refuses with `reason` until a snapshot is served, for a service that has none yet.
    pub fn refusing(reason: UnavailableReason) -> Self {
        Self {
            current: RwLock::new(Held {
                admission: Admission::Refuse(reason),
                epoch: CancellationToken::new(),
                served: VecDeque::new(),
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
        let (snapshot, dropped) = snapshot.in_epoch(&current.epoch);
        // A receiver whose sender is gone is a snapshot already dropped; forget it so the list does not grow.
        current
            .served
            .retain_mut(|served| matches!(served.try_recv(), Err(oneshot::error::TryRecvError::Empty)));
        current.served.push_back(dropped);
        current.admission = Admission::Serve(Arc::new(snapshot));
    }

    /// Makes every later [`load`](Self::load) refuse with `reason`. Any reason but *checking* also withdraws every
    /// snapshot served, so no old route policy is kept (specification §3.9), and returns them for the caller to wait
    /// on; *checking* withdraws none and returns an empty [`Withdrawn`].
    pub fn refuse(&self, reason: UnavailableReason) -> Withdrawn {
        let mut current = self.current.write().unwrap_or_else(PoisonError::into_inner);
        let served = if reason == UnavailableReason::Checking {
            VecDeque::new()
        } else {
            std::mem::replace(&mut current.epoch, CancellationToken::new()).cancel();
            std::mem::take(&mut current.served)
        };
        current.admission = Admission::Refuse(reason);
        Withdrawn(served)
    }

    /// Starts an admission pause, after which no request is admitted until the returned guard ends the pause.
    ///
    /// While serving, this is one store of *refuse* `checking`. A holder that already refuses keeps its reason, because
    /// nothing is admitted to pause (an approval from Unavailable with `PolicyInvalid` changes no state), and still
    /// returns the guard.
    ///
    /// A commit of a new approval must take the guard by reference, so that it cannot run without the pause in place.
    pub fn pause(&self) -> AdmissionPause<'_> {
        let mut current = self.current.write().unwrap_or_else(PoisonError::into_inner);
        if matches!(current.admission, Admission::Serve(_)) {
            current.admission = Admission::Refuse(UnavailableReason::Checking);
        }
        AdmissionPause { holder: self }
    }
}

/// The snapshots a withdrawal ended: each is dropped once the last request holding it has finished.
#[derive(Debug)]
pub struct Withdrawn(VecDeque<oneshot::Receiver<()>>);

impl Withdrawn {
    /// Waits up to `within` for every snapshot to be dropped, vault included, and returns how many are still held.
    ///
    /// A request that ignores its cancellation holds its snapshot until it ends, so the wait is bounded and the caller
    /// reports a non-zero count rather than claiming the secrets are cleared (specification §3.9, §3.11).
    pub async fn released(&mut self, within: Duration) -> usize {
        // A sender dropping without a value resolves its receiver with an error, which is the signal. A receiver is
        // removed once it resolves, because polling it again would panic, and the wait can be called again.
        let all = async {
            while let Some(dropped) = self.0.front_mut() {
                let _ = dropped.await;
                self.0.pop_front();
            }
        };
        let _ = tokio::time::timeout(within, all).await;
        self.0
            .retain_mut(|dropped| matches!(dropped.try_recv(), Err(oneshot::error::TryRecvError::Empty)));
        self.0.len()
    }
}

/// Proof that new requests are not being admitted: held from the pause's start until the config check that follows ends
/// it, by [`resume`](Self::resume) or [`fail`](Self::fail).
///
/// Dropping it without ending the pause leaves the holder refusing, with *checking* if it was serving, so an error path
/// that forgets to end it keeps the service closed rather than reopening it on a policy nobody checked.
#[derive(Debug)]
#[must_use = "dropping the pause leaves requests refused"]
pub struct AdmissionPause<'a> {
    holder: &'a SnapshotHolder,
}

/// The store's approval commit takes this guard as its proof that admission is paused; it is the only production
/// implementation of [`iron_vault_store::AdmissionPaused`].
impl iron_vault_store::AdmissionPaused for AdmissionPause<'_> {}

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
