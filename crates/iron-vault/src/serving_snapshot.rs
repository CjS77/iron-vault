// SPDX-License-Identifier: MPL-2.0
//! Holds what the request side serves with, and swaps it as one unit
//! ([spec §8](../../../design/iron-vault-specification.md#8-request-flow),
//! [§12](../../../design/iron-vault-specification.md#12-configuration-approval-and-reload)).
//!
//! A [`ServingSnapshot`] is everything one request needs: the active policy, the vault's healthy records, the upstream
//! clients and the rate limiter. The service context builds one per passed config check and stores it in the
//! [`SnapshotHolder`]; every request loads its [`Admission`] from the holder once and uses only that. So the route a
//! request was authorized against, the credential record it resolves, the client it sends with and the limiter it was
//! charged by always come from one activation.
//!
//! ```text
//!   config check passes ──→ holder.serve(B)            ──→ new requests load Serve(B)
//!                                                          requests already on A finish on A
//!   lock, failed check  ──→ holder.refuse(reason)      ──→ new requests load Refuse(reason): 503
//!                                                          A and B are withdrawn, so their requests stop
//!   approval commit     ──→ holder.pause()             ──→ new requests load Refuse(checking): 503
//!                           then resume(C) or fail(..)     requests on B finish on B, or are withdrawn on fail
//! ```
//!
//! A reload replaces the whole snapshot: requests that already loaded the old one finish on it, and none loads it after
//! the replacement. A snapshot withdrawn from its requests tells them to stop ([`ServingSnapshot::withdrawn`]).

use std::collections::VecDeque;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use iron_vault_policy::{ActivePolicy, CatalogEntry, CredentialCatalog, CredentialName, RateLimiter, RouteName, UnavailableCause};
use iron_vault_store::{ApproverId, CredentialRecord, OpenReport, RecordId, Vault};
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
    /// The approver that signed the approval the snapshot was built from, which the next approver prompt asks first.
    /// `None` only for a snapshot built without an approval, as in tests.
    signed_by: Option<ApproverId>,
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
    /// Activation records no fingerprint of its catalog, so the check uses what the policy does expose: a route is
    /// unavailable through its credential exactly when the vault holds no healthy record for it. A route unavailable
    /// only through its pinned CA has a healthy record. This catches a policy activated against another vault, or
    /// before a record was damaged or repaired: the mix that would send a request to a route with no record to resolve.
    /// It cannot tell apart two vaults with the same healthy names, and it does not compare permitted origins or kinds.
    /// The clients and the limiter carry no identity to check.
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
                signed_by: None,
                withdrawn: CancellationToken::new(),
                released: None,
            }),
        }
    }

    /// Returns the snapshot with `approver` recorded as the signer of the approval it was built from.
    pub fn signed_by(self, approver: ApproverId) -> Self {
        Self {
            signed_by: Some(approver),
            ..self
        }
    }

    /// Returns the approver that signed the active approval, or `None` when the snapshot was built without one. The
    /// next approver prompt asks this approver first.
    pub fn signer(&self) -> Option<ApproverId> {
        self.signed_by
    }

    /// Ties the snapshot to `epoch`, so ending the epoch withdraws it, and returns it with a receiver that resolves
    /// once the snapshot is dropped.
    fn in_epoch(mut self, epoch: &CancellationToken) -> (Self, oneshot::Receiver<()>) {
        let (released, dropped) = oneshot::channel();
        self.withdrawn = epoch.child_token();
        self.released = Some(released);
        (self, dropped)
    }

    /// Returns the policy requests are authorized against.
    pub fn policy(&self) -> &ActivePolicy {
        &self.policy
    }

    /// Returns the healthy record named `credential`, or `None` when it is missing or damaged. A request resolves the
    /// slot value and its permitted origins from this one record.
    pub fn record(&self, credential: &CredentialName) -> Option<&CredentialRecord> {
        self.vault.record(credential)
    }

    /// Lists every credential the vault manifest lists, in name order, with its standing and the routes that standing
    /// makes unavailable, for `status` and `list`.
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

    /// Maps every credential the vault manifest lists, damaged ones included, to its record ID, for a vault change's
    /// summary.
    pub fn record_ids(&self) -> BTreeMap<CredentialName, RecordId> {
        let entries = self.vault.manifest().entries().iter();
        entries.map(|(id, entry)| (entry.name().clone(), *id)).collect()
    }

    /// Lists the routes `credential` makes unavailable. A route unavailable only through its pinned CA is not one of
    /// them.
    fn unavailable_routes_of(&self, credential: &CredentialName) -> Vec<RouteName> {
        let routes = self.policy.config().routes().iter();
        routes
            .filter(|(route, config)| {
                config.credential() == credential && self.policy.is_unavailable_for(route, UnavailableCause::CredentialUnusable)
            })
            .map(|(route, _)| route.clone())
            .collect()
    }

    /// Lists every route unavailable for a cause of its own, in name order. In v0 the only such cause is a pinned CA
    /// that could not be loaded.
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

    /// Returns the upstream clients built for the policy.
    pub fn clients(&self) -> &UpstreamClients {
        &self.clients
    }

    /// Returns the rate limiter built for the policy.
    pub fn limiter(&self) -> &RateLimiter {
        &self.limiter
    }

    /// Completes once the holder withdraws this snapshot (on a failed check or a lock), or at once if it already has.
    /// A request running on the snapshot stops when this completes, where the transport permits
    /// ([spec §12](../../../design/iron-vault-specification.md#12-configuration-approval-and-reload)).
    pub fn withdrawn(&self) -> WaitForCancellationFutureOwned {
        self.withdrawn.clone().cancelled_owned()
    }

    /// Returns `true` if and only if the holder has withdrawn this snapshot.
    #[cfg(test)]
    pub(crate) fn is_withdrawn(&self) -> bool {
        self.withdrawn.is_cancelled()
    }
}

/// The catalog of the vault the snapshot's policy was activated against. The vault change check overlays its planned
/// change on this catalog, and activates the approved config against the result.
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
/// A plain lock guards that one value. The lock is held only to clone or store it, so a request never waits on
/// another's work. A request's load and every store each take the lock once, so a request sees exactly one value, and
/// no request is admitted to a snapshot after a store that replaced it.
///
/// Callers must store, on every service state transition, the value that the new state's
/// [`request_interface`](crate::service_state::ServiceState::request_interface) names, so the reason a `503` carries
/// has one source.
///
/// Every snapshot served belongs to one withdrawal epoch. Storing any refusal but
/// [`Checking`](UnavailableReason::Checking) ends the epoch: every snapshot served since the last such refusal is
/// withdrawn, including an old one a request is still streaming from after a reload, and the next snapshot starts a new
/// epoch. *Checking* withdraws nothing, because a check that passes ends on a new snapshot, and the requests admitted
/// before the pause finish on the old one.
///
/// For example: serve A, then serve B after a reload, then refuse `locked`. The lock withdraws both A and B, because a
/// long download admitted under A may still be running.
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
    /// Creates a holder that serves `snapshot`.
    pub fn new(snapshot: ServingSnapshot) -> Self {
        let holder = Self::refusing(UnavailableReason::Checking);
        holder.serve(snapshot);
        holder
    }

    /// Creates a holder that refuses with `reason` until a snapshot is served, for a service that has none yet.
    pub fn refusing(reason: UnavailableReason) -> Self {
        Self {
            current: RwLock::new(Held {
                admission: Admission::Refuse(reason),
                epoch: CancellationToken::new(),
                served: VecDeque::new(),
            }),
        }
    }

    /// Returns the request's admission. The proxy handler calls this once per request, before it identifies the caller,
    /// and keeps the result to the end of the request.
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
    /// snapshot served, so no old route policy is kept
    /// ([spec §12](../../../design/iron-vault-specification.md#12-configuration-approval-and-reload)), and returns
    /// them for the caller to wait on; *checking* withdraws none and returns an empty [`Withdrawn`].
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
    /// While serving, this is one store of *refuse* `checking` (glossary: *Admission pause*). A holder that already
    /// refuses keeps its reason and still returns the guard: nothing is admitted, so there is nothing to pause. That is
    /// the case for an approval from Unavailable with `PolicyInvalid`.
    ///
    /// The store's approval commit takes the guard by reference, so it cannot run without the pause in place.
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
    /// A request that ignores its cancellation holds its snapshot until it ends. So the wait is bounded, and the
    /// caller reports a non-zero count and does not claim the secrets are cleared
    /// ([spec §12](../../../design/iron-vault-specification.md#12-configuration-approval-and-reload),
    /// [§14](../../../design/iron-vault-specification.md#14-recipients-startup-and-memory)).
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
/// Dropping it without ending the pause leaves the holder refusing, with *checking* if it was serving. So an error path
/// that forgets to end the pause keeps the service closed, and never reopens it on a policy nobody checked.
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
