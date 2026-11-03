//! The serving snapshot: everything one request is served with, swapped as a unit (specification §3.5, §3.9).
//!
//! A request takes the snapshot once with [`SnapshotHolder::load`] and uses only that, so the route it was authorized
//! against, the credential record it resolves, the client it sends with and the limiter it was charged by always come
//! from one activation. A reload replaces the whole snapshot; requests that already loaded the old one finish on it,
//! and none loads it after the replacement.

use std::sync::{Arc, PoisonError, RwLock};

use iron_vault_policy::{ActivePolicy, CredentialName, RateLimiter, RouteName};
use iron_vault_store::{CredentialRecord, Vault};

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
}

/// Why a policy and a vault cannot form one snapshot.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SnapshotError {
    /// The policy's availability for a route disagrees with whether the vault holds a healthy record for its credential,
    /// so the policy was activated against another vault or against this vault in another state.
    #[error("route {route} is {} in the policy, but the vault {} a healthy record for its credential", availability(*.available), holds(*.available))]
    PolicyVaultMismatch {
        /// The route whose availability disagrees.
        route: RouteName,
        /// What the policy says: `true` when the route is available.
        available: bool,
    },
}

fn availability(available: bool) -> &'static str {
    if available { "available" } else { "unavailable" }
}

fn holds(available: bool) -> &'static str {
    if available { "has no" } else { "holds" }
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
            Some((route, available, _)) => Err(SnapshotError::PolicyVaultMismatch {
                route: route.clone(),
                available,
            }),
            None => Ok(Self {
                policy,
                vault,
                clients,
                limiter,
            }),
        }
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
}

/// The snapshot new requests are served with.
///
/// A lock around an `Arc` rather than an atomic pointer: the lock is held only to clone or swap the `Arc`, so a
/// request never waits on another's work, and it adds no dependency.
#[derive(Debug)]
pub struct SnapshotHolder {
    current: RwLock<Arc<ServingSnapshot>>,
}

impl SnapshotHolder {
    /// A holder whose current snapshot is `snapshot`.
    pub fn new(snapshot: ServingSnapshot) -> Self {
        Self {
            current: RwLock::new(Arc::new(snapshot)),
        }
    }

    /// The current snapshot. The pipeline calls this once per request and keeps the result to the end of the request.
    pub fn load(&self) -> Arc<ServingSnapshot> {
        // A poisoned lock still holds a whole `Arc`, since the guarded code only clones or assigns one.
        Arc::clone(&self.current.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Makes `snapshot` the one every later [`load`](Self::load) returns; requests holding the old one are unaffected.
    ///
    /// Nothing calls this yet: reload (EP-22) is its only intended caller.
    pub fn replace(&self, snapshot: ServingSnapshot) {
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(snapshot);
    }
}

#[cfg(test)]
mod tests;
