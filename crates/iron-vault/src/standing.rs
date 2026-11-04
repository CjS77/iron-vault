//! What the config check learns about each credential and route beyond the policy: each credential's standing and each
//! route fault (glossary: *Credential standing*, *Route fault*). The status report carries them, and the admin protocol
//! encodes them; neither is defined there, so the domain does not depend on the wire format.
//!
//! No type here can hold a secret value, a record digest, a permitted origin or a CA's path, so a report built from them
//! cannot leak one.

use iron_vault_policy::{CredentialName, RouteName};
use iron_vault_store::RecordDamage;

/// One credential's standing and the routes it makes unavailable (glossary: *Credential standing*).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialStanding {
    /// The credential's name.
    pub name: CredentialName,
    /// Whether its record loaded.
    pub standing: Standing,
    /// The routes that cannot serve because of it, in name order; never a route unavailable only through a route fault.
    pub unavailable_routes: Vec<RouteName>,
}

/// Whether a credential record can serve requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// The record loaded.
    Healthy,
    /// The manifest lists the record but it did not load.
    Damaged(RecordDamage),
}

/// A route unavailable for a cause of its own, which no credential standing explains (glossary: *Route fault*).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteFault {
    /// The route's name.
    pub name: RouteName,
    /// Why it is unavailable.
    pub kind: RouteFaultKind,
}

/// Why a route is unavailable, apart from its credential. It carries no path, PEM byte or load error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RouteFaultKind {
    /// The route's pinned CA could not be loaded.
    #[error("pinned CA unavailable")]
    PinnedCaUnavailable,
}
