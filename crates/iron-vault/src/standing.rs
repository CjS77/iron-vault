//! What the config check learns about each credential and route beyond the policy: each credential's standing and each
//! route fault ([glossary: *Credential standing*, *Route fault*](../../../design/glossary.md#terms)). The status report
//! carries them, and the admin protocol encodes them; neither is defined there, so the domain does not depend on the
//! wire format.
//!
//! No type here can hold a secret value, a record digest or a CA's path, so a report built from them cannot leak one.
//! Permitted origins are held only for a healthy record, and only `list` sends them.

use iron_vault_policy::{CredentialKind, CredentialName, Host, Port, RouteName};
use iron_vault_store::RecordDamage;

/// One credential's standing and the routes it makes unavailable ([glossary: *Credential standing*](../../../design/glossary.md#terms)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialStanding {
    /// The credential's name.
    pub name: CredentialName,
    /// Whether its record loaded or is damaged.
    pub standing: Standing,
    /// The routes that cannot serve because of it, in name order; never a route unavailable only through a route fault.
    pub unavailable_routes: Vec<RouteName>,
    /// The record's kind and permitted origins. `None` for a damaged record, whose origins cannot be trusted, and in a
    /// status report, whose wire form leaves them out.
    pub summary: Option<RecordSummary>,
}

/// What `list` shows of a healthy record beyond its name: the kind and the permitted origins, never material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordSummary {
    /// The record's kind.
    pub kind: CredentialKind,
    /// The permitted origins in ascending order, at least one.
    pub origins: Vec<(Host, Port)>,
}

/// Whether a credential record can serve requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// The record loaded.
    Healthy,
    /// The manifest lists the record but it did not load.
    Damaged(RecordDamage),
}

/// A route unavailable for a cause of its own, which no credential standing explains
/// ([glossary: *Route fault*](../../../design/glossary.md#terms)).
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
