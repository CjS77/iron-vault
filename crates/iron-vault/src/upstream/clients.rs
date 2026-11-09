//! The upstream clients for one active policy: one per upstream trust its routes use (specification §10).
//!
//! Built once when a policy is activated, so a request never builds a client or reads a CA file. Routes with the
//! built-in roots share one client, and routes that pin the same CA file share that file's client.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use iron_vault_policy::{ActivePolicy, RouteName};

use super::client::{ClientBuildError, TransportLimits, UpstreamClient};
use super::trust::{PinnedCaError, UpstreamTrust};
use crate::audit::AuditEvent;
use crate::audit::route::PinnedCaUnavailable;
use crate::deployment::DeploymentProfile;
use crate::trusted_path::ExpectedOwner;

/// Each route's upstream client, keyed in name and path order so building them is deterministic.
#[derive(Debug)]
pub struct UpstreamClients {
    built_in: UpstreamClient,
    pinned: BTreeMap<PathBuf, UpstreamClient>,
    /// Each route's pinned CA path, `None` for the built-in roots, or why that CA's client failed.
    routes: BTreeMap<RouteName, Result<Option<PathBuf>, PinnedClientError>>,
}

/// Why a route's pinned CA gave no client.
#[derive(Debug, Clone, thiserror::Error)]
pub enum PinnedClientError {
    /// The pinned CA file could not be loaded.
    #[error(transparent)]
    Ca(#[from] PinnedCaError),
    /// The client over the pinned CA could not be built.
    #[error(transparent)]
    Build(#[from] ClientBuildError),
}

/// Why [`UpstreamClients::for_route`] has no client for a route.
#[derive(Debug, Clone, thiserror::Error)]
pub enum RouteClientError {
    /// The route is not a route of the policy the clients were built for.
    #[error("route {0} is not in the active policy")]
    NotAvailable(RouteName),
    /// The route's pinned CA gave no client.
    #[error("route {route} has no upstream client: {source}")]
    PinnedCa {
        /// The route.
        route: RouteName,
        /// Why its pinned CA gave no client.
        source: PinnedClientError,
    },
}

impl UpstreamClients {
    /// Builds the clients for every route of `policy`, reading each distinct pinned CA file once through its
    /// trusted-path rule.
    ///
    /// Only the built-in client failing is an error here, since no route could then be served. A pinned CA that fails
    /// gives its routes a [`RouteClientError::PinnedCa`] and leaves every other route its client. That makes only those
    /// routes unavailable, like a damaged credential record (§12): the config check passes them to
    /// [`mark_unusable_routes`](Self::mark_unusable_routes) before the policy serves, so a request to one is refused
    /// before it reaches [`for_route`](Self::for_route). A route already unavailable through its credential is tried
    /// too, so it reports both causes.
    pub fn new(
        policy: &ActivePolicy,
        profile: DeploymentProfile,
        owner: ExpectedOwner,
        limits: TransportLimits,
    ) -> Result<Self, ClientBuildError> {
        Self::build(policy, limits, |path| UpstreamTrust::pinned(path, profile, owner))
    }

    /// [`new`](Self::new) with the pinned-CA loader passed in, so integration tests can pin a test CA without a
    /// trusted path on disk. The `test-support` feature that exposes it is enabled only by this crate's own
    /// dev-dependency.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_pinned_loader(
        policy: &ActivePolicy,
        limits: TransportLimits,
        load_pinned: impl Fn(&Path) -> Result<UpstreamTrust, PinnedCaError>,
    ) -> Result<Self, ClientBuildError> {
        Self::build(policy, limits, load_pinned)
    }

    /// The client for `route`.
    pub fn for_route(&self, route: &RouteName) -> Result<&UpstreamClient, RouteClientError> {
        match self.routes.get(route) {
            None => Err(RouteClientError::NotAvailable(route.clone())),
            Some(Err(source)) => Err(RouteClientError::PinnedCa {
                route: route.clone(),
                source: source.clone(),
            }),
            Some(Ok(None)) => Ok(&self.built_in),
            // Unreachable by construction: `build` records `Ok(Some(path))` only for a path whose client it loaded into
            // `pinned`; a path that failed to load is recorded as the error above.
            Some(Ok(Some(path))) => self.pinned.get(path).ok_or_else(|| RouteClientError::NotAvailable(route.clone())),
        }
    }

    /// The routes whose pinned CA gave no client, in name order, with the reason.
    pub fn unusable_routes(&self) -> impl Iterator<Item = (&RouteName, &PinnedClientError)> {
        self.routes
            .iter()
            .filter_map(|(route, client)| client.as_ref().err().map(|error| (route, error)))
    }

    /// `policy` with every route whose pinned CA gave no client also unavailable for that cause, each logged at WARN.
    ///
    /// The event names the route and the `ca_file` field, never the path, the PEM bytes or the load error.
    pub fn mark_unusable_routes(&self, policy: ActivePolicy) -> ActivePolicy {
        let unusable: Vec<&RouteName> = self.unusable_routes().map(|(route, _)| route).collect();
        unusable.iter().for_each(|route| {
            PinnedCaUnavailable { route }.emit();
        });
        policy.with_pinned_ca_unavailable(unusable)
    }

    /// [`new`](Self::new) with the pinned-CA loader passed in, so it is testable without a trusted path on disk.
    fn build(
        policy: &ActivePolicy,
        limits: TransportLimits,
        load_pinned: impl Fn(&Path) -> Result<UpstreamTrust, PinnedCaError>,
    ) -> Result<Self, ClientBuildError> {
        let built_in = UpstreamClient::new(&UpstreamTrust::BuiltIn, limits)?;
        let ca_files = route_ca_files(policy);
        let loaded: BTreeMap<PathBuf, Result<UpstreamClient, PinnedClientError>> = ca_files
            .values()
            .flatten()
            .copied()
            .collect::<BTreeSet<&Path>>()
            .into_iter()
            .map(|path| (path.to_path_buf(), pinned_client(path, limits, &load_pinned)))
            .collect();
        let routes = ca_files
            .into_iter()
            .map(|(route, path)| (route.clone(), route_entry(path, &loaded)))
            .collect();
        let pinned = loaded
            .into_iter()
            .filter_map(|(path, client)| client.ok().map(|client| (path, client)))
            .collect();
        Ok(Self { built_in, pinned, routes })
    }
}

/// Each route's pinned CA path, `None` for the built-in roots.
fn route_ca_files(policy: &ActivePolicy) -> BTreeMap<&RouteName, Option<&Path>> {
    policy
        .config()
        .routes()
        .iter()
        .map(|(name, route)| (name, route.ca_file().map(|ca_file| ca_file.as_path())))
        .collect()
}

fn pinned_client(
    path: &Path,
    limits: TransportLimits,
    load_pinned: impl Fn(&Path) -> Result<UpstreamTrust, PinnedCaError>,
) -> Result<UpstreamClient, PinnedClientError> {
    let trust = load_pinned(path)?;
    Ok(UpstreamClient::new(&trust, limits)?)
}

/// A route's entry: its CA path, or a copy of the error its CA's client failed with. A pinned route never falls back
/// to the built-in roots.
fn route_entry(
    path: Option<&Path>,
    loaded: &BTreeMap<PathBuf, Result<UpstreamClient, PinnedClientError>>,
) -> Result<Option<PathBuf>, PinnedClientError> {
    path.map(|path| match loaded.get(path) {
        Some(Err(error)) => Err(error.clone()),
        _ => Ok(path.to_path_buf()),
    })
    .transpose()
}

#[cfg(test)]
mod tests;
