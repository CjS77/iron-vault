// SPDX-License-Identifier: MPL-2.0
//! The vault change summary ([glossary: *Vault change summary*][gl], [design][design]): the service's own account of one
//! `replace` or `rm`, which the owner reads before owner presence ([spec §5][s5]). The CLI's display of it
//! is never evidence of what the owner authorized.
//!
//! It is pure: the service context builds it under the service-wide lock, from the served policy and its credential
//! report, so it stays true until the write. It holds names, record IDs, kinds and origins only, never material. Every
//! configured name it prints follows the name rule (`[a-z0-9_-]`) and every host is validated, so nothing in it needs the
//! escaping a free-text value would ([§18][s18]).
//!
//! [gl]: ../../../design/glossary.md#terms
//! [design]: ../../../design/credential-commands.md#vault-change-summary
//! [s5]: ../../../design/iron-vault-specification.md#5-service-and-cli-separation-of-concerns
//! [s18]: ../../../design/iron-vault-specification.md#18-logging

use std::fmt;

use iron_vault_policy::{ActivePolicy, CallerName, Host, Port, RouteName, UnavailableCause};

use crate::service_context::CurrentRecord;
use crate::standing::{CredentialStanding, Standing};
use crate::vault_change_check::PlannedChange;

/// What one `replace` or `rm` changes, as the owner is shown it before owner presence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultChangeSummary {
    change: PlannedChange,
    current: CurrentRecord,
    routes: Vec<RouteUse>,
    available_again: Vec<RouteName>,
}

/// One route of the active config that uses the changed name, with the callers it is granted to, in name order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteUse {
    /// The route.
    pub route: RouteName,
    /// The callers the active config grants the route.
    pub callers: Vec<CallerName>,
}

impl VaultChangeSummary {
    /// Builds the summary of `change` to `current`, whose standing in the service's credential report is `before`, with the
    /// routes `policy` has that use it. Only a damaged record's routes can become available again: a healthy record makes
    /// none unavailable, and a route that also has a pinned CA fault stays unavailable.
    pub fn new(change: PlannedChange, current: CurrentRecord, before: &CredentialStanding, policy: &ActivePolicy) -> Self {
        let config = policy.config();
        let routes = config
            .routes()
            .iter()
            .filter(|(_, route)| route.credential() == change.name())
            .map(|(route, _)| RouteUse {
                route: route.clone(),
                callers: config
                    .callers()
                    .iter()
                    .filter(|(_, caller)| caller.routes().contains(route))
                    .map(|(name, _)| name.clone())
                    .collect(),
            })
            .collect();
        let available_again = before
            .unavailable_routes
            .iter()
            .filter(|route| !policy.is_unavailable_for(route, UnavailableCause::PinnedCaUnavailable))
            .cloned()
            .collect();
        Self {
            change,
            current,
            routes,
            available_again,
        }
    }

    /// The change the summary describes.
    pub fn change(&self) -> &PlannedChange {
        &self.change
    }

    /// The record the change supersedes or removes.
    pub fn current(&self) -> &CurrentRecord {
        &self.current
    }

    /// The old kind and origins, or why they are unknown.
    fn old_kind_and_origins(&self) -> (String, String) {
        match (&self.current.standing, &self.current.summary) {
            (_, Some(summary)) => (summary.kind.as_str().to_owned(), origins_line(summary.origins.iter())),
            (Standing::Damaged(damage), None) => {
                let unknown = format!("unknown (record damaged: {damage})");
                (unknown.clone(), unknown)
            }
            (Standing::Healthy, None) => ("unknown".to_owned(), "unknown".to_owned()),
        }
    }

    fn routes_line(&self) -> String {
        if self.routes.is_empty() {
            return "none".to_owned();
        }
        let routes = self
            .routes
            .iter()
            .map(|used| format!("{} (callers: {})", used.route, names_line(&used.callers)));
        routes.collect::<Vec<_>>().join(", ")
    }
}

/// Formats the text the owner reads, one line per fact, each ending in a newline
/// ([Vault change summary](../../../design/credential-commands.md#vault-change-summary)).
impl fmt::Display for VaultChangeSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self.change.name();
        let (old_kind, old_origins) = self.old_kind_and_origins();
        match &self.change {
            PlannedChange::Replace { kind, origins, .. } => {
                writeln!(f, "replace credential {name}")?;
                writeln!(
                    f,
                    "  record: {} -> a new record ID, assigned when the change is written",
                    self.current.record_id
                )?;
                writeln!(f, "  kind: {old_kind} -> {}", kind.as_str())?;
                writeln!(f, "  origins: {old_origins} -> {}", origins_line(origins.iter()))?;
            }
            PlannedChange::Remove(_) => {
                writeln!(f, "remove credential {name}")?;
                writeln!(f, "  record: {}", self.current.record_id)?;
                writeln!(f, "  kind: {old_kind}")?;
                writeln!(f, "  origins: {old_origins}")?;
            }
        }
        writeln!(f, "  routes using {name}: {}", self.routes_line())?;
        if matches!(self.current.standing, Standing::Damaged(_)) && matches!(self.change, PlannedChange::Replace { .. }) {
            writeln!(f, "  routes available again: {}", names_line(&self.available_again))?;
        }
        Ok(())
    }
}

/// Formats origins as `host:port`, separated by `, `.
fn origins_line<'a>(origins: impl Iterator<Item = &'a (Host, Port)>) -> String {
    let origins = origins.map(|(host, port)| format!("{host}:{}", port.get()));
    origins.collect::<Vec<_>>().join(", ")
}

/// Formats names separated by `, `, or `none` when there are none.
fn names_line<N: fmt::Display>(names: &[N]) -> String {
    if names.is_empty() {
        return "none".to_owned();
    }
    names.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
}

#[cfg(test)]
mod tests;
