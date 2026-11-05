//! Audit events about routes and the responses they relay (`design/audit-logging.md`, "Routes and responses").

use iron_vault_policy::{CredentialName, RouteName};

use super::{AUDIT_TARGET, AuditEvent, EventName};

/// `route.pinned-ca-unavailable`: a route's pinned CA could not be loaded, so the route is unavailable. Neither the
/// path, the PEM bytes nor the load error is recorded.
#[derive(Debug, Clone, Copy)]
pub struct PinnedCaUnavailable<'a> {
    /// The unavailable route.
    pub route: &'a RouteName,
}

impl AuditEvent for PinnedCaUnavailable<'_> {
    const NAME: EventName = EventName("route.pinned-ca-unavailable");

    fn emit(&self) {
        tracing::warn!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            route = self.route.as_str(),
            config_field = "ca_file",
            "the route's pinned CA could not be loaded; the route is unavailable",
        );
    }
}

/// `response.scrubbed` (glossary: *Scrub event*): a scrub pattern matched in a relayed response. It counts matches and
/// never records the matched bytes.
#[derive(Debug, Clone, Copy)]
pub struct ResponseScrubbed<'a> {
    /// The route that relayed the response.
    pub route: &'a RouteName,
    /// The credential whose secret matched.
    pub credential: &'a CredentialName,
    /// Matches in the response's headers and body.
    pub matches: u64,
}

impl AuditEvent for ResponseScrubbed<'_> {
    const NAME: EventName = EventName("response.scrubbed");

    fn emit(&self) {
        tracing::warn!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            route = self.route.as_str(),
            credential = self.credential.as_str(),
            matches = self.matches,
            "scrubbed a secret from a response",
        );
    }
}
