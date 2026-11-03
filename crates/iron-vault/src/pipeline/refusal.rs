//! The §3.12 answer for each pipeline refusal: one status, one fixed body, and the high-severity event for a defect.
//!
//! The table in [`PipelineRefusal::status`] is the one place a refusal becomes a status, so the rules about what a
//! refusal may reveal are reviewed together:
//!
//! - `401` names no scheme, token header or listener caller, and carries no `WWW-Authenticate`, so a client without a
//!   token learns nothing about where to look for one;
//! - `403` and `404` get different statuses and neither body names a route or a grant: §3.12 requires that `404`
//!   disclose no other caller's grants, and a constant body per status meets that;
//! - `503` carries a redacted reason: the same body whether the vault is damaged, a record is missing or a kind failed;
//! - a refusal that only a service defect can cause answers `500` "internal error".
//!
//! Every body is a constant. No body repeats caller input, a route the caller is not granted, or a library error,
//! whose text may hold a URL or a header value (§3.15).

use iron_vault_policy::{AssembleError, AuthzError, ChargeError, CredentialName, RouteName};

use super::PipelineRefusal;

const TEXT_PLAIN: &str = "text/plain; charset=utf-8";

/// What the request interface sends back for a refused request: a status, a constant `text/plain` body and, for `429`,
/// a `Retry-After` in whole seconds.
///
/// Free of HTTP-library types, so the table is tested without a server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusalResponse {
    status: u16,
    body: &'static str,
    retry_after: Option<u64>,
}

impl RefusalResponse {
    fn new(status: u16, body: &'static str) -> Self {
        Self {
            status,
            body,
            retry_after: None,
        }
    }

    /// The HTTP status.
    pub fn status(&self) -> u16 {
        self.status
    }

    /// The body, a fixed string chosen per status.
    pub fn body(&self) -> &'static str {
        self.body
    }

    /// The response headers: `Content-Type`, and `Retry-After` when rate limited. Never `WWW-Authenticate`.
    pub fn headers(&self) -> Vec<(&'static str, String)> {
        let retry_after = self.retry_after.map(|secs| ("Retry-After", secs.to_string()));
        std::iter::once(("Content-Type", TEXT_PLAIN.to_owned()))
            .chain(retry_after)
            .collect()
    }
}

impl PipelineRefusal {
    /// The HTTP status this refusal is answered with (§3.12).
    pub fn status(&self) -> u16 {
        match self {
            Self::Unauthenticated(_) => 401,
            Self::Authz(AuthzError::Forbidden { .. }) => 403,
            Self::Authz(AuthzError::NotFound) => 404,
            Self::Charge(ChargeError::Limited(_)) => 429,
            Self::Authz(AuthzError::Unavailable { .. }) | Self::NoHealthyRecord { .. } | Self::Kind(_) => 503,
            Self::Target(_) | Self::Method | Self::Sanitize(_) => 400,
            Self::Assemble(AssembleError::ForeignMarker | AssembleError::MalformedMarker) => 400,
            // §3.12 has no row for these: only a service defect reaches them, so `500` is the honest status. This list
            // and `defect()` name the same variants; a test checks that a `500` is exactly a logged defect.
            Self::Charge(ChargeError::UnknownRoute { .. } | ChargeError::NotGranted { .. })
            | Self::Assemble(
                AssembleError::NonAsciiSlotValue | AssembleError::HeaderValue(_) | AssembleError::Header(_) | AssembleError::Target(_),
            )
            | Self::FinalCheck(_) => 500,
        }
    }

    /// The full response for this refusal: its status, the constant body for that status and any `Retry-After`.
    pub fn respond(&self) -> RefusalResponse {
        let status = self.status();
        let mut response = RefusalResponse::new(status, body_for(status));
        if let Self::Charge(ChargeError::Limited(limited)) = self {
            response.retry_after = Some(limited.retry_after().as_secs());
        }
        response
    }

    /// Raises the high-severity event if this refusal is a service defect; nothing for a caller error.
    ///
    /// The event holds the route and credential names and a fixed label for the defect, never the URL, a header or a
    /// library error (§3.15). EP-26 replaces it with the audit event; keep the route, credential and defect label.
    pub fn report(&self, route: &RouteName, credential: &CredentialName) {
        if let Some(defect) = self.defect() {
            tracing::error!(severity = "high", %route, %credential, defect, "request refused by a service defect");
        }
    }

    /// A fixed label for a refusal that only a service defect can cause; `None` for a caller error or a route failure.
    fn defect(&self) -> Option<&'static str> {
        match self {
            Self::FinalCheck(error) => Some(final_check_label(error)),
            Self::Assemble(error) => assemble_label(error),
            Self::Charge(error) => charge_label(error),
            Self::Unauthenticated(_)
            | Self::Authz(_)
            | Self::NoHealthyRecord { .. }
            | Self::Kind(_)
            | Self::Target(_)
            | Self::Method
            | Self::Sanitize(_) => None,
        }
    }
}

/// The constant body for `status`, one per status the pipeline answers.
fn body_for(status: u16) -> &'static str {
    match status {
        400 => "bad request",
        401 => "unauthorized",
        403 => "forbidden",
        404 => "not found",
        429 => "too many requests",
        503 => "service unavailable",
        _ => "internal error",
    }
}

/// The variant name of a final-check failure; the variants carry nothing, so naming them discloses nothing.
fn final_check_label(error: &iron_vault_policy::FinalCheckError) -> &'static str {
    use iron_vault_policy::FinalCheckError as E;
    match error {
        E::Scheme => "Scheme",
        E::UserInfo => "UserInfo",
        E::Fragment => "Fragment",
        E::Host => "Host",
        E::Port => "Port",
        E::Origin => "Origin",
        E::Path => "Path",
        E::Method => "Method",
        E::ReservedHeader => "ReservedHeader",
        E::Slot => "Slot",
        E::SlotValue => "SlotValue",
        E::CredentialOutsideSlot => "CredentialOutsideSlot",
    }
}

/// The label of a charge failure; `None` for a rate limit, which the caller caused.
fn charge_label(error: &ChargeError) -> Option<&'static str> {
    match error {
        ChargeError::Limited(_) => None,
        ChargeError::UnknownRoute { .. } => Some("ChargeUnknownRoute"),
        ChargeError::NotGranted { .. } => Some("ChargeNotGranted"),
    }
}

/// The label of a construction defect; `None` for a marker error, which the caller caused.
fn assemble_label(error: &AssembleError) -> Option<&'static str> {
    match error {
        AssembleError::ForeignMarker | AssembleError::MalformedMarker => None,
        AssembleError::NonAsciiSlotValue => Some("AssembleNonAsciiSlotValue"),
        AssembleError::HeaderValue(_) => Some("AssembleHeaderValue"),
        AssembleError::Header(_) => Some("AssembleHeader"),
        AssembleError::Target(_) => Some("AssembleTarget"),
    }
}
