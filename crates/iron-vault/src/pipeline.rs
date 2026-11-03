//! The request pipeline: §3.5 steps 3-8, from an incoming request to a checked request (specification §3.5, §3.6).
//!
//! [`prepare`] runs one step after another, and each returns early, so no step runs before the one ahead of it has
//! passed:
//!
//! 1. identify the caller from the connection's listener and peer uid and the caller-token header (step 3);
//! 2. parse the request target and method, then authorize them against the caller's grants (step 4);
//! 3. sanitize the caller's headers with the listener's caller-token header;
//! 4. charge the route's and the caller's rate limits (step 5);
//! 5. look up the route's credential record and resolve it for the route's slot (step 6);
//! 6. build the upstream target and assemble the outgoing request, filling the slot once (step 7);
//! 7. run the final outgoing-request check (step 8).
//!
//! **Why sanitizing follows authorization and precedes the charge.** Headers cannot change which route is selected,
//! so authorization does not need them sanitized, and authenticating first means a caller without a token learns
//! nothing about framing rules. Sanitizing does two things. Its framing check refuses an ambiguous body length, which
//! §3.12 treats as a malformed request, like the target checks of step 4; running it before the charge means a
//! malformed request neither spends the route's allowance nor resolves a credential. Its stripping of control headers
//! and caller authentication is what step 7 requires before the slot is filled, and it is pure, so doing it earlier
//! changes no byte of the outgoing request.
//!
//! **The credential comes from the route.** Step 6 looks up the credential the route's configuration names; markers in
//! the request are never consulted to choose one (§8.2 Q-1). A marker in the slot is only checked against that
//! credential when the slot is filled, and a marker anywhere else is inert text.
//!
//! Step 2 of §3.5, the request-form gate, runs before authentication and is not part of this pipeline. This module
//! refuses absolute-form and authority-form targets ([`RequestTarget::parse`]) and `CONNECT` (the method allowlist) too,
//! after authentication. It does not refuse upgrades: sanitizing only strips `Upgrade` as a reserved header.

use std::fmt;
use std::time::Instant;

use iron_vault_kinds::{KindError, ScrubPatterns};
use iron_vault_policy::{
    ActivePolicy, AssembleError, AuthorizedRequest, AuthzError, CallerName, ChargeError, CheckedRequest, CredentialName, FinalCheckError,
    HeaderName, HeaderValue, ListenerName, Method, OutgoingHeaders, OutgoingRequest, RateLimiter, RequestTarget, RouteConfig, RouteName,
    SanitizeError, TargetError, Unauthenticated, UpstreamTarget, authorize, final_check, identify_caller, sanitize,
};
use iron_vault_store::{CredentialRecord, ResolvedCredential};

use crate::connection_tags::ConnectionTags;
use crate::serving_snapshot::ServingSnapshot;

/// The parts of a caller's request the pipeline reads: the method text, the raw request target and the header pairs.
///
/// Free of HTTP-library types, so the pipeline is tested without a server. The headers may hold a caller token, and
/// the query may hold caller secrets, so `Debug` shows neither the target nor any header value. The method text is
/// caller-controlled and may be any token, so `Debug` redacts it too, as [`PipelineRefusal::Method`] drops it.
pub struct RequestHead {
    /// The method token exactly as sent.
    pub method: String,
    /// The request target exactly as sent.
    pub target: String,
    /// The caller's headers, in the order sent.
    pub headers: Vec<(HeaderName, HeaderValue)>,
}

impl fmt::Debug for RequestHead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestHead")
            .field("method", &"<redacted>")
            .field("target", &"<redacted>")
            .field("headers", &self.headers)
            .finish()
    }
}

/// A request the pipeline accepted: the checked request for the transport, the scrub patterns for its response, and
/// the route and credential names for its events.
///
/// It holds the credential in the checked request and every encoded form of it in the scrub patterns, so it has no
/// `Clone`, and its `Debug` is the redacted `Debug` of each part.
#[derive(Debug)]
pub struct Prepared {
    request: CheckedRequest,
    patterns: ScrubPatterns,
    route: RouteName,
    credential: CredentialName,
}

impl Prepared {
    /// The request the transport sends.
    pub fn request(&self) -> &CheckedRequest {
        &self.request
    }

    /// The checked request alone, for the transport to send. The scrub patterns are dropped with the rest.
    pub fn into_request(self) -> CheckedRequest {
        self.request
    }

    /// The forms of the injected secret that response scrubbing removes.
    pub fn patterns(&self) -> &ScrubPatterns {
        &self.patterns
    }

    /// The route the request was authorized on.
    pub fn route(&self) -> &RouteName {
        &self.route
    }

    /// The credential the route selected and the request carries.
    pub fn credential(&self) -> &CredentialName {
        &self.credential
    }
}

/// Why the pipeline stopped a request: one variant per step that can fail, each answered with one §3.12 status.
///
/// Every variant keeps only what is safe to log: route, caller and credential names, never a header value, query text
/// or slot value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PipelineRefusal {
    /// The caller could not be identified.
    #[error(transparent)]
    Unauthenticated(#[from] Unauthenticated),
    /// The request target is malformed.
    #[error(transparent)]
    Target(#[from] TargetError),
    /// The method is not one a route may allow. The method text is caller-controlled, so it is not kept.
    #[error("the request method is not one a route may allow")]
    Method,
    /// No route matches, or the caller may not make this request on the route that does.
    #[error(transparent)]
    Authz(#[from] AuthzError),
    /// The caller's headers frame the body ambiguously.
    #[error(transparent)]
    Sanitize(#[from] SanitizeError),
    /// A rate limit is exhausted, or the limiter does not know the route or caller.
    #[error(transparent)]
    Charge(#[from] ChargeError),
    /// The vault holds no healthy record for the route's credential: it is missing or damaged.
    #[error("route {route} has no healthy record for credential {credential}")]
    NoHealthyRecord {
        /// The route authorized.
        route: RouteName,
        /// The credential the route names.
        credential: CredentialName,
    },
    /// The credential's kind could not produce a value for the route's slot.
    #[error(transparent)]
    Kind(#[from] KindError),
    /// The outgoing request could not be built: a foreign or malformed marker in the slot, or a construction defect.
    #[error(transparent)]
    Assemble(#[from] AssembleError),
    /// The outgoing request failed the final check: a policy or construction defect.
    #[error(transparent)]
    FinalCheck(#[from] FinalCheckError),
}

/// Runs §3.5 steps 3-8 for `head`, which arrived on the connection `tags` describes, against one serving snapshot at
/// `now`.
///
/// `now` is when the request is charged against its rate limits; the caller passes the current instant.
pub fn prepare(snapshot: &ServingSnapshot, tags: &ConnectionTags, head: RequestHead, now: Instant) -> Result<Prepared, PipelineRefusal> {
    run(snapshot, tags, head, now)
}

/// What the pipeline reads from a serving snapshot. Tests supply their own to observe which records are looked up.
trait Sources {
    /// The policy requests are authorized against.
    fn policy(&self) -> &ActivePolicy;
    /// The rate limiter built for that policy.
    fn limiter(&self) -> &RateLimiter;
    /// The healthy record named `credential`.
    fn record(&self, credential: &CredentialName) -> Option<&CredentialRecord>;
}

impl Sources for ServingSnapshot {
    fn policy(&self) -> &ActivePolicy {
        ServingSnapshot::policy(self)
    }

    fn limiter(&self) -> &RateLimiter {
        ServingSnapshot::limiter(self)
    }

    fn record(&self, credential: &CredentialName) -> Option<&CredentialRecord> {
        ServingSnapshot::record(self, credential)
    }
}

/// The steps in order; see the module documentation for why they run in this order.
fn run(sources: &impl Sources, tags: &ConnectionTags, head: RequestHead, now: Instant) -> Result<Prepared, PipelineRefusal> {
    let policy = sources.policy();
    let RequestHead { method, target, headers } = head;
    let caller = identify_caller(policy, tags.listener(), tags.peer_uid(), &headers)?;
    let authorized = authorize_request(policy, &caller, &method, &target)?;
    let headers = sanitize(headers, &token_header(policy, tags.listener())?)?;
    // Looked up before the charge, so nothing that can fail runs after it except resolution onward.
    let route = selected_route(policy, &authorized)?;
    charge_and_build(sources, &caller, route, &authorized, headers, now)
        .inspect_err(|refusal| refusal.report(authorized.route(), route.credential()))
}

/// Steps 5-8: charge, resolve, assemble and check. A defect here raises its high-severity event in the caller, where
/// the route and credential are known.
fn charge_and_build(
    sources: &impl Sources,
    caller: &CallerName,
    route: &RouteConfig,
    authorized: &AuthorizedRequest,
    headers: OutgoingHeaders,
    now: Instant,
) -> Result<Prepared, PipelineRefusal> {
    // §3.5 step 5 also obtains owner confirmation, which needs no code in v0: activation refuses a route with
    // `confirm = "touch"` unless `Capabilities::touch_provider` is set, and v0 never sets it (§2, §8.2 "Touch policy
    // without a device"). A confirmation provider must add its check here, after the charge and before resolution.
    sources.limiter().charge(caller, authorized.route(), now)?;
    let resolved = resolve(sources, route, authorized)?;
    let outgoing = assemble(route, authorized, headers, &resolved)?;
    let request = final_check(outgoing, authorized, route.upstream(), route.slot(), &resolved.bound())?;
    Ok(Prepared {
        request,
        patterns: resolved.into_patterns(),
        route: authorized.route().clone(),
        credential: route.credential().clone(),
    })
}

/// Parses the target and the method, then checks the caller's grant and the route's restrictions (§3.5 step 4).
fn authorize_request(policy: &ActivePolicy, caller: &CallerName, method: &str, target: &str) -> Result<AuthorizedRequest, PipelineRefusal> {
    let (path, query) = RequestTarget::parse(target)?.into_parts();
    let method = Method::try_from(method).map_err(|_| PipelineRefusal::Method)?;
    Ok(authorize(policy, caller, &method, &path, query)?)
}

/// The header that carries a caller token on `listener`, which sanitizing strips.
///
/// Caller identification passed, so the listener is in the policy; one that is not cannot have authenticated anyone.
fn token_header(policy: &ActivePolicy, listener: &ListenerName) -> Result<HeaderName, Unauthenticated> {
    let config = policy.config().listeners().get(listener).ok_or(Unauthenticated)?;
    Ok(config.caller_token_header())
}

/// The configuration of the route `authorized` selected.
///
/// Authorization returns only routes the policy serves, so a miss means the route is unavailable.
fn selected_route<'p>(policy: &'p ActivePolicy, authorized: &AuthorizedRequest) -> Result<&'p RouteConfig, AuthzError> {
    let route = authorized.route();
    policy.route(route).ok_or_else(|| AuthzError::Unavailable { route: route.clone() })
}

/// Resolves the credential the route names for the route's slot (§3.5 step 6); never one a marker names.
fn resolve<'s>(
    sources: &'s impl Sources,
    route: &RouteConfig,
    authorized: &AuthorizedRequest,
) -> Result<ResolvedCredential<'s>, PipelineRefusal> {
    let credential = route.credential();
    let record = sources.record(credential).ok_or_else(|| PipelineRefusal::NoHealthyRecord {
        route: authorized.route().clone(),
        credential: credential.clone(),
    })?;
    Ok(record.resolve(route.slot(), authorized)?)
}

/// Builds the upstream target and fills the route's slot once with the resolved value (§3.5 step 7).
fn assemble(
    route: &RouteConfig,
    authorized: &AuthorizedRequest,
    headers: OutgoingHeaders,
    resolved: &ResolvedCredential<'_>,
) -> Result<OutgoingRequest, AssembleError> {
    let target = UpstreamTarget::build(route.upstream(), authorized)?;
    OutgoingRequest::assemble(
        authorized,
        target,
        headers,
        route.slot(),
        route.credential(),
        resolved.bound().value(),
    )
}

mod refusal;
pub use refusal::RefusalResponse;

#[cfg(test)]
mod tests;
