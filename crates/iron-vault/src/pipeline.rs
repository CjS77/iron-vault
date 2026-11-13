// SPDX-License-Identifier: MPL-2.0
//! The request pipeline: turns an incoming request into a checked request, the only form the upstream client sends,
//! or into a pipeline refusal ([spec §8][s8] steps 3-8, [§9][s9]). The proxy handler calls it once per request; it
//! is where the service decides who is asking, what they may do and which credential the request carries.
//!
//! [`prepare`] runs one step after another, and each returns early, so no step runs before the one ahead of it has
//! passed:
//!
//! 1. identify the caller from the connection's listener and peer uid and the caller-token header (step 3);
//! 2. parse the request target and method, then authorize them against the caller's grants (step 4);
//! 3. sanitize the caller's headers with the listener's caller-token header, and ask for only the codings the
//!    response stage decodes;
//! 4. charge the route's and the caller's rate limits (step 5);
//! 5. look up the route's credential record and resolve it for the route's slot (step 6);
//! 6. build the upstream target and assemble the outgoing request, filling the slot once (step 7);
//! 7. run the final outgoing-request check (step 8).
//!
//! For example, with a route `fx` whose prefix is `/fx`, upstream `https://api.fx.example` and a query slot
//! `access_key`:
//!
//! ```text
//! GET /fx/latest?base=USD               caller `fx-mcp`, identified by its peer account
//!   authorize   ─► route `fx`, method `GET`, path `/latest`, query `base=USD`
//!   sanitize    ─► caller token, hop-by-hop and forwarding headers removed
//!   charge      ─► one token from the `fx` bucket, or 429
//!   resolve     ─► the record of the credential `fx` names; never one a marker names
//!   assemble    ─► GET https://api.fx.example/latest?base=USD&access_key=<secret>
//!   final check ─► https, permitted host and port, inside the base path: a checked request
//! ```
//!
//! **Why sanitizing follows authorization and precedes the charge.** Headers cannot change which route is selected,
//! so authorization does not need them sanitized, and authenticating first means a caller without a token learns
//! nothing about framing rules. Sanitizing does two things. Its framing check refuses an ambiguous body length, which
//! [§15][s15] treats as a malformed request, like the target checks of step 4; running it before the charge means a
//! malformed request neither spends the route's allowance nor resolves a credential. Its stripping of control headers
//! and caller authentication is what step 7 requires before the slot is filled, and it is pure, so doing it earlier
//! changes no byte of the outgoing request.
//!
//! **The credential comes from the route.** Step 6 looks up the credential the route's configuration names; markers in
//! the request are never consulted to choose one ([implementation spec §2.2][i22], Q-1). A marker in the slot is only
//! checked against that credential when the slot is filled, and a marker anywhere else is inert text.
//!
//! Step 2 of [§8][s8], the request-form gate, runs before authentication and is not part of this pipeline. This module
//! refuses absolute-form and authority-form targets ([`RequestTarget::parse`]) and `CONNECT` (the method allowlist) too,
//! after authentication. It does not refuse upgrades: sanitizing only strips `Upgrade` as a reserved header.
//!
//! [s8]: ../../../design/iron-vault-specification.md#8-request-flow
//! [s9]: ../../../design/iron-vault-specification.md#9-url-header-and-slot-rules
//! [s15]: ../../../design/iron-vault-specification.md#15-service-states-and-errors
//! [i22]: ../../../design/implementation-specification.md#22-product-decisions-and-resulting-behavior

use std::fmt;
use std::time::Instant;

use iron_vault_kinds::{KindError, ScrubPatterns};
use iron_vault_policy::{
    ActivePolicy, AssembleError, AuthorizedRequest, AuthzError, CallerName, ChargeError, CheckedRequest, CredentialName, FinalCheckError,
    HeaderName, HeaderValue, Host, ListenerName, Method, OutgoingHeaders, OutgoingRequest, RateLimiter, RequestTarget, RouteConfig,
    RouteName, SanitizeError, TargetError, Unauthenticated, UpstreamTarget, authorize, final_check, identify_caller, sanitize,
};
use iron_vault_store::{CredentialRecord, ResolvedCredential};

use crate::connection_tags::ConnectionTags;
use crate::content_coding::UPSTREAM_ACCEPT_ENCODING;
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

/// What the pipeline learned about a request before it stopped, for the request event: the caller once identified, and
/// the route with its credential once selected. Left empty by a step that has not been reached.
#[derive(Debug, Default)]
pub struct Identified {
    /// The caller, once identified.
    pub caller: Option<CallerName>,
    /// The route the request selected, its credential and its upstream's host as configured.
    pub route: Option<(RouteName, CredentialName, Host)>,
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

    /// Splits off the checked request for the transport and the scrub patterns for the response stage, which keeps the
    /// patterns until the response ends.
    pub fn into_parts(self) -> (CheckedRequest, ScrubPatterns) {
        (self.request, self.patterns)
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

/// Why the pipeline stopped a request: one variant per step that can fail, each answered with one
/// [§15](../../../design/iron-vault-specification.md#15-service-states-and-errors) status.
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

/// Runs [§8](../../../design/iron-vault-specification.md#8-request-flow) steps 3-8 for `head`, which arrived on the
/// connection `tags` describes, against one serving snapshot at `now`.
///
/// `now` is when the request is charged against its rate limits; the caller passes the current instant. `identified`
/// receives the caller and route as they are found, so a refusal still says who asked for what.
pub fn prepare(
    snapshot: &ServingSnapshot,
    tags: &ConnectionTags,
    head: RequestHead,
    now: Instant,
    identified: &mut Identified,
) -> Result<Prepared, PipelineRefusal> {
    run(snapshot, tags, head, now, identified)
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

/// Runs the steps in order; the module documentation says why they run in this order.
fn run(
    sources: &impl Sources,
    tags: &ConnectionTags,
    head: RequestHead,
    now: Instant,
    identified: &mut Identified,
) -> Result<Prepared, PipelineRefusal> {
    let policy = sources.policy();
    let RequestHead { method, target, headers } = head;
    let caller = identify_caller(policy, tags.listener(), tags.peer_uid(), &headers)?;
    identified.caller = Some(caller.clone());
    let authorized = authorize_request(policy, &caller, &method, &target).inspect_err(|refusal| {
        identified.route = refused_route(policy, refusal);
    })?;
    // Looked up before sanitizing, so every later refusal can name the route and credential, and before the charge, so
    // nothing that can fail runs after it except resolution onward.
    let route = selected_route(policy, &authorized)?;
    identified.route = Some(selected(authorized.route(), route));
    let mut headers = sanitize(headers, &token_header(policy, tags.listener())?)?;
    ask_for_decodable_codings(&mut headers);
    charge_and_build(sources, &caller, route, &authorized, headers, now)
}

/// Replaces the caller's `Accept-Encoding` with [`UPSTREAM_ACCEPT_ENCODING`], the codings the response stage decodes
/// ([§11](../../../design/iron-vault-specification.md#11-responses-redirects-and-scrubbing)), so an upstream never
/// answers in one the service must refuse. The caller's value is never forwarded; the request handler reads it from the
/// caller's request to choose the coding it emits.
///
/// Neither step can fail, since the constant is a valid value and `Accept-Encoding` is not reserved; if one did, the
/// request would go without the header, which only asks for an uncompressed reply.
fn ask_for_decodable_codings(headers: &mut OutgoingHeaders) {
    headers.remove_all(&HeaderName::accept_encoding());
    let inserted = HeaderValue::try_from(UPSTREAM_ACCEPT_ENCODING.as_bytes())
        .ok()
        .and_then(|value| headers.insert(HeaderName::accept_encoding(), value).ok());
    debug_assert!(inserted.is_some(), "the service's Accept-Encoding could not be set");
}

/// Runs steps 5-8: charge, resolve, assemble and check. A defect here is reported by the request handler, which knows the
/// request's ID.
fn charge_and_build(
    sources: &impl Sources,
    caller: &CallerName,
    route: &RouteConfig,
    authorized: &AuthorizedRequest,
    headers: OutgoingHeaders,
    now: Instant,
) -> Result<Prepared, PipelineRefusal> {
    // §8 step 5 also obtains owner confirmation, which needs no code in v0: `confirm = "touch"` is refused when the
    // config is read, so no route here requires it (§6). A confirmation provider must add its check here, after the
    // charge and before resolution.
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

/// Parses the target and the method, then checks the caller's grant and the route's restrictions
/// ([§8](../../../design/iron-vault-specification.md#8-request-flow) step 4).
fn authorize_request(policy: &ActivePolicy, caller: &CallerName, method: &str, target: &str) -> Result<AuthorizedRequest, PipelineRefusal> {
    let (path, query) = RequestTarget::parse(target)?.into_parts();
    let method = Method::try_from(method).map_err(|_| PipelineRefusal::Method)?;
    Ok(authorize(policy, caller, &method, &path, query)?)
}

/// Returns the route and credential of an authorization refusal that names its route, so the request event can still
/// say which route the caller asked for.
fn refused_route(policy: &ActivePolicy, refusal: &PipelineRefusal) -> Option<(RouteName, CredentialName, Host)> {
    match refusal {
        PipelineRefusal::Authz(AuthzError::Forbidden { route, .. } | AuthzError::Unavailable { route }) => {
            policy.config().routes().get(route).map(|config| selected(route, config))
        }
        _ => None,
    }
}

/// Returns what the request event records about the selected `route`: its name, its credential and its upstream host.
fn selected(route: &RouteName, config: &RouteConfig) -> (RouteName, CredentialName, Host) {
    (route.clone(), config.credential().clone(), config.upstream().host().clone())
}

/// Returns the header that carries a caller token on `listener`, which sanitizing strips.
///
/// Caller identification passed, so the listener is in the policy; one that is not cannot have authenticated anyone.
fn token_header(policy: &ActivePolicy, listener: &ListenerName) -> Result<HeaderName, Unauthenticated> {
    let config = policy.config().listeners().get(listener).ok_or(Unauthenticated)?;
    Ok(config.caller_token_header())
}

/// Returns the configuration of the route `authorized` selected.
///
/// Authorization returns only routes the policy serves, so a miss means the route is unavailable.
fn selected_route<'p>(policy: &'p ActivePolicy, authorized: &AuthorizedRequest) -> Result<&'p RouteConfig, AuthzError> {
    let route = authorized.route();
    policy.route(route).ok_or_else(|| AuthzError::Unavailable { route: route.clone() })
}

/// Resolves the credential the route names for the route's slot
/// ([§8](../../../design/iron-vault-specification.md#8-request-flow) step 6); never one a marker names.
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

/// Builds the upstream target and fills the route's slot once with the resolved value
/// ([§8](../../../design/iron-vault-specification.md#8-request-flow) step 7).
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
