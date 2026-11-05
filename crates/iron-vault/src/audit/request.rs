//! The request event, `request.completed`, and the `request.defect` audit event that accompanies a service defect
//! (`design/audit-logging.md`, "Request event").
//!
//! The request server owns the event. It makes a [`RequestRecord`] for each request it receives and gives the handler a
//! [`RequestFacts`] handle to fill in what it learns: the caller, the route and why it refused. The record is the only
//! thing that writes the event. It travels in the outermost response body and writes the event when that body ends or
//! is dropped, or from its own `Drop` when no response was ever produced, so a request that ends in any way writes it
//! exactly once.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use iron_vault_policy::{AssembleError, AuthzError, CallerName, ChargeError, CredentialName, Host, ListenerName, Refusal, RouteName};
use uuid::Uuid;

use super::route::ResponseScrubbed;
use super::{AUDIT_TARGET, AuditEvent, EventName};
use crate::connection_tags::ServiceClose;
use crate::pipeline::PipelineRefusal;
use crate::proxy_handler::RelayFailure;
use crate::service_state::UnavailableReason;
use crate::upstream::transport_error::TransportError;

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests;

/// The `tracing` target of every request event. Like [`AUDIT_TARGET`] it is no module's path, nor a prefix of one.
pub const REQUEST_TARGET: &str = "iron-vault.request";

/// A request's random identifier, a version 4 UUID that joins its request event to the audit events about it. It is
/// never sent to the caller or the upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestId(Uuid);

impl RequestId {
    /// A new random ID.
    pub fn generate() -> Self {
        Self(Uuid::new_v4())
    }
}

impl fmt::Display for RequestId {
    /// The hyphenated lowercase form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0.hyphenated(), f)
    }
}

/// Why a request failed: one fixed snake_case label per check, never the caller's input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)] // Each variant is its label; the design's reason-code tables say what raises it.
pub enum ReasonCode {
    ConnectNotSupported,
    NotOriginForm,
    UpgradeNotSupported,
    UnsupportedVersion,
    RequestTooLarge,
    RequestTimeout,
    Locked,
    PolicyInvalid,
    Checking,
    RecoveryNeeded,
    BadHeader,
    Withdrawn,
    Unauthenticated,
    BadTarget,
    BadMethod,
    NoRoute,
    NotGranted,
    MethodNotAllowed,
    PathNotAllowed,
    RouteUnavailable,
    AmbiguousFraming,
    RateLimited,
    CredentialUnavailable,
    CredentialUnusable,
    ForeignMarker,
    MalformedMarker,
    ServiceDefect,
    UpstreamTimeout,
    UpstreamConnect,
    UpstreamTls,
    UpstreamProtocol,
    UpstreamBody,
    UnsupportedCoding,
    RedirectRefused,
    BodyCorrupt,
    BodyTruncated,
    BodySizeLimit,
    BodyRatioLimit,
    BodyEncode,
    Deadline,
    CallerGone,
    ServiceClosed,
}

impl ReasonCode {
    /// The label written in the `reason` field.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConnectNotSupported => "connect_not_supported",
            Self::NotOriginForm => "not_origin_form",
            Self::UpgradeNotSupported => "upgrade_not_supported",
            Self::UnsupportedVersion => "unsupported_version",
            Self::RequestTooLarge => "request_too_large",
            Self::RequestTimeout => "request_timeout",
            Self::Locked => "locked",
            Self::PolicyInvalid => "policy_invalid",
            Self::Checking => "checking",
            Self::RecoveryNeeded => "recovery_needed",
            Self::BadHeader => "bad_header",
            Self::Withdrawn => "withdrawn",
            Self::Unauthenticated => "unauthenticated",
            Self::BadTarget => "bad_target",
            Self::BadMethod => "bad_method",
            Self::NoRoute => "no_route",
            Self::NotGranted => "not_granted",
            Self::MethodNotAllowed => "method_not_allowed",
            Self::PathNotAllowed => "path_not_allowed",
            Self::RouteUnavailable => "route_unavailable",
            Self::AmbiguousFraming => "ambiguous_framing",
            Self::RateLimited => "rate_limited",
            Self::CredentialUnavailable => "credential_unavailable",
            Self::CredentialUnusable => "credential_unusable",
            Self::ForeignMarker => "foreign_marker",
            Self::MalformedMarker => "malformed_marker",
            Self::ServiceDefect => "service_defect",
            Self::UpstreamTimeout => "upstream_timeout",
            Self::UpstreamConnect => "upstream_connect",
            Self::UpstreamTls => "upstream_tls",
            Self::UpstreamProtocol => "upstream_protocol",
            Self::UpstreamBody => "upstream_body",
            Self::UnsupportedCoding => "unsupported_coding",
            Self::RedirectRefused => "redirect_refused",
            Self::BodyCorrupt => "body_corrupt",
            Self::BodyTruncated => "body_truncated",
            Self::BodySizeLimit => "body_size_limit",
            Self::BodyRatioLimit => "body_ratio_limit",
            Self::BodyEncode => "body_encode",
            Self::Deadline => "deadline",
            Self::CallerGone => "caller_gone",
            Self::ServiceClosed => "service_closed",
        }
    }
}

impl From<UnavailableReason> for ReasonCode {
    fn from(reason: UnavailableReason) -> Self {
        match reason {
            UnavailableReason::Locked => Self::Locked,
            UnavailableReason::PolicyInvalid => Self::PolicyInvalid,
            UnavailableReason::Checking => Self::Checking,
            UnavailableReason::RecoveryNeeded => Self::RecoveryNeeded,
        }
    }
}

impl From<TransportError> for ReasonCode {
    fn from(error: TransportError) -> Self {
        match error {
            TransportError::Timeout => Self::UpstreamTimeout,
            TransportError::Connect => Self::UpstreamConnect,
            TransportError::Tls => Self::UpstreamTls,
            TransportError::Protocol => Self::UpstreamProtocol,
            TransportError::Body => Self::UpstreamBody,
        }
    }
}

impl From<RelayFailure> for ReasonCode {
    fn from(failure: RelayFailure) -> Self {
        match failure {
            RelayFailure::Corrupt => Self::BodyCorrupt,
            RelayFailure::Truncated => Self::BodyTruncated,
            RelayFailure::SizeLimit => Self::BodySizeLimit,
            RelayFailure::RatioLimit => Self::BodyRatioLimit,
            RelayFailure::Encode => Self::BodyEncode,
            RelayFailure::Upstream => Self::UpstreamBody,
        }
    }
}

impl From<&PipelineRefusal> for ReasonCode {
    fn from(refusal: &PipelineRefusal) -> Self {
        match refusal {
            PipelineRefusal::Unauthenticated(_) => Self::Unauthenticated,
            PipelineRefusal::Target(_) => Self::BadTarget,
            PipelineRefusal::Method => Self::BadMethod,
            PipelineRefusal::Authz(AuthzError::NotFound) => Self::NoRoute,
            PipelineRefusal::Authz(AuthzError::Forbidden { reason, .. }) => match reason {
                Refusal::NotGranted => Self::NotGranted,
                Refusal::Method => Self::MethodNotAllowed,
                Refusal::Path => Self::PathNotAllowed,
            },
            PipelineRefusal::Authz(AuthzError::Unavailable { .. }) => Self::RouteUnavailable,
            PipelineRefusal::Sanitize(_) => Self::AmbiguousFraming,
            PipelineRefusal::Charge(ChargeError::Limited(_)) => Self::RateLimited,
            PipelineRefusal::NoHealthyRecord { .. } => Self::CredentialUnavailable,
            PipelineRefusal::Kind(_) => Self::CredentialUnusable,
            PipelineRefusal::Assemble(AssembleError::ForeignMarker) => Self::ForeignMarker,
            PipelineRefusal::Assemble(AssembleError::MalformedMarker) => Self::MalformedMarker,
            PipelineRefusal::Charge(ChargeError::UnknownRoute { .. } | ChargeError::NotGranted { .. })
            | PipelineRefusal::Assemble(
                AssembleError::NonAsciiSlotValue | AssembleError::HeaderValue(_) | AssembleError::Header(_) | AssembleError::Target(_),
            )
            | PipelineRefusal::FinalCheck(_) => Self::ServiceDefect,
        }
    }
}

/// What the handler has learned about a request, kept outside its future so it survives the future being dropped at the
/// request timeout or the body limit.
#[derive(Debug, Default)]
struct State {
    caller: Option<CallerName>,
    route: Option<RouteName>,
    credential: Option<CredentialName>,
    upstream_host: Option<Host>,
    reason: Option<ReasonCode>,
    /// Scrub matches in the relayed response so far, once the handler built one; `None` when it relayed nothing.
    scrub_matches: Option<u64>,
    /// Set when the request server replaces the handler's answer; the handler's later facts are ignored.
    sealed: bool,
}

#[derive(Debug)]
struct Shared {
    id: RequestId,
    state: Mutex<State>,
    request_bytes: AtomicU64,
}

/// The handle through which the handler and the request body record facts about a request. It can set facts but cannot
/// write the event, so a handler cannot forget to write it or write it twice.
#[derive(Debug, Clone)]
pub struct RequestFacts(Arc<Shared>);

impl RequestFacts {
    fn state(&self) -> MutexGuard<'_, State> {
        self.0.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The request's ID.
    pub fn id(&self) -> RequestId {
        self.0.id
    }

    /// The caller the request authenticated as.
    pub fn caller(&self, caller: &CallerName) {
        let mut state = self.state();
        if !state.sealed {
            state.caller = Some(caller.clone());
        }
    }

    /// The route the request selected, its credential and its upstream's host, the enrolled name only.
    pub fn route(&self, route: &RouteName, credential: &CredentialName, upstream_host: &Host) {
        let mut state = self.state();
        if !state.sealed {
            state.route = Some(route.clone());
            state.credential = Some(credential.clone());
            state.upstream_host = Some(upstream_host.clone());
        }
    }

    /// Why the request failed. The first reason recorded wins.
    pub fn refuse(&self, reason: ReasonCode) {
        let mut state = self.state();
        if !state.sealed {
            state.reason = state.reason.or(Some(reason));
        }
    }

    /// The running total of scrub matches in the relayed response's headers and body, recorded as they are found so a
    /// body that fails or is dropped mid-stream still reports them.
    pub fn scrub_matches(&self, total: u64) {
        let mut state = self.state();
        if !state.sealed {
            state.scrub_matches = Some(total);
        }
    }

    /// Counts `bytes` of the request body read from the caller.
    pub fn add_request_bytes(&self, bytes: u64) {
        self.0.request_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Writes the high-severity `request.defect` event for a refusal only a service defect can cause (§3.6). The caller
    /// records the request's `service_defect` reason as it does any other.
    pub fn report_defect(&self, defect: &'static str) {
        let state = self.state();
        RequestDefect {
            id: self.id(),
            route: state.route.as_ref(),
            credential: state.credential.as_ref(),
            defect,
        }
        .emit();
    }

    /// Records the request server's own refusal of a request the handler has had: it overrides the handler's reason, drops
    /// the facts that describe an answer the caller never received, and seals the handle.
    fn override_reason(&self, reason: ReasonCode) {
        let mut state = self.state();
        state.reason = Some(reason);
        state.upstream_host = None;
        state.scrub_matches = None;
        state.sealed = true;
    }
}

/// How the response body carrying a record ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ending {
    /// The body reached its end, or was dropped unpolled because it had nothing to send.
    Clean,
    /// The body failed, or was dropped before its end; with no reason recorded, the caller or the service closed it.
    Cut,
}

/// One request's record, made when the request server receives it. It writes the request event once: when the response
/// body carrying it ends, or when it is dropped.
#[derive(Debug)]
pub struct RequestRecord {
    facts: RequestFacts,
    listener: ListenerName,
    http_method: String,
    started: Instant,
    service_close: ServiceClose,
    status: Option<u16>,
    response_bytes: u64,
    written: bool,
}

impl RequestRecord {
    /// The record of a request that arrived on `listener` with `method`, a connection of which `service_close` flags.
    pub fn new(listener: ListenerName, method: &str, service_close: ServiceClose) -> Self {
        let shared = Shared {
            id: RequestId::generate(),
            state: Mutex::default(),
            request_bytes: AtomicU64::new(0),
        };
        Self {
            facts: RequestFacts(Arc::new(shared)),
            listener,
            http_method: iron_vault_policy::escaped(method),
            started: Instant::now(),
            service_close,
            status: None,
            response_bytes: 0,
            written: false,
        }
    }

    /// The handle for the handler.
    pub fn facts(&self) -> RequestFacts {
        self.facts.clone()
    }

    /// Records the request server's own refusal, made before the handler had the request.
    pub fn refuse(&self, reason: ReasonCode) {
        self.facts.refuse(reason);
    }

    /// Records the request server's own refusal of a request the handler had, which replaces the handler's answer.
    pub fn replace_answer(&self, reason: ReasonCode) {
        self.facts.override_reason(reason);
    }

    /// Records the status of the response the request server produced. A record never given one was dropped before any
    /// response existed.
    pub fn answered(&mut self, status: u16) {
        self.status = Some(status);
    }

    /// Counts `bytes` of the response body handed to hyper.
    pub fn sent(&mut self, bytes: u64) {
        self.response_bytes = self.response_bytes.saturating_add(bytes);
    }

    /// Writes the request event, and the scrub event when a pattern matched in the relayed response, unless they were
    /// written already. A cut with no reason recorded is the caller's or the service's close.
    pub fn end(&mut self, ending: Ending) {
        if std::mem::replace(&mut self.written, true) {
            return;
        }
        let state = self.facts.state();
        let reason = state.reason.or_else(|| (ending == Ending::Cut).then(|| self.dropped_reason()));
        RequestEvent {
            id: self.facts.id(),
            listener: &self.listener,
            http_method: &self.http_method,
            state: &state,
            status: self.status,
            request_bytes: self.facts.0.request_bytes.load(Ordering::Relaxed),
            response_bytes: self.response_bytes,
            duration_ms: self.duration_ms(),
            reason,
        }
        .emit();
        if let (Some(matches @ 1..), Some(route), Some(credential)) = (state.scrub_matches, &state.route, &state.credential) {
            ResponseScrubbed {
                request_id: self.facts.id(),
                route,
                credential,
                matches,
            }
            .emit();
        }
    }

    /// Why a request with no recorded reason ended before its body did: the service closed its connection, or the caller did.
    fn dropped_reason(&self) -> ReasonCode {
        match self.service_close.is_set() {
            true => ReasonCode::ServiceClosed,
            false => ReasonCode::CallerGone,
        }
    }

    fn duration_ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

impl Drop for RequestRecord {
    /// Writes the event if no body ending has: the record was dropped before a response existed, or with its body.
    fn drop(&mut self) {
        self.end(Ending::Cut);
    }
}

/// `request.completed`: one request has ended. Fields not known by then are left out, never filled with a placeholder.
struct RequestEvent<'a> {
    id: RequestId,
    listener: &'a ListenerName,
    http_method: &'a str,
    state: &'a State,
    status: Option<u16>,
    request_bytes: u64,
    response_bytes: u64,
    duration_ms: u64,
    reason: Option<ReasonCode>,
}

impl AuditEvent for RequestEvent<'_> {
    const NAME: EventName = EventName("request.completed");

    fn emit(&self) {
        let state = self.state;
        let upstream_host = state.upstream_host.as_ref().map(ToString::to_string);
        tracing::info!(
            target: REQUEST_TARGET,
            event = Self::NAME.as_str(),
            request_id = self.id.to_string().as_str(),
            listener = self.listener.as_str(),
            http_method = self.http_method,
            caller = state.caller.as_ref().map(CallerName::as_str),
            route = state.route.as_ref().map(RouteName::as_str),
            credential = state.credential.as_ref().map(CredentialName::as_str),
            upstream_host = upstream_host.as_deref(),
            status = self.status.map(u64::from),
            request_bytes = self.request_bytes,
            response_bytes = self.response_bytes,
            duration_ms = self.duration_ms,
            scrubbed = state.scrub_matches.map(|matches| matches > 0),
            outcome = if self.reason.is_some() { "failure" } else { "success" },
            reason = self.reason.map(ReasonCode::as_str),
            "request completed",
        );
    }
}

/// `request.defect`: a request was refused by a service defect. It names the failed check by a fixed label, never the
/// URL, a header or a library error.
struct RequestDefect<'a> {
    id: RequestId,
    route: Option<&'a RouteName>,
    credential: Option<&'a CredentialName>,
    defect: &'static str,
}

impl AuditEvent for RequestDefect<'_> {
    const NAME: EventName = EventName("request.defect");

    fn emit(&self) {
        tracing::error!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            request_id = self.id.to_string().as_str(),
            route = self.route.map(RouteName::as_str),
            credential = self.credential.map(CredentialName::as_str),
            defect = self.defect,
            "request refused by a service defect",
        );
    }
}
