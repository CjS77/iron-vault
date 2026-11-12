//! The proxy handler: serves one caller request end to end, from the request server to the upstream and back
//! ([spec §8][s8]). It is the request interface's [`RequestHandler`]: the part of the service that turns an approved
//! route into an upstream call carrying the stored credential, without the caller ever holding that credential.
//!
//! A request's whole path through the service, with the module that owns each stage:
//!
//! ```text
//!  caller
//!    │ HTTP/1.1 request, with a caller token unless its listener or peer account identifies it
//!    ▼
//!  request listener     Unix socket or TCP, TLS handshake when configured;                      request_listeners
//!    │                  tags the connection with its listener name and peer uid
//!    ▼
//!  request server       connection, header, body and time limits;                               request_server
//!    │                  request form gate: origin-form targets only, no upgrade
//!    ▼
//!  proxy handler        loads the serving snapshot once, or answers 503                         this module
//!    ▼
//!  request pipeline     identify caller ─► authorize route ─► sanitize headers                  pipeline
//!    │                  ─► charge rate limit ─► resolve credential
//!    │                  ─► assemble, filling the slot once ─► final outgoing-request check
//!    │ checked request and scrub patterns
//!    ▼
//!  upstream client      HTTPS with verified TLS, no ambient proxy, no redirects followed        upstream
//!    │ response head, body still streaming
//!    ▼
//!  relay                headers: strip, rewrite `Location`, scrub                               proxy_handler::relay
//!    │                  body: decode ─► decompression budget ─► scrub ─► re-encode
//!    ▼
//!  caller
//! ```
//!
//! Per request the handler loads the serving snapshot once and uses only that. It runs the request pipeline
//! ([§8][s8] steps 3-8), sends the checked request with the caller's body through the route's upstream client (step 9),
//! and relays the response (step 10, [§11][s11]). Each failure gets one fixed answer, and none formats a library error
//! ([§18][s18]):
//!
//! | Failure | Answer |
//! |---|---|
//! | The service holds no snapshot (locked, policy invalid, checking, recovery needed) | `503` with the [`UnavailableReason`] text, before the caller is identified |
//! | The snapshot is withdrawn before the response head | `503` with the generic body, not the reason |
//! | The snapshot is withdrawn after the response head | The caller's connection is aborted |
//! | The pipeline refuses the request | Its [`RefusalResponse`] |
//! | The route has no upstream client | `503` |
//! | The upstream exchange fails | [`TransportError::status`]: `502`, or `504` for a timeout |
//! | No response headers by the request deadline | `504` |
//! | The response has a content coding the service does not decode, a coded `206`, or a transfer coding besides `chunked` | `502` |
//! | The response's `Location` leaves the route's upstream base or is ambiguous, or it has several ([§11][s11]) | `502` |
//! | The response body fails after its head was sent: upstream error, decode error, truncated coding, decompression budget | The caller's connection is aborted |
//!
//! The request deadline bounds the body as well: the request server fails a response body still streaming at it.
//!
//! [s8]: ../../../design/iron-vault-specification.md#8-request-flow
//! [s11]: ../../../design/iron-vault-specification.md#11-responses-redirects-and-scrubbing
//! [s18]: ../../../design/iron-vault-specification.md#18-logging

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use futures_core::Stream;
use http_body_util::{BodyExt, Full};
use hyper::HeaderMap;
use hyper::body::Body;
use hyper::header::{ACCEPT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, HeaderValue as HttpHeaderValue};
use hyper::http::request::Parts;
use hyper::{Request, Response, StatusCode};
use iron_vault_policy::{HeaderName, HeaderValue, ListenerConfig};
use tokio::time::Instant;

use crate::audit::{ReasonCode, RequestFacts};
use crate::pipeline::{Identified, PipelineRefusal, RefusalResponse, RequestHead, prepare};
use crate::request_server::{ConnectionTags, RequestBody, RequestHandler, ResponseBody};
use crate::service_state::UnavailableReason;
use crate::serving_snapshot::{Admission, ServingSnapshot, SnapshotHolder};
use crate::upstream::body::{UpstreamBody, UpstreamBodyError};
use crate::upstream::transport_error::TransportError;

mod relay;
mod withdrawn;
pub(crate) use relay::ResponseContext;
pub use relay::{RelayFailure, RelayedBody, ResponseOutcome};
use withdrawn::UntilWithdrawn;

/// The request handler that serves every request from the current serving snapshot.
#[derive(Debug)]
pub struct ProxyHandler {
    snapshots: Arc<SnapshotHolder>,
}

impl ProxyHandler {
    /// Creates a handler that serves each request from the snapshot `snapshots` holds when the request arrives.
    pub fn new(snapshots: Arc<SnapshotHolder>) -> Self {
        Self { snapshots }
    }
}

impl RequestHandler for ProxyHandler {
    fn handle(
        &self,
        request: Request<RequestBody>,
        tags: &ConnectionTags,
        deadline: Instant,
        facts: &RequestFacts,
    ) -> impl Future<Output = Response<ResponseBody>> + Send {
        // Loaded once, here, so the whole request runs on one activation even if a reload lands while it is in flight.
        let admission = self.snapshots.load();
        let (tags, facts) = (tags.clone(), facts.clone());
        async move {
            match admission {
                Admission::Serve(snapshot) => serve(snapshot, &tags, request, deadline, &facts).await,
                Admission::Refuse(reason) => unavailable(reason, &facts),
            }
        }
    }
}

/// Serves `request` from `snapshot` until the snapshot is withdrawn. A request withdrawn before its response head is
/// dropped, which cancels its upstream request, and answered with a fixed `503`; one withdrawn after it has its body fail,
/// so the caller's connection is aborted instead of ended as if the body were complete
/// ([§12](../../../design/iron-vault-specification.md#12-configuration-approval-and-reload)).
///
/// The response body keeps `snapshot` alive until the body is dropped, because the body owns the request's injected
/// secret patterns: a lock that waits for the snapshot to drop therefore also waits for the body.
async fn serve(
    snapshot: Arc<ServingSnapshot>,
    tags: &ConnectionTags,
    request: Request<RequestBody>,
    deadline: Instant,
    facts: &RequestFacts,
) -> Response<ResponseBody> {
    let answer = tokio::select! {
        biased;
        () = snapshot.withdrawn() => Err(refused(facts, ReasonCode::Withdrawn, StatusCode::SERVICE_UNAVAILABLE)),
        answer = proxy(&snapshot, tags, request, deadline, facts) => answer,
    };
    match answer {
        Ok(response) => response.map(|body| UntilWithdrawn::new(body, snapshot, facts.clone()).boxed_unsync()),
        Err(refusal) => fixed(&refusal),
    }
}

/// Runs the pipeline, sends the request and relays the response. A failure before the response head becomes a fixed
/// answer; its reason goes into `facts`, with the caller and route as far as the pipeline found them.
async fn proxy(
    snapshot: &ServingSnapshot,
    tags: &ConnectionTags,
    request: Request<RequestBody>,
    deadline: Instant,
    facts: &RequestFacts,
) -> Result<Response<ResponseBody>, RefusalResponse> {
    let (parts, body) = request.into_parts();
    let head = request_head(&parts).ok_or_else(|| refused(facts, ReasonCode::BadHeader, StatusCode::BAD_REQUEST))?;
    let mut identified = Identified::default();
    let prepared = prepare(snapshot, tags, head, std::time::Instant::now(), &mut identified);
    record_identity(facts, &identified);
    let prepared = prepared.map_err(|refusal| refuse_pipeline(facts, &refusal))?;
    let unavailable = || refused(facts, ReasonCode::RouteUnavailable, StatusCode::SERVICE_UNAVAILABLE);
    let client = snapshot.clients().for_route(prepared.route()).map_err(|_| unavailable())?;
    let route_config = snapshot.policy().route(prepared.route()).ok_or_else(unavailable)?;
    let (request, patterns) = prepared.into_parts();
    // The URL actually sent, which holds a query slot's secret: kept only until the response head is decided.
    let request_url = request.url().clone();
    let context = ResponseContext {
        method: request.method(),
        patterns,
        facts: facts.clone(),
        accept_encoding: accept_encoding(&parts.headers),
        limits: *snapshot.policy().config().limits(),
    };
    let send = client.send(request, upstream_body(&parts, body));
    let response = tokio::time::timeout_at(deadline, send)
        .await
        .unwrap_or(Err(TransportError::Timeout))
        .map_err(|error| refused(facts, error.into(), error.status()))?;
    relay::relay(response, token_header(snapshot, tags), context, route_config, &request_url)
}

/// Records the caller and route the pipeline found, with the route's upstream host as configured.
fn record_identity(facts: &RequestFacts, identified: &Identified) {
    identified.caller.iter().for_each(|caller| facts.caller(caller));
    identified
        .route
        .iter()
        .for_each(|(route, credential, host)| facts.route(route, credential, host));
}

/// Records a pipeline refusal's reason and returns its answer. A service defect also raises its high-severity event.
fn refuse_pipeline(facts: &RequestFacts, refusal: &PipelineRefusal) -> RefusalResponse {
    facts.refuse(refusal.into());
    refusal.defect().iter().for_each(|defect| facts.report_defect(defect));
    refusal.respond()
}

/// Records `reason` as why the request failed and returns the fixed answer with `status`.
fn refused(facts: &RequestFacts, reason: ReasonCode, status: StatusCode) -> RefusalResponse {
    facts.refuse(reason);
    RefusalResponse::fixed(status.as_u16())
}

/// Copies the method, target and headers the pipeline reads out of hyper's request parts. Returns `None` if a header
/// does not convert, which hyper's parser should never let through. hyper groups a repeated header's values together,
/// so headers keep their order of first appearance.
fn request_head(parts: &Parts) -> Option<RequestHead> {
    let headers = parts
        .headers
        .iter()
        .map(|(name, value)| {
            Some((
                HeaderName::try_from(name.as_str()).ok()?,
                HeaderValue::try_from(value.as_bytes()).ok()?,
            ))
        })
        .collect::<Option<_>>()?;
    let target = parts
        .uri
        .path_and_query()
        .map_or_else(|| parts.uri.path(), |target| target.as_str());
    Some(RequestHead {
        method: parts.method.as_str().to_owned(),
        target: target.to_owned(),
        headers,
    })
}

/// Returns the caller's `Accept-Encoding`, its repeated headers joined into one list as
/// [RFC 9110 §5.3](https://www.rfc-editor.org/rfc/rfc9110#section-5.3) allows. Returns `None` when the caller sent
/// none, or when the joined list is not a valid header value, which `choose_emitted` would treat as absent too.
fn accept_encoding(headers: &HeaderMap) -> Option<HttpHeaderValue> {
    let values: Vec<&[u8]> = headers.get_all(ACCEPT_ENCODING).iter().map(HttpHeaderValue::as_bytes).collect();
    (!values.is_empty())
        .then(|| values.join(&b", "[..]))
        .and_then(|joined| HttpHeaderValue::from_bytes(&joined).ok())
}

/// Turns the caller's body into the upstream body: empty when the caller sent none, otherwise streamed with its declared
/// length.
///
/// A `Content-Length: 0` is a declared empty body, so it is forwarded as one; a request with no framing at all has no
/// body and gets none.
fn upstream_body(parts: &Parts, body: RequestBody) -> UpstreamBody {
    let declared = parts
        .headers
        .contains_key(CONTENT_LENGTH)
        .then(|| body.size_hint().exact())
        .flatten();
    match declared.is_none() && body.is_end_stream() {
        true => UpstreamBody::empty(),
        false => UpstreamBody::stream(declared, CallerChunks(body)),
    }
}

/// Yields the caller's body as the data chunks the upstream client forwards. Trailers are dropped: the client sends
/// none.
struct CallerChunks(RequestBody);

impl Stream for CallerChunks {
    type Item = Result<Bytes, UpstreamBodyError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match ready!(Pin::new(&mut self.0).poll_frame(cx)) {
                None => return Poll::Ready(None),
                Some(Err(_)) => return Poll::Ready(Some(Err(UpstreamBodyError))),
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        return Poll::Ready(Some(Ok(data)));
                    }
                }
            }
        }
    }
}

/// Returns the caller-token header of the listener the request arrived on. The pipeline identified the caller there,
/// so the listener is in the policy.
fn token_header(snapshot: &ServingSnapshot, tags: &ConnectionTags) -> Option<HeaderName> {
    snapshot
        .policy()
        .config()
        .listeners()
        .get(tags.listener())
        .map(ListenerConfig::caller_token_header)
}

/// Answers a request refused at admission with `503`, the redacted [`UnavailableReason`] as its whole body. The caller
/// is not identified first: with no snapshot there is no policy to identify it against
/// ([§15](../../../design/iron-vault-specification.md#15-service-states-and-errors)).
fn unavailable(reason: UnavailableReason, facts: &RequestFacts) -> Response<ResponseBody> {
    facts.refuse(reason.into());
    text_response(StatusCode::SERVICE_UNAVAILABLE, reason.as_str())
}

/// Converts a refusal into a hyper response.
fn fixed(refusal: &RefusalResponse) -> Response<ResponseBody> {
    let mut response = text_response(
        StatusCode::from_u16(refusal.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        refusal.body(),
    );
    let headers = response.headers_mut();
    refusal.headers().into_iter().for_each(|(name, value)| {
        if let Ok(value) = HttpHeaderValue::try_from(value) {
            headers.insert(name, value);
        }
    });
    response
}

/// Builds a `text/plain` response with `status` and a constant `body`.
fn text_response(status: StatusCode, body: &'static str) -> Response<ResponseBody> {
    let body = Full::new(Bytes::from_static(body.as_bytes()));
    let mut response = Response::new(body.map_err(|never| match never {}).boxed_unsync());
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HttpHeaderValue::from_static("text/plain; charset=utf-8"));
    response
}
