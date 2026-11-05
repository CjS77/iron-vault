//! The proxy handler: one request end to end, from the request server to the upstream and back (specification §3.5).
//!
//! Per request it loads the serving snapshot once and uses only that, runs the request pipeline (§3.5 steps 3-8),
//! sends the checked request with the caller's body through the route's upstream client (step 9), and relays the
//! response, decoded, through the scrubber with the injected credential's scrub patterns and re-encoded when the caller
//! requires it (step 10, §3.8). Each failure gets one
//! fixed answer, and none formats a library error (§3.15):
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
//! | The response's `Location` leaves the route's upstream base or is ambiguous, or it has several (§3.8) | `502` |
//! | The response body fails after its head was sent: upstream error, decode error, truncated coding, decompression budget | The caller's connection is aborted |
//!
//! The request deadline bounds the body as well: the request server fails a response body still streaming at it.

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
    /// A handler serving from whichever snapshot `snapshots` holds when each request arrives.
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
/// so the caller's connection is aborted rather than ended as if the body were complete (§3.9).
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
        Ok(response) => response.map(|body| UntilWithdrawn::new(body, snapshot).boxed_unsync()),
        Err(refusal) => fixed(&refusal),
    }
}

/// Runs the pipeline, sends and relays; any failure before the response head is a fixed answer, whose reason is recorded
/// in `facts` together with the caller and route as far as they were found.
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
    record_identity(facts, snapshot, &identified);
    let prepared = prepared.map_err(|refusal| refuse_pipeline(facts, &refusal))?;
    let unavailable = || refused(facts, ReasonCode::RouteUnavailable, StatusCode::SERVICE_UNAVAILABLE);
    let client = snapshot.clients().for_route(prepared.route()).map_err(|_| unavailable())?;
    let (route, credential) = (prepared.route().clone(), prepared.credential().clone());
    let route_config = snapshot.policy().route(&route).ok_or_else(unavailable)?;
    let (request, patterns) = prepared.into_parts();
    // The URL actually sent, which holds a query slot's secret: kept only until the response head is decided.
    let request_url = request.url().clone();
    let context = ResponseContext {
        method: request.method(),
        patterns,
        route,
        credential,
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
fn record_identity(facts: &RequestFacts, snapshot: &ServingSnapshot, identified: &Identified) {
    identified.caller.iter().for_each(|caller| facts.caller(caller));
    if let Some((route, credential)) = &identified.route {
        if let Some(config) = snapshot.policy().route(route) {
            facts.route(route, credential, config.upstream().host());
        }
    }
}

/// The answer to a pipeline refusal. Its reason is recorded, and a service defect also raises its high-severity event.
fn refuse_pipeline(facts: &RequestFacts, refusal: &PipelineRefusal) -> RefusalResponse {
    facts.refuse(refusal.into());
    refusal.defect().iter().for_each(|defect| facts.report_defect(defect));
    refusal.respond()
}

/// The fixed answer with `status`, recording `reason` as why the request failed.
fn refused(facts: &RequestFacts, reason: ReasonCode, status: StatusCode) -> RefusalResponse {
    facts.refuse(reason);
    RefusalResponse::fixed(status.as_u16())
}

/// The request head the pipeline reads, or `None` if a header does not convert, which hyper's parser should never let
/// through. hyper groups a repeated header's values together, so headers keep their order of first appearance.
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

/// The caller's `Accept-Encoding`, its repeated headers joined into one list as RFC 9110 §5.3 allows; `None` when it
/// sent none, or when the joined list is not a valid value, which `choose_emitted` would treat as absent too.
fn accept_encoding(headers: &HeaderMap) -> Option<HttpHeaderValue> {
    let values: Vec<&[u8]> = headers.get_all(ACCEPT_ENCODING).iter().map(HttpHeaderValue::as_bytes).collect();
    (!values.is_empty())
        .then(|| values.join(&b", "[..]))
        .and_then(|joined| HttpHeaderValue::from_bytes(&joined).ok())
}

/// The caller's body as the upstream body: none when the caller sent none, else streamed with its declared length.
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

/// The caller's body as the data chunks the upstream client forwards. Trailers are dropped: the client sends none.
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

/// The caller-token header of the listener the request arrived on. The pipeline identified the caller there, so the
/// listener is in the policy.
fn token_header(snapshot: &ServingSnapshot, tags: &ConnectionTags) -> Option<HeaderName> {
    snapshot
        .policy()
        .config()
        .listeners()
        .get(tags.listener())
        .map(ListenerConfig::caller_token_header)
}

/// The `503` for a request refused at admission: the redacted reason as its whole body. It is given before the caller is
/// identified, because with no snapshot there is no policy to identify the caller against (§3.12).
fn unavailable(reason: UnavailableReason, facts: &RequestFacts) -> Response<ResponseBody> {
    facts.refuse(reason.into());
    text_response(StatusCode::SERVICE_UNAVAILABLE, reason.as_str())
}

/// A refusal as a hyper response.
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

/// A `text/plain` response with `status` and a constant `body`.
fn text_response(status: StatusCode, body: &'static str) -> Response<ResponseBody> {
    let body = Full::new(Bytes::from_static(body.as_bytes()));
    let mut response = Response::new(body.map_err(|never| match never {}).boxed_unsync());
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HttpHeaderValue::from_static("text/plain; charset=utf-8"));
    response
}
