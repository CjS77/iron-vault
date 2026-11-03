//! The proxy handler: one request end to end, from the request server to the upstream and back (specification §3.5).
//!
//! Per request it loads the serving snapshot once and uses only that, runs the request pipeline (§3.5 steps 3-8),
//! sends the checked request with the caller's body through the route's upstream client (step 9), and relays the
//! response through the scrubber with the injected credential's scrub patterns (step 10, §3.8). Each failure gets one
//! fixed answer, and none formats a library error (§3.15):
//!
//! | Failure | Answer |
//! |---|---|
//! | The pipeline refuses the request | Its [`RefusalResponse`] |
//! | The route has no upstream client | `503` |
//! | The upstream exchange fails | [`TransportError::status`]: `502`, or `504` for a timeout |
//! | No response headers by the request deadline | `504` |
//! | The response has a content coding, or a transfer coding besides `chunked`, which the scrubber cannot see through | `502` |
//! | The response's `Location` leaves the route's upstream base or is ambiguous, or it has several (§3.8) | `502` |
//! | The response body fails after its head was sent | The caller's connection is aborted |
//!
//! The request deadline bounds the body as well: the request server fails a response body still streaming at it.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use futures_core::Stream;
use http_body_util::{BodyExt, Full};
use hyper::body::Body;
use hyper::header::{CONTENT_LENGTH, HeaderValue as HttpHeaderValue};
use hyper::http::request::Parts;
use hyper::{Request, Response, StatusCode};
use iron_vault_policy::{HeaderName, HeaderValue, ListenerConfig};
use tokio::time::Instant;

use crate::pipeline::{RefusalResponse, RequestHead, prepare};
use crate::request_server::{ConnectionTags, RequestBody, RequestHandler, ResponseBody};
use crate::serving_snapshot::{ServingSnapshot, SnapshotHolder};
use crate::upstream::body::{UpstreamBody, UpstreamBodyError};
use crate::upstream::transport_error::TransportError;

mod relay;
pub(crate) use relay::ResponseContext;
pub use relay::{RelayedBody, ResponseOutcome};

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
    ) -> impl Future<Output = Response<ResponseBody>> + Send {
        // Loaded once, here, so the whole request runs on one activation even if a reload lands while it is in flight.
        let snapshot = self.snapshots.load();
        let tags = tags.clone();
        async move {
            match proxy(&snapshot, &tags, request, deadline).await {
                Ok(response) => response,
                Err(refusal) => fixed(&refusal),
            }
        }
    }
}

/// Runs the pipeline, sends and relays; any failure before the response head is a fixed answer.
async fn proxy(
    snapshot: &ServingSnapshot,
    tags: &ConnectionTags,
    request: Request<RequestBody>,
    deadline: Instant,
) -> Result<Response<ResponseBody>, RefusalResponse> {
    let (parts, body) = request.into_parts();
    let head = request_head(&parts).ok_or_else(|| RefusalResponse::fixed(StatusCode::BAD_REQUEST.as_u16()))?;
    let prepared = prepare(snapshot, tags, head, std::time::Instant::now()).map_err(|refusal| refusal.respond())?;
    let client = snapshot
        .clients()
        .for_route(prepared.route())
        .map_err(|_| RefusalResponse::fixed(StatusCode::SERVICE_UNAVAILABLE.as_u16()))?;
    let (route, credential) = (prepared.route().clone(), prepared.credential().clone());
    let route_config = snapshot
        .policy()
        .route(&route)
        .ok_or_else(|| RefusalResponse::fixed(StatusCode::SERVICE_UNAVAILABLE.as_u16()))?;
    let (request, patterns) = prepared.into_parts();
    // The URL actually sent, which holds a query slot's secret: kept only until the response head is decided.
    let request_url = request.url().clone();
    let context = ResponseContext {
        method: request.method(),
        patterns,
        route,
        credential,
    };
    let send = client.send(request, upstream_body(&parts, body));
    let response = tokio::time::timeout_at(deadline, send)
        .await
        .unwrap_or(Err(TransportError::Timeout))
        .map_err(|error| RefusalResponse::fixed(error.status().as_u16()))?;
    relay::relay(response, token_header(snapshot, tags), context, route_config, &request_url)
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

/// A refusal as a hyper response.
fn fixed(refusal: &RefusalResponse) -> Response<ResponseBody> {
    let body = Full::new(Bytes::from_static(refusal.body().as_bytes()));
    let mut response = Response::new(body.map_err(|never| match never {}).boxed_unsync());
    *response.status_mut() = StatusCode::from_u16(refusal.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let headers = response.headers_mut();
    refusal.headers().into_iter().for_each(|(name, value)| {
        if let Ok(value) = HttpHeaderValue::try_from(value) {
            headers.insert(name, value);
        }
    });
    response
}
