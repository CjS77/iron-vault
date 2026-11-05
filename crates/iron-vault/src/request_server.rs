//! The request server (spec §3.5 step 1, §9): HTTP/1.1 on every connection the request listeners accept, bounded by
//! the operational limits before anyone is authenticated.
//!
//! Callers reach the service over local sockets and loopback, so it serves HTTP/1.1 only; HTTP/2 from callers is out
//! of scope, and a TLS listener offers only `http/1.1` by ALPN.
//!
//! Each limit and how a request that breaks it is answered:
//!
//! | Limit | Enforced by | Answer |
//! |---|---|---|
//! | Request form (§3.5 step 2) | [`check_form`], first, before the body limit and the handler | `400` |
//! | `max_connections` | A semaphore permit taken before the TLS handshake | Closed unread |
//! | `max_header_bytes` | hyper's `max_header_size`, which counts the request line and headers on the wire exactly | `431` |
//! | `max_header_count` | hyper's `max_headers` | `431` |
//! | `max_request_body_bytes` | `Content-Length` before the handler runs, else [`RequestBody`] as it streams | `413` |
//! | `request_timeout_secs` | A deadline from the request head to the last byte of the response, handed to the handler | `408`, or dropped |
//! | Header read timeout | hyper's `header_read_timeout`: [`HEADER_READ_TIMEOUT`], or the request timeout if shorter | Closed |
//!
//! hyper answers both header limits with `431`: it reports a head that is too long and one with too many headers as
//! the same error. A request target over 65,534 bytes gets `414` instead, from hyper's own URI limit; that is
//! reachable only when `max_header_bytes` is over 64 KiB. A request past the request timeout gets `408` if no response
//! has started; once one has, its body fails at the deadline and the connection is dropped. Every `413` and `408`
//! closes the connection, since the rest of that request is never read.
//!
//! The handler sees only the connection tags the transport set ([`ConnectionTags`]), never anything from the request
//! that claims to be one (§3.4).

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Body, Incoming};
use hyper::header::{CONNECTION, CONTENT_TYPE, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use iron_vault_policy::{Limits, ListenerName};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio::time::Instant;

pub use crate::connection_tags::ConnectionTags;
use crate::library_error::LibraryError;
use crate::request_listeners::{IncomingConnection, RequestListeners};

mod body;
mod form;
use body::{Deadline, Overflow};
pub use body::{RequestBody, RequestBodyError};
pub use form::{FormViolation, check_form};

/// The longest a connection may take to send a request's headers, so a client that trickles them (slowloris) cannot
/// hold a connection slot. It matches the TLS listener's handshake timeout.
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// hyper's smallest allowed read buffer; a smaller header limit is still exact, since `max_header_size` enforces it.
const MIN_READ_BUFFER: usize = 8192;

/// The error a response body may fail with.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The body of a response the handler returns.
pub type ResponseBody = UnsyncBoxBody<Bytes, BoxError>;

impl ConnectionTags {
    fn of(connection: &IncomingConnection) -> Self {
        Self::new(connection.listener().clone(), connection.peer().map(|peer| peer.uid()))
    }
}

/// Answers one request that has passed the request server's limits. The proxy handler implements it.
pub trait RequestHandler: Send + Sync + 'static {
    /// The response to `request`, which arrived on the connection `tags` describes. Its body fails with
    /// [`RequestBodyError::TooLarge`] once it passes the body limit, and the server then answers `413` itself.
    ///
    /// `deadline` is the request deadline. A handler that answers by then is heard, even at the deadline itself, so it
    /// can give its own status for what it was waiting on; otherwise the server answers `408`. A response body still
    /// streaming at the deadline fails there.
    fn handle(
        &self,
        request: Request<RequestBody>,
        tags: &ConnectionTags,
        deadline: Instant,
    ) -> impl Future<Output = Response<ResponseBody>> + Send;
}

/// Serves HTTP/1.1 on the request listeners under one set of operational limits.
#[derive(Debug)]
pub struct RequestServer<H> {
    handler: Arc<H>,
    limits: Limits,
    http: http1::Builder,
    connections: Arc<Semaphore>,
}

impl<H: RequestHandler> RequestServer<H> {
    /// A server that hands each request within `limits` to `handler`.
    pub fn new(limits: Limits, handler: H) -> Self {
        let permits = to_usize(limits.max_connections()).min(Semaphore::MAX_PERMITS);
        Self {
            handler: Arc::new(handler),
            limits,
            http: http_builder(&limits),
            connections: Arc::new(Semaphore::new(permits)),
        }
    }

    /// Accepts and serves connections on `listeners` until the returned future is dropped, which closes every
    /// connection it is serving. A connection over `max_connections` is closed before it is read.
    pub async fn serve(&self, listeners: &RequestListeners) -> Infallible {
        let mut connections = Connections::default();
        loop {
            let incoming = listeners.accept().await;
            self.admit(&mut connections, incoming);
        }
    }

    /// Serves as [`serve`](Self::serve) does until `stop` completes, then closes every connection it is serving and
    /// returns once each connection's task has ended, so nothing of the connections outlives the call, whatever runtime
    /// it runs on.
    pub async fn serve_until(&self, listeners: &RequestListeners, stop: impl Future<Output = ()>) {
        let mut connections = Connections::default();
        self.accept_until(listeners, &mut connections, stop).await;
        connections.close_all().await;
    }

    /// Accepts on `listeners` until `stop` completes, serving each connection in `connections`, and leaves every
    /// connection open: a listener rebuild hands them to the next accept loop, so their requests are not cut off.
    pub async fn accept_until(&self, listeners: &RequestListeners, connections: &mut Connections, stop: impl Future<Output = ()>) {
        let mut stop = std::pin::pin!(stop);
        loop {
            tokio::select! {
                incoming = listeners.accept() => self.admit(connections, incoming),
                () = &mut stop => break,
            }
        }
    }

    /// The limits this server enforces.
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Serves `incoming` in a task of its own, or closes it unread when `max_connections` are already open.
    fn admit(&self, connections: &mut Connections, incoming: IncomingConnection) {
        connections.reap();
        match Arc::clone(&self.connections).try_acquire_owned() {
            Ok(permit) => {
                let listener = incoming.listener().clone();
                connections.spawn(listener, self.connection(permit, incoming));
            }
            Err(_) => tracing::debug!(
                "listener {}: connection closed: {} connections are already open",
                incoming.listener(),
                self.limits.max_connections()
            ),
        }
    }

    /// Serves one connection, holding `permit` until it closes.
    fn connection(&self, permit: OwnedSemaphorePermit, incoming: IncomingConnection) -> impl Future<Output = ()> + Send + 'static {
        let (http, handler, limits) = (self.http.clone(), Arc::clone(&self.handler), self.limits);
        async move {
            let _permit = permit;
            let tags = ConnectionTags::of(&incoming);
            let stream = match incoming.establish().await {
                Ok(stream) => stream,
                Err(e) => return tracing::debug!("listener {}: {e}", tags.listener()),
            };
            let listener = tags.listener().clone();
            let service = service_fn(move |request| respond(Arc::clone(&handler), tags.clone(), limits, request));
            if let Err(e) = http.serve_connection(TokioIo::new(stream), service).await {
                tracing::debug!(error_kind = %e.kind_label(), "listener {listener}: connection ended");
            }
        }
    }
}

/// The connections a request server is serving, by the listener each arrived on, so a listener rebuild can close the
/// connections of the listeners it closes and keep the rest. Dropping it aborts every connection.
#[derive(Debug, Default)]
pub struct Connections(BTreeMap<ListenerName, JoinSet<()>>);

impl Connections {
    /// Closes the connections of every listener not in `kept` and waits for each one's task to end.
    pub async fn close_except(&mut self, kept: &BTreeSet<ListenerName>) {
        let (kept, closed): (BTreeMap<_, _>, BTreeMap<_, _>) =
            std::mem::take(&mut self.0).into_iter().partition(|(name, _)| kept.contains(name));
        self.0 = kept;
        // Each set aborts its own tasks and waits for them; awaiting needs a loop, since nothing here joins futures.
        for mut set in closed.into_values() {
            set.shutdown().await;
        }
    }

    /// Closes every connection and waits for each one's task to end.
    pub async fn close_all(&mut self) {
        self.close_except(&BTreeSet::new()).await;
    }

    fn spawn(&mut self, listener: ListenerName, connection: impl Future<Output = ()> + Send + 'static) {
        self.0.entry(listener).or_default().spawn(connection);
    }

    /// Forgets the connections that have ended, so the sets do not grow.
    fn reap(&mut self) {
        self.0.values_mut().for_each(|set| while set.try_join_next().is_some() {});
        self.0.retain(|_, set| !set.is_empty());
    }
}

/// hyper's HTTP/1.1 settings for the header limits and the header read timeout.
fn http_builder(limits: &Limits) -> http1::Builder {
    let header_bytes = to_usize(limits.max_header_bytes());
    let mut http = http1::Builder::new();
    http.timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT.min(request_timeout(limits)))
        .max_header_size(header_bytes)
        .max_buf_size(header_bytes.max(MIN_READ_BUFFER))
        .max_headers(to_usize(limits.max_header_count()));
    http
}

/// Runs the handler on one request within the body limit and the whole-request deadline.
async fn respond<H: RequestHandler>(
    handler: Arc<H>,
    tags: ConnectionTags,
    limits: Limits,
    request: Request<Incoming>,
) -> Result<Response<ResponseBody>, Infallible> {
    let deadline = Instant::now() + request_timeout(&limits);
    if let Err(violation) = check_form(request.method(), request.uri(), request.version(), request.headers()) {
        return Ok(form_refusal(violation));
    }
    let max_body = limits.max_request_body_bytes();
    if request.body().size_hint().lower() > max_body {
        return Ok(refusal(StatusCode::PAYLOAD_TOO_LARGE));
    }
    let overflow = Arc::new(Overflow::default());
    let request = request.map(|body| RequestBody::new(body, max_body, Arc::clone(&overflow)));
    // The handler is polled before the deadline, so one that times out its own wait at the same deadline is heard.
    let response = tokio::select! {
        biased;
        () = overflow.tripped() => refusal(StatusCode::PAYLOAD_TOO_LARGE),
        response = handler.handle(request, &tags, deadline) => response,
        () = tokio::time::sleep_until(deadline) => refusal(StatusCode::REQUEST_TIMEOUT),
    };
    // A handler may answer in the same poll in which its body passed the limit.
    let response = match overflow.is_tripped() {
        true => refusal(StatusCode::PAYLOAD_TOO_LARGE),
        false => response,
    };
    Ok(response.map(|body| Deadline::new(body, deadline).boxed_unsync()))
}

/// An empty response with `status` that closes the connection.
fn refusal(status: StatusCode) -> Response<ResponseBody> {
    let mut response = Response::new(Empty::new().map_err(|never| match never {}).boxed_unsync());
    *response.status_mut() = status;
    response.headers_mut().insert(CONNECTION, HeaderValue::from_static("close"));
    response
}

/// A `400` that closes the connection, with the rule broken as its body; the body never repeats the target.
fn form_refusal(violation: FormViolation) -> Response<ResponseBody> {
    let mut response = refusal(StatusCode::BAD_REQUEST);
    *response.body_mut() = Full::new(Bytes::from(violation.to_string()))
        .map_err(|never| match never {})
        .boxed_unsync();
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
    response
}

fn request_timeout(limits: &Limits) -> Duration {
    Duration::from_secs(limits.request_timeout_secs())
}

/// Every limit fits a `usize` on the platforms the service runs on; saturating keeps a 32-bit build bounded.
fn to_usize(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests;
