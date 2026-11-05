//! The task that accepts on the request listeners, and the listener rebuild that replaces it without cutting off the
//! requests already being served.

use std::collections::BTreeMap;
use std::sync::Arc;

use iron_vault_policy::{Limits, ListenerConfig, ListenerName};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::proxy_handler::ProxyHandler;
use crate::request_listeners::{OpenError, Rebuilt, RequestListeners};
use crate::request_server::{Connections, RequestServer};
use crate::serving_snapshot::SnapshotHolder;
use crate::socket_activation::PassedSockets;
use crate::trusted_path_report::ServicePaths;

/// The request server with the proxy handler, accepting on one listener set until it is stopped or rebuilt.
///
/// Every request it serves takes its admission from the holder, so the same server answers `503` while the set is
/// provisional and serves once a snapshot is held. The connections live beside the accept loop rather than in it, so a
/// rebuild can stop accepting without closing them.
#[derive(Debug)]
pub(super) struct Serving {
    names: Vec<ListenerName>,
    server: Arc<RequestServer<ProxyHandler>>,
    /// What a server built for new limits admits requests by.
    holder: Arc<SnapshotHolder>,
    stop: oneshot::Sender<()>,
    task: JoinHandle<(RequestListeners, Connections)>,
}

impl Serving {
    /// Serves `listeners` under `limits`, admitting each request by `holder`.
    pub(super) fn start(listeners: RequestListeners, limits: Limits, holder: Arc<SnapshotHolder>) -> Self {
        let server = Arc::new(RequestServer::new(limits, ProxyHandler::new(Arc::clone(&holder))));
        Self::accept(listeners, Connections::default(), server, holder)
    }

    /// Accepts on `listeners` with `server`, adding to `connections`.
    fn accept(
        listeners: RequestListeners,
        mut connections: Connections,
        server: Arc<RequestServer<ProxyHandler>>,
        holder: Arc<SnapshotHolder>,
    ) -> Self {
        let names = listeners.names().cloned().collect();
        let (stop, stopped) = oneshot::channel();
        let accepting = Arc::clone(&server);
        let task = tokio::spawn(async move {
            // A dropped sender stops accepting as a sent signal does.
            accepting
                .accept_until(&listeners, &mut connections, async {
                    let _ = stopped.await;
                })
                .await;
            (listeners, connections)
        });
        Self {
            names,
            server,
            holder,
            stop,
            task,
        }
    }

    /// The names of the listeners being served, in name order.
    pub(super) fn names(&self) -> Vec<ListenerName> {
        self.names.clone()
    }

    /// The listener rebuild against the verified `listeners` and `limits`, adopting from `passed` where it can.
    ///
    /// Accepting pauses while the set is rebuilt; a connection that arrives meanwhile waits in its socket's backlog.
    /// The connections of every listener the rebuild closes are closed before this returns, so the next snapshot is
    /// never served through them. The rest stay open, so a request admitted on the old snapshot finishes on it. New
    /// limits close every connection, since the old ones were admitted under the old limits and hold the old server's
    /// connection permits.
    pub(super) async fn rebuild(
        self,
        listeners: &BTreeMap<ListenerName, ListenerConfig>,
        limits: Limits,
        paths: &ServicePaths,
        passed: &mut PassedSockets,
    ) -> (Self, Vec<OpenError>) {
        let (server, holder) = (Arc::clone(&self.server), Arc::clone(&self.holder));
        let (current, mut connections) = self.halt().await;
        let Rebuilt {
            listeners: rebuilt,
            kept,
            failures,
        } = current.rebuild(listeners, paths, passed);
        let server = if *server.limits() == limits {
            connections.close_except(&kept).await;
            server
        } else {
            connections.close_all().await;
            Arc::new(RequestServer::new(limits, ProxyHandler::new(Arc::clone(&holder))))
        };
        (Self::accept(rebuilt, connections, server, holder), failures)
    }

    /// Stops accepting, closes every connection being served and waits for each to end, then closes the listeners,
    /// removing the socket files the service bound.
    pub(super) async fn stop(self) {
        let (listeners, mut connections) = self.halt().await;
        connections.close_all().await;
        drop(listeners);
    }

    /// Stops accepting and returns the listeners, with their sockets still open, and the connections, still running. A
    /// task that panicked has dropped both, which closed them, so a rebuild then opens every listener afresh.
    async fn halt(self) -> (RequestListeners, Connections) {
        // A failed send means the task has already ended, which `await` below reports.
        let _ = self.stop.send(());
        self.task.await.unwrap_or_else(|error| {
            tracing::error!("the request listener task failed: {error}");
            (RequestListeners::empty(), Connections::default())
        })
    }
}
