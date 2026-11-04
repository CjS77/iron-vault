//! The task that serves the request listeners, and getting them back from it for a rebuild.

use std::sync::Arc;

use iron_vault_policy::{Limits, ListenerName};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::proxy_handler::ProxyHandler;
use crate::request_listeners::RequestListeners;
use crate::request_server::RequestServer;
use crate::serving_snapshot::SnapshotHolder;

/// The request server with the proxy handler, accepting on one listener set until it is stopped.
///
/// Every request it serves takes its admission from the holder, so the same task answers `503` while the set is
/// provisional and serves once a snapshot is held.
#[derive(Debug)]
pub(super) struct Serving {
    names: Vec<ListenerName>,
    stop: oneshot::Sender<()>,
    task: JoinHandle<RequestListeners>,
}

impl Serving {
    /// Serves `listeners` under `limits`, admitting each request by `holder`.
    pub(super) fn start(listeners: RequestListeners, limits: Limits, holder: Arc<SnapshotHolder>) -> Self {
        let names = listeners.names().cloned().collect();
        let (stop, stopped) = oneshot::channel();
        let server = RequestServer::new(limits, ProxyHandler::new(holder));
        let task = tokio::spawn(async move {
            tokio::select! {
                never = server.serve(&listeners) => match never {},
                _ = stopped => {}
            }
            listeners
        });
        Self { names, stop, task }
    }

    /// The names of the listeners being served, in name order.
    pub(super) fn names(&self) -> Vec<ListenerName> {
        self.names.clone()
    }

    /// Stops accepting, closes every connection being served, and returns the listeners with their sockets still open.
    /// A task that panicked has dropped them, which closed them, so a rebuild then opens every listener afresh.
    pub(super) async fn stop(self) -> RequestListeners {
        // The task ends whether the signal is received or the sender is dropped, so a failed send needs no handling.
        let _ = self.stop.send(());
        self.task.await.unwrap_or_else(|error| {
            tracing::error!("the request listener task failed: {error}");
            RequestListeners::empty()
        })
    }
}
