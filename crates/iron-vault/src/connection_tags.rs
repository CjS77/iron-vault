//! The connection tags the transport sets on every request (§3.4). They live outside the Linux-only request server so
//! the request pipeline, which reads them, stays pure and builds on every platform.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use iron_vault_policy::ListenerName;

/// What the transport says about the connection a request arrived on: its listener and, on a Unix socket, the peer's
/// uid. Only the request server builds these, from the accepted connection, so a request can never set them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionTags {
    listener: ListenerName,
    peer_uid: Option<u32>,
}

impl ConnectionTags {
    /// Tags for a connection accepted on `listener` from `peer_uid`. Crate-private, so nothing outside the service can
    /// forge them. Outside tests only the request server calls it, and that is built only on Linux.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn new(listener: ListenerName, peer_uid: Option<u32>) -> Self {
        Self { listener, peer_uid }
    }

    /// The listener the connection arrived on.
    pub fn listener(&self) -> &ListenerName {
        &self.listener
    }

    /// The peer's uid as the kernel reported it on a Unix socket; `None` on TCP, which reports no account.
    pub fn peer_uid(&self) -> Option<u32> {
        self.peer_uid
    }
}

/// Whether the service itself is closing the connections of a listener, so a request that ends because its connection
/// was aborted is recorded as the service's doing and not the caller's (`design/audit-logging.md`, "Closes the service
/// makes"). It is set before the connections are aborted and shared by clones, but it is not part of [`ConnectionTags`],
/// which the pipeline compares by value.
#[derive(Debug, Clone, Default)]
pub struct ServiceClose(Arc<AtomicBool>);

impl ServiceClose {
    /// Records that the service is closing the connections that hold a clone of this flag.
    pub fn set(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// Whether the service has begun closing the connections.
    pub fn is_set(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}
