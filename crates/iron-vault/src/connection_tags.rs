//! The connection tags the transport sets on every request (§3.4). They live outside the Linux-only request server so
//! the request pipeline, which reads them, stays pure and builds on every platform.

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
