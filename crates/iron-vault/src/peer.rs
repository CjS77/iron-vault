//! Who is at the other end of a Unix socket, as the kernel reports it (spec §5, §7).
//!
//! Both the admin socket and the request sockets judge a connection only by this answer: the admin socket checks it
//! against the admin principals, and a request socket hands it to caller authentication. Nothing the peer sends takes
//! part.

// Windows has no Unix-socket peer credentials in std; its transports get their own adapter.
#[cfg(unix)]
mod adapter;
#[cfg(all(test, unix))]
mod tests;

#[cfg(unix)]
pub use adapter::peer_identity;

/// What the kernel reported about the process at the other end of a Unix socket.
///
/// Its fields are private and only the platform adapter behind [`peer_identity`] builds one, so a peer identity always
/// comes from the kernel, never from something the peer sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerIdentity {
    uid: u32,
    gid: u32,
    pid: u32,
}

impl PeerIdentity {
    /// A peer identity for unit tests of the rules that judge one; outside tests only the adapter builds one.
    #[cfg(test)]
    pub(crate) const fn for_test(uid: u32, gid: u32, pid: u32) -> Self {
        Self { uid, gid, pid }
    }

    /// The peer's effective uid when it connected; the only field that decides who the peer is.
    pub const fn uid(&self) -> u32 {
        self.uid
    }

    /// The peer's effective gid when it connected.
    pub const fn gid(&self) -> u32 {
        self.gid
    }

    /// The peer's process ID, for the audit log only. It is never used to look up an executable: `/proc/<pid>/exe`
    /// cannot tell the owner from malware running as the same account (§7), and the pid may already be reused.
    pub const fn pid(&self) -> u32 {
        self.pid
    }
}
