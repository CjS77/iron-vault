//! Who is at the other end of a Unix socket, as the kernel reports it ([spec §5][s5], [§7][s7]).
//!
//! Both the admin socket and the request sockets judge a connection only by this answer: the admin socket checks it
//! against the admin principals, and a request socket hands it to caller authentication. Nothing the peer sends takes
//! part.
//!
//! [s5]: ../../../design/iron-vault-specification.md#5-service-and-cli-separation-of-concerns
//! [s7]: ../../../design/iron-vault-specification.md#7-caller-authentication-and-listeners

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
    pid: Option<u32>,
}

impl PeerIdentity {
    /// Creates a peer identity for unit tests of the rules that judge one; outside tests only the adapter builds one.
    #[cfg(test)]
    pub(crate) const fn for_test(uid: u32, gid: u32, pid: u32) -> Self {
        Self { uid, gid, pid: Some(pid) }
    }

    /// Creates a test peer whose pid the kernel could not report, as for a peer in another PID namespace.
    #[cfg(test)]
    pub(crate) const fn for_test_without_pid(uid: u32, gid: u32) -> Self {
        Self { uid, gid, pid: None }
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
    /// cannot tell the owner from malware running as the same account
    /// ([§7](../../../design/iron-vault-specification.md#7-caller-authentication-and-listeners)), and the pid may
    /// already be reused. It is absent when the peer is in a PID namespace the service cannot see, such as the host CLI
    /// talking to the service in the Container profile.
    pub const fn pid(&self) -> Option<u32> {
        self.pid
    }
}
