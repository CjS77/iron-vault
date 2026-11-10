//! The platform adapter that asks the kernel who is at the other end of a Unix socket.

use std::io;

use tokio::net::UnixStream;

use super::PeerIdentity;

/// Reads the peer's credentials from `SO_PEERCRED`, which the kernel recorded when the peer connected; nothing the
/// peer sends can change them.
///
/// tokio reads them into `libc::ucred`, where the pid 0 the kernel reports for a peer outside this PID namespace is an
/// ordinary value. rustix's `socket_peercred` must not be used here: it decodes the pid into a non-zero type without
/// checking it.
#[cfg(target_os = "linux")]
pub fn peer_identity(stream: &UnixStream) -> io::Result<PeerIdentity> {
    let cred = stream.peer_cred()?;
    Ok(PeerIdentity {
        uid: cred.uid(),
        gid: cred.gid(),
        pid: visible_pid(cred.pid().unwrap_or(0))?,
    })
}

/// Converts the raw pid from `SO_PEERCRED`. The kernel reports 0 when the peer is in a PID namespace this process
/// cannot see, such as the host CLI talking to a containerised service, so 0 means "no pid", not an error. A negative
/// pid can only come from a broken kernel interface, so it is refused.
pub(super) fn visible_pid(raw: i32) -> io::Result<Option<u32>> {
    match u32::try_from(raw) {
        Ok(0) => Ok(None),
        Ok(pid) => Ok(Some(pid)),
        Err(_) => Err(io::Error::new(io::ErrorKind::InvalidData, "negative peer pid")),
    }
}

/// No peer-credential adapter exists for this platform yet, so every connection that needs one is refused.
#[cfg(not(target_os = "linux"))]
pub fn peer_identity(_stream: &UnixStream) -> io::Result<PeerIdentity> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Unix socket peer credentials are not supported on this platform",
    ))
}
