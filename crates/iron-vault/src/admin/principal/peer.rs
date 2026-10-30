//! The platform adapter that asks the kernel who is at the other end of a Unix socket.

use std::io;
use std::os::fd::AsFd;

use super::PeerIdentity;

/// Reads the peer's credentials from `SO_PEERCRED`, which the kernel recorded when the peer connected; nothing the
/// peer sends can change them. `stream` is a connected Unix stream socket, blocking or not; any other descriptor is
/// an error.
#[cfg(target_os = "linux")]
pub fn peer_identity(stream: impl AsFd) -> io::Result<PeerIdentity> {
    let cred = rustix::net::sockopt::socket_peercred(stream)?;
    let pid = u32::try_from(cred.pid.as_raw_pid()).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "negative peer pid"))?;
    Ok(PeerIdentity {
        uid: cred.uid.as_raw(),
        gid: cred.gid.as_raw(),
        pid,
    })
}

/// No peer-credential adapter exists for this platform yet, so every admin connection is refused.
#[cfg(not(target_os = "linux"))]
pub fn peer_identity(_stream: impl AsFd) -> io::Result<PeerIdentity> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "admin socket peer credentials are not supported on this platform",
    ))
}
