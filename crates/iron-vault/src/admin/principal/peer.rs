//! The platform adapter that asks the kernel who is at the other end of a Unix socket.

use std::io;
use std::os::unix::net::UnixStream;

use super::PeerIdentity;

/// Reads the peer's credentials from `SO_PEERCRED`, which the kernel recorded when the peer connected; nothing the
/// peer sends can change them.
#[cfg(target_os = "linux")]
pub fn peer_identity(stream: &UnixStream) -> io::Result<PeerIdentity> {
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
pub fn peer_identity(_stream: &UnixStream) -> io::Result<PeerIdentity> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "admin socket peer credentials are not supported on this platform",
    ))
}
