//! Who may use the admin socket (spec §3.2): an admin principal, judged only from the uid the kernel reports for the
//! connecting process.
//!
//! The socket's `0600` mode is the first barrier; this check refuses everyone else even when those permissions are
//! wrong. It is the only admin identity check, so nothing the client sends, no source port and no executable name takes
//! part. The rule is pure: [`peer_identity`] is the only part that asks the kernel.

// Windows has no Unix-socket peer credentials in std; its admin transport gets its own adapter.
#[cfg(unix)]
mod peer;
#[cfg(test)]
mod tests;

#[cfg(unix)]
pub use peer::peer_identity;
use thiserror::Error;

use crate::deployment::DeploymentProfile;

/// What the kernel reported about the process at the other end of a Unix socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerIdentity {
    /// The peer's effective uid when it connected; the only field that decides admission.
    pub uid: u32,
    /// The peer's effective gid when it connected.
    pub gid: u32,
    /// The peer's process ID, for the audit log only. It is never used to look up an executable: `/proc/<pid>/exe`
    /// cannot tell the owner from malware running as the same account (§3.4), and the pid may already be reused.
    pub pid: u32,
}

/// A peer the admin principal check accepted.
///
/// Its fields are private and only [`AdminPrincipals::accepts`] builds one, so holding an `AdminPrincipal` proves the
/// check ran. Code outside this module cannot construct it:
///
/// ```compile_fail,E0451
/// use iron_vault::admin::principal::{AdminPrincipal, PeerIdentity};
///
/// let forged = AdminPrincipal { peer: PeerIdentity { uid: 0, gid: 0, pid: 1 } };
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdminPrincipal {
    peer: PeerIdentity,
}

impl AdminPrincipal {
    /// The accepted peer, for the audit log.
    pub const fn peer(&self) -> PeerIdentity {
        self.peer
    }
}

/// The admin principals of one installation, fixed by its deployment profile and never configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdminPrincipals {
    profile: DeploymentProfile,
    service_uid: u32,
}

impl AdminPrincipals {
    /// The admin principals of `profile`, whose service account has `service_uid`. In development the service account
    /// is the invoking user.
    pub const fn new(profile: DeploymentProfile, service_uid: u32) -> Self {
        Self { profile, service_uid }
    }

    /// Accepts `peer` when its uid is an admin principal: root or the service account in a protected install, and only
    /// the service account in development, never root, because a development build refuses to run as root.
    pub fn accepts(&self, peer: PeerIdentity) -> Result<AdminPrincipal, NotAnAdminPrincipal> {
        match self.profile {
            DeploymentProfile::Protected if peer.uid == 0 || peer.uid == self.service_uid => Ok(AdminPrincipal { peer }),
            DeploymentProfile::Development if peer.uid != 0 && peer.uid == self.service_uid => Ok(AdminPrincipal { peer }),
            DeploymentProfile::Protected => Err(NotAnAdminPrincipal::Protected { uid: peer.uid }),
            DeploymentProfile::Development => Err(NotAnAdminPrincipal::Development { uid: peer.uid }),
        }
    }
}

/// The admin socket refused a peer whose uid is not an admin principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum NotAnAdminPrincipal {
    /// A protected install refused the peer; the owner reaches the service by becoming a host administrator.
    #[error("uid {uid} may not use the admin socket; run the command through `sudo`")]
    Protected {
        /// The refused uid.
        uid: u32,
    },
    /// A development install refused the peer.
    #[error("uid {uid} may not use the admin socket; run the command as the user that runs the development service, not root")]
    Development {
        /// The refused uid.
        uid: u32,
    },
}

impl NotAnAdminPrincipal {
    /// The refused uid.
    pub const fn uid(&self) -> u32 {
        match self {
            Self::Protected { uid } | Self::Development { uid } => *uid,
        }
    }
}
