//! Decides who may use the admin socket: an admin principal, judged only from the uid the kernel reports for the
//! connecting process
//! ([spec §5: How the service identifies an admin principal](../../../../design/iron-vault-specification.md#how-the-service-identifies-an-admin-principal)).
//!
//! The socket's `0600` mode is the first barrier; this check refuses everyone else even when those permissions are
//! wrong. It is the only admin identity check, so nothing the client sends, no source port and no executable name takes
//! part. The rule is pure: [`peer_identity`] is the only part that asks the kernel. The rule by deployment profile:
//!
//! ```text
//! profile       accepted uid
//! Protected     0 (root) only; the owner runs the CLI through sudo
//! Container     0 (root) only; the owner runs the CLI on the host through sudo
//! Development   the uid the service runs as, never 0
//! ```

#[cfg(test)]
mod tests;

pub use crate::peer::PeerIdentity;
#[cfg(unix)]
pub use crate::peer::peer_identity;
use thiserror::Error;

use crate::deployment::DeploymentProfile;

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
    /// Returns the accepted peer, for the audit log.
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
    /// Makes the admin principals of `profile`. `service_uid` matters only in development, where the service account is
    /// the invoking user and the only admin principal.
    pub const fn new(profile: DeploymentProfile, service_uid: u32) -> Self {
        Self { profile, service_uid }
    }

    /// Accepts `peer` when its uid is an admin principal, and refuses it with [`NotAnAdminPrincipal`] otherwise.
    ///
    /// A protected install or a container accepts only root. No administrator acts as the service account, and accepting
    /// it would let anything that takes over the service lock the vault or spend the owner's passphrase attempts.
    /// Development accepts only the invoking user, never root, because a development build refuses to run as root.
    pub fn accepts(&self, peer: PeerIdentity) -> Result<AdminPrincipal, NotAnAdminPrincipal> {
        match self.profile {
            DeploymentProfile::Protected | DeploymentProfile::Container if peer.uid() == 0 => Ok(AdminPrincipal { peer }),
            DeploymentProfile::Development if peer.uid() != 0 && peer.uid() == self.service_uid => Ok(AdminPrincipal { peer }),
            DeploymentProfile::Protected => Err(NotAnAdminPrincipal::Protected { uid: peer.uid() }),
            DeploymentProfile::Development => Err(NotAnAdminPrincipal::Development { uid: peer.uid() }),
            DeploymentProfile::Container => Err(NotAnAdminPrincipal::Container { uid: peer.uid() }),
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
    /// A container install refused the peer; the owner reaches the service from the host, where root owns the admin
    /// socket.
    #[error("uid {uid} may not use the admin socket; run the command on the host through `sudo`")]
    Container {
        /// The refused uid.
        uid: u32,
    },
}

impl NotAnAdminPrincipal {
    /// Returns the refused uid.
    pub const fn uid(&self) -> u32 {
        match self {
            Self::Protected { uid } | Self::Development { uid } | Self::Container { uid } => *uid,
        }
    }
}
