//! Audit events about the admin socket (`design/audit-logging.md`, "Admin commands").

use super::{AUDIT_TARGET, AuditEvent, EventName};
use crate::admin::protocol::{AdminCommand, FrameError};
use crate::peer::PeerIdentity;

/// `admin.command`: an admin principal's request was read. It names the command and the uid the kernel reported, never
/// an argument, since arguments can hold secrets.
#[derive(Debug, Clone, Copy)]
pub struct AdminCommandRead {
    /// The command requested.
    pub command: AdminCommand,
    /// The admin principal that sent it.
    pub principal: PeerIdentity,
}

impl AuditEvent for AdminCommandRead {
    const NAME: EventName = EventName("admin.command");

    fn emit(&self) {
        tracing::info!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            command = self.command.label(),
            principal_uid = self.principal.uid(),
            "admin command read",
        );
    }
}

/// Why an admin connection or request was refused before any command ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminRefusal {
    /// The peer's uid is not an admin principal.
    NotAdminPrincipal,
    /// The kernel would not report the peer's credentials.
    PeerUnreadable,
    /// The connection cap was reached.
    Busy,
    /// The frame's protocol version is not the service's.
    UnsupportedVersion,
    /// The frame did not decode.
    MalformedFrame,
    /// The frame named a command the service does not define.
    UnknownCommand,
    /// The exchange's first frame was not a request.
    UnexpectedFrame,
}

impl AdminRefusal {
    /// The refusal for a request frame that failed to decode.
    pub const fn of_frame(error: FrameError) -> Self {
        match error {
            FrameError::UnsupportedVersion(_) => Self::UnsupportedVersion,
            FrameError::UnknownCommand(_) => Self::UnknownCommand,
            _ => Self::MalformedFrame,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::NotAdminPrincipal => "not_admin_principal",
            Self::PeerUnreadable => "peer_unreadable",
            Self::Busy => "busy",
            Self::UnsupportedVersion => "unsupported_version",
            Self::MalformedFrame => "malformed_frame",
            Self::UnknownCommand => "unknown_command",
            Self::UnexpectedFrame => "unexpected_frame",
        }
    }
}

/// `admin.refused`: an admin connection or request was refused before any command ran. The peer's uid and pid are
/// recorded when the kernel reported them.
#[derive(Debug, Clone, Copy)]
pub struct AdminRefused {
    /// Why.
    pub refusal: AdminRefusal,
    /// The peer, when known.
    pub peer: Option<PeerIdentity>,
}

impl AuditEvent for AdminRefused {
    const NAME: EventName = EventName("admin.refused");

    fn emit(&self) {
        tracing::warn!(
            target: AUDIT_TARGET,
            event = Self::NAME.as_str(),
            refusal = self.refusal.label(),
            peer_uid = self.peer.map(|peer| peer.uid()),
            peer_pid = self.peer.map(|peer| peer.pid()),
            "admin request refused",
        );
    }
}
