// SPDX-License-Identifier: MPL-2.0
//! Why an approved or provisional listener did not open, as [`status`][status] reports it.
//!
//! A listener that fails to open is left out while the others keep serving, so without a report the owner would learn of
//! it only from the log. The reason is one fixed category chosen from the open error, never the error's text: that text
//! names paths and addresses, and no type here can hold a file's contents or a key.
//!
//! [status]: ../../../design/admin-protocol.md#status

use iron_vault_policy::ListenerName;

// Mapping an open error to a reason needs the Linux-only listeners; the types and wire codes here do not, since the CLI
// decodes `status` on every platform.
#[cfg(target_os = "linux")]
mod open_error;
#[cfg(target_os = "linux")]
pub use open_error::failures;

/// A listener that is not open and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerFailure {
    /// The listener the config names.
    pub name: ListenerName,
    /// Why it did not open.
    pub reason: ListenerFailureReason,
}

/// The fixed categories of listener open failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerFailureReason {
    /// The TLS key is not the leaf certificate's key.
    TlsKeyMismatch,
    /// A TLS file is missing, or fails its trusted-path rule.
    TlsFileUnreadable,
    /// The certificate file is not a well-formed certificate chain.
    TlsCertificateInvalid,
    /// The TLS key file does not hold exactly one key the TLS provider can use, or the pair could not be checked.
    TlsKeyUnusable,
    /// The address or socket path is already taken.
    AddressInUse,
    /// A plain-HTTP TCP listener is off loopback.
    PlainOffLoopback,
    /// The socket's path or its directory fails the rules for a request socket.
    SocketPath,
    /// A protected install's TCP listener was not passed by systemd.
    SocketActivationMissing,
    /// The socket systemd passed does not match the listener.
    SocketActivationMismatch,
    /// The socket could not be bound or registered for another reason.
    BindRefused,
}

impl ListenerFailureReason {
    /// Every reason.
    pub const ALL: [Self; 10] = [
        Self::TlsKeyMismatch,
        Self::TlsFileUnreadable,
        Self::TlsCertificateInvalid,
        Self::TlsKeyUnusable,
        Self::AddressInUse,
        Self::PlainOffLoopback,
        Self::SocketPath,
        Self::SocketActivationMissing,
        Self::SocketActivationMismatch,
        Self::BindRefused,
    ];

    /// The category's name, as documented for `status`.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::TlsKeyMismatch => "tls-key-mismatch",
            Self::TlsFileUnreadable => "tls-file-unreadable",
            Self::TlsCertificateInvalid => "tls-certificate-invalid",
            Self::TlsKeyUnusable => "tls-key-unusable",
            Self::AddressInUse => "address-in-use",
            Self::PlainOffLoopback => "plain-http-off-loopback",
            Self::SocketPath => "socket-path",
            Self::SocketActivationMissing => "socket-activation-missing",
            Self::SocketActivationMismatch => "socket-activation-mismatch",
            Self::BindRefused => "bind-refused",
        }
    }

    /// A short phrase for the owner.
    pub const fn words(self) -> &'static str {
        match self {
            Self::TlsKeyMismatch => "the TLS key does not match the certificate",
            Self::TlsFileUnreadable => "a TLS file is missing or not readable under the trusted-path rules",
            Self::TlsCertificateInvalid => "the TLS certificate file is not a usable certificate",
            Self::TlsKeyUnusable => "the TLS key file holds no usable key",
            Self::AddressInUse => "the address or socket path is already in use",
            Self::PlainOffLoopback => "plain HTTP is not allowed off loopback",
            Self::SocketPath => "the socket path or its directory is not acceptable",
            Self::SocketActivationMissing => "systemd passed no socket for it",
            Self::SocketActivationMismatch => "the socket systemd passed does not match the listener",
            Self::BindRefused => "the socket could not be opened",
        }
    }

    /// The wire code, as [`status`](../../../design/admin-protocol.md#status) lists it. Literal, so reordering [`ALL`](Self::ALL) cannot
    /// change the protocol.
    pub const fn code(self) -> u8 {
        match self {
            Self::TlsKeyMismatch => 1,
            Self::TlsFileUnreadable => 2,
            Self::TlsCertificateInvalid => 3,
            Self::TlsKeyUnusable => 4,
            Self::AddressInUse => 5,
            Self::PlainOffLoopback => 6,
            Self::SocketPath => 7,
            Self::SocketActivationMissing => 8,
            Self::SocketActivationMismatch => 9,
            Self::BindRefused => 10,
        }
    }

    /// Returns the reason a wire `code` stands for, or `None` for an unknown code.
    pub fn from_code(code: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|reason| reason.code() == code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_reason_round_trips_through_its_code() {
        ListenerFailureReason::ALL
            .iter()
            .for_each(|reason| assert_eq!(ListenerFailureReason::from_code(reason.code()), Some(*reason)));
        assert_eq!(ListenerFailureReason::from_code(0), None);
        assert_eq!(ListenerFailureReason::from_code(11), None);
    }

    #[test]
    fn the_wire_codes_are_the_documented_ones() {
        let codes: Vec<u8> = ListenerFailureReason::ALL.iter().map(|reason| reason.code()).collect();
        assert_eq!(codes, (1..=10).collect::<Vec<u8>>());
    }
}
