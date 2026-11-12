//! Why an approved or provisional listener did not open, as `status` reports it (`design/admin-protocol.md#status`).
//!
//! A listener that fails to open is left out while the others keep serving, so without a report the owner would learn of
//! it only from the log. The reason is one fixed category chosen from the open error, never the error's text: that text
//! names paths and addresses, and no type here can hold a file's contents or a key.

use std::io;

use iron_vault_policy::ListenerName;

use crate::listener_tls::ListenerTlsError;
use crate::request_listeners::OpenError;
use crate::request_socket::RequestBindError;
use crate::socket_activation::{AdoptError, NotActivated};
use crate::socket_file::BindError;

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
    /// Every reason, in wire-code order.
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

    /// The wire code: the index in [`ALL`](Self::ALL) plus one.
    pub fn code(self) -> u8 {
        (1..).zip(Self::ALL).find(|(_, reason)| *reason == self).map_or(0, |(code, _)| code)
    }

    /// The reason a wire `code` stands for.
    pub fn from_code(code: u8) -> Option<Self> {
        usize::from(code).checked_sub(1).and_then(|index| Self::ALL.get(index)).copied()
    }

    fn of(error: &OpenError) -> Self {
        match error {
            OpenError::Tls(error) => Self::of_tls(error),
            OpenError::Unix { source, .. } => Self::of_bind(source),
            OpenError::NotActivated(_) => Self::SocketActivationMissing,
            OpenError::Adopt(error) => Self::of_adopt(error),
            OpenError::Tcp { kind, .. } | OpenError::Register { kind, .. } => Self::of_kind(*kind),
            OpenError::PlainOffLoopback { .. } => Self::PlainOffLoopback,
            OpenError::NoRuntime | OpenError::NoRuntimeDir => Self::BindRefused,
        }
    }

    fn of_kind(kind: io::ErrorKind) -> Self {
        match kind {
            io::ErrorKind::AddrInUse => Self::AddressInUse,
            _ => Self::BindRefused,
        }
    }

    fn of_tls(error: &ListenerTlsError) -> Self {
        match error {
            ListenerTlsError::KeyMismatch { .. } => Self::TlsKeyMismatch,
            ListenerTlsError::Unreadable { .. } => Self::TlsFileUnreadable,
            ListenerTlsError::MalformedPem { .. }
            | ListenerTlsError::NotOnlyCertificates { .. }
            | ListenerTlsError::NoCertificates { .. } => Self::TlsCertificateInvalid,
            ListenerTlsError::NotOneKey { .. }
            | ListenerTlsError::UnusableKey { .. }
            | ListenerTlsError::KeyNotChecked { .. }
            | ListenerTlsError::ProtocolVersions { .. } => Self::TlsKeyUnusable,
        }
    }

    fn of_bind(error: &RequestBindError) -> Self {
        match error {
            RequestBindError::AdminSocketPath { .. }
            | RequestBindError::NoDirectory { .. }
            | RequestBindError::UntrustedDirectory { .. } => Self::SocketPath,
            RequestBindError::Bind(BindError::Io { kind, .. }) => Self::of_kind(*kind),
            RequestBindError::Bind(_) => Self::BindRefused,
        }
    }

    fn of_adopt(error: &AdoptError) -> Self {
        match error {
            AdoptError::Missing { .. } => Self::SocketActivationMissing,
            AdoptError::NoDirectory { .. } | AdoptError::UntrustedDirectory { .. } | AdoptError::SocketFile { .. } => Self::SocketPath,
            AdoptError::Activation(_)
            | AdoptError::NotStream { .. }
            | AdoptError::NotListening { .. }
            | AdoptError::AddressMismatch { .. }
            | AdoptError::Io { .. } => Self::SocketActivationMismatch,
        }
    }
}

/// The listener `error` is about, or `None` for an error about the whole set.
fn listener_of(error: &OpenError) -> Option<&ListenerName> {
    match error {
        OpenError::Unix { listener, .. }
        | OpenError::Tcp { listener, .. }
        | OpenError::PlainOffLoopback { listener, .. }
        | OpenError::Register { listener, .. }
        | OpenError::NotActivated(NotActivated { listener }) => Some(listener),
        OpenError::Tls(error) => Some(tls_listener(error)),
        OpenError::Adopt(error) => adopt_listener(error),
        OpenError::NoRuntime | OpenError::NoRuntimeDir => None,
    }
}

fn tls_listener(error: &ListenerTlsError) -> &ListenerName {
    match error {
        ListenerTlsError::Unreadable { listener, .. }
        | ListenerTlsError::MalformedPem { listener, .. }
        | ListenerTlsError::NotOnlyCertificates { listener, .. }
        | ListenerTlsError::NoCertificates { listener, .. }
        | ListenerTlsError::NotOneKey { listener, .. }
        | ListenerTlsError::UnusableKey { listener, .. }
        | ListenerTlsError::KeyMismatch { listener, .. }
        | ListenerTlsError::KeyNotChecked { listener, .. }
        | ListenerTlsError::ProtocolVersions { listener, .. } => listener,
    }
}

fn adopt_listener(error: &AdoptError) -> Option<&ListenerName> {
    match error {
        AdoptError::Activation(_) => None,
        AdoptError::Missing { listener, .. }
        | AdoptError::NotStream { listener }
        | AdoptError::NotListening { listener }
        | AdoptError::AddressMismatch { listener, .. }
        | AdoptError::NoDirectory { listener, .. }
        | AdoptError::UntrustedDirectory { listener, .. }
        | AdoptError::SocketFile { listener, .. }
        | AdoptError::Io { listener, .. } => Some(listener),
    }
}

/// The failures `errors` come to, in name order. An error about the whole set (the runtime directory is unknown, the
/// activation variables are malformed) leaves every listener in `configured` unopened, so it is reported for each.
pub fn failures<'a>(errors: &[OpenError], configured: impl Iterator<Item = &'a ListenerName>) -> Vec<ListenerFailure> {
    let mut failures: Vec<_> = match errors.iter().find(|error| listener_of(error).is_none()) {
        Some(error) => configured
            .map(|name| ListenerFailure {
                name: name.clone(),
                reason: ListenerFailureReason::of(error),
            })
            .collect(),
        None => errors
            .iter()
            .filter_map(|error| listener_of(error).map(|name| (name, ListenerFailureReason::of(error))))
            .map(|(name, reason)| ListenerFailure {
                name: name.clone(),
                reason,
            })
            .collect(),
    };
    failures.sort_by(|a, b| a.name.cmp(&b.name));
    failures
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
    fn an_error_about_the_whole_set_fails_every_configured_listener() {
        let names: Vec<ListenerName> = vec!["a".parse().unwrap(), "b".parse().unwrap()];
        let listed = failures(&[OpenError::NoRuntimeDir], names.iter());
        assert_eq!(listed.iter().map(|failure| failure.name.clone()).collect::<Vec<_>>(), names);
        assert!(listed.iter().all(|failure| failure.reason == ListenerFailureReason::BindRefused));
    }
}
