// SPDX-License-Identifier: MPL-2.0
//! Maps a listener open error to the fixed category `status` reports. Linux-only, like the listeners that fail.

use std::io;

use super::{ListenerFailure, ListenerFailureReason};
use crate::listener_tls::ListenerTlsError;
use crate::request_listeners::OpenError;
use crate::request_socket::RequestBindError;
use crate::socket_activation::{AdoptError, NotActivated};
use crate::socket_file::BindError;
use iron_vault_policy::ListenerName;

impl ListenerFailureReason {
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
            RequestBindError::Bind(BindError::Occupied { .. }) => Self::AddressInUse,
            RequestBindError::Bind(BindError::Unverified { .. }) => Self::BindRefused,
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

/// Returns the listener `error` is about, or `None` for an error about the whole set.
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
        // `adopt` never returns it: the activation variables are parsed in `PassedSockets::take` before the service starts.
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

/// Returns the failures `errors` come to, in name order. An error about the whole set (`NoRuntime`, `NoRuntimeDir`) leaves
/// every listener in `configured` unopened, so it is reported for each.
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
    fn an_occupied_path_is_an_address_in_use() {
        let occupied = BindError::Occupied {
            role: crate::socket_file::SocketRole::Request,
            path: "/run/x.sock".into(),
            found: "a file".to_owned(),
            owner: 0,
        };
        assert_eq!(
            ListenerFailureReason::of_bind(&RequestBindError::Bind(occupied)),
            ListenerFailureReason::AddressInUse
        );
    }

    #[test]
    fn an_error_about_the_whole_set_fails_every_configured_listener() {
        let names: Vec<ListenerName> = vec!["a".parse().unwrap(), "b".parse().unwrap()];
        let listed = failures(&[OpenError::NoRuntimeDir], names.iter());
        assert_eq!(listed.iter().map(|failure| failure.name.clone()).collect::<Vec<_>>(), names);
        assert!(listed.iter().all(|failure| failure.reason == ListenerFailureReason::BindRefused));
    }
}
