//! A `[listeners.<name>]` section: where callers reach the request interface (spec §6, §7).

use std::net::SocketAddr;

use serde::Deserialize;
use thiserror::Error;

use crate::config_path::ConfigPath;
use crate::display::quoted;
use crate::header_name::HeaderName;
use crate::reserved_headers::{CALLER_TOKEN_HEADERS, is_reserved};

/// The header callers authenticate with when a listener sets no `token_header`.
pub const DEFAULT_TOKEN_HEADER: &str = "proxy-authorization";

/// A validated listener.
///
/// TOML forms:
///
/// ```toml
/// [listeners.local]
/// unix_socket = "/run/iron-vault/proxy.sock"
///
/// [listeners.naomi-backoffice]
/// address = "10.20.0.2:7878"
/// tls_certificate = "/etc/iron-vault/tls/server.crt"
/// tls_key = "/etc/iron-vault/tls/server.key"
/// token_header = "X-Iron-Vault-Token"
/// ```
///
/// A TCP listener on a non-loopback address must have TLS (§7), but a `ListenerConfig` does not guarantee it: the rule
/// needs the listener's name to be reported usefully, so [`ValidatedConfig`](crate::ValidatedConfig) enforces it at
/// load and an unsafe configuration is never approved. The listeners from [`ParsedConfig::listeners`](crate::ParsedConfig)
/// are unchecked, and whoever opens one must test [`plain_off_loopback`](Self::plain_off_loopback) first.
/// Whether the callers on a listener may use `isolated-network` or `peer`
/// authentication depends on every caller section, so [`ValidatedConfig`](crate::ValidatedConfig) checks it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "RawListener")]
pub struct ListenerConfig {
    endpoint: Endpoint,
    token_header: Option<HeaderName>,
}

/// Where a listener accepts connections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    /// A Unix domain socket. Any local account may connect; the caller's peer account (`auth = "peer"`) or caller
    /// token decides what it may use (spec §7).
    UnixSocket(ConfigPath),
    /// A TCP address, with TLS required unless the address is loopback.
    Tcp {
        /// The address to listen on; its port is never 0.
        address: SocketAddr,
        /// The server certificate and key, if configured.
        tls: Option<TlsFiles>,
    },
}

/// The server certificate chain and private key a TLS listener presents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsFiles {
    certificate: ConfigPath,
    key: ConfigPath,
}

impl TlsFiles {
    /// The PEM certificate chain.
    pub fn certificate(&self) -> &ConfigPath {
        &self.certificate
    }

    /// The PEM private key.
    pub fn key(&self) -> &ConfigPath {
        &self.key
    }
}

/// Why a listener section was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ListenerError {
    /// Neither `unix_socket` nor `address` was set.
    #[error("listener needs exactly one of unix_socket or address; neither is set")]
    NoEndpoint,
    /// Both `unix_socket` and `address` were set.
    #[error("listener needs exactly one of unix_socket or address; both are set")]
    BothEndpoints,
    /// `address` is not an `ip:port` socket address.
    #[error("listener address {address} is not an IP address and port such as 127.0.0.1:7878 or [::1]:7878")]
    BadAddress {
        /// The rejected address, escaped so control characters never reach a log raw.
        address: String,
    },
    /// `address` uses port 0, which would bind a random port no caller is configured for.
    #[error("listener address {address} uses port 0")]
    ZeroPort {
        /// The rejected address.
        address: SocketAddr,
    },
    /// Only one of `tls_certificate` and `tls_key` was set.
    #[error("listener sets only one of tls_certificate and tls_key; set both or neither")]
    IncompleteTls,
    /// TLS files were set on a Unix socket listener.
    #[error("tls_certificate and tls_key apply only to an address listener, not a unix_socket")]
    TlsOnUnixSocket,
    /// `token_header` names a header that controls transport or forwarding.
    #[error("token_header {header} is a reserved header; choose a dedicated header such as X-Iron-Vault-Token")]
    ReservedTokenHeader {
        /// The rejected header as configured.
        header: String,
    },
}

impl ListenerConfig {
    /// Where the listener accepts connections.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// The address of a plain-HTTP TCP listener that is not on loopback, which would carry caller tokens in clear text
    /// (spec §7). `None` for a Unix socket, a TLS listener, or a loopback address.
    ///
    /// Loopback is `127.0.0.0/8` or `::1`. An IPv4-mapped address such as `::ffff:127.0.0.1` is deliberately not loopback:
    /// whether a dual-stack socket on it stays on the host depends on platform settings this crate cannot see.
    pub fn plain_off_loopback(&self) -> Option<SocketAddr> {
        match &self.endpoint {
            Endpoint::Tcp { address, tls: None } if !address.ip().is_loopback() => Some(*address),
            _ => None,
        }
    }

    /// The dedicated caller-token header, if the listener sets one instead of using `Proxy-Authorization`.
    pub fn token_header(&self) -> Option<&HeaderName> {
        self.token_header.as_ref()
    }

    /// The header that carries a caller token on this listener, and that sanitizing must strip: the dedicated
    /// `token_header`, or `Proxy-Authorization` when the listener sets none.
    pub fn caller_token_header(&self) -> HeaderName {
        self.token_header.clone().unwrap_or_else(HeaderName::proxy_authorization)
    }
}

/// The `[listeners.<name>]` table as written.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawListener {
    unix_socket: Option<ConfigPath>,
    address: Option<String>,
    tls_certificate: Option<ConfigPath>,
    tls_key: Option<ConfigPath>,
    token_header: Option<HeaderName>,
}

impl TryFrom<RawListener> for ListenerConfig {
    type Error = ListenerError;

    fn try_from(raw: RawListener) -> Result<Self, Self::Error> {
        let tls = tls_files(raw.tls_certificate, raw.tls_key)?;
        let endpoint = match (raw.unix_socket, raw.address) {
            (None, None) => Err(ListenerError::NoEndpoint),
            (Some(_), Some(_)) => Err(ListenerError::BothEndpoints),
            (Some(_), None) if tls.is_some() => Err(ListenerError::TlsOnUnixSocket),
            (Some(path), None) => Ok(Endpoint::UnixSocket(path)),
            (None, Some(address)) => tcp_endpoint(&address, tls),
        }?;
        let token_header = raw.token_header.map(check_token_header).transpose()?;
        Ok(Self { endpoint, token_header })
    }
}

/// Pairs the certificate and key, rejecting one without the other.
fn tls_files(certificate: Option<ConfigPath>, key: Option<ConfigPath>) -> Result<Option<TlsFiles>, ListenerError> {
    match (certificate, key) {
        (Some(certificate), Some(key)) => Ok(Some(TlsFiles { certificate, key })),
        (None, None) => Ok(None),
        _ => Err(ListenerError::IncompleteTls),
    }
}

/// Parses `address` and applies the port and TLS rules.
fn tcp_endpoint(text: &str, tls: Option<TlsFiles>) -> Result<Endpoint, ListenerError> {
    let address: SocketAddr = text.parse().map_err(|_| ListenerError::BadAddress { address: quoted(text) })?;
    match () {
        () if address.port() == 0 => Err(ListenerError::ZeroPort { address }),
        () => Ok(Endpoint::Tcp { address, tls }),
    }
}

/// Rejects a reserved header as the caller-token header.
///
/// Reserved headers carry framing, hop-by-hop or forwarding meaning (spec §9), which an intermediary may add,
/// rewrite or drop, so a token placed in one could be lost or replaced in transit. [`CALLER_TOKEN_HEADERS`] are the
/// exceptions: `Proxy-Authorization` is the default, and `X-Iron-Vault-Token` is the dedicated header, which is
/// reserved only so that no listener forwards it.
fn check_token_header(header: HeaderName) -> Result<HeaderName, ListenerError> {
    match is_reserved(&header) && !CALLER_TOKEN_HEADERS.contains(&header.lowercase()) {
        true => Err(ListenerError::ReservedTokenHeader {
            header: header.as_str().to_owned(),
        }),
        false => Ok(header),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TLS: &str = "tls_certificate = \"/etc/iron-vault/tls/server.crt\"\ntls_key = \"/etc/iron-vault/tls/server.key\"";

    fn parse(s: &str) -> Result<ListenerConfig, toml::de::Error> {
        toml::from_str(s)
    }

    fn rejected(s: &str, expected: &str) {
        let err = parse(s).unwrap_err().to_string();
        assert!(err.contains(expected), "{s}: {err}");
    }

    fn tcp(listener: &ListenerConfig) -> (SocketAddr, bool) {
        match listener.endpoint() {
            Endpoint::Tcp { address, tls } => (*address, tls.is_some()),
            Endpoint::UnixSocket(_) => panic!("expected a TCP endpoint"),
        }
    }

    #[test]
    fn spec_unix_socket_example_parses() {
        let l = parse(r#"unix_socket = "/run/iron-vault/proxy.sock""#).unwrap();
        assert_eq!(l.endpoint(), &Endpoint::UnixSocket("/run/iron-vault/proxy.sock".parse().unwrap()));
        assert_eq!(l.token_header(), None);
    }

    #[test]
    fn spec_tls_example_parses() {
        let l = parse(&format!("address = \"10.20.0.2:7878\"\n{TLS}")).unwrap();
        assert_eq!(tcp(&l), ("10.20.0.2:7878".parse().unwrap(), true));
        let Endpoint::Tcp { tls: Some(tls), .. } = l.endpoint() else {
            panic!("expected TLS")
        };
        assert_eq!(tls.certificate().to_string(), "/etc/iron-vault/tls/server.crt");
        assert_eq!(tls.key().to_string(), "/etc/iron-vault/tls/server.key");
    }

    #[test]
    fn loopback_without_tls_is_accepted() {
        ["127.0.0.1:7878", "127.255.0.9:7878", "[::1]:7878"]
            .iter()
            .for_each(|a| assert_eq!(tcp(&parse(&format!("address = \"{a}\"")).unwrap()), (a.parse().unwrap(), false)));
    }

    #[test]
    fn non_loopback_without_tls_parses() {
        ["10.20.0.2:7878", "0.0.0.0:7878", "[::]:7878", "[::ffff:127.0.0.1]:7878"]
            .iter()
            .for_each(|a| assert!(!tcp(&parse(&format!("address = \"{a}\"")).unwrap()).1));
    }

    #[test]
    fn non_loopback_with_tls_is_accepted() {
        ["0.0.0.0:7878", "[::]:7878"]
            .iter()
            .for_each(|a| assert!(tcp(&parse(&format!("address = \"{a}\"\n{TLS}")).unwrap()).1));
    }

    #[test]
    fn endpoint_must_be_exactly_one() {
        rejected("", "neither is set");
        rejected(
            "unix_socket = \"/run/iron-vault/proxy.sock\"\naddress = \"127.0.0.1:7878\"",
            "both are set",
        );
    }

    #[test]
    fn tls_needs_both_files_and_a_tcp_listener() {
        rejected(
            "address = \"10.20.0.2:7878\"\ntls_certificate = \"/etc/iron-vault/tls/server.crt\"",
            "set both or neither",
        );
        rejected(
            "address = \"127.0.0.1:7878\"\ntls_key = \"/etc/iron-vault/tls/server.key\"",
            "set both or neither",
        );
        rejected(
            &format!("unix_socket = \"/run/iron-vault/proxy.sock\"\n{TLS}"),
            "apply only to an address listener",
        );
    }

    #[test]
    fn relative_paths_are_rejected() {
        rejected(
            "address = \"10.20.0.2:7878\"\ntls_certificate = \"tls/server.crt\"\ntls_key = \"/etc/k\"",
            "must be absolute",
        );
        rejected("unix_socket = \"proxy.sock\"", "must be absolute");
    }

    #[test]
    fn bad_addresses_are_rejected() {
        [
            "localhost:7878",
            "127.0.0.1",
            "::1:7878",
            "127.0.0.1:65536",
            "127.0.0.1:-1",
            "",
            "127.0.0.1:7878\n",
        ]
        .iter()
        .for_each(|a| rejected(&format!("address = {a:?}"), "is not an IP address and port"));
        rejected("address = \"127.0.0.1:0\"", "uses port 0");
        assert!(!parse("address = \"\\u001b[31m:1\"").unwrap_err().to_string().contains('\u{1b}'));
    }

    #[test]
    fn token_header_is_optional_and_validated() {
        let l = parse("unix_socket = \"/run/iron-vault/proxy.sock\"\ntoken_header = \"X-Iron-Vault-Token\"").unwrap();
        assert_eq!(l.token_header().map(HeaderName::as_str), Some("X-Iron-Vault-Token"));
        let explicit = parse("address = \"127.0.0.1:7878\"\ntoken_header = \"Proxy-Authorization\"").unwrap();
        assert_eq!(explicit.token_header().map(HeaderName::lowercase), Some(DEFAULT_TOKEN_HEADER));
        rejected(
            "address = \"127.0.0.1:7878\"\ntoken_header = \"X Token\"",
            "not allowed in an HTTP token",
        );
    }

    #[test]
    fn caller_token_header_defaults_to_proxy_authorization() {
        let dedicated = parse("unix_socket = \"/run/iron-vault/proxy.sock\"\ntoken_header = \"X-Iron-Vault-Token\"").unwrap();
        assert_eq!(dedicated.caller_token_header().as_str(), "X-Iron-Vault-Token");
        let default = parse("address = \"127.0.0.1:7878\"").unwrap();
        assert_eq!(default.caller_token_header().as_str(), "Proxy-Authorization");
        assert_eq!(default.caller_token_header().lowercase(), DEFAULT_TOKEN_HEADER);
    }

    #[test]
    fn only_the_caller_token_headers_may_be_reserved_token_headers() {
        ["Proxy-Authorization", "X-Iron-Vault-Token", "x-iron-vault-token"]
            .iter()
            .for_each(|h| {
                assert!(
                    parse(&format!("address = \"127.0.0.1:7878\"\ntoken_header = \"{h}\"")).is_ok(),
                    "{h}"
                )
            });
        rejected(
            "address = \"127.0.0.1:7878\"\ntoken_header = \"X-Forwarded-Token\"",
            "token_header X-Forwarded-Token is a reserved header; choose a dedicated header such as X-Iron-Vault-Token",
        );
    }

    #[test]
    fn client_address_and_host_override_headers_cannot_carry_the_token() {
        [
            "X-Host",
            "X-Original-Host",
            "X-HTTP-Host-Override",
            "True-Client-IP",
            "X-Client-IP",
            "CF-Connecting-IP",
        ]
        .iter()
        .for_each(|h| {
            rejected(
                &format!("address = \"127.0.0.1:7878\"\ntoken_header = \"{h}\""),
                "is a reserved header",
            )
        });
    }

    #[test]
    fn reserved_token_headers_are_rejected() {
        [
            "Host",
            "Content-Length",
            "Transfer-Encoding",
            "Connection",
            "Upgrade",
            "Forwarded",
            "X-Forwarded-For",
            "Proxy-Authenticate",
        ]
        .iter()
        .for_each(|h| {
            rejected(
                &format!("address = \"127.0.0.1:7878\"\ntoken_header = \"{h}\""),
                "is a reserved header",
            )
        });
    }

    #[test]
    fn unknown_fields_are_rejected() {
        rejected("unix_socket = \"/run/iron-vault/proxy.sock\"\nport = 7878", "unknown field");
    }
}
