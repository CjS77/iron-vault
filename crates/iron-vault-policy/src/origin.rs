//! One permitted origin as the owner writes it when enrolling a credential (spec §6).
//!
//! The scheme is always HTTPS, so it is implicit and never written: an origin is a host and an optional port. The CLI
//! parses each `--origin` with [`parse_origin`] before connecting, and the service parses the requested origins of an
//! `add` request again, so both apply the one rule.

use thiserror::Error;

use crate::host::{Host, HostError};
use crate::port::{Port, PortError};

/// Why an origin was rejected.
///
/// Messages name the rule and never the rejected text, so a diagnostic cannot echo an argument (§5).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OriginError {
    /// The origin names a scheme; HTTPS is implied and never written.
    #[error("an origin is a host and an optional port without a scheme; HTTPS is implied")]
    Scheme,
    /// The origin has a path, query or fragment.
    #[error("an origin has no path, query or fragment")]
    Path,
    /// A bracketed IPv6 literal is not closed, or something other than `:port` follows it.
    #[error("a bracketed IPv6 origin is written `[address]` or `[address]:port`")]
    Brackets,
    /// The host is not a valid host name or IP literal.
    #[error("the host is not valid: {}", host_rule(.0))]
    Host(HostError),
    /// The port is not a decimal number from 1 to 65535.
    #[error("the port is not valid: {0}")]
    Port(PortError),
}

/// Parses `host`, `host:port`, `[v6]` or `[v6]:port` into the canonical host and the port, which defaults to 443.
pub fn parse_origin(text: &str) -> Result<(Host, Port), OriginError> {
    if text.contains("://") {
        return Err(OriginError::Scheme);
    }
    if text.contains(['/', '?', '#']) {
        return Err(OriginError::Path);
    }
    let (host, port) = split_host_port(text)?;
    let host = host.parse::<Host>().map_err(OriginError::Host)?;
    let port = port.map_or(Ok(Port::HTTPS), str::parse).map_err(OriginError::Port)?;
    Ok((host, port))
}

/// Splits off the port at the colon after the host. An unbracketed host has no colon of its own, and a bracketed one
/// keeps its brackets for [`Host`] to parse.
fn split_host_port(text: &str) -> Result<(&str, Option<&str>), OriginError> {
    if !text.starts_with('[') {
        return Ok(text.split_once(':').map_or((text, None), |(host, port)| (host, Some(port))));
    }
    let end = text.find(']').ok_or(OriginError::Brackets)? + 1;
    let (host, rest) = text.split_at(end);
    match rest {
        "" => Ok((host, None)),
        _ => rest.strip_prefix(':').map(|port| (host, Some(port))).ok_or(OriginError::Brackets),
    }
}

/// The host rule broken, without the label or character that broke it.
fn host_rule(error: &HostError) -> String {
    match error {
        HostError::ForbiddenCharacter(_) => "it contains a character that is not allowed in a host name".to_owned(),
        HostError::InvalidLabel(_) => "a label is not a valid DNS label".to_owned(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin(text: &str) -> (String, u16) {
        let (host, port) = parse_origin(text).unwrap_or_else(|e| panic!("{text:?} should parse: {e}"));
        (host.to_string(), port.get())
    }

    fn reject(text: &str) -> OriginError {
        parse_origin(text).expect_err(text)
    }

    #[test]
    fn every_form_parses_and_the_port_defaults_to_443() {
        assert_eq!(origin("api.fx.example"), ("api.fx.example".into(), 443));
        assert_eq!(origin("API.fx.example:8443"), ("api.fx.example".into(), 8443));
        assert_eq!(origin("[2001:DB8::1]"), ("[2001:db8::1]".into(), 443));
        assert_eq!(origin("[::1]:8443"), ("[::1]".into(), 8443));
        assert_eq!(origin("192.0.2.1:1"), ("192.0.2.1".into(), 1));
    }

    #[test]
    fn a_scheme_or_a_path_is_refused() {
        assert_eq!(reject("https://api.fx.example"), OriginError::Scheme);
        assert_eq!(reject("api.fx.example/v1"), OriginError::Path);
        assert_eq!(reject("api.fx.example?x"), OriginError::Path);
        assert_eq!(reject("api.fx.example#x"), OriginError::Path);
    }

    #[test]
    fn invalid_ports_are_refused() {
        assert_eq!(reject("x:0"), OriginError::Port(PortError::Zero));
        ["x:65536", "x:", "x:0443", "x:+1", "[::1]:"]
            .into_iter()
            .for_each(|text| assert_eq!(reject(text), OriginError::Port(PortError::NotCanonical), "{text}"));
    }

    #[test]
    fn invalid_hosts_and_brackets_are_refused() {
        assert!(matches!(reject(""), OriginError::Host(HostError::Empty)));
        assert!(matches!(reject(":443"), OriginError::Host(HostError::Empty)));
        assert!(matches!(reject("user@x"), OriginError::Host(_)));
        assert!(matches!(reject("x:1:2"), OriginError::Port(_)));
        assert_eq!(reject("[::1"), OriginError::Brackets);
        assert_eq!(reject("[::1]443"), OriginError::Brackets);
        assert!(matches!(reject("[x]"), OriginError::Host(HostError::InvalidIpv6)));
    }

    #[test]
    fn messages_never_quote_the_rejected_text() {
        ["bad_label.example", "-x.example", "user@x", "https://secret", "x:65536"]
            .into_iter()
            .for_each(|text| {
                let message = reject(text).to_string();
                assert!(
                    !message.contains(text) && !message.contains("bad_label") && !message.contains("-x"),
                    "{message}"
                );
            });
    }
}
