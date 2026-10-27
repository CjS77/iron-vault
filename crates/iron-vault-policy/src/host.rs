//! The canonical form of an upstream host.
//!
//! Every host comparison in Iron Vault (credential record, route upstream, final outgoing-request check) uses the
//! [`Host`] produced here, so a host is converted exactly once and compared byte for byte afterwards (§3.6).

use std::fmt;
use std::str::FromStr;

use serde::Deserialize;
use thiserror::Error;

/// DNS limit on a whole name, excluding the root label's trailing dot.
const MAX_NAME_LEN: usize = 253;
/// DNS limit on a single label.
const MAX_LABEL_LEN: usize = 63;

/// An upstream host name or IP literal in its one canonical form.
///
/// Canonical forms:
/// - **Domain names** go through the WHATWG/UTS #46 conversion the `url` crate applies: ASCII is lowercased and
///   non-ASCII labels become punycode (`xn--`). One trailing dot is removed. Every label must then be 1–63 letters,
///   digits or hyphens, not starting or ending with a hyphen.
/// - **IPv4 literals** are accepted only in canonical dotted-decimal form (`192.0.2.1`). Shorthand, octal and hex
///   forms such as `127.1`, `0x7f.1`, `010.0.0.1` or `2130706433` are rejected rather than reinterpreted, because the
///   address they denote is not what a reader of the configuration would expect.
/// - **IPv6 literals** must be bracketed (`[2001:db8::1]`) and are stored in the `url` crate's compressed lowercase
///   serialization, brackets included, so the canonical form is exactly what appears in a URL authority.
///
/// Equality is exact on the canonical form. There is deliberately no suffix or wildcard matching: `evil-api.example.com`
/// and `api.example.com.evil` are simply different hosts.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct Host(String);

/// Why a host was rejected.
///
/// Variants carry no copy of the rejected input, because a mistyped host field could contain user-info.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HostError {
    /// The host is empty, or is only a trailing dot.
    #[error("host is empty")]
    Empty,
    /// The host contains an ASCII character that cannot appear in a host name, such as `@`, `:`, `%`, `*` or `_`.
    #[error("host contains {0:?}, which is not allowed in a host name")]
    ForbiddenCharacter(char),
    /// The host is a bracketed literal that is not a valid IPv6 address (zone identifiers are not accepted).
    #[error("host is not a valid bracketed IPv6 literal")]
    InvalidIpv6,
    /// The host denotes an IP address but is not written in canonical form, so it would be reinterpreted.
    #[error("host denotes an IP address but is not written as a canonical IPv4 or bracketed IPv6 literal")]
    NonCanonicalIp,
    /// The host is not a valid domain name under IDNA processing.
    #[error("host is not a valid domain name")]
    InvalidDomain,
    /// A label of the converted domain name is empty, too long, or contains characters other than letters, digits
    /// and interior hyphens.
    #[error("host label {0:?} is not a valid DNS label")]
    InvalidLabel(String),
    /// The converted domain name is longer than DNS allows.
    #[error("host is longer than {MAX_NAME_LEN} characters")]
    TooLong,
}

impl Host {
    /// The canonical form, suitable for comparison and for use as a URL authority host.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for Host {
    type Err = HostError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw.starts_with('[') {
            true => parse_ipv6(raw),
            false => parse_unbracketed(raw),
        }
    }
}

impl TryFrom<String> for Host {
    type Error = HostError;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        raw.parse()
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn parse_ipv6(raw: &str) -> Result<Host, HostError> {
    match url::Host::parse(raw) {
        Ok(ip @ url::Host::Ipv6(_)) => Ok(Host(ip.to_string())),
        _ => Err(HostError::InvalidIpv6),
    }
}

fn parse_unbracketed(raw: &str) -> Result<Host, HostError> {
    let name = raw.strip_suffix('.').unwrap_or(raw);
    if name.is_empty() {
        return Err(HostError::Empty);
    }
    check_ascii_characters(name)?;
    match url::Host::parse(name).map_err(|_| HostError::InvalidDomain)? {
        url::Host::Domain(ascii) => check_domain(ascii),
        url::Host::Ipv4(addr) if addr.to_string() == name => Ok(Host(addr.to_string())),
        url::Host::Ipv4(_) | url::Host::Ipv6(_) => Err(HostError::NonCanonicalIp),
    }
}

/// Rejects ASCII that has no place in a host name before the `url` crate can percent-decode or reinterpret it.
/// Non-ASCII characters pass through to IDNA processing.
fn check_ascii_characters(name: &str) -> Result<(), HostError> {
    name.chars()
        .find(|c| c.is_ascii() && !(c.is_ascii_alphanumeric() || matches!(c, '-' | '.')))
        .map_or(Ok(()), |c| Err(HostError::ForbiddenCharacter(c)))
}

/// IDNA output can still contain empty labels or characters that are not valid in DNS, so it is checked again.
fn check_domain(ascii: String) -> Result<Host, HostError> {
    if ascii.len() > MAX_NAME_LEN {
        return Err(HostError::TooLong);
    }
    match ascii.split('.').find(|label| !is_dns_label(label)) {
        Some(label) => Err(HostError::InvalidLabel(label.to_owned())),
        None => Ok(Host(ascii)),
    }
}

fn is_dns_label(label: &str) -> bool {
    (1..=MAX_LABEL_LEN).contains(&label.len())
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(raw: &str) -> Host {
        raw.parse().unwrap_or_else(|e| panic!("{raw:?} should parse: {e}"))
    }

    fn reject(raw: &str) -> HostError {
        raw.parse::<Host>().expect_err(raw)
    }

    #[test]
    fn case_and_trailing_dot_are_canonicalized() {
        assert_eq!(host("API.Example.COM."), host("api.example.com"));
        assert_eq!(host("API.Example.COM.").as_str(), "api.example.com");
    }

    #[test]
    fn suffix_lookalikes_are_different_hosts() {
        assert_ne!(host("evil-api.example.com"), host("api.example.com"));
        assert_ne!(host("api.example.com.evil"), host("api.example.com"));
        assert_ne!(host("sub.api.example.com"), host("api.example.com"));
    }

    #[test]
    fn spec_example_hosts_are_accepted() {
        ["api.fx.example", "api.venice.ai", "api.search.brave.com"]
            .into_iter()
            .for_each(|raw| assert_eq!(host(raw).as_str(), raw));
    }

    #[test]
    fn single_label_names_are_accepted() {
        assert_eq!(host("upstream").as_str(), "upstream");
    }

    #[test]
    fn international_names_become_punycode() {
        assert_eq!(host("Bücher.example").as_str(), "xn--bcher-kva.example");
        assert_eq!(host("xn--bcher-kva.example"), host("bücher.example"));
    }

    #[test]
    fn empty_hosts_are_rejected() {
        assert_eq!(reject(""), HostError::Empty);
        assert_eq!(reject("."), HostError::Empty);
    }

    #[test]
    fn wildcards_user_info_and_ports_are_rejected() {
        assert_eq!(reject("*.example.com"), HostError::ForbiddenCharacter('*'));
        assert_eq!(reject("user@example.com"), HostError::ForbiddenCharacter('@'));
        assert_eq!(reject("example.com:443"), HostError::ForbiddenCharacter(':'));
        assert_eq!(reject("example.com/"), HostError::ForbiddenCharacter('/'));
        assert_eq!(reject("example.com\\"), HostError::ForbiddenCharacter('\\'));
        assert_eq!(reject("under_score.example"), HostError::ForbiddenCharacter('_'));
        assert_eq!(reject(" example.com"), HostError::ForbiddenCharacter(' '));
        assert_eq!(reject("exa\tmple.com"), HostError::ForbiddenCharacter('\t'));
    }

    #[test]
    fn percent_encoded_hosts_are_rejected() {
        assert_eq!(reject("ex%61mple.com"), HostError::ForbiddenCharacter('%'));
    }

    #[test]
    fn malformed_labels_are_rejected() {
        assert!(matches!(reject("a..example"), HostError::InvalidLabel(_)));
        assert!(matches!(reject(".example.com"), HostError::InvalidLabel(_)));
        assert!(matches!(reject("example.com.."), HostError::InvalidLabel(_)));
        assert!(matches!(reject("-api.example"), HostError::InvalidLabel(_)));
        assert!(matches!(reject("api-.example"), HostError::InvalidLabel(_)));
        assert!(matches!(reject(&format!("{}.example", "a".repeat(64))), HostError::InvalidLabel(_)));
    }

    #[test]
    fn overlong_names_are_rejected() {
        let long = vec!["a".repeat(60); 5].join(".");
        assert_eq!(reject(&long), HostError::TooLong);
    }

    #[test]
    fn invalid_punycode_is_rejected() {
        assert_eq!(reject("xn--a.example"), HostError::InvalidDomain);
    }

    #[test]
    fn canonical_ipv4_is_accepted() {
        assert_eq!(host("192.0.2.1").as_str(), "192.0.2.1");
        assert_eq!(host("192.0.2.1."), host("192.0.2.1"));
    }

    #[test]
    fn non_canonical_ipv4_is_rejected() {
        ["127.1", "0x7f.1", "0x7f.0.0.1", "010.0.0.1", "2130706433", "1.2.3.04", "0x7f000001"]
            .into_iter()
            .for_each(|raw| assert_eq!(reject(raw), HostError::NonCanonicalIp, "{raw}"));
    }

    #[test]
    fn out_of_range_ipv4_is_rejected() {
        assert_eq!(reject("256.0.0.1"), HostError::InvalidDomain);
    }

    #[test]
    fn numeric_hosts_reached_through_idna_mapping_are_rejected() {
        assert_eq!(reject("\u{ff11}\u{ff12}\u{ff17}.0.0.1"), HostError::NonCanonicalIp);
    }

    #[test]
    fn ipv6_is_normalized() {
        assert_eq!(host("[2001:DB8:0:0:0:0:0:1]").as_str(), "[2001:db8::1]");
        assert_eq!(host("[::1]"), host("[0:0:0:0:0:0:0:1]"));
    }

    #[test]
    fn ipv6_with_embedded_ipv4_uses_the_url_serialization() {
        let mapped = host("[::ffff:192.0.2.1]");
        assert_eq!(mapped.as_str(), "[::ffff:c000:201]");
        assert_eq!(url::Url::parse(&format!("https://{mapped}/")).map(|u| u.host_str().map(str::to_owned)), Ok(Some(mapped.to_string())));
    }

    #[test]
    fn malformed_ipv6_is_rejected() {
        ["[::1", "[fe80::1%25eth0]", "[::1]:443", "[example.com]", "[]"]
            .into_iter()
            .for_each(|raw| assert_eq!(reject(raw), HostError::InvalidIpv6, "{raw}"));
        assert_eq!(reject("::1"), HostError::ForbiddenCharacter(':'));
    }

    #[test]
    fn canonical_forms_are_fixed_points() {
        ["api.example.com", "xn--bcher-kva.example", "192.0.2.1", "[2001:db8::1]"]
            .into_iter()
            .for_each(|raw| assert_eq!(host(host(raw).as_str()), host(raw)));
    }

    #[test]
    fn deserializes_through_validation() {
        use serde::de::IntoDeserializer;
        use serde::de::value::{Error, StringDeserializer};

        let ok: Result<Host, Error> = Host::deserialize(IntoDeserializer::<Error>::into_deserializer("API.example.com".to_owned()));
        assert_eq!(ok.map(|h| h.to_string()), Ok("api.example.com".to_owned()));
        let bad: StringDeserializer<Error> = "*.example.com".to_owned().into_deserializer();
        assert!(Host::deserialize(bad).is_err());
    }
}
