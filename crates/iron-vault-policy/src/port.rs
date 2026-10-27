//! Upstream TCP ports.

use std::fmt;
use std::num::NonZeroU16;
use std::str::FromStr;

use serde::Deserialize;
use thiserror::Error;

/// A non-zero TCP port.
///
/// An omitted HTTPS port is stored as [`Port::HTTPS`] rather than left implicit, so the configured upstream, the
/// credential record and the final outgoing-request check always compare two explicit numbers (§3.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "u16")]
pub struct Port(NonZeroU16);

/// Why a port was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PortError {
    /// Port 0 is not a connectable port.
    #[error("port 0 is not allowed")]
    Zero,
    /// The text is not a decimal number from 1 to 65535 written without sign or leading zeros.
    #[error("port must be a decimal number from 1 to 65535 without sign or leading zeros")]
    NotCanonical,
}

impl Port {
    /// The default HTTPS port, applied whenever an upstream URL omits its port.
    pub const HTTPS: Port = Port(NonZeroU16::MIN.saturating_add(442));

    /// The port number.
    pub fn get(self) -> u16 {
        self.0.get()
    }
}

impl TryFrom<u16> for Port {
    type Error = PortError;

    fn try_from(port: u16) -> Result<Self, Self::Error> {
        NonZeroU16::new(port).map(Port).ok_or(PortError::Zero)
    }
}

/// Only canonical decimal text is accepted: `0443` or `+443` would be read as 443 by a URL parser, and a port that
/// does not look like the number it means is an odd form worth refusing.
impl FromStr for Port {
    type Err = PortError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let canonical = text.bytes().all(|b| b.is_ascii_digit()) && !text.is_empty() && (text == "0" || !text.starts_with('0'));
        match canonical {
            true => text.parse::<u16>().map_err(|_| PortError::NotCanonical)?.try_into(),
            false => Err(PortError::NotCanonical),
        }
    }
}

impl fmt::Display for Port {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_default_is_443() {
        assert_eq!(Port::HTTPS.get(), 443);
        assert_eq!(Port::try_from(443), Ok(Port::HTTPS));
    }

    #[test]
    fn zero_is_rejected() {
        assert_eq!(Port::try_from(0), Err(PortError::Zero));
        assert_eq!("0".parse::<Port>(), Err(PortError::Zero));
    }

    #[test]
    fn canonical_text_is_accepted() {
        assert_eq!("8443".parse::<Port>().map(Port::get), Ok(8443));
        assert_eq!("1".parse::<Port>().map(Port::get), Ok(1));
        assert_eq!("65535".parse::<Port>().map(Port::get), Ok(65535));
    }

    #[test]
    fn non_canonical_text_is_rejected() {
        ["", "0443", "00", "+443", "-1", " 443", "443 ", "65536", "4x3", "٤٤٣"]
            .into_iter()
            .for_each(|text| assert_eq!(text.parse::<Port>(), Err(PortError::NotCanonical), "{text:?}"));
    }

    #[test]
    fn deserializes_through_validation() {
        use serde::de::IntoDeserializer;
        use serde::de::value::{Error, U16Deserializer};

        let ok: U16Deserializer<Error> = 8443u16.into_deserializer();
        assert_eq!(Port::deserialize(ok).map(Port::get), Ok(8443));
        let zero: U16Deserializer<Error> = 0u16.into_deserializer();
        assert!(Port::deserialize(zero).is_err());
    }
}
