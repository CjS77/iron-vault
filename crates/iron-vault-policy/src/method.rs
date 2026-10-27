//! HTTP methods that a route may allow.
//!
//! The set is a closed allowlist: `CONNECT` would turn the proxy into a tunnel (spec §3.5 step 2) and `TRACE`
//! reflects request headers, including injected credentials, back to the caller. Neither can ever be granted.

use std::fmt;
use std::str::FromStr;

use serde::Deserialize;
use thiserror::Error;

/// An HTTP method from the allowlist a route may grant (spec §3.3, §3.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "String")]
pub enum Method {
    /// `GET`
    Get,
    /// `HEAD`
    Head,
    /// `POST`
    Post,
    /// `PUT`
    Put,
    /// `PATCH`
    Patch,
    /// `DELETE`
    Delete,
    /// `OPTIONS`
    Options,
}

/// A method token that is not on the allowlist.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MethodError {
    /// A method Iron Vault refuses outright because it would leak credentials or tunnel traffic.
    #[error("method {0} is never allowed")]
    Forbidden(&'static str),
    /// Any other token, including lowercase spellings of allowed methods.
    #[error("unsupported method {0}; expected one of GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS")]
    Unsupported(
        /// The rejected token, escaped so control characters never reach a log raw.
        String,
    ),
}

const ALL: [Method; 7] = [Method::Get, Method::Head, Method::Post, Method::Put, Method::Patch, Method::Delete, Method::Options];

const FORBIDDEN: [&str; 2] = ["CONNECT", "TRACE"];

impl Method {
    /// The method's canonical uppercase token.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
            Self::Options => "OPTIONS",
        }
    }
}

impl TryFrom<&str> for Method {
    type Error = MethodError;

    /// Matches the token exactly; method names are case-sensitive (RFC 9110 §9.1).
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        ALL.into_iter().find(|m| m.as_str() == s).ok_or_else(|| {
            FORBIDDEN
                .into_iter()
                .find(|f| *f == s)
                .map_or_else(|| MethodError::Unsupported(format!("\"{}\"", s.escape_default())), MethodError::Forbidden)
        })
    }
}

impl TryFrom<String> for Method {
    type Error = MethodError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::try_from(s.as_str())
    }
}

impl FromStr for Method {
    type Err = MethodError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use serde::de::IntoDeserializer;
    use serde::de::value::Error as DeError;

    use super::*;

    #[test]
    fn allowlist_round_trips() {
        ALL.iter().for_each(|m| assert_eq!(m.as_str().parse::<Method>().unwrap(), *m));
    }

    #[test]
    fn connect_and_trace_are_forbidden() {
        assert_eq!(Method::try_from("CONNECT"), Err(MethodError::Forbidden("CONNECT")));
        assert_eq!(Method::try_from("TRACE"), Err(MethodError::Forbidden("TRACE")));
    }

    #[test]
    fn lowercase_and_unknown_are_unsupported() {
        ["get", "Post", "connect", "", "GET ", "PROPFIND"]
            .iter()
            .for_each(|s| assert!(matches!(Method::try_from(*s), Err(MethodError::Unsupported(_))), "{s:?}"));
    }

    #[test]
    fn control_characters_are_escaped() {
        let err = Method::try_from("GET\r\nX-Evil: 1").unwrap_err();
        assert_eq!(err, MethodError::Unsupported("\"GET\\r\\nX-Evil: 1\"".into()));
        assert!(!err.to_string().chars().any(char::is_control));
    }

    #[test]
    fn deserialize_validates() {
        let ok: Result<Method, DeError> = Method::deserialize("PATCH".to_owned().into_deserializer());
        assert_eq!(ok.unwrap(), Method::Patch);
        let bad: Result<Method, DeError> = Method::deserialize("TRACE".to_owned().into_deserializer());
        assert!(bad.is_err());
    }
}
