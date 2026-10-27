//! Absolute filesystem paths named in configuration, such as listener sockets and TLS material (spec §3.3, §3.4).
//!
//! Only the text is checked here. Whether the file exists and who owns it is an I/O question for the binary.

use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

use serde::Deserialize;
use thiserror::Error;

use crate::display::quoted;

/// An absolute path with no NUL byte and no `..` component.
///
/// The service is started from an arbitrary directory, so a relative path would resolve somewhere the owner did not
/// review. A `..` component lets a path that reads as inside a protected directory resolve outside it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct ConfigPath(PathBuf);

/// Why a configuration path was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConfigPathError {
    /// The path does not start at the filesystem root.
    #[error("path {path} must be absolute")]
    Relative {
        /// The rejected path, escaped so control characters never reach a log raw.
        path: String,
    },
    /// The path contains a NUL byte, which the operating system would silently truncate at.
    #[error("path {path} contains a NUL byte")]
    Nul {
        /// The rejected path, escaped.
        path: String,
    },
    /// The path contains a `..` component.
    #[error("path {path} must not contain a '..' component")]
    ParentComponent {
        /// The rejected path, escaped.
        path: String,
    },
}

impl ConfigPath {
    /// The validated path.
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

impl TryFrom<&str> for ConfigPath {
    type Error = ConfigPathError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let path = Path::new(s);
        match () {
            () if s.contains('\0') => Err(ConfigPathError::Nul { path: quoted(s) }),
            () if !path.is_absolute() => Err(ConfigPathError::Relative { path: quoted(s) }),
            () if path.components().any(|c| c == Component::ParentDir) => Err(ConfigPathError::ParentComponent { path: quoted(s) }),
            () => Ok(Self(path.to_path_buf())),
        }
    }
}

impl TryFrom<String> for ConfigPath {
    type Error = ConfigPathError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::try_from(s.as_str())
    }
}

impl FromStr for ConfigPath {
    type Err = ConfigPathError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

impl fmt::Display for ConfigPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.display())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_examples_parse() {
        ["/run/iron-vault/proxy.sock", "/etc/iron-vault/tls/server.crt", "/etc/iron-vault/tls/server.key", "/"]
            .iter()
            .for_each(|s| assert_eq!(s.parse::<ConfigPath>().unwrap().as_path(), Path::new(s)));
    }

    #[test]
    fn relative_paths_are_rejected() {
        ["", "server.crt", "./server.crt", "tls/server.crt", "~/server.crt"]
            .iter()
            .for_each(|s| assert!(matches!(ConfigPath::try_from(*s), Err(ConfigPathError::Relative { .. })), "{s:?}"));
    }

    #[test]
    fn parent_components_are_rejected() {
        ["/etc/iron-vault/../shadow", "/..", "/run/iron-vault/.."]
            .iter()
            .for_each(|s| assert!(matches!(ConfigPath::try_from(*s), Err(ConfigPathError::ParentComponent { .. })), "{s:?}"));
    }

    #[test]
    fn dotted_names_are_not_parent_components() {
        ["/etc/iron-vault/..key", "/etc/iron-vault/key..", "/etc/./iron-vault"]
            .iter()
            .for_each(|s| assert!(s.parse::<ConfigPath>().is_ok(), "{s}"));
    }

    #[test]
    fn nul_is_rejected_and_escaped() {
        let err = ConfigPath::try_from("/etc/key\0.pem").unwrap_err();
        assert!(matches!(err, ConfigPathError::Nul { .. }));
        assert!(!err.to_string().chars().any(char::is_control), "{err}");
    }

    #[test]
    fn errors_escape_control_characters() {
        let err = ConfigPath::try_from("tls/\u{1b}[31m\n.crt").unwrap_err();
        assert!(!err.to_string().chars().any(char::is_control), "{err}");
    }
}
