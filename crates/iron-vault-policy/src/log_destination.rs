//! The `[logging] destination` setting: where the approved config sends the service's log
//! ([spec §18](../../../design/iron-vault-specification.md#18-logging)).
//!
//! This is the setting as written and checked for shape. Opening the directory and verifying its owner and mode is the
//! service's job (`TrustedPathRule::LogDir`), as is choosing the destination at runtime.

use std::fmt;
use std::path::Path;

use serde::Deserialize;
use thiserror::Error;

use crate::config_path::{ConfigPath, ConfigPathError};
use crate::display::quoted;

/// The literal that selects stdout.
const STDOUT: &str = "stdout";

/// A configured log destination: stdout, or an absolute directory path.
///
/// A path is valid on construction: absolute, with no control character and no `..` component.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "String")]
pub enum LogDestinationSetting {
    /// The literal `"stdout"`.
    Stdout,
    /// The log directory.
    Directory(ConfigPath),
}

/// Why a `[logging] destination` was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LogDestinationError {
    /// The value contains a control character, which would let a log line be forged or hidden.
    #[error("log destination {value} contains a control character")]
    ControlCharacter {
        /// The rejected value, escaped.
        value: String,
    },
    /// The value is neither `"stdout"` nor a valid absolute path.
    #[error("log destination must be \"stdout\" or an absolute directory: {0}")]
    Path(#[from] ConfigPathError),
    /// The directory is, or lies inside, a directory the service keeps other files in.
    #[error("log directory {path} must be outside the {reserved} {reserved_path}")]
    InsideReserved {
        /// The log directory, escaped.
        path: String,
        /// Which directory it collides with: `state directory` or `config directory`.
        reserved: &'static str,
        /// That directory, escaped.
        reserved_path: String,
    },
}

impl LogDestinationSetting {
    /// The log directory, or `None` for stdout.
    pub fn directory(&self) -> Option<&Path> {
        match self {
            Self::Stdout => None,
            Self::Directory(path) => Some(path.as_path()),
        }
    }

    /// Refuses a directory that is, or lies inside, one of the `reserved` directories, each given as (label, path).
    ///
    /// Log files in the state directory would be foreign files that make `unlock` refuse, and beside `config.toml` they
    /// would sit in a directory whose contents the service does not own. The policy crate does not know where the
    /// state and config directories are, so the service passes them in when it checks a config.
    ///
    /// The comparison is lexical: it compares path components only and resolves no symlink. The caller must pass
    /// canonicalised paths for the destination and for each reserved directory, because a symlink alias defeats a
    /// lexical check (on Fedora Atomic `/home` is a symlink to `/var/home`). `TrustedPathRule::LogDir` checks owner and
    /// mode only and does not cover this rule.
    pub fn check_outside(&self, reserved: &[(&'static str, &Path)]) -> Result<(), LogDestinationError> {
        let Some(dir) = self.directory() else { return Ok(()) };
        reserved
            .iter()
            .find(|(_, other)| dir.starts_with(other))
            .map_or(Ok(()), |(label, other)| {
                Err(LogDestinationError::InsideReserved {
                    path: quoted(&dir.to_string_lossy()),
                    reserved: label,
                    reserved_path: quoted(&other.to_string_lossy()),
                })
            })
    }
}

impl TryFrom<&str> for LogDestinationSetting {
    type Error = LogDestinationError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            STDOUT => Ok(Self::Stdout),
            _ if s.chars().any(char::is_control) => Err(LogDestinationError::ControlCharacter { value: quoted(s) }),
            _ => Ok(Self::Directory(ConfigPath::try_from(s)?)),
        }
    }
}

impl TryFrom<String> for LogDestinationSetting {
    type Error = LogDestinationError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::try_from(s.as_str())
    }
}

impl fmt::Display for LogDestinationSetting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stdout => f.write_str(STDOUT),
            Self::Directory(path) => write!(f, "{path}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setting(s: &str) -> Result<LogDestinationSetting, LogDestinationError> {
        LogDestinationSetting::try_from(s)
    }

    #[test]
    fn stdout_and_absolute_directories_parse() {
        assert_eq!(setting("stdout"), Ok(LogDestinationSetting::Stdout));
        let dir = setting("/srv/iron-vault/log").unwrap();
        assert_eq!(dir.directory(), Some(Path::new("/srv/iron-vault/log")));
        assert_eq!(dir.to_string(), "/srv/iron-vault/log");
    }

    #[test]
    fn malformed_values_are_refused() {
        assert!(matches!(
            setting("logs"),
            Err(LogDestinationError::Path(ConfigPathError::Relative { .. }))
        ));
        assert!(matches!(
            setting("Stdout"),
            Err(LogDestinationError::Path(ConfigPathError::Relative { .. }))
        ));
        assert!(matches!(
            setting(""),
            Err(LogDestinationError::Path(ConfigPathError::Relative { .. }))
        ));
        assert!(matches!(
            setting("/var/log/../etc"),
            Err(LogDestinationError::Path(ConfigPathError::ParentComponent { .. }))
        ));
        [
            "/var/log/a\nb",
            "/var/log/a\tb",
            "/var/log/a\x1b[2J",
            "/var/log/a\x7f",
            "/var/log/a\0b",
        ]
        .iter()
        .for_each(|v| {
            let err = setting(v).unwrap_err();
            assert!(matches!(err, LogDestinationError::ControlCharacter { .. }), "{err}");
            assert!(!err.to_string().chars().any(char::is_control), "{err}");
        });
    }

    #[test]
    fn directory_inside_or_equal_to_a_reserved_directory_is_refused() {
        let reserved = [
            ("state directory", Path::new("/var/lib/iron-vault")),
            ("config directory", Path::new("/etc/iron-vault")),
        ];
        ["/var/lib/iron-vault", "/var/lib/iron-vault/logs", "/etc/iron-vault/log"]
            .iter()
            .for_each(|d| {
                let err = setting(d).unwrap().check_outside(&reserved).unwrap_err();
                assert!(matches!(err, LogDestinationError::InsideReserved { .. }), "{err}");
            });
        ["/var/lib/iron-vault-log", "/var/lib", "/var/log/iron-vault"]
            .iter()
            .for_each(|d| assert_eq!(setting(d).unwrap().check_outside(&reserved), Ok(()), "{d}"));
        assert_eq!(LogDestinationSetting::Stdout.check_outside(&reserved), Ok(()));
    }
}
