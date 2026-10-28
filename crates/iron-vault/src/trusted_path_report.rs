//! The trusted-path report: every trusted path a deployment names, checked in a fixed order, for startup and `status`.
//!
//! This module only reports. Whether an unsafe or unchecked path stops the service is the deployment profile's
//! decision.

use std::path::{Path, PathBuf};

use crate::path_metadata::{self, CollectError};
use crate::trusted_path::{self, ExpectedOwner, Profile, TrustedPathRule, UnsafePath};

/// The name of the state-directory lock file inside the state directory.
const STATE_LOCK_FILE: &str = "lock";

/// The trusted paths a deployment names, with its profile and expected owner. The running binary is not listed: it
/// is found from the process itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServicePaths {
    /// Who may own the binary and config.
    pub profile: Profile,
    /// Who must own the state and runtime directories and the state files.
    pub owner: ExpectedOwner,
    /// The configuration file. Its directory is checked as the config path's last ancestor.
    pub config: PathBuf,
    /// The state directory.
    pub state_dir: PathBuf,
    /// The runtime directory holding the service's sockets, when the deployment uses one.
    pub runtime_dir: Option<PathBuf>,
}

/// Why a trusted path is not trusted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PathFailure {
    /// A component broke its rule.
    #[error(transparent)]
    Unsafe(#[from] UnsafePath),
    /// The path's metadata could not be collected, so it went unchecked.
    #[error(transparent)]
    Uncollected(#[from] CollectError),
}

/// One checked trusted path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedPathEntry {
    /// The rule the path was checked against.
    pub rule: TrustedPathRule,
    /// The path as the service names it; empty for the binary when the process could not name its own executable.
    pub path: PathBuf,
    /// Whether the path is trusted.
    pub outcome: Result<(), PathFailure>,
}

/// Every trusted path, in a fixed order: binary, config, state directory, state lock file, then runtime directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedPathReport {
    /// The checked paths, in report order.
    pub entries: Vec<TrustedPathEntry>,
}

impl TrustedPathReport {
    /// Checks the running binary and every path in `paths`.
    pub fn check(paths: &ServicePaths) -> Self {
        let named = [
            Some((TrustedPathRule::Config, paths.config.clone())),
            Some((TrustedPathRule::StateDir, paths.state_dir.clone())),
            Some((TrustedPathRule::StateFile, paths.state_dir.join(STATE_LOCK_FILE))),
            paths.runtime_dir.clone().map(|dir| (TrustedPathRule::RuntimeDir, dir)),
        ];
        let entries = named.into_iter().flatten().map(|(rule, path)| TrustedPathEntry {
            outcome: check_path(rule, paths.profile, paths.owner, &path),
            rule,
            path,
        });
        Self {
            entries: std::iter::once(binary_entry(paths.profile, paths.owner)).chain(entries).collect(),
        }
    }
}

/// Collects `path`'s metadata and checks it against `rule`.
pub fn check_path(rule: TrustedPathRule, profile: Profile, owner: ExpectedOwner, path: &Path) -> Result<(), PathFailure> {
    let components = path_metadata::collect(path)?;
    Ok(trusted_path::check(rule, profile, owner, &components)?)
}

/// The running binary's entry: it must still be the file the process started from, and pass the binary rule.
fn binary_entry(profile: Profile, owner: ExpectedOwner) -> TrustedPathEntry {
    let rule = TrustedPathRule::Binary;
    match std::env::current_exe() {
        Ok(path) => {
            let outcome = path_metadata::ensure_running_binary(&path)
                .map_err(PathFailure::from)
                .and_then(|()| check_path(rule, profile, owner, &path));
            TrustedPathEntry { rule, path, outcome }
        }
        Err(e) => {
            let outcome = Err(PathFailure::Uncollected(CollectError::Io {
                path: PathBuf::new(),
                kind: e.kind(),
            }));
            TrustedPathEntry {
                rule,
                path: PathBuf::new(),
                outcome,
            }
        }
    }
}
